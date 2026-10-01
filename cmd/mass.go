package cmd

import (
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/leviathan-offsec/FenrirLVX/pkg/banner"
	"github.com/leviathan-offsec/FenrirLVX/pkg/engine"
	"github.com/leviathan-offsec/FenrirLVX/pkg/shodan"
	"github.com/spf13/cobra"
)

var (
	massQuery     string
	massPages     int
	massKey       string
	massDelay     int
	massPrecision bool
)

var massCmd = &cobra.Command{
	Use:   "mass",
	Short: "Mass WordPress scanning via Shodan",
	Run: func(cmd *cobra.Command, args []string) {
		if massKey == "" {
			fmt.Println("[-] Shodan API key required. Use -k <key>")
			os.Exit(1)
		}
		banner.Print()
		fmt.Printf("%s[*]%s Querying Shodan: %s%s\n", banner.Green, banner.Reset, massQuery, banner.Reset)
		fmt.Printf("%s[*]%s Pages: %d (~%d targets), delay: %ds%s\n\n",
			banner.Green, banner.Reset,
			massPages, massPages*100, massDelay, banner.Reset)
		targets, err := shodan.SearchHosts(massKey, massQuery, massPages, massDelay)
		if err != nil {
			fmt.Printf("[-] Shodan: %v\n", err)
			os.Exit(1)
		}
		if len(targets) == 0 {
			fmt.Println("[-] No targets.")
			os.Exit(1)
		}

		fmt.Printf("\n%s[+]%s Scanning %d targets...%s\n\n",
			banner.Green, banner.Reset, len(targets), banner.Reset)

		db, err := engine.LoadVulnDB("vuln_db.json")
		if err != nil {
			fmt.Printf("[-] Load DB: %v\n", err)
			os.Exit(1)
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, 10)
		var mu sync.Mutex

		var (
			vulnCount      int
			pluginCount    int
			processedCount int
			honeypotCount  int
		)

		for _, target := range targets {
			wg.Add(1)
			go func(t shodan.Target) {
				defer wg.Done()
				sem <- struct{}{}
				defer func() { <-sem }()

				start := time.Now()
				var body []byte
				var resp *http.Response

				if t.Hostname != "" {
					_, resp, body = engine.Fingerprint(t.Hostname)
				}
				if body == nil {
					_, resp, body = engine.FingerprintWithIP(t.IP, t.Hostname)
				}
				if body == nil {
					return
				}
				elapsed := time.Since(start)

				hp := engine.DetectHoneypot(resp, body, elapsed, 0)
				if hp.IsHoneypot {
					mu.Lock()
					honeypotCount++
					processedCount++
					fmt.Printf("%s[SKIP]%s %s — %s\n", banner.Yellow, banner.Reset, t.IP, hp.Reason)
					mu.Unlock()
					return
				}

				plugins, themes := engine.Enumerate(t.IP, body)
				if len(plugins) == 0 {
					return
				}

				hp = engine.DetectHoneypot(resp, body, elapsed, len(plugins))
				if hp.IsHoneypot {
					mu.Lock()
					honeypotCount++
					processedCount++
					fmt.Printf("%s[SKIP]%s %s — %s\n", banner.Yellow, banner.Reset, t.IP, hp.Reason)
					mu.Unlock()
					return
				}

				vulns := engine.CheckVulns(plugins, db, massPrecision)
				cov := engine.SummarizeCoverage(plugins, db, massPrecision)

				f := &engine.Finding{
					Target:       t.IP,
					Hostname:     t.Hostname,
					IP:           t.IP,
					Plugins:      plugins,
					Themes:       themes,
					Vulns:        vulns,
					Coverage:     cov,
					FetchedAt:    time.Now(),
					ScanDuration: elapsed,
				}
				if resp != nil {
					f.StatusCode = resp.StatusCode
					f.ServerHeader = resp.Header.Get("Server")
				}

				if len(vulns) > 0 {
					f.Emails = engine.ExtractContactEmails(body, t.Hostname)
					base := "https://" + t.IP
					if t.Hostname != "" {
						base = "https://" + t.Hostname
					}
					// security.txt
					if st := engine.FetchSecurityTxt(base); len(st) > 0 {
						f.Emails = append(st, f.Emails...)
					}
					hits := engine.EnrichWithChangelog(f, base)
					score := engine.ConfidenceScore(f, hits)

					mu.Lock()
					processedCount++
					pluginCount += len(plugins)
					vulnCount++
					fmt.Print(f.Display(score, hits))
					mu.Unlock()
					return
				}

				mu.Lock()
				processedCount++
				pluginCount += len(plugins)
				fmt.Print(f.Display(0, 0))
				mu.Unlock()
			}(target)
		}

		wg.Wait()

		fmt.Printf("\n%s============================%s\n", banner.Cyan, banner.Reset)
		fmt.Printf("%sFENRIR MASS SCAN SUMMARY%s\n", banner.Cyan, banner.Reset)
		fmt.Printf("%s============================%s\n", banner.Cyan, banner.Reset)
		fmt.Printf("  Targets queried:      %d\n", len(targets))
		fmt.Printf("  Targets processed:    %d\n", processedCount)
		fmt.Printf("  Honeypots skipped:    %d\n", honeypotCount)
		fmt.Printf("  Plugins found:        %d\n", pluginCount)
		fmt.Printf("  %sVulnerable targets:   %d%s\n", banner.Red, vulnCount, banner.Reset)
		fmt.Printf("  Clean:                %d\n", processedCount-vulnCount-honeypotCount)
		fmt.Printf("%s============================%s\n", banner.Cyan, banner.Reset)
	},
}

func init() {
	massCmd.Flags().StringVarP(&massQuery, "query", "q", `http.component:"WordPress" http.status:200`, "Shodan query")
	massCmd.Flags().IntVarP(&massPages, "pages", "p", 1, "Shodan pages (100 each)")
	massCmd.Flags().IntVarP(&massDelay, "delay", "d", 5, "Seconds between Shodan pages")
	massCmd.Flags().StringVarP(&massKey, "shodan-key", "k", "", "Shodan API key")
	massCmd.Flags().BoolVarP(&massPrecision, "precision", "P", true, "Exact version matches only")
	rootCmd.AddCommand(massCmd)
}
