package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/leviathan-offsec/FenrirLVX/pkg/banner"
	"github.com/leviathan-offsec/FenrirLVX/pkg/engine"
	"github.com/leviathan-offsec/FenrirLVX/pkg/shodan"
	"github.com/spf13/cobra"
)

var (
	wpTarget string
	wpKey    string
)

var wordpressCmd = &cobra.Command{
	Use:   "wordpress",
	Short: "Single target: Shodan recon + tech detection + XML-RPC",
	Run: func(cmd *cobra.Command, args []string) {
		if wpTarget == "" {
			fmt.Println("[-] Target required. Use -t <domain>")
			os.Exit(1)
		}

		banner.Print()

		clean := strings.TrimPrefix(wpTarget, "https://")
		clean = strings.TrimPrefix(clean, "http://")
		clean = strings.Split(clean, "/")[0]

		fmt.Printf("%s[1] SHODAN RECON%s\n", banner.Cyan, banner.Reset)
		if wpKey != "" {
			if ip := engine.ResolveIP(clean); ip != "" {
				host, err := shodan.GetHost(wpKey, ip)
				if err == nil {
					fmt.Printf("  IP:    %s\n", host.IPStr)
					fmt.Printf("  Org:   %s\n", host.Org)
					fmt.Printf("  Ports: %v\n", host.Ports)
				} else {
					fmt.Printf("  %s[-] %v%s\n", banner.Cyan, err, banner.Reset)
				}
			}
		} else {
			fmt.Printf("  %s[-] No Shodan key. Skipping.%s\n", banner.Cyan, banner.Reset)
		}

		fmt.Printf("\n%s[2] TECH & ENUM%s\n", banner.Cyan, banner.Reset)
		tech, resp, body := engine.Fingerprint(wpTarget)
		if body == nil {
			return
		}
		plugins, themes := engine.Enumerate(wpTarget, body)

		if _, ok := tech["WordPress"]; !ok {
			fmt.Printf("  %s[-] Not WordPress.%s\n", banner.Cyan, banner.Reset)
			return
		}

		db, _ := engine.LoadVulnDB("vuln_db.json")
		vulns := engine.CheckVulns(plugins, db, true)
		cov := engine.SummarizeCoverage(plugins, db, true)

		f := &engine.Finding{
			Target:   clean,
			Hostname: clean,
			IP:       engine.ResolveIP(clean),
			Plugins:  plugins,
			Themes:   themes,
			Vulns:    vulns,
			Coverage: cov,
		}
		if resp != nil {
			f.StatusCode = resp.StatusCode
			f.ServerHeader = resp.Header.Get("Server")
		}

		if len(vulns) > 0 {
			f.Emails = engine.ExtractContactEmails(body, clean)
			base := "https://" + clean
			hits := engine.EnrichWithChangelog(f, base)
			score := engine.ConfidenceScore(f, hits)
			fmt.Print(f.Display(score, hits))
		} else {
			fmt.Print(f.Display(0, 0))
		}

		fmt.Printf("\n%s[3] XML-RPC%s\n", banner.Cyan, banner.Reset)
		if engine.CheckXMLRPC("https://" + clean + "/xmlrpc.php") {
			fmt.Printf("  %s[!] ENABLED — brute force vector%s\n", banner.Red, banner.Reset)
		} else {
			fmt.Printf("  %s[+] disabled or blocked%s\n", banner.Cyan, banner.Reset)
		}
	},
}

func init() {
	wordpressCmd.Flags().StringVarP(&wpTarget, "target", "t", "", "Target domain")
	wordpressCmd.Flags().StringVarP(&wpKey, "shodan-key", "k", "", "Shodan API key")
	rootCmd.AddCommand(wordpressCmd)
}
