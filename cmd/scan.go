package cmd

import (
	"fmt"
	"os"

	"github.com/leviathan-offsec/FenrirLVX/pkg/banner"
	"github.com/leviathan-offsec/FenrirLVX/pkg/engine"
	"github.com/spf13/cobra"
)

var scanTarget string

var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Basic WordPress scan (no Shodan)",
	Run: func(cmd *cobra.Command, args []string) {
		if scanTarget == "" {
			fmt.Println("[-] Target required. Use -t <url>")
			os.Exit(1)
		}

		banner.Print()
		tech, resp, body := engine.Fingerprint(scanTarget)
		if body == nil {
			return
		}

		plugins, themes := engine.Enumerate(scanTarget, body)
		if _, ok := tech["WordPress"]; !ok {
			fmt.Printf("  %s[-] Not a WordPress site.%s\n", banner.Cyan, banner.Reset)
			return
		}

		db, err := engine.LoadVulnDB("vuln_db.json")
		if err != nil {
			fmt.Printf("  %s[-] Load vuln DB: %v%s\n", banner.Red, err, banner.Reset)
			return
		}

		vulns := engine.CheckVulns(plugins, db, true)

		f := &engine.Finding{
			Target:   scanTarget,
			Hostname: scanTarget,
			IP:       engine.ResolveIP(scanTarget),
			Plugins:  plugins,
			Themes:   themes,
			Vulns:    vulns,
		}
		if resp != nil {
			f.StatusCode = resp.StatusCode
			f.ServerHeader = resp.Header.Get("Server")
		}

		if len(vulns) > 0 {
			f.Emails = engine.ExtractContactEmails(body, scanTarget)
			base := "https://" + scanTarget
			hits := engine.EnrichWithChangelog(f, base)
			score := engine.ConfidenceScore(f, hits)
			fmt.Print(f.Display(score, hits))
		} else {
			fmt.Print(f.Display(0, 0))
		}
	},
}

func init() {
	scanCmd.Flags().StringVarP(&scanTarget, "target", "t", "", "Target URL")
	rootCmd.AddCommand(scanCmd)
}
