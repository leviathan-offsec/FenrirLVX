package cmd

import (
	"fmt"
	"os"

	"github.com/leviathan-offsec/FenrirLVX/pkg/banner"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "fenrir",
	Short: "FENRIR — WordPress recon at scale",
	Run: func(cmd *cobra.Command, args []string) {
		banner.Print()
		// Checked, not ignored. With no subcommand this IS the tool's output,
		// so a write failure here means the user got a banner and nothing else.
		if err := cmd.Help(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] cannot render help: %v\n", err)
			os.Exit(1)
		}
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
