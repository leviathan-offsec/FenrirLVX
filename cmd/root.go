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
		cmd.Help()
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
