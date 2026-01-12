package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/ethpandaops/xatu-mcp/internal/version"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("xatu-mcp", version.Full())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
