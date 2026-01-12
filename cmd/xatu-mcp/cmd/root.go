// Package cmd provides CLI commands for xatu-mcp.
package cmd

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	cfgFile  string
	logLevel string
	log      *logrus.Logger
)

func init() {
	log = logrus.New()
	log.SetOutput(os.Stderr)
	log.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})
}

var rootCmd = &cobra.Command{
	Use:   "xatu-mcp",
	Short: "MCP server for Ethereum network analytics via Xatu data",
	Long: `xatu-mcp is a Model Context Protocol (MCP) server that provides
secure sandboxed Python execution for Ethereum data analysis.

It connects to Xatu ClickHouse clusters and exposes tools and resources
for querying blockchain data through Claude and other MCP clients.`,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		level, err := logrus.ParseLevel(strings.ToLower(logLevel))
		if err != nil {
			return err
		}
		log.SetLevel(level)
		return nil
	},
	SilenceUsage: true,
}

// Execute runs the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "",
		"config file (default: CONFIG_PATH env var or config.yaml)")
	rootCmd.PersistentFlags().StringVar(&logLevel, "log-level", "info",
		"log level (debug, info, warn, error)")
}
