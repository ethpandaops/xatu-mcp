// Package main is the entry point for xatu-mcp.
package main

import (
	"os"

	"github.com/ethpandaops/xatu-mcp/cmd/xatu-mcp/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
