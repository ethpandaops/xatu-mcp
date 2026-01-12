package cmd

import (
	"context"
	"fmt"
	"os/signal"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/observability"
	"github.com/ethpandaops/xatu-mcp/pkg/server"
)

var (
	transport string
	host      string
	port      int
)

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the MCP server",
	Long: `Start the MCP server with the specified transport.

Available transports:
  stdio           - Standard input/output (default, for Claude Desktop)
  sse             - Server-Sent Events over HTTP
  streamable-http - HTTP streaming transport

Examples:
  # Start with stdio transport (for Claude Desktop)
  xatu-mcp serve

  # Start with SSE transport on port 2480
  xatu-mcp serve --transport sse --port 2480

  # Start with custom config
  xatu-mcp serve -c /path/to/config.yaml`,
	RunE: runServe,
}

func init() {
	rootCmd.AddCommand(serveCmd)

	serveCmd.Flags().StringVarP(&transport, "transport", "t", "",
		"Transport protocol (stdio, sse, streamable-http)")
	serveCmd.Flags().StringVar(&host, "host", "",
		"Host to bind to (overrides config, only for HTTP transports)")
	serveCmd.Flags().IntVar(&port, "port", 0,
		"Port to bind to (overrides config, only for HTTP transports)")
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Load configuration
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Apply CLI overrides
	if transport != "" {
		cfg.Server.Transport = transport
	}

	if host != "" {
		cfg.Server.Host = host
	}

	if port != 0 {
		cfg.Server.Port = port
	}

	log.WithFields(logrus.Fields{
		"transport": cfg.Server.Transport,
		"host":      cfg.Server.Host,
		"port":      cfg.Server.Port,
	}).Info("Starting xatu-mcp server")

	// Start observability service
	obsSvc := observability.NewService(log, cfg.Observability)
	if err := obsSvc.Start(ctx); err != nil {
		return fmt.Errorf("starting observability: %w", err)
	}

	defer func() {
		if stopErr := obsSvc.Stop(); stopErr != nil {
			log.WithError(stopErr).Error("Failed to stop observability service")
		}
	}()

	// Build and start the server
	builder := server.NewBuilder(log, cfg)

	svc, err := builder.Build(ctx)
	if err != nil {
		return fmt.Errorf("building server: %w", err)
	}

	// Start the server (this blocks until context is cancelled)
	if err := svc.Start(ctx); err != nil {
		return fmt.Errorf("running server: %w", err)
	}

	log.Info("Shutting down...")

	return svc.Stop()
}
