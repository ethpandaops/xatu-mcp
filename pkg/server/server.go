// Package server provides the MCP server implementation for xatu-mcp.
package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/internal/version"
	"github.com/ethpandaops/xatu-mcp/pkg/auth"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/grafana"
	"github.com/ethpandaops/xatu-mcp/pkg/observability"
	"github.com/ethpandaops/xatu-mcp/pkg/resource"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
	"github.com/ethpandaops/xatu-mcp/pkg/tool"
)

// Transport constants.
const (
	TransportStdio          = "stdio"
	TransportSSE            = "sse"
	TransportStreamableHTTP = "streamable-http"
)

// Service is the main MCP server service.
type Service interface {
	// Start initializes and starts the MCP server.
	Start(ctx context.Context) error
	// Stop gracefully shuts down the server.
	Stop() error
}

// service implements the Service interface.
type service struct {
	log              logrus.FieldLogger
	cfg              config.ServerConfig
	authCfg          config.AuthConfig
	toolRegistry     tool.Registry
	resourceRegistry resource.Registry
	sandbox          sandbox.Service
	grafana          grafana.Client
	auth             auth.SimpleService
	mcpServer        *mcpserver.MCPServer
	sseServer        *mcpserver.SSEServer
	httpServer       *http.Server
	mu               sync.Mutex
	done             chan struct{}
	running          bool
}

// NewService creates a new MCP server service.
func NewService(
	log logrus.FieldLogger,
	cfg config.ServerConfig,
	authCfg config.AuthConfig,
	toolRegistry tool.Registry,
	resourceRegistry resource.Registry,
	sandboxSvc sandbox.Service,
	grafanaClient grafana.Client,
	authSvc auth.SimpleService,
) Service {
	return &service{
		log:              log.WithField("component", "server"),
		cfg:              cfg,
		authCfg:          authCfg,
		toolRegistry:     toolRegistry,
		resourceRegistry: resourceRegistry,
		sandbox:          sandboxSvc,
		grafana:          grafanaClient,
		auth:             authSvc,
		done:             make(chan struct{}),
	}
}

// Start initializes and starts the MCP server.
func (s *service) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()

		return errors.New("server already running")
	}
	s.mu.Unlock()

	s.log.WithFields(logrus.Fields{
		"transport": s.cfg.Transport,
		"version":   version.Version,
	}).Info("Starting MCP server")

	// Mark as running only after successful initialization.
	s.mu.Lock()
	s.running = true
	s.mu.Unlock()

	// Create the MCP server
	s.mcpServer = mcpserver.NewMCPServer(
		"xatu-mcp",
		version.Version,
		mcpserver.WithToolCapabilities(true),
		mcpserver.WithResourceCapabilities(true, true),
		mcpserver.WithLogging(),
	)

	// Register tools
	s.registerTools()

	// Register resources
	s.registerResources()

	// Start the appropriate transport
	switch s.cfg.Transport {
	case TransportStdio:
		return s.runStdio(ctx)
	case TransportSSE:
		return s.runSSE(ctx)
	case TransportStreamableHTTP:
		return s.runStreamableHTTP(ctx)
	default:
		return fmt.Errorf("unknown transport: %s", s.cfg.Transport)
	}
}

// Stop gracefully shuts down the server.
func (s *service) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.log.Info("Stopping MCP server")

	close(s.done)
	s.running = false

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.log.WithError(err).Error("Failed to shutdown HTTP server")
		}
	}

	if s.sseServer != nil {
		if err := s.sseServer.Shutdown(shutdownCtx); err != nil {
			s.log.WithError(err).Error("Failed to shutdown SSE server")
		}
	}

	// Stop the auth service.
	if s.auth != nil {
		if err := s.auth.Stop(); err != nil {
			s.log.WithError(err).Error("Failed to stop auth service")
		}
	}

	// Stop the Grafana client.
	if s.grafana != nil {
		if err := s.grafana.Stop(); err != nil {
			s.log.WithError(err).Error("Failed to stop Grafana client")
		}
	}

	// Stop the sandbox service.
	if s.sandbox != nil {
		if err := s.sandbox.Stop(shutdownCtx); err != nil {
			s.log.WithError(err).Error("Failed to stop sandbox service")
		}
	}

	s.log.Info("MCP server stopped")

	return nil
}

// registerTools registers all tools with the MCP server.
func (s *service) registerTools() {
	for _, def := range s.toolRegistry.Definitions() {
		s.log.WithField("tool", def.Tool.Name).Debug("Registering tool with MCP server")

		// Wrap the handler to add metrics
		handler := s.wrapToolHandler(def.Tool.Name, def.Handler)
		s.mcpServer.AddTool(def.Tool, handler)
	}
}

// registerResources registers all resources with the MCP server.
func (s *service) registerResources() {
	// Register static resources
	for _, res := range s.resourceRegistry.ListStatic() {
		s.log.WithField("uri", res.URI).Debug("Registering static resource with MCP server")

		uri := res.URI
		s.mcpServer.AddResource(res, s.createResourceHandler(uri))
	}

	// Register template resources
	for _, tmpl := range s.resourceRegistry.ListTemplates() {
		templateURI := ""
		if tmpl.URITemplate != nil {
			templateURI = tmpl.URITemplate.Raw()
		}

		s.log.WithField("template", templateURI).Debug("Registering template resource with MCP server")

		s.mcpServer.AddResourceTemplate(tmpl, s.createResourceTemplateHandler())
	}
}

// wrapToolHandler wraps a tool handler with metrics.
func (s *service) wrapToolHandler(toolName string, handler tool.Handler) mcpserver.ToolHandlerFunc {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		startTime := time.Now()

		result, err := handler(ctx, req)

		// Record duration.
		duration := time.Since(startTime).Seconds()
		observability.ToolCallDuration.WithLabelValues(toolName).Observe(duration)

		if err != nil {
			observability.ToolCallsTotal.WithLabelValues(toolName, "error").Inc()

			return nil, err
		}

		observability.ToolCallsTotal.WithLabelValues(toolName, "success").Inc()

		return result, nil
	}
}

// createResourceHandler creates a resource handler for a static resource.
func (s *service) createResourceHandler(uri string) mcpserver.ResourceHandlerFunc {
	return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		content, mimeType, err := s.resourceRegistry.Read(ctx, uri)
		if err != nil {
			return nil, err
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      uri,
				MIMEType: mimeType,
				Text:     content,
			},
		}, nil
	}
}

// createResourceTemplateHandler creates a handler for template resources.
func (s *service) createResourceTemplateHandler() mcpserver.ResourceTemplateHandlerFunc {
	return func(ctx context.Context, req mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
		content, mimeType, err := s.resourceRegistry.Read(ctx, req.Params.URI)
		if err != nil {
			return nil, err
		}

		return []mcp.ResourceContents{
			mcp.TextResourceContents{
				URI:      req.Params.URI,
				MIMEType: mimeType,
				Text:     content,
			},
		}, nil
	}
}

// runStdio runs the server using stdio transport.
func (s *service) runStdio(ctx context.Context) error {
	s.log.Info("Running MCP server with stdio transport")

	// Run in a goroutine and wait for context cancellation
	errCh := make(chan error, 1)

	go func() {
		errCh <- mcpserver.ServeStdio(s.mcpServer)
	}()

	select {
	case <-ctx.Done():
		return nil
	case <-s.done:
		return nil
	case err := <-errCh:
		return err
	}
}

// runSSE runs the server using SSE transport.
func (s *service) runSSE(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	s.log.WithField("address", addr).Info("Running MCP server with SSE transport")

	opts := []mcpserver.SSEOption{
		mcpserver.WithKeepAlive(true),
	}

	if s.cfg.BaseURL != "" {
		opts = append(opts, mcpserver.WithBaseURL(s.cfg.BaseURL))
	}

	s.sseServer = mcpserver.NewSSEServer(s.mcpServer, opts...)

	// Build HTTP handler with auth.
	handler := s.buildHTTPHandler(s.sseServer)

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- s.httpServer.ListenAndServe()
	}()

	observability.ActiveConnections.Inc()
	defer observability.ActiveConnections.Dec()

	select {
	case <-ctx.Done():
		return s.httpServer.Shutdown(ctx)
	case <-s.done:
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}
}

// runStreamableHTTP runs the server using streamable HTTP transport.
func (s *service) runStreamableHTTP(ctx context.Context) error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Host, s.cfg.Port)

	s.log.WithField("address", addr).Info("Running MCP server with streamable-http transport")

	// StreamableHTTP uses the same SSE server infrastructure with different settings.
	opts := []mcpserver.SSEOption{
		mcpserver.WithKeepAlive(true),
	}

	if s.cfg.BaseURL != "" {
		opts = append(opts, mcpserver.WithBaseURL(s.cfg.BaseURL))
	}

	s.sseServer = mcpserver.NewSSEServer(s.mcpServer, opts...)

	// Build HTTP handler with auth.
	handler := s.buildHTTPHandler(s.sseServer)

	s.httpServer = &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)

	go func() {
		errCh <- s.httpServer.ListenAndServe()
	}()

	observability.ActiveConnections.Inc()
	defer observability.ActiveConnections.Dec()

	select {
	case <-ctx.Done():
		return s.httpServer.Shutdown(ctx)
	case <-s.done:
		return nil
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return err
		}

		return nil
	}
}

// buildHTTPHandler creates an HTTP handler with routes.
func (s *service) buildHTTPHandler(mcpHandler http.Handler) http.Handler {
	r := chi.NewRouter()

	// Apply auth middleware if enabled.
	if s.auth != nil && s.auth.Enabled() {
		r.Use(s.auth.Middleware())
	}

	// Mount auth routes (discovery endpoints, OAuth flow).
	if s.auth != nil {
		s.auth.MountRoutes(r)
	}

	// Health endpoints.
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})
	r.Get("/ready", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready"))
	})

	// Mount MCP handler.
	r.Handle("/sse", mcpHandler)
	r.Handle("/sse/*", mcpHandler)
	r.Handle("/message", mcpHandler)
	r.Handle("/message/*", mcpHandler)

	return r
}

// Compile-time interface compliance check.
var _ Service = (*service)(nil)
