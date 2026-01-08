package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/auth"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/grafana"
	"github.com/ethpandaops/xatu-mcp/pkg/resource"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
	"github.com/ethpandaops/xatu-mcp/pkg/tool"
)

// Dependencies contains all the services required to run the MCP server.
type Dependencies struct {
	Logger           logrus.FieldLogger
	Config           *config.Config
	ToolRegistry     tool.Registry
	ResourceRegistry resource.Registry
	Sandbox          sandbox.Service
	Grafana          grafana.Client
	Auth             auth.SimpleService
}

// Builder constructs and wires all dependencies for the MCP server.
type Builder struct {
	log logrus.FieldLogger
	cfg *config.Config
}

// NewBuilder creates a new server builder.
func NewBuilder(log logrus.FieldLogger, cfg *config.Config) *Builder {
	return &Builder{
		log: log.WithField("component", "builder"),
		cfg: cfg,
	}
}

// Build constructs all dependencies and returns the server service.
func (b *Builder) Build(ctx context.Context) (Service, error) {
	b.log.Info("Building xatu-mcp server dependencies")

	// Create sandbox service
	sandboxSvc, err := b.buildSandbox()
	if err != nil {
		return nil, fmt.Errorf("building sandbox: %w", err)
	}

	// Start the sandbox service to initialize Docker client
	if err := sandboxSvc.Start(ctx); err != nil {
		return nil, fmt.Errorf("starting sandbox: %w", err)
	}

	b.log.WithField("backend", sandboxSvc.Name()).Info("Sandbox service started")

	// Create Grafana client
	grafanaClient := b.buildGrafana()

	// Start the Grafana client to initialize and discover datasources
	if err := grafanaClient.Start(ctx); err != nil {
		// Clean up sandbox on failure
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("starting grafana client: %w", err)
	}

	b.log.Info("Grafana client started")

	// Create auth service
	authSvc, err := b.buildAuth()
	if err != nil {
		// Clean up on failure
		_ = sandboxSvc.Stop(ctx)
		_ = grafanaClient.Stop()

		return nil, fmt.Errorf("building auth: %w", err)
	}

	// Start the auth service
	if err := authSvc.Start(ctx); err != nil {
		// Clean up on failure
		_ = sandboxSvc.Stop(ctx)
		_ = grafanaClient.Stop()

		return nil, fmt.Errorf("starting auth: %w", err)
	}

	if authSvc.Enabled() {
		b.log.Info("Auth service started")
	}

	// Create tool registry and register tools
	toolReg := b.buildToolRegistry(sandboxSvc, b.cfg.Storage)

	// Create resource registry and register resources
	resourceReg := b.buildResourceRegistry(grafanaClient)

	// Create and return the server service
	return NewService(
		b.log,
		b.cfg.Server,
		b.cfg.Auth,
		toolReg,
		resourceReg,
		sandboxSvc,
		grafanaClient,
		authSvc,
	), nil
}

// buildSandbox creates the sandbox service.
func (b *Builder) buildSandbox() (sandbox.Service, error) {
	return sandbox.New(b.cfg.Sandbox, b.log)
}

// buildGrafana creates the Grafana client.
func (b *Builder) buildGrafana() grafana.Client {
	return grafana.NewClient(b.log, &grafana.Config{
		URL:            b.cfg.Grafana.URL,
		ServiceToken:   b.cfg.Grafana.ServiceToken,
		Timeout:        b.cfg.Grafana.Timeout,
		DatasourceUIDs: b.cfg.Grafana.DatasourceUIDs,
	})
}

// buildAuth creates the auth service.
func (b *Builder) buildAuth() (auth.SimpleService, error) {
	return auth.NewSimpleService(b.log, b.cfg.Auth, b.cfg.Server.BaseURL)
}

// buildToolRegistry creates and populates the tool registry.
func (b *Builder) buildToolRegistry(
	sandboxSvc sandbox.Service,
	storageCfg *config.StorageConfig,
) tool.Registry {
	reg := tool.NewRegistry(b.log)

	// Register execute_python tool
	reg.Register(tool.NewExecutePythonTool(b.log, sandboxSvc, b.cfg))

	// Register file tools
	reg.Register(tool.NewListOutputFilesTool(b.log))
	reg.Register(tool.NewGetOutputFileTool(b.log))

	// Register get_image tool if storage is configured
	if storageCfg != nil && storageCfg.PublicURLPrefix != "" {
		reg.Register(tool.NewGetImageTool(b.log, tool.GetImageConfig{
			PublicURLPrefix:   storageCfg.PublicURLPrefix,
			InternalURLPrefix: storageCfg.InternalURLPrefix,
		}))

		b.log.WithFields(logrus.Fields{
			"public_url_prefix":   storageCfg.PublicURLPrefix,
			"internal_url_prefix": storageCfg.InternalURLPrefix,
		}).Debug("Registered get_image tool")
	}

	b.log.WithField("tool_count", len(reg.List())).Info("Tool registry built")

	return reg
}

// buildResourceRegistry creates and populates the resource registry.
func (b *Builder) buildResourceRegistry(grafanaClient grafana.Client) resource.Registry {
	reg := resource.NewRegistry(b.log)

	// Register datasources resources
	resource.RegisterDatasourcesResources(b.log, reg, grafanaClient)

	// Register examples resources
	resource.RegisterExamplesResources(b.log, reg)

	// Register networks resources
	resource.RegisterNetworksResources(b.log, reg)

	// Register API resources
	resource.RegisterAPIResources(b.log, reg)

	staticCount := len(reg.ListStatic())
	templateCount := len(reg.ListTemplates())
	b.log.WithFields(logrus.Fields{
		"static_count":   staticCount,
		"template_count": templateCount,
	}).Info("Resource registry built")

	return reg
}
