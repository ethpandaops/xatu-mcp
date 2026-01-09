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

	// Create cartographoor client for network discovery
	cartographoorClient := b.buildCartographoor()

	// Start the cartographoor client to fetch initial network data
	if err := cartographoorClient.Start(ctx); err != nil {
		// Clean up on failure
		_ = sandboxSvc.Stop(ctx)
		_ = grafanaClient.Stop()

		return nil, fmt.Errorf("starting cartographoor client: %w", err)
	}

	b.log.Info("Cartographoor client started")

	// Create ClickHouse schema client for table discovery (optional)
	schemaClient := b.buildClickHouseSchema(grafanaClient)

	// Start the schema client if configured
	if schemaClient != nil {
		if err := schemaClient.Start(ctx); err != nil {
			// Clean up on failure
			_ = sandboxSvc.Stop(ctx)
			_ = grafanaClient.Stop()
			_ = cartographoorClient.Stop()

			return nil, fmt.Errorf("starting clickhouse schema client: %w", err)
		}

		b.log.Info("ClickHouse schema client started")
	}

	// Create auth service
	authSvc, err := b.buildAuth()
	if err != nil {
		// Clean up on failure
		_ = sandboxSvc.Stop(ctx)
		_ = grafanaClient.Stop()
		_ = cartographoorClient.Stop()

		if schemaClient != nil {
			_ = schemaClient.Stop()
		}

		return nil, fmt.Errorf("building auth: %w", err)
	}

	// Start the auth service
	if err := authSvc.Start(ctx); err != nil {
		// Clean up on failure
		_ = sandboxSvc.Stop(ctx)
		_ = grafanaClient.Stop()
		_ = cartographoorClient.Stop()

		if schemaClient != nil {
			_ = schemaClient.Stop()
		}

		return nil, fmt.Errorf("starting auth: %w", err)
	}

	if authSvc.Enabled() {
		b.log.Info("Auth service started")
	}

	// Create tool registry and register tools
	toolReg := b.buildToolRegistry(sandboxSvc)

	// Create resource registry and register resources
	resourceReg := b.buildResourceRegistry(grafanaClient, cartographoorClient, schemaClient, toolReg)

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
	// Convert config datasource configs to grafana package format
	datasources := make([]grafana.DatasourceConfig, len(b.cfg.Grafana.Datasources))
	for i, ds := range b.cfg.Grafana.Datasources {
		datasources[i] = grafana.DatasourceConfig{
			UID:         ds.UID,
			Description: ds.Description,
		}
	}

	return grafana.NewClient(b.log, &grafana.Config{
		URL:            b.cfg.Grafana.URL,
		ServiceToken:   b.cfg.Grafana.ServiceToken,
		Timeout:        b.cfg.Grafana.Timeout,
		DatasourceUIDs: b.cfg.Grafana.DatasourceUIDs,
		Datasources:    datasources,
	})
}

// buildAuth creates the auth service.
func (b *Builder) buildAuth() (auth.SimpleService, error) {
	return auth.NewSimpleService(b.log, b.cfg.Auth, b.cfg.Server.BaseURL)
}

// buildToolRegistry creates and populates the tool registry.
func (b *Builder) buildToolRegistry(sandboxSvc sandbox.Service) tool.Registry {
	reg := tool.NewRegistry(b.log)

	// Register execute_python tool
	reg.Register(tool.NewExecutePythonTool(b.log, sandboxSvc, b.cfg))

	// Register search_examples tool
	reg.Register(tool.NewSearchExamplesTool(b.log))

	b.log.WithField("tool_count", len(reg.List())).Info("Tool registry built")

	return reg
}

// buildCartographoor creates the cartographoor client for network discovery.
func (b *Builder) buildCartographoor() resource.CartographoorClient {
	return resource.NewCartographoorClient(b.log, resource.CartographoorConfig{
		URL:      resource.DefaultCartographoorURL,
		CacheTTL: resource.DefaultCacheTTL,
		Timeout:  resource.DefaultHTTPTimeout,
	})
}

// buildClickHouseSchema creates the ClickHouse schema client for table discovery.
// Returns nil if schema discovery is not configured.
func (b *Builder) buildClickHouseSchema(grafanaClient grafana.Client) resource.ClickHouseSchemaClient {
	if !b.cfg.SchemaDiscovery.IsEnabled() {
		b.log.Info("Schema discovery is disabled (no datasources configured)")

		return nil
	}

	// Convert config datasource mappings to resource package format
	datasources := make([]resource.DatasourceMapping, len(b.cfg.SchemaDiscovery.Datasources))
	for i, ds := range b.cfg.SchemaDiscovery.Datasources {
		datasources[i] = resource.DatasourceMapping{
			UID:     ds.UID,
			Cluster: ds.Cluster,
		}
	}

	return resource.NewClickHouseSchemaClient(b.log, resource.ClickHouseSchemaConfig{
		RefreshInterval: b.cfg.SchemaDiscovery.RefreshInterval,
		QueryTimeout:    resource.DefaultSchemaQueryTimeout,
		Datasources:     datasources,
	}, grafanaClient)
}

// buildResourceRegistry creates and populates the resource registry.
func (b *Builder) buildResourceRegistry(
	grafanaClient grafana.Client,
	cartographoorClient resource.CartographoorClient,
	schemaClient resource.ClickHouseSchemaClient,
	toolReg tool.Registry,
) resource.Registry {
	reg := resource.NewRegistry(b.log)

	// Register datasources resources
	resource.RegisterDatasourcesResources(b.log, reg, grafanaClient)

	// Register examples resources
	resource.RegisterExamplesResources(b.log, reg)

	// Register networks resources
	resource.RegisterNetworksResources(b.log, reg, cartographoorClient)

	// Register API resources
	resource.RegisterAPIResources(b.log, reg)

	// Register getting-started resource (needs tool registry for dynamic content)
	resource.RegisterGettingStartedResources(b.log, reg, toolReg)

	// Register ClickHouse schema resources if schema discovery is enabled
	if schemaClient != nil {
		resource.RegisterClickHouseSchemaResources(b.log, reg, schemaClient)
	}

	staticCount := len(reg.ListStatic())
	templateCount := len(reg.ListTemplates())
	b.log.WithFields(logrus.Fields{
		"static_count":   staticCount,
		"template_count": templateCount,
	}).Info("Resource registry built")

	return reg
}
