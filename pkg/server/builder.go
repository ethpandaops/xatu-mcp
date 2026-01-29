package server

import (
	"context"
	"fmt"
	"os"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/auth"
	"github.com/ethpandaops/mcp/pkg/config"
	"github.com/ethpandaops/mcp/pkg/embedding"
	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/proxy"
	"github.com/ethpandaops/mcp/pkg/proxy/handlers"
	"github.com/ethpandaops/mcp/pkg/resource"
	"github.com/ethpandaops/mcp/pkg/sandbox"
	"github.com/ethpandaops/mcp/pkg/tool"

	clickhouseplugin "github.com/ethpandaops/mcp/plugins/clickhouse"
	lokiplugin "github.com/ethpandaops/mcp/plugins/loki"
	prometheusplugin "github.com/ethpandaops/mcp/plugins/prometheus"
)

// Dependencies contains all the services required to run the MCP server.
type Dependencies struct {
	Logger           logrus.FieldLogger
	Config           *config.Config
	ToolRegistry     tool.Registry
	ResourceRegistry resource.Registry
	Sandbox          sandbox.Service
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
	b.log.Info("Building MCP server dependencies")

	// Build and initialize plugin registry.
	pluginReg, err := b.buildPluginRegistry()
	if err != nil {
		return nil, fmt.Errorf("building plugin registry: %w", err)
	}

	// Create sandbox service.
	sandboxSvc, err := b.buildSandbox()
	if err != nil {
		return nil, fmt.Errorf("building sandbox: %w", err)
	}

	// Start the sandbox service to initialize Docker client.
	if err := sandboxSvc.Start(ctx); err != nil {
		return nil, fmt.Errorf("starting sandbox: %w", err)
	}

	b.log.WithField("backend", sandboxSvc.Name()).Info("Sandbox service started")

	// Start all initialized plugins (e.g., schema discovery).
	if err := pluginReg.StartAll(ctx); err != nil {
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("starting plugins: %w", err)
	}

	b.log.Info("All plugins started")

	// Create and start credential proxy service.
	// Proxy is always enabled - sandbox containers never receive credentials directly.
	proxySvc := b.buildProxy(pluginReg)
	if err := proxySvc.Start(ctx); err != nil {
		pluginReg.StopAll(ctx)
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("starting proxy: %w", err)
	}

	b.log.WithField("url", proxySvc.URL()).Info("Credential proxy started")

	// Create cartographoor client for network discovery.
	cartographoorClient := b.buildCartographoor()

	// Start the cartographoor client to fetch initial network data.
	if err := cartographoorClient.Start(ctx); err != nil {
		_ = proxySvc.Stop(ctx)
		pluginReg.StopAll(ctx)
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("starting cartographoor client: %w", err)
	}

	b.log.Info("Cartographoor client started")

	// Create auth service.
	authSvc, err := b.buildAuth()
	if err != nil {
		_ = cartographoorClient.Stop()
		_ = proxySvc.Stop(ctx)
		pluginReg.StopAll(ctx)
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("building auth: %w", err)
	}

	// Start the auth service.
	if err := authSvc.Start(ctx); err != nil {
		_ = cartographoorClient.Stop()
		_ = proxySvc.Stop(ctx)
		pluginReg.StopAll(ctx)
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("starting auth: %w", err)
	}

	if authSvc.Enabled() {
		b.log.Info("Auth service started")
	}

	// Create embedding model and example index for semantic search.
	exampleIndex, err := b.buildExampleIndex(pluginReg)
	if err != nil {
		_ = authSvc.Stop()
		_ = cartographoorClient.Stop()
		_ = proxySvc.Stop(ctx)
		pluginReg.StopAll(ctx)
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("building example index: %w", err)
	}

	if exampleIndex != nil {
		b.log.Info("Semantic search example index built")
	}

	// Create tool registry and register tools.
	toolReg := b.buildToolRegistry(sandboxSvc, exampleIndex, pluginReg, proxySvc)

	// Create resource registry and register resources.
	resourceReg := b.buildResourceRegistry(cartographoorClient, pluginReg, toolReg)

	// Create and return the server service.
	return NewService(
		b.log,
		b.cfg.Server,
		b.cfg.Auth,
		toolReg,
		resourceReg,
		sandboxSvc,
		authSvc,
	), nil
}

// buildPluginRegistry creates the plugin registry, registers all compiled-in
// plugins, and initializes those with config.
func (b *Builder) buildPluginRegistry() (*plugin.Registry, error) {
	reg := plugin.NewRegistry(b.log)

	// Register all compiled-in plugins.
	reg.Add(clickhouseplugin.New())
	reg.Add(prometheusplugin.New())
	reg.Add(lokiplugin.New())

	// Initialize plugins that have config.
	for _, name := range reg.All() {
		rawYAML, err := b.cfg.PluginConfigYAML(name)
		if err != nil {
			return nil, fmt.Errorf("getting config for plugin %q: %w", name, err)
		}

		if rawYAML == nil {
			b.log.WithField("plugin", name).Debug("Plugin not configured, skipping")

			continue
		}

		if err := reg.InitPlugin(name, rawYAML); err != nil {
			return nil, fmt.Errorf("initializing plugin %q: %w", name, err)
		}
	}

	b.log.WithField("initialized_count", len(reg.Initialized())).Info("Plugin registry built")

	return reg, nil
}

// buildSandbox creates the sandbox service.
func (b *Builder) buildSandbox() (sandbox.Service, error) {
	return sandbox.New(b.cfg.Sandbox, b.log)
}

// buildAuth creates the auth service.
func (b *Builder) buildAuth() (auth.SimpleService, error) {
	return auth.NewSimpleService(b.log, b.cfg.Auth, b.cfg.Server.BaseURL)
}

// buildProxy creates the credential proxy service.
func (b *Builder) buildProxy(pluginReg *plugin.Registry) proxy.Service {
	opts := proxy.Options{
		Config: proxy.Config{
			ListenAddr:  b.cfg.Proxy.ListenAddr,
			TokenTTL:    b.cfg.Proxy.TokenTTL,
			SandboxHost: b.cfg.Proxy.SandboxHost,
		},
	}

	// Collect proxy configs from all plugins.
	for _, p := range pluginReg.Initialized() {
		cfg := p.ProxyConfig()
		if cfg == nil {
			continue
		}

		switch c := cfg.(type) {
		case []handlers.ClickHouseConfig:
			opts.ClickHouse = c
		case []handlers.PrometheusConfig:
			opts.Prometheus = c
		case []handlers.LokiConfig:
			opts.Loki = c
		}
	}

	// Add S3 config from storage config.
	if b.cfg.Storage != nil {
		opts.S3 = &handlers.S3Config{
			Endpoint:        b.cfg.Storage.Endpoint,
			AccessKey:       b.cfg.Storage.AccessKey,
			SecretKey:       b.cfg.Storage.SecretKey,
			Bucket:          b.cfg.Storage.Bucket,
			Region:          b.cfg.Storage.Region,
			PublicURLPrefix: b.cfg.Storage.PublicURLPrefix,
		}
	}

	return proxy.New(b.log, opts)
}

// buildToolRegistry creates and populates the tool registry.
func (b *Builder) buildToolRegistry(
	sandboxSvc sandbox.Service,
	exampleIndex *resource.ExampleIndex,
	pluginReg *plugin.Registry,
	proxySvc proxy.Service,
) tool.Registry {
	reg := tool.NewRegistry(b.log)

	// Register execute_python tool.
	reg.Register(tool.NewExecutePythonTool(b.log, sandboxSvc, b.cfg, pluginReg, proxySvc))

	// Register search_examples tool (requires example index).
	if exampleIndex != nil {
		reg.Register(tool.NewSearchExamplesTool(b.log, exampleIndex, pluginReg))
	}

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

// buildExampleIndex creates the semantic search index for examples.
// Returns nil if semantic search is disabled or model is not available.
func (b *Builder) buildExampleIndex(pluginReg *plugin.Registry) (*resource.ExampleIndex, error) {
	cfg := b.cfg.SemanticSearch
	if cfg.ModelPath == "" {
		return nil, fmt.Errorf("semantic_search.model_path is required")
	}

	// Check if model file exists.
	if _, err := os.Stat(cfg.ModelPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("embedding model not found at %s (run 'make download-models' to fetch it)", cfg.ModelPath)
	}

	embedder, err := embedding.New(cfg.ModelPath, cfg.GPULayers)
	if err != nil {
		return nil, fmt.Errorf("creating embedder: %w", err)
	}

	index, err := resource.NewExampleIndex(b.log, embedder, resource.GetQueryExamples(pluginReg))
	if err != nil {
		_ = embedder.Close()

		return nil, fmt.Errorf("building example index: %w", err)
	}

	return index, nil
}

// buildResourceRegistry creates and populates the resource registry.
func (b *Builder) buildResourceRegistry(
	cartographoorClient resource.CartographoorClient,
	pluginReg *plugin.Registry,
	toolReg tool.Registry,
) resource.Registry {
	reg := resource.NewRegistry(b.log)

	// Register datasources resources (from plugin registry).
	resource.RegisterDatasourcesResources(b.log, reg, pluginReg)

	// Register examples resources (from plugin registry).
	resource.RegisterExamplesResources(b.log, reg, pluginReg)

	// Register networks resources.
	resource.RegisterNetworksResources(b.log, reg, cartographoorClient)

	// Register Python library API resources (from plugin registry).
	resource.RegisterAPIResources(b.log, reg, pluginReg)

	// Register getting-started resource.
	resource.RegisterGettingStartedResources(b.log, reg, toolReg, pluginReg)

	// Register plugin-specific resources (e.g., clickhouse://tables).
	for _, p := range pluginReg.Initialized() {
		if err := p.RegisterResources(b.log, reg); err != nil {
			b.log.WithError(err).WithField("plugin", p.Name()).Warn("Failed to register plugin resources")
		}
	}

	staticCount := len(reg.ListStatic())
	templateCount := len(reg.ListTemplates())

	b.log.WithFields(logrus.Fields{
		"static_count":   staticCount,
		"template_count": templateCount,
	}).Info("Resource registry built")

	return reg
}
