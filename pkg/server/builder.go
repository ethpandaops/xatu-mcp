package server

import (
	"context"
	"fmt"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/clickhouse"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
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
	ClickHouse       clickhouse.Client
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

	// Create ClickHouse client
	chClient, err := b.buildClickHouse()
	if err != nil {
		// Clean up sandbox on failure
		_ = sandboxSvc.Stop(ctx)

		return nil, fmt.Errorf("building clickhouse client: %w", err)
	}

	// Create tool registry and register tools
	toolReg := b.buildToolRegistry(sandboxSvc)

	// Create resource registry and register resources
	resourceReg := b.buildResourceRegistry(chClient)

	// Create and return the server service (sandbox is passed for lifecycle management)
	return NewService(
		b.log,
		b.cfg.Server,
		toolReg,
		resourceReg,
		sandboxSvc,
	), nil
}

// buildSandbox creates the sandbox service.
func (b *Builder) buildSandbox() (sandbox.Service, error) {
	return sandbox.New(b.cfg.Sandbox, b.log)
}

// buildClickHouse creates the ClickHouse client.
func (b *Builder) buildClickHouse() (clickhouse.Client, error) {
	clusters := b.cfg.ClickHouse.ToClusters()

	return clickhouse.NewClient(b.log, clusters), nil
}

// buildToolRegistry creates and populates the tool registry.
func (b *Builder) buildToolRegistry(sandboxSvc sandbox.Service) tool.Registry {
	reg := tool.NewRegistry(b.log)

	// Register execute_python tool
	reg.Register(tool.NewExecutePythonTool(b.log, sandboxSvc, b.cfg))

	// Register file tools
	reg.Register(tool.NewListOutputFilesTool(b.log))
	reg.Register(tool.NewGetOutputFileTool(b.log))

	b.log.WithField("tool_count", len(reg.List())).Info("Tool registry built")

	return reg
}

// buildResourceRegistry creates and populates the resource registry.
func (b *Builder) buildResourceRegistry(chClient clickhouse.Client) resource.Registry {
	reg := resource.NewRegistry(b.log)

	// Create cluster provider adapter
	provider := newClusterProviderAdapter(chClient)

	// Create schema client factory
	clientFactory := func(clusterName string) (resource.SchemaClient, error) {
		return newSchemaClientAdapter(chClient, clusterName), nil
	}

	// Register schema resources
	resource.RegisterSchemaResources(b.log, reg, provider, clientFactory)

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

// buildSandboxEnv builds the environment variables for sandbox execution.
func (b *Builder) buildSandboxEnv() map[string]string {
	env := make(map[string]string, 20)

	// Add ClickHouse cluster configurations
	if b.cfg.ClickHouse.Xatu != nil {
		b.addClusterEnv(env, "XATU", b.cfg.ClickHouse.Xatu)
	}

	if b.cfg.ClickHouse.XatuExperimental != nil {
		b.addClusterEnv(env, "XATU_EXPERIMENTAL", b.cfg.ClickHouse.XatuExperimental)
	}

	if b.cfg.ClickHouse.XatuCBT != nil {
		b.addClusterEnv(env, "XATU_CBT", b.cfg.ClickHouse.XatuCBT)
	}

	// Add Prometheus configuration
	if b.cfg.Prometheus != nil && b.cfg.Prometheus.URL != "" {
		env["XATU_PROMETHEUS_URL"] = b.cfg.Prometheus.URL
	}

	// Add Loki configuration
	if b.cfg.Loki != nil && b.cfg.Loki.URL != "" {
		env["XATU_LOKI_URL"] = b.cfg.Loki.URL
	}

	// Add S3 storage configuration
	if b.cfg.Storage != nil {
		env["XATU_S3_ENDPOINT"] = b.cfg.Storage.Endpoint
		env["XATU_S3_ACCESS_KEY"] = b.cfg.Storage.AccessKey
		env["XATU_S3_SECRET_KEY"] = b.cfg.Storage.SecretKey
		env["XATU_S3_BUCKET"] = b.cfg.Storage.Bucket
		env["XATU_S3_REGION"] = b.cfg.Storage.Region

		if b.cfg.Storage.PublicURLPrefix != "" {
			env["XATU_S3_PUBLIC_URL_PREFIX"] = b.cfg.Storage.PublicURLPrefix
		}
	}

	return env
}

// addClusterEnv adds environment variables for a ClickHouse cluster.
func (b *Builder) addClusterEnv(env map[string]string, prefix string, cluster *config.ClusterConfig) {
	env[prefix+"_CLICKHOUSE_HOST"] = cluster.Host
	env[prefix+"_CLICKHOUSE_PORT"] = fmt.Sprintf("%d", cluster.Port)
	env[prefix+"_CLICKHOUSE_PROTOCOL"] = cluster.Protocol
	env[prefix+"_CLICKHOUSE_USER"] = cluster.User
	env[prefix+"_CLICKHOUSE_PASSWORD"] = cluster.Password
	env[prefix+"_CLICKHOUSE_DATABASE"] = cluster.Database
}

// clusterProviderAdapter adapts clickhouse.Client to resource.ClusterProvider.
type clusterProviderAdapter struct {
	client clickhouse.Client
}

func newClusterProviderAdapter(client clickhouse.Client) resource.ClusterProvider {
	return &clusterProviderAdapter{client: client}
}

func (a *clusterProviderAdapter) GetCluster(name string) (*clickhouse.ClusterInfo, bool) {
	return a.client.GetCluster(name)
}

func (a *clusterProviderAdapter) ListClusters() []*clickhouse.ClusterInfo {
	infos := a.client.ListClusters()
	result := make([]*clickhouse.ClusterInfo, len(infos))

	for i := range infos {
		result[i] = &infos[i]
	}

	return result
}

// schemaClientAdapter adapts clickhouse.Client to resource.SchemaClient.
type schemaClientAdapter struct {
	client      clickhouse.Client
	clusterName string
}

func newSchemaClientAdapter(client clickhouse.Client, clusterName string) resource.SchemaClient {
	return &schemaClientAdapter{
		client:      client,
		clusterName: clusterName,
	}
}

func (a *schemaClientAdapter) ListTables(ctx context.Context) ([]clickhouse.TableInfo, error) {
	return a.client.ListTables(ctx, a.clusterName)
}

func (a *schemaClientAdapter) GetTableInfo(ctx context.Context, tableName string) (*clickhouse.TableInfo, error) {
	return a.client.GetTableInfo(ctx, a.clusterName, tableName)
}

func (a *schemaClientAdapter) GetTableSchema(ctx context.Context, tableName string) ([]clickhouse.ColumnInfo, error) {
	return a.client.GetTableSchema(ctx, a.clusterName, tableName)
}
