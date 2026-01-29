package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/proxy/handlers"
	"github.com/ethpandaops/mcp/pkg/types"
)

// Compile-time interface check
var _ plugin.Plugin = (*Plugin)(nil)

type Plugin struct {
	cfg          Config
	log          logrus.FieldLogger
	schemaClient ClickHouseSchemaClient
}

func New() *Plugin {
	return &Plugin{}
}

func (p *Plugin) Name() string { return "clickhouse" }

func (p *Plugin) Init(rawConfig []byte) error {
	return yaml.Unmarshal(rawConfig, &p.cfg)
}

func (p *Plugin) ApplyDefaults() {
	for i := range p.cfg.Clusters {
		if p.cfg.Clusters[i].Timeout == 0 {
			p.cfg.Clusters[i].Timeout = 120
		}
	}
	if p.cfg.SchemaDiscovery.RefreshInterval == 0 {
		p.cfg.SchemaDiscovery.RefreshInterval = 15 * time.Minute
	}
}

func (p *Plugin) Validate() error {
	names := make(map[string]struct{}, len(p.cfg.Clusters))
	for i, ch := range p.cfg.Clusters {
		if ch.Name == "" {
			return fmt.Errorf("clusters[%d].name is required", i)
		}
		if _, exists := names[ch.Name]; exists {
			return fmt.Errorf("clusters[%d].name %q is duplicated", i, ch.Name)
		}
		names[ch.Name] = struct{}{}
		if ch.Host == "" {
			return fmt.Errorf("clusters[%d].host is required", i)
		}
		if ch.Database == "" {
			return fmt.Errorf("clusters[%d].database is required", i)
		}
		if ch.Username == "" {
			return fmt.Errorf("clusters[%d].username is required", i)
		}
		if ch.Password == "" {
			return fmt.Errorf("clusters[%d].password is required", i)
		}
	}
	// Validate schema discovery datasources reference valid clusters
	for i, ds := range p.cfg.SchemaDiscovery.Datasources {
		if ds.Name == "" {
			return fmt.Errorf("schema_discovery.datasources[%d].name is required", i)
		}
		if ds.Cluster == "" {
			return fmt.Errorf("schema_discovery.datasources[%d].cluster is required", i)
		}
		if _, exists := names[ds.Name]; !exists {
			return fmt.Errorf("schema_discovery.datasources[%d].name %q does not reference a configured cluster", i, ds.Name)
		}
	}
	return nil
}

// SandboxEnv returns credential-free environment variables for the sandbox.
// Credentials are never passed to sandbox containers - they connect via
// the credential proxy instead.
func (p *Plugin) SandboxEnv() (map[string]string, error) {
	if len(p.cfg.Clusters) == 0 {
		return nil, nil
	}

	// Return datasource info without credentials.
	type datasourceInfo struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Database    string `json:"database"`
	}

	infos := make([]datasourceInfo, 0, len(p.cfg.Clusters))
	for _, cluster := range p.cfg.Clusters {
		infos = append(infos, datasourceInfo{
			Name:        cluster.Name,
			Description: cluster.Description,
			Database:    cluster.Database,
		})
	}

	infosJSON, err := json.Marshal(infos)
	if err != nil {
		return nil, fmt.Errorf("marshaling ClickHouse datasource info: %w", err)
	}

	return map[string]string{
		"ETHPANDAOPS_CLICKHOUSE_DATASOURCES": string(infosJSON),
	}, nil
}

// ProxyConfig returns the configuration needed by the credential proxy.
func (p *Plugin) ProxyConfig() any {
	if len(p.cfg.Clusters) == 0 {
		return nil
	}

	configs := make([]handlers.ClickHouseConfig, 0, len(p.cfg.Clusters))

	for _, cluster := range p.cfg.Clusters {
		host, port := parseHostPort(cluster.Host, 443)

		configs = append(configs, handlers.ClickHouseConfig{
			Name:       cluster.Name,
			Host:       host,
			Port:       port,
			Database:   cluster.Database,
			Username:   cluster.Username,
			Password:   cluster.Password,
			Secure:     cluster.IsSecure(),
			SkipVerify: cluster.SkipVerify,
			Timeout:    cluster.Timeout,
		})
	}

	return configs
}

// parseHostPort extracts host and port from a host:port string.
// Handles IPv6 addresses in bracket notation [::1]:port.
func parseHostPort(hostPort string, defaultPort int) (string, int) {
	// Handle IPv6 with brackets: [::1]:port
	if len(hostPort) > 0 && hostPort[0] == '[' {
		bracketIdx := -1
		for i, c := range hostPort {
			if c == ']' {
				bracketIdx = i
				break
			}
		}
		if bracketIdx > 0 {
			host := hostPort[1:bracketIdx]
			if bracketIdx+1 < len(hostPort) && hostPort[bracketIdx+1] == ':' {
				portStr := hostPort[bracketIdx+2:]
				if port, err := strconv.Atoi(portStr); err == nil {
					return host, port
				}
			}
			return host, defaultPort
		}
	}

	// Handle host:port (IPv4 or hostname)
	re := regexp.MustCompile(`^([^:]+):(\d+)$`)
	if matches := re.FindStringSubmatch(hostPort); len(matches) == 3 {
		if port, err := strconv.Atoi(matches[2]); err == nil {
			return matches[1], port
		}
	}

	return hostPort, defaultPort
}

func (p *Plugin) DatasourceInfo() []types.DatasourceInfo {
	infos := make([]types.DatasourceInfo, 0, len(p.cfg.Clusters))
	for _, ch := range p.cfg.Clusters {
		infos = append(infos, types.DatasourceInfo{
			Type:        "clickhouse",
			Name:        ch.Name,
			Description: ch.Description,
			Metadata: map[string]string{
				"database": ch.Database,
			},
		})
	}
	return infos
}

func (p *Plugin) Examples() map[string]types.ExampleCategory {
	result := make(map[string]types.ExampleCategory, len(queryExamples))
	for k, v := range queryExamples {
		result[k] = v
	}
	return result
}

// PythonAPIDocs returns the ClickHouse module documentation.
func (p *Plugin) PythonAPIDocs() map[string]types.ModuleDoc {
	return map[string]types.ModuleDoc{
		"clickhouse": {
			Description: "Query ClickHouse databases for Ethereum blockchain data. Use search_examples tool for query patterns.",
			Functions: map[string]types.FunctionDoc{
				"list_datasources": {
					Signature:   "clickhouse.list_datasources() -> list[dict]",
					Description: "List available ClickHouse clusters. Prefer datasources://clickhouse resource instead.",
					Returns:     "List of dicts with 'name', 'description', 'database' keys",
				},
				"query": {
					Signature:   "clickhouse.query(cluster: str, sql: str) -> pandas.DataFrame",
					Description: "Execute SQL query, return DataFrame",
					Parameters: map[string]string{
						"cluster": "'xatu' or 'xatu-cbt' - see mcp://getting-started for syntax differences",
						"sql":     "SQL query string",
					},
					Returns: "pandas.DataFrame",
				},
				"query_raw": {
					Signature:   "clickhouse.query_raw(cluster: str, sql: str) -> tuple[list[tuple], list[str]]",
					Description: "Execute SQL query, return raw tuples",
					Parameters: map[string]string{
						"cluster": "'xatu' or 'xatu-cbt'",
						"sql":     "SQL query string",
					},
					Returns: "(rows, column_names)",
				},
			},
		},
	}
}

// GettingStartedSnippet returns ClickHouse-specific getting-started content.
func (p *Plugin) GettingStartedSnippet() string {
	return `## ClickHouse Cluster Rules

Xatu data is split across **TWO clusters** with **DIFFERENT syntax**:

| Cluster | Contains | Table Syntax | Network Filter |
|---------|----------|--------------|----------------|
| **xatu** | Raw events | ` + "`FROM table_name`" + ` | ` + "`WHERE meta_network_name = 'mainnet'`" + ` |
| **xatu-cbt** | Pre-aggregated | ` + "`FROM mainnet.table_name`" + ` | Database prefix IS the filter |

**Always filter by partition column** (usually ` + "`slot_start_date_time`" + `) to avoid timeouts.

## Canonical vs Head Data

- **Canonical** = finalized (no reorgs) - use for historical analysis
- **Head** = latest (may reorg) - use for real-time monitoring
- Tables have variants: ` + "`fct_block_canonical`" + ` vs ` + "`fct_block_head`"
}

func (p *Plugin) RegisterResources(log logrus.FieldLogger, reg plugin.ResourceRegistry) error {
	p.log = log.WithField("plugin", "clickhouse")
	if p.schemaClient != nil {
		RegisterSchemaResources(p.log, reg, p.schemaClient)
	}
	return nil
}

func (p *Plugin) Start(ctx context.Context) error {
	if !p.cfg.SchemaDiscovery.IsEnabled() {
		if p.log != nil {
			p.log.Debug("Schema discovery disabled, skipping")
		}
		return nil
	}

	// Create the schema client
	if p.log == nil {
		p.log = logrus.WithField("plugin", "clickhouse")
	}

	p.schemaClient = NewClickHouseSchemaClient(
		p.log,
		ClickHouseSchemaConfig{
			RefreshInterval: p.cfg.SchemaDiscovery.RefreshInterval,
			QueryTimeout:    DefaultSchemaQueryTimeout,
			Datasources:     p.cfg.SchemaDiscovery.Datasources,
		},
		p.cfg.Clusters,
	)

	return p.schemaClient.Start(ctx)
}

func (p *Plugin) Stop(_ context.Context) error {
	if p.schemaClient != nil {
		return p.schemaClient.Stop()
	}
	return nil
}
