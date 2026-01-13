// Package config provides configuration loading for xatu-mcp.
package config

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the main configuration structure.
type Config struct {
	Server          ServerConfig          `yaml:"server"`
	ClickHouse      []ClickHouseConfig    `yaml:"clickhouse"`
	Prometheus      []PrometheusConfig    `yaml:"prometheus"`
	Loki            []LokiConfig          `yaml:"loki"`
	Auth            AuthConfig            `yaml:"auth"`
	Sandbox         SandboxConfig         `yaml:"sandbox"`
	Storage         *StorageConfig        `yaml:"storage,omitempty"`
	Observability   ObservabilityConfig   `yaml:"observability"`
	SchemaDiscovery SchemaDiscoveryConfig `yaml:"schema_discovery"`
}

// AuthConfig holds authentication configuration.
type AuthConfig struct {
	Enabled     bool          `yaml:"enabled"`
	GitHub      *GitHubConfig `yaml:"github,omitempty"`
	AllowedOrgs []string      `yaml:"allowed_orgs,omitempty"`
	Tokens      TokensConfig  `yaml:"tokens"`
}

// GitHubConfig holds GitHub OAuth configuration.
type GitHubConfig struct {
	ClientID     string `yaml:"client_id"`
	ClientSecret string `yaml:"client_secret"`
}

// TokensConfig holds JWT token configuration.
type TokensConfig struct {
	SecretKey string `yaml:"secret_key"`
}

// ServerConfig holds server-specific configuration.
type ServerConfig struct {
	Host      string `yaml:"host"`
	Port      int    `yaml:"port"`
	BaseURL   string `yaml:"base_url"`
	Transport string `yaml:"transport"`
}

// ClickHouseConfig holds configuration for a ClickHouse cluster.
type ClickHouseConfig struct {
	// Name is the logical identifier for this cluster (required).
	Name string `yaml:"name" json:"name"`

	// Description provides context about this cluster for LLM consumption.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// Host is the ClickHouse server address in host:port format (required).
	Host string `yaml:"host" json:"host"`

	// Database is the default database to use (required).
	Database string `yaml:"database" json:"database"`

	// Username is the authentication username (required).
	Username string `yaml:"username" json:"username"`

	// Password is the authentication password (required).
	Password string `yaml:"password" json:"password"`

	// Secure enables TLS for the connection. Defaults to true.
	Secure *bool `yaml:"secure,omitempty" json:"secure,omitempty"`

	// SkipVerify disables TLS certificate verification. Defaults to false.
	SkipVerify bool `yaml:"skip_verify,omitempty" json:"skip_verify,omitempty"`

	// Timeout is the query timeout in seconds. Defaults to 120.
	Timeout int `yaml:"timeout,omitempty" json:"timeout,omitempty"`

	// Protocol specifies the connection protocol: "native" or "http". Defaults to "native".
	// Use "http" for HTTPS connections through proxies like Cloudflare.
	Protocol string `yaml:"protocol,omitempty" json:"protocol,omitempty"`
}

// IsHTTP returns whether HTTP protocol should be used.
func (c *ClickHouseConfig) IsHTTP() bool {
	return c.Protocol == "http"
}

// IsSecure returns whether TLS is enabled (defaults to true).
func (c *ClickHouseConfig) IsSecure() bool {
	if c.Secure == nil {
		return true
	}

	return *c.Secure
}

// PrometheusConfig holds configuration for a Prometheus instance.
type PrometheusConfig struct {
	// Name is the logical identifier for this instance (required).
	Name string `yaml:"name" json:"name"`

	// Description provides context about this instance for LLM consumption.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// URL is the Prometheus server URL (required).
	URL string `yaml:"url" json:"url"`

	// Username is the authentication username (optional, for basic auth).
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password is the authentication password (optional, for basic auth).
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// SkipVerify disables TLS certificate verification. Defaults to false.
	SkipVerify bool `yaml:"skip_verify,omitempty" json:"skip_verify,omitempty"`

	// Timeout is the query timeout in seconds. Defaults to 60.
	Timeout int `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// LokiConfig holds configuration for a Loki instance.
type LokiConfig struct {
	// Name is the logical identifier for this instance (required).
	Name string `yaml:"name" json:"name"`

	// Description provides context about this instance for LLM consumption.
	Description string `yaml:"description,omitempty" json:"description,omitempty"`

	// URL is the Loki server URL (required).
	URL string `yaml:"url" json:"url"`

	// Username is the authentication username (optional, for basic auth).
	Username string `yaml:"username,omitempty" json:"username,omitempty"`

	// Password is the authentication password (optional, for basic auth).
	Password string `yaml:"password,omitempty" json:"password,omitempty"`

	// SkipVerify disables TLS certificate verification. Defaults to false.
	SkipVerify bool `yaml:"skip_verify,omitempty" json:"skip_verify,omitempty"`

	// Timeout is the query timeout in seconds. Defaults to 60.
	Timeout int `yaml:"timeout,omitempty" json:"timeout,omitempty"`
}

// SchemaDiscoveryConfig holds configuration for ClickHouse schema discovery.
type SchemaDiscoveryConfig struct {
	// Enabled controls whether schema discovery is active. Defaults to true if datasources are configured.
	Enabled *bool `yaml:"enabled,omitempty"`

	// RefreshInterval is the duration between schema refresh cycles. Defaults to 15 minutes.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`

	// Datasources lists the ClickHouse clusters to discover schemas from.
	// Each entry references a ClickHouse cluster by name.
	Datasources []SchemaDiscoveryDatasource `yaml:"datasources"`
}

// SchemaDiscoveryDatasource maps a ClickHouse cluster name to a logical cluster name for schema discovery.
type SchemaDiscoveryDatasource struct {
	// Name references a ClickHouse cluster by its name (from clickhouse[].name).
	Name string `yaml:"name"`

	// Cluster is the logical cluster name used in schema resources (e.g., "xatu", "xatu-cbt").
	Cluster string `yaml:"cluster"`
}

// IsEnabled returns whether schema discovery is enabled.
// Defaults to true if at least one datasource is configured.
func (c *SchemaDiscoveryConfig) IsEnabled() bool {
	if c.Enabled != nil {
		return *c.Enabled
	}

	return len(c.Datasources) > 0
}

// SandboxConfig holds sandbox execution configuration.
type SandboxConfig struct {
	Backend        string  `yaml:"backend"`
	Image          string  `yaml:"image"`
	Timeout        int     `yaml:"timeout"`
	MemoryLimit    string  `yaml:"memory_limit"`
	CPULimit       float64 `yaml:"cpu_limit"`
	Network        string  `yaml:"network"`
	HostSharedPath string  `yaml:"host_shared_path,omitempty"`

	// Session configuration for persistent execution environments.
	Sessions SessionConfig `yaml:"sessions"`
}

// SessionConfig holds configuration for persistent sandbox sessions.
type SessionConfig struct {
	// Enabled controls whether session support is available. Defaults to true.
	Enabled *bool `yaml:"enabled,omitempty"`
	// TTL is the duration after which an idle session is destroyed (since last use).
	TTL time.Duration `yaml:"ttl"`
	// MaxDuration is the maximum lifetime of a session regardless of activity.
	MaxDuration time.Duration `yaml:"max_duration"`
	// MaxSessions is the maximum number of concurrent sessions allowed.
	MaxSessions int `yaml:"max_sessions"`
}

// IsEnabled returns whether sessions are enabled (defaults to true).
func (c *SessionConfig) IsEnabled() bool {
	if c.Enabled == nil {
		return true // Default to enabled
	}
	return *c.Enabled
}

// StorageConfig holds S3 storage configuration.
type StorageConfig struct {
	Endpoint        string `yaml:"endpoint"`
	AccessKey       string `yaml:"access_key"`
	SecretKey       string `yaml:"secret_key"`
	Bucket          string `yaml:"bucket"`
	Region          string `yaml:"region"`
	PublicURLPrefix string `yaml:"public_url_prefix,omitempty"`
}

// ObservabilityConfig holds observability configuration.
type ObservabilityConfig struct {
	MetricsEnabled bool   `yaml:"metrics_enabled"`
	MetricsPort    int    `yaml:"metrics_port"`
	TracingEnabled bool   `yaml:"tracing_enabled"`
	OTLPEndpoint   string `yaml:"otlp_endpoint,omitempty"`
}

// envVarPattern matches ${VAR_NAME} patterns for environment variable substitution.
var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

// Load loads configuration from a YAML file with environment variable substitution.
func Load(path string) (*Config, error) {
	if path == "" {
		path = os.Getenv("CONFIG_PATH")
		if path == "" {
			path = "config.yaml"
		}
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config file %s: %w", path, err)
	}

	// Substitute environment variables
	substituted, err := substituteEnvVars(string(data))
	if err != nil {
		return nil, fmt.Errorf("substituting env vars: %w", err)
	}

	var cfg Config
	if err := yaml.Unmarshal([]byte(substituted), &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}

	// Apply defaults
	applyDefaults(&cfg)

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("validating config: %w", err)
	}

	return &cfg, nil
}

// substituteEnvVars replaces ${VAR_NAME} patterns with environment variable values.
// Lines that are comments (starting with #) are skipped to allow commented optional sections
// in config files without requiring their environment variables to be set.
func substituteEnvVars(content string) (string, error) {
	var missingVars []string
	lines := strings.Split(content, "\n")

	for i, line := range lines {
		// Skip lines that are YAML comments.
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}

		lines[i] = envVarPattern.ReplaceAllStringFunc(line, func(match string) string {
			varName := envVarPattern.FindStringSubmatch(match)[1]
			value := os.Getenv(varName)
			if value == "" {
				missingVars = append(missingVars, varName)
				return match
			}
			return value
		})
	}

	if len(missingVars) > 0 {
		return "", fmt.Errorf("missing environment variables: %v", missingVars)
	}

	return strings.Join(lines, "\n"), nil
}

// applyDefaults sets default values for configuration fields.
func applyDefaults(cfg *Config) {
	if cfg.Server.Host == "" {
		cfg.Server.Host = "0.0.0.0"
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 2480
	}
	if cfg.Server.Transport == "" {
		cfg.Server.Transport = "stdio"
	}

	// ClickHouse defaults.
	for i := range cfg.ClickHouse {
		if cfg.ClickHouse[i].Timeout == 0 {
			cfg.ClickHouse[i].Timeout = 120
		}
	}

	// Prometheus defaults.
	for i := range cfg.Prometheus {
		if cfg.Prometheus[i].Timeout == 0 {
			cfg.Prometheus[i].Timeout = 60
		}
	}

	// Loki defaults.
	for i := range cfg.Loki {
		if cfg.Loki[i].Timeout == 0 {
			cfg.Loki[i].Timeout = 60
		}
	}

	if cfg.Sandbox.Backend == "" {
		cfg.Sandbox.Backend = "docker"
	}
	if cfg.Sandbox.Timeout == 0 {
		cfg.Sandbox.Timeout = 60
	}
	if cfg.Sandbox.MemoryLimit == "" {
		cfg.Sandbox.MemoryLimit = "2g"
	}
	if cfg.Sandbox.CPULimit == 0 {
		cfg.Sandbox.CPULimit = 1.0
	}

	// Session defaults.
	if cfg.Sandbox.Sessions.TTL == 0 {
		cfg.Sandbox.Sessions.TTL = 30 * time.Minute
	}

	if cfg.Sandbox.Sessions.MaxDuration == 0 {
		cfg.Sandbox.Sessions.MaxDuration = 4 * time.Hour
	}

	if cfg.Sandbox.Sessions.MaxSessions == 0 {
		cfg.Sandbox.Sessions.MaxSessions = 10
	}

	if cfg.Observability.MetricsPort == 0 {
		cfg.Observability.MetricsPort = 2490
	}

	// Schema discovery defaults.
	if cfg.SchemaDiscovery.RefreshInterval == 0 {
		cfg.SchemaDiscovery.RefreshInterval = 15 * time.Minute
	}
}

// MaxSandboxTimeout is the maximum allowed sandbox timeout in seconds.
const MaxSandboxTimeout = 600

// Validate validates the configuration.
func (c *Config) Validate() error {
	// Validate ClickHouse configs.
	chNames := make(map[string]struct{}, len(c.ClickHouse))
	for i, ch := range c.ClickHouse {
		if ch.Name == "" {
			return fmt.Errorf("clickhouse[%d].name is required", i)
		}
		if _, exists := chNames[ch.Name]; exists {
			return fmt.Errorf("clickhouse[%d].name %q is duplicated", i, ch.Name)
		}
		chNames[ch.Name] = struct{}{}

		if ch.Host == "" {
			return fmt.Errorf("clickhouse[%d].host is required", i)
		}
		if ch.Database == "" {
			return fmt.Errorf("clickhouse[%d].database is required", i)
		}
		if ch.Username == "" {
			return fmt.Errorf("clickhouse[%d].username is required", i)
		}
		if ch.Password == "" {
			return fmt.Errorf("clickhouse[%d].password is required", i)
		}
	}

	// Validate Prometheus configs.
	promNames := make(map[string]struct{}, len(c.Prometheus))
	for i, p := range c.Prometheus {
		if p.Name == "" {
			return fmt.Errorf("prometheus[%d].name is required", i)
		}
		if _, exists := promNames[p.Name]; exists {
			return fmt.Errorf("prometheus[%d].name %q is duplicated", i, p.Name)
		}
		promNames[p.Name] = struct{}{}

		if p.URL == "" {
			return fmt.Errorf("prometheus[%d].url is required", i)
		}
	}

	// Validate Loki configs.
	lokiNames := make(map[string]struct{}, len(c.Loki))
	for i, l := range c.Loki {
		if l.Name == "" {
			return fmt.Errorf("loki[%d].name is required", i)
		}
		if _, exists := lokiNames[l.Name]; exists {
			return fmt.Errorf("loki[%d].name %q is duplicated", i, l.Name)
		}
		lokiNames[l.Name] = struct{}{}

		if l.URL == "" {
			return fmt.Errorf("loki[%d].url is required", i)
		}
	}

	// Validate schema discovery datasources reference valid ClickHouse clusters.
	for i, ds := range c.SchemaDiscovery.Datasources {
		if ds.Name == "" {
			return fmt.Errorf("schema_discovery.datasources[%d].name is required", i)
		}
		if ds.Cluster == "" {
			return fmt.Errorf("schema_discovery.datasources[%d].cluster is required", i)
		}
		if _, exists := chNames[ds.Name]; !exists {
			return fmt.Errorf("schema_discovery.datasources[%d].name %q does not reference a configured clickhouse cluster", i, ds.Name)
		}
	}

	if c.Sandbox.Image == "" {
		return errors.New("sandbox.image is required")
	}

	// Validate sandbox timeout is within bounds.
	if c.Sandbox.Timeout > MaxSandboxTimeout {
		return fmt.Errorf("sandbox.timeout cannot exceed %d seconds", MaxSandboxTimeout)
	}

	return nil
}
