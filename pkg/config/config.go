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
	Grafana         GrafanaConfig         `yaml:"grafana"`
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

// GrafanaConfig holds Grafana connection configuration.
type GrafanaConfig struct {
	// URL is the base URL of the Grafana instance.
	URL string `yaml:"url"`

	// ServiceToken is the Grafana service account token for authentication.
	ServiceToken string `yaml:"service_token"`

	// Timeout is the HTTP request timeout in seconds. Defaults to 120.
	Timeout int `yaml:"timeout"`

	// DatasourceUIDs optionally restricts which datasources are available.
	// If empty, all discovered datasources of supported types are used.
	// Deprecated: Use Datasources instead for more control.
	DatasourceUIDs []string `yaml:"datasource_uids,omitempty"`

	// Datasources configures which datasources are available and their descriptions.
	// If specified, only these datasources are exposed (supersedes DatasourceUIDs).
	Datasources []DatasourceConfig `yaml:"datasources,omitempty"`
}

// DatasourceConfig configures a single datasource with optional description.
type DatasourceConfig struct {
	// UID is the Grafana datasource UID (required).
	UID string `yaml:"uid"`

	// Description provides context about this datasource for LLM consumption.
	// Should include usage guidelines, common labels/filters, and best practices.
	Description string `yaml:"description,omitempty"`
}

// SchemaDiscoveryConfig holds configuration for ClickHouse schema discovery.
type SchemaDiscoveryConfig struct {
	// Enabled controls whether schema discovery is active. Defaults to true if datasources are configured.
	Enabled *bool `yaml:"enabled,omitempty"`

	// RefreshInterval is the duration between schema refresh cycles. Defaults to 15 minutes.
	RefreshInterval time.Duration `yaml:"refresh_interval,omitempty"`

	// Datasources lists the ClickHouse datasources to discover schemas from.
	// Each datasource must specify both the Grafana datasource UID and the cluster name.
	Datasources []DatasourceMapping `yaml:"datasources"`
}

// DatasourceMapping maps a Grafana datasource UID to a cluster name.
type DatasourceMapping struct {
	// UID is the Grafana datasource UID (e.g., "PDF61E9E97939C7ED").
	UID string `yaml:"uid"`

	// Cluster is the logical cluster name (e.g., "xatu", "xatu-cbt").
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

	// Grafana defaults.
	if cfg.Grafana.Timeout == 0 {
		cfg.Grafana.Timeout = 120
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
	if c.Grafana.URL == "" {
		return errors.New("grafana.url is required")
	}

	if c.Grafana.ServiceToken == "" {
		return errors.New("grafana.service_token is required")
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
