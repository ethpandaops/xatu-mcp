// Package config provides configuration loading for the MCP server.
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
	Server         ServerConfig         `yaml:"server"`
	Plugins        map[string]yaml.Node `yaml:"plugins"`
	Auth           AuthConfig           `yaml:"auth"`
	Sandbox        SandboxConfig        `yaml:"sandbox"`
	Storage        *StorageConfig       `yaml:"storage,omitempty"`
	Observability  ObservabilityConfig  `yaml:"observability"`
	SemanticSearch SemanticSearchConfig `yaml:"semantic_search"`
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

// SemanticSearchConfig holds configuration for semantic example search.
type SemanticSearchConfig struct {
	// ModelPath is the path to the GGUF embedding model file (required).
	ModelPath string `yaml:"model_path,omitempty"`

	// GPULayers is the number of layers to offload to GPU (0 = CPU only).
	GPULayers int `yaml:"gpu_layers,omitempty"`
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
	MetricsEnabled bool `yaml:"metrics_enabled"`
	MetricsPort    int  `yaml:"metrics_port"`
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

// PluginConfigYAML returns the raw YAML bytes for a given plugin name.
// Returns nil if the plugin is not configured.
func (c *Config) PluginConfigYAML(name string) ([]byte, error) {
	node, ok := c.Plugins[name]
	if !ok {
		return nil, nil
	}

	data, err := yaml.Marshal(&node)
	if err != nil {
		return nil, fmt.Errorf("marshaling plugin %q config: %w", name, err)
	}

	return data, nil
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

	// Semantic search defaults.
	if cfg.SemanticSearch.ModelPath == "" {
		// Prefer local dev path if present, otherwise fall back to container path.
		localPath := "models/MiniLM-L6-v2.Q8_0.gguf"
		containerPath := "/usr/share/mcp/MiniLM-L6-v2.Q8_0.gguf"

		switch {
		case fileExists(localPath):
			cfg.SemanticSearch.ModelPath = localPath
		case fileExists(containerPath):
			cfg.SemanticSearch.ModelPath = containerPath
		default:
			cfg.SemanticSearch.ModelPath = localPath
		}
	}
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// MaxSandboxTimeout is the maximum allowed sandbox timeout in seconds.
const MaxSandboxTimeout = 600

// Validate validates the configuration.
func (c *Config) Validate() error {
	if c.Sandbox.Image == "" {
		return errors.New("sandbox.image is required")
	}

	// Validate sandbox timeout is within bounds.
	if c.Sandbox.Timeout > MaxSandboxTimeout {
		return fmt.Errorf("sandbox.timeout cannot exceed %d seconds", MaxSandboxTimeout)
	}

	return nil
}
