// Package proxy provides a credential proxy service that holds datasource credentials
// in the MCP server and proxies requests from sandbox containers.
package proxy

import "time"

// Config holds the proxy service configuration.
type Config struct {
	// ListenAddr is the address to listen on (default: ":8081").
	ListenAddr string `yaml:"listen_addr,omitempty"`

	// TokenTTL is the duration a token is valid for (default: 1h).
	TokenTTL time.Duration `yaml:"token_ttl,omitempty"`

	// SandboxHost is the hostname/IP that sandbox containers should use to reach the proxy.
	// Defaults to "host.docker.internal".
	SandboxHost string `yaml:"sandbox_host,omitempty"`
}

// ApplyDefaults sets default values for configuration fields.
func (c *Config) ApplyDefaults() {
	if c.ListenAddr == "" {
		c.ListenAddr = ":8081"
	}

	if c.TokenTTL == 0 {
		c.TokenTTL = 1 * time.Hour
	}

	if c.SandboxHost == "" {
		c.SandboxHost = "host.docker.internal"
	}
}
