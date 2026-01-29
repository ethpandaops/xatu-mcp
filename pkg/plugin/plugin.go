// Package plugin defines the Plugin interface and registry for
// datasource plugins that extend the MCP server.
package plugin

import (
	"context"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/types"
)

// CartographoorAware is an optional interface that plugins can implement
// to receive the cartographoor client for network discovery.
// The client parameter is passed as any to avoid circular imports;
// plugins should type-assert to resource.CartographoorClient.
type CartographoorAware interface {
	SetCartographoorClient(client any)
}

// DefaultEnabled is an optional interface that plugins can implement
// to indicate they should be initialized even without explicit config.
// This is useful for plugins like dora that work with discovered data
// and require no user configuration.
type DefaultEnabled interface {
	// DefaultEnabled returns true if the plugin should be initialized
	// without explicit config in the config file.
	DefaultEnabled() bool
}

// ResourceRegistry is the interface plugins use to register MCP resources.
// This avoids a circular dependency between plugin and resource packages.
// pkg/resource.Registry satisfies this interface.
type ResourceRegistry interface {
	RegisterStatic(res types.StaticResource)
	RegisterTemplate(res types.TemplateResource)
}

// Plugin is the interface that all datasource plugins must implement.
type Plugin interface {
	// Name returns the plugin identifier (e.g. "clickhouse").
	Name() string

	// Init parses the raw YAML config section for this plugin.
	Init(rawConfig []byte) error

	// ApplyDefaults sets default values before validation.
	ApplyDefaults()

	// Validate checks that the parsed config is valid.
	Validate() error

	// SandboxEnv returns credential-free environment variables for the sandbox.
	// Credentials are never passed to sandbox containers - they connect via
	// the credential proxy instead.
	SandboxEnv() (map[string]string, error)

	// ProxyConfig returns configuration for the credential proxy.
	// The returned value should be a slice of config structs appropriate
	// for the plugin type (e.g., []handlers.ClickHouseConfig).
	ProxyConfig() any

	// DatasourceInfo returns metadata about configured datasources
	// for the datasources:// MCP resource.
	DatasourceInfo() []types.DatasourceInfo

	// Examples returns query examples organized by category.
	Examples() map[string]types.ExampleCategory

	// PythonAPIDocs returns API documentation for the plugin's
	// Python module, keyed by module name.
	PythonAPIDocs() map[string]types.ModuleDoc

	// GettingStartedSnippet returns a Markdown snippet to include
	// in the getting-started resource.
	GettingStartedSnippet() string

	// RegisterResources registers any custom MCP resources
	// (e.g. clickhouse://tables) with the resource registry.
	RegisterResources(log logrus.FieldLogger, reg ResourceRegistry) error

	// Start performs async initialization (e.g. schema discovery).
	Start(ctx context.Context) error

	// Stop cleans up resources.
	Stop(ctx context.Context) error
}
