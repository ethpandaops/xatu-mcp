package plugin

import (
	"context"
	"fmt"
	"maps"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/types"
)

// Registry tracks all compiled-in plugins and which ones are
// initialized (have config and passed Init/Validate).
type Registry struct {
	log         logrus.FieldLogger
	mu          sync.RWMutex
	all         map[string]Plugin
	initialized []Plugin
}

// NewRegistry creates a new plugin registry.
func NewRegistry(log logrus.FieldLogger) *Registry {
	return &Registry{
		log:         log.WithField("component", "plugin_registry"),
		all:         make(map[string]Plugin, 4),
		initialized: make([]Plugin, 0, 4),
	}
}

// Add registers a compiled-in plugin by name.
// This does not initialize the plugin; call InitPlugin for that.
func (r *Registry) Add(p Plugin) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.all[p.Name()] = p
	r.log.WithField("plugin", p.Name()).Debug("Registered plugin")
}

// InitPlugin initializes a plugin with the given raw YAML config.
// It calls Init, ApplyDefaults, and Validate in sequence.
func (r *Registry) InitPlugin(name string, rawConfig []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	p, ok := r.all[name]
	if !ok {
		return fmt.Errorf("unknown plugin %q", name)
	}

	if err := p.Init(rawConfig); err != nil {
		return fmt.Errorf("initializing plugin %q: %w", name, err)
	}

	p.ApplyDefaults()

	if err := p.Validate(); err != nil {
		return fmt.Errorf("validating plugin %q: %w", name, err)
	}

	r.initialized = append(r.initialized, p)

	r.log.WithField("plugin", name).Info("Plugin initialized")

	return nil
}

// Initialized returns all plugins that passed Init/Validate.
func (r *Registry) Initialized() []Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := make([]Plugin, len(r.initialized))
	copy(result, r.initialized)

	return result
}

// All returns the names of all compiled-in plugins.
func (r *Registry) All() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	names := make([]string, 0, len(r.all))
	for name := range r.all {
		names = append(names, name)
	}

	return names
}

// Get returns a plugin by name, or nil if not found.
func (r *Registry) Get(name string) Plugin {
	r.mu.RLock()
	defer r.mu.RUnlock()

	return r.all[name]
}

// StartAll starts all initialized plugins.
func (r *Registry) StartAll(ctx context.Context) error {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	for _, p := range plugins {
		if err := p.Start(ctx); err != nil {
			return fmt.Errorf("starting plugin %q: %w", p.Name(), err)
		}

		r.log.WithField("plugin", p.Name()).Info("Plugin started")
	}

	return nil
}

// StopAll stops all initialized plugins.
func (r *Registry) StopAll(ctx context.Context) {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	for _, p := range plugins {
		if err := p.Stop(ctx); err != nil {
			r.log.WithError(err).WithField("plugin", p.Name()).Warn("Failed to stop plugin")
		}
	}
}

// SandboxEnv aggregates credential-free sandbox environment variables
// from all initialized plugins. Credentials are never passed to sandbox
// containers - they connect via the credential proxy instead.
func (r *Registry) SandboxEnv() (map[string]string, error) {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	env := make(map[string]string, 8)

	for _, p := range plugins {
		pEnv, err := p.SandboxEnv()
		if err != nil {
			return nil, fmt.Errorf("getting sandbox env for plugin %q: %w", p.Name(), err)
		}

		maps.Copy(env, pEnv)
	}

	return env, nil
}

// DatasourceInfo aggregates datasource info from all initialized plugins.
func (r *Registry) DatasourceInfo() []types.DatasourceInfo {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	var infos []types.DatasourceInfo
	for _, p := range plugins {
		infos = append(infos, p.DatasourceInfo()...)
	}

	return infos
}

// Examples aggregates query examples from all initialized plugins.
func (r *Registry) Examples() map[string]types.ExampleCategory {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	result := make(map[string]types.ExampleCategory, 16)

	for _, p := range plugins {
		maps.Copy(result, p.Examples())
	}

	return result
}

// PythonAPIDocs aggregates Python API docs from all initialized plugins.
func (r *Registry) PythonAPIDocs() map[string]types.ModuleDoc {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	result := make(map[string]types.ModuleDoc, 8)

	for _, p := range plugins {
		maps.Copy(result, p.PythonAPIDocs())
	}

	return result
}

// GettingStartedSnippets aggregates getting-started snippets from
// all initialized plugins.
func (r *Registry) GettingStartedSnippets() string {
	r.mu.RLock()
	plugins := make([]Plugin, len(r.initialized))
	copy(plugins, r.initialized)
	r.mu.RUnlock()

	var snippets string
	for _, p := range plugins {
		snippet := p.GettingStartedSnippet()
		if snippet != "" {
			snippets += snippet + "\n"
		}
	}

	return snippets
}
