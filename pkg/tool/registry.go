// Package tool provides MCP tool registration and handling.
package tool

import (
	"context"
	"fmt"
	"sync"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// Handler processes a tool call and returns the result.
type Handler func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error)

// Definition describes a tool's metadata and handler.
type Definition struct {
	Tool    mcp.Tool
	Handler Handler
	Scope   string // Required OAuth scope (empty = no auth required).
}

// Registry manages tool registration and lookup.
type Registry interface {
	// Register adds a tool definition to the registry.
	Register(def Definition)
	// List returns all registered tool definitions.
	List() []mcp.Tool
	// Get retrieves a tool handler and its required scope by name.
	// Returns the handler, scope, and a boolean indicating if the tool exists.
	Get(name string) (Handler, string, bool)
	// Definitions returns all registered tool definitions.
	Definitions() []Definition
}

type registry struct {
	log   logrus.FieldLogger
	mu    sync.RWMutex
	tools map[string]Definition
}

// NewRegistry creates a new tool registry.
func NewRegistry(log logrus.FieldLogger) Registry {
	return &registry{
		log:   log.WithField("component", "tool-registry"),
		tools: make(map[string]Definition, 8),
	}
}

// Register adds a tool definition to the registry.
func (r *registry) Register(def Definition) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.tools[def.Tool.Name]; exists {
		r.log.WithField("tool", def.Tool.Name).Warn("Overwriting existing tool definition")
	}

	r.tools[def.Tool.Name] = def
	r.log.WithFields(logrus.Fields{
		"tool":  def.Tool.Name,
		"scope": def.Scope,
	}).Debug("Registered tool")
}

// List returns all registered tool definitions as MCP tools.
func (r *registry) List() []mcp.Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	tools := make([]mcp.Tool, 0, len(r.tools))
	for _, def := range r.tools {
		tools = append(tools, def.Tool)
	}

	return tools
}

// Get retrieves a tool handler and its required scope by name.
func (r *registry) Get(name string) (Handler, string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	def, exists := r.tools[name]
	if !exists {
		return nil, "", false
	}

	return def.Handler, def.Scope, true
}

// Definitions returns all registered tool definitions.
func (r *registry) Definitions() []Definition {
	r.mu.RLock()
	defer r.mu.RUnlock()

	defs := make([]Definition, 0, len(r.tools))
	for _, def := range r.tools {
		defs = append(defs, def)
	}

	return defs
}

// CallToolError creates an error result for a tool call.
func CallToolError(err error) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: fmt.Sprintf("Error: %s", err.Error()),
			},
		},
		IsError: true,
	}
}

// CallToolSuccess creates a successful text result for a tool call.
func CallToolSuccess(text string) *mcp.CallToolResult {
	return &mcp.CallToolResult{
		Content: []mcp.Content{
			mcp.TextContent{
				Type: "text",
				Text: text,
			},
		},
	}
}

// Compile-time interface compliance check.
var _ Registry = (*registry)(nil)
