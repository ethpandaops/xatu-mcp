package resource

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/plugin"
)

// ToolLister provides access to registered tools.
type ToolLister interface {
	List() []mcp.Tool
}

// gettingStartedHeader contains the static workflow guidance.
const gettingStartedHeader = `# Getting Started Guide

## Workflow

1. **Discover** → Read datasource resources to find available data sources and schemas
2. **Find patterns** → ` + "`search_examples`" + ` tool or ` + "`examples://queries`" + ` resource
3. **Execute** → ` + "`execute_python`" + ` tool with the ethpandaops library

`

// gettingStartedFooter contains static tips.
const gettingStartedFooter = `
## Sessions

- **Reuse session_id** from tool responses for faster execution and file persistence
- Files in ` + "`/workspace/`" + ` persist across calls; Python variables do NOT
- Use ` + "`storage.upload()`" + ` for permanent URLs (see ` + "`python://ethpandaops`" + ` for API details)
`

// RegisterGettingStartedResources registers the mcp://getting-started
// resource.
func RegisterGettingStartedResources(
	log logrus.FieldLogger,
	reg Registry,
	toolReg ToolLister,
	pluginReg *plugin.Registry,
) {
	log = log.WithField("resource", "getting_started")

	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"ethpandaops://getting-started",
			"Getting Started Guide",
			mcp.WithResourceDescription("Essential guide for querying data - read this first!"),
			mcp.WithMIMEType("text/markdown"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 1.0),
		),
		Handler: createGettingStartedHandler(reg, toolReg, pluginReg),
	})

	log.Debug("Registered getting-started resource")
}

// createGettingStartedHandler creates a handler that dynamically
// builds content from platform resources and plugin snippets.
func createGettingStartedHandler(
	reg Registry,
	toolReg ToolLister,
	pluginReg *plugin.Registry,
) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		var sb strings.Builder

		// Write header with workflow and critical requirements.
		sb.WriteString(gettingStartedHeader)

		// Include plugin-specific getting-started snippets.
		snippets := pluginReg.GettingStartedSnippets()
		if snippets != "" {
			sb.WriteString(snippets)
		}

		// Dynamically list tools.
		sb.WriteString("## Available Tools\n\n")

		tools := toolReg.List()
		sort.Slice(tools, func(i, j int) bool {
			return tools[i].Name < tools[j].Name
		})

		for _, tool := range tools {
			// Get first line of description.
			desc := tool.Description
			if idx := strings.Index(desc, "\n"); idx > 0 {
				desc = desc[:idx]
			}

			desc = strings.TrimSpace(desc)

			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", tool.Name, desc))
		}

		// Dynamically list resources.
		sb.WriteString("\n## Available Resources\n\n")

		// Static resources.
		staticResources := reg.ListStatic()
		sort.Slice(staticResources, func(i, j int) bool {
			return staticResources[i].URI < staticResources[j].URI
		})

		for _, res := range staticResources {
			// Skip self-reference.
			if res.URI == "ethpandaops://getting-started" {
				continue
			}

			sb.WriteString(fmt.Sprintf("- `%s` - %s\n", res.URI, res.Name))
		}

		// Template resources.
		templates := reg.ListTemplates()
		if len(templates) > 0 {
			sb.WriteString("\n**Templates:**\n")

			sort.Slice(templates, func(i, j int) bool {
				return templates[i].URITemplate.Raw() < templates[j].URITemplate.Raw()
			})

			for _, tmpl := range templates {
				sb.WriteString(fmt.Sprintf("- `%s` - %s\n", tmpl.URITemplate.Raw(), tmpl.Name))
			}
		}

		// Write footer with tips.
		sb.WriteString(gettingStartedFooter)

		return sb.String(), nil
	}
}
