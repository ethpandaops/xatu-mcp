package resource

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// ToolLister provides access to registered tools.
type ToolLister interface {
	List() []mcp.Tool
}

// gettingStartedHeader contains the static workflow guidance.
const gettingStartedHeader = `# Xatu Getting Started Guide

## Workflow

1. **Discover** → ` + "`datasources://clickhouse`" + ` for cluster names, ` + "`clickhouse://tables`" + ` for schemas
2. **Find patterns** → ` + "`search_examples`" + ` tool or ` + "`examples://queries`" + ` resource
3. **Execute** → ` + "`execute_python`" + ` tool with the xatu library

## ⚠️ CRITICAL: Cluster Rules

Xatu data is split across **TWO clusters** with **DIFFERENT syntax**:

| Cluster | Contains | Table Syntax | Network Filter |
|---------|----------|--------------|----------------|
| **xatu** | Raw events | ` + "`FROM table_name`" + ` | ` + "`WHERE meta_network_name = 'mainnet'`" + ` |
| **xatu-cbt** | Pre-aggregated | ` + "`FROM mainnet.table_name`" + ` | Database prefix IS the filter |

**Always filter by partition column** (usually ` + "`slot_start_date_time`" + `) to avoid timeouts.

## Canonical vs Head Data

- **Canonical** = finalized (no reorgs) → use for historical analysis
- **Head** = latest (may reorg) → use for real-time monitoring
- Tables have variants: ` + "`fct_block_canonical`" + ` vs ` + "`fct_block_head`" + `
`

// gettingStartedFooter contains static tips.
const gettingStartedFooter = `
## Sessions

- **Reuse session_id** from tool responses for faster execution and file persistence
- Files in ` + "`/workspace/`" + ` persist across calls; Python variables do NOT
- Use ` + "`storage.upload()`" + ` for permanent URLs (see ` + "`python://xatu`" + ` for API details)
`

// RegisterGettingStartedResources registers the xatu://getting-started resource.
func RegisterGettingStartedResources(
	log logrus.FieldLogger,
	reg Registry,
	toolReg ToolLister,
) {
	log = log.WithField("resource", "getting_started")

	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"xatu://getting-started",
			"Xatu Getting Started Guide",
			mcp.WithResourceDescription("Essential guide for querying Ethereum data with Xatu - read this first!"),
			mcp.WithMIMEType("text/markdown"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 1.0),
		),
		Handler: createGettingStartedHandler(reg, toolReg),
	})

	log.Debug("Registered getting-started resource")
}

// createGettingStartedHandler creates a handler that dynamically builds content.
func createGettingStartedHandler(reg Registry, toolReg ToolLister) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		var sb strings.Builder

		// Write header with workflow and critical requirements
		sb.WriteString(gettingStartedHeader)

		// Dynamically list tools
		sb.WriteString("## Available Tools\n\n")

		tools := toolReg.List()
		sort.Slice(tools, func(i, j int) bool {
			return tools[i].Name < tools[j].Name
		})

		for _, tool := range tools {
			// Get first line of description
			desc := tool.Description
			if idx := strings.Index(desc, "\n"); idx > 0 {
				desc = desc[:idx]
			}

			// Trim any leading emoji or special chars for cleaner output
			desc = strings.TrimSpace(desc)
			if strings.HasPrefix(desc, "⚠️") {
				// Skip warning lines, get next meaningful line
				lines := strings.Split(tool.Description, "\n")
				for _, line := range lines {
					line = strings.TrimSpace(line)
					if line != "" && !strings.HasPrefix(line, "⚠️") {
						desc = line
						break
					}
				}
			}

			sb.WriteString(fmt.Sprintf("- **%s**: %s\n", tool.Name, desc))
		}

		// Dynamically list resources
		sb.WriteString("\n## Available Resources\n\n")

		// Static resources
		staticResources := reg.ListStatic()
		sort.Slice(staticResources, func(i, j int) bool {
			return staticResources[i].URI < staticResources[j].URI
		})

		for _, res := range staticResources {
			// Skip self-reference
			if res.URI == "xatu://getting-started" {
				continue
			}

			sb.WriteString(fmt.Sprintf("- `%s` - %s\n", res.URI, res.Name))
		}

		// Template resources
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

		// Write footer with tips
		sb.WriteString(gettingStartedFooter)

		return sb.String(), nil
	}
}
