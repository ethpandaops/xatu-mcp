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

## Quick Start Workflow

- **Search for examples first**: Use the search_examples tool to find relevant query patterns
- **List available datasources**: Use the datasources://list resource to list available datasources
- **Look up table schemas**: Use the clickhouse-schema://{cluster}/{table} resource to look up table schemas
- **Execute your query**: Use the execute_python tool with the adapted example

## Required Query Filters

⚠️ **CRITICAL**:  Clickhouse guidelines:
1. **Xatu Data is split in 2 clusters**: ` + "`xatu` and `xatu-cbt`" + `.
  - "xatu" is the main cluster and contains the raw data. All networks land in the same "default" database.
  - "xatu-cbt" contains aggregated data and will usually always be quicker to query. Databases are named after the network name.
2. **Network filter when using "xatu" cluster**: ` + "`meta_network_name = '$network_name'`" + `. When using "xatu-cbt" cluster, you should use the "$network_name".database_name instead.` + "```" + `
3. **Time/partition filter**: ` + "`$partition_column >= now() - INTERVAL 1 HOUR`" + `

`

// gettingStartedFooter contains static tips.
const gettingStartedFooter = `
## Tips

- Use search_examples("block") to find block-related query patterns
- Use search_examples("validator") to find validator-related patterns
- Write output files to /workspace/ directory before uploading
- Avoid spamming stdout with too much text
- If the user asks for a chart or file, use the storage.upload() tool to upload the chart to S3 and return the URL. 
  - Note: If you are Claude Code, your may need to manually recite the URL to the user towards the end of your response to avoid it being cut off.
`

// RegisterGettingStartedResources registers the xatu://getting-started resource.
func RegisterGettingStartedResources(
	log logrus.FieldLogger,
	reg Registry,
	toolReg ToolLister,
) {
	log = log.WithField("resource", "getting_started")

	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "xatu://getting-started",
			Name:        "Xatu Getting Started Guide",
			Description: "Essential guide for querying Ethereum data with Xatu - read this first!",
			MIMEType:    "text/markdown",
		},
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
