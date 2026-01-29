package resource

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/types"
)

// RegisterExamplesResources registers the examples://queries resource.
func RegisterExamplesResources(log logrus.FieldLogger, reg Registry, pluginReg *plugin.Registry) {
	log = log.WithField("resource", "examples")

	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"examples://queries",
			"Query Examples",
			mcp.WithResourceDescription("Example queries for ClickHouse, Prometheus, and Loki data"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.6),
		),
		Handler: createExamplesHandler(pluginReg),
	})

	log.Debug("Registered examples resources")
}

func createExamplesHandler(pluginReg *plugin.Registry) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		examples := pluginReg.Examples()

		data, err := json.MarshalIndent(examples, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling examples: %w", err)
		}

		return string(data), nil
	}
}

// GetQueryExamples returns all query examples from the plugin registry.
func GetQueryExamples(pluginReg *plugin.Registry) map[string]types.ExampleCategory {
	return pluginReg.Examples()
}
