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

// DatasourcesResponse is the JSON response for datasources resources.
type DatasourcesResponse struct {
	Datasources []types.DatasourceInfo `json:"datasources"`
}

// RegisterDatasourcesResources registers the datasources:// resources
// with the registry.
func RegisterDatasourcesResources(
	log logrus.FieldLogger,
	reg Registry,
	pluginReg *plugin.Registry,
) {
	log = log.WithField("resource", "datasources")

	// datasources://list - all datasources
	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"datasources://list",
			"All Datasources",
			mcp.WithResourceDescription("List of all configured datasources (ClickHouse, Prometheus, Loki)"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.8),
		),
		Handler: createDatasourcesHandler(pluginReg, ""),
	})

	// datasources://clickhouse
	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"datasources://clickhouse",
			"ClickHouse Datasources",
			mcp.WithResourceDescription("Configured ClickHouse clusters for blockchain data queries"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.7),
		),
		Handler: createDatasourcesHandler(pluginReg, "clickhouse"),
	})

	// datasources://prometheus
	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"datasources://prometheus",
			"Prometheus Datasources",
			mcp.WithResourceDescription("Configured Prometheus instances for metrics queries"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.7),
		),
		Handler: createDatasourcesHandler(pluginReg, "prometheus"),
	})

	// datasources://loki
	reg.RegisterStatic(StaticResource{
		Resource: mcp.NewResource(
			"datasources://loki",
			"Loki Datasources",
			mcp.WithResourceDescription("Configured Loki instances for log queries"),
			mcp.WithMIMEType("application/json"),
			mcp.WithAnnotations([]mcp.Role{mcp.RoleAssistant}, 0.7),
		),
		Handler: createDatasourcesHandler(pluginReg, "loki"),
	})

	log.Debug("Registered datasources resources")
}

func createDatasourcesHandler(pluginReg *plugin.Registry, filterType string) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		allInfos := pluginReg.DatasourceInfo()

		var filtered []types.DatasourceInfo
		if filterType == "" {
			if allInfos == nil {
				filtered = make([]types.DatasourceInfo, 0)
			} else {
				filtered = allInfos
			}
		} else {
			filtered = make([]types.DatasourceInfo, 0, len(allInfos))
			for _, info := range allInfos {
				if info.Type == filterType {
					filtered = append(filtered, info)
				}
			}
		}

		response := DatasourcesResponse{Datasources: filtered}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling datasources: %w", err)
		}

		return string(data), nil
	}
}
