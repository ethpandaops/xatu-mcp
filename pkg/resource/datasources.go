package resource

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// datasourcesResponse is the JSON response for datasources://list.
type datasourcesResponse struct {
	ClickHouse []clickHouseData   `json:"clickhouse"`
	Prometheus []prometheusData   `json:"prometheus"`
	Loki       []lokiInstanceData `json:"loki"`
}

type clickHouseData struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Database    string `json:"database"`
}

type prometheusData struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

type lokiInstanceData struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	URL         string `json:"url"`
}

// clickHouseListResponse is the JSON response for datasources://clickhouse.
type clickHouseListResponse struct {
	Clusters []clickHouseData `json:"clusters"`
	Count    int              `json:"count"`
}

// prometheusListResponse is the JSON response for datasources://prometheus.
type prometheusListResponse struct {
	Instances []prometheusData `json:"instances"`
	Count     int              `json:"count"`
}

// lokiListResponse is the JSON response for datasources://loki.
type lokiListResponse struct {
	Instances []lokiInstanceData `json:"instances"`
	Count     int                `json:"count"`
}

// RegisterDatasourcesResources registers the datasources:// resources with the registry.
func RegisterDatasourcesResources(
	log logrus.FieldLogger,
	reg Registry,
	chConfigs []config.ClickHouseConfig,
	promConfigs []config.PrometheusConfig,
	lokiConfigs []config.LokiConfig,
) {
	log = log.WithField("resource", "datasources")

	// Register static datasources://list resource
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "datasources://list",
			Name:        "Available Datasources",
			Description: "List all datasources available for queries (ClickHouse, Prometheus, Loki)",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			chData := make([]clickHouseData, 0, len(chConfigs))
			for _, ch := range chConfigs {
				chData = append(chData, clickHouseData{
					Name:        ch.Name,
					Description: ch.Description,
					Database:    ch.Database,
				})
			}

			promData := make([]prometheusData, 0, len(promConfigs))
			for _, p := range promConfigs {
				promData = append(promData, prometheusData{
					Name:        p.Name,
					Description: p.Description,
					URL:         p.URL,
				})
			}

			lData := make([]lokiInstanceData, 0, len(lokiConfigs))
			for _, l := range lokiConfigs {
				lData = append(lData, lokiInstanceData{
					Name:        l.Name,
					Description: l.Description,
					URL:         l.URL,
				})
			}

			response := datasourcesResponse{
				ClickHouse: chData,
				Prometheus: promData,
				Loki:       lData,
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling datasources response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	// Register datasources://clickhouse
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "datasources://clickhouse",
			Name:        "ClickHouse Clusters",
			Description: "List available ClickHouse clusters",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			data := make([]clickHouseData, 0, len(chConfigs))
			for _, ch := range chConfigs {
				data = append(data, clickHouseData{
					Name:        ch.Name,
					Description: ch.Description,
					Database:    ch.Database,
				})
			}

			response := clickHouseListResponse{
				Clusters: data,
				Count:    len(data),
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling clickhouse response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	// Register datasources://prometheus
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "datasources://prometheus",
			Name:        "Prometheus Instances",
			Description: "List available Prometheus instances",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			data := make([]prometheusData, 0, len(promConfigs))
			for _, p := range promConfigs {
				data = append(data, prometheusData{
					Name:        p.Name,
					Description: p.Description,
					URL:         p.URL,
				})
			}

			response := prometheusListResponse{
				Instances: data,
				Count:     len(data),
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling prometheus response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	// Register datasources://loki
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "datasources://loki",
			Name:        "Loki Instances",
			Description: "List available Loki instances",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			data := make([]lokiInstanceData, 0, len(lokiConfigs))
			for _, l := range lokiConfigs {
				data = append(data, lokiInstanceData{
					Name:        l.Name,
					Description: l.Description,
					URL:         l.URL,
				})
			}

			response := lokiListResponse{
				Instances: data,
				Count:     len(data),
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling loki response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	log.Debug("Registered datasources resources")
}
