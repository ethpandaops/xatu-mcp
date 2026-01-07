package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/clickhouse"
)

// SchemaClient defines the interface for querying ClickHouse schema information.
type SchemaClient interface {
	// ListTables returns a list of all tables in the cluster.
	ListTables(ctx context.Context) ([]clickhouse.TableInfo, error)

	// GetTableInfo returns metadata about a specific table.
	GetTableInfo(ctx context.Context, tableName string) (*clickhouse.TableInfo, error)

	// GetTableSchema returns the column schema for a table.
	GetTableSchema(ctx context.Context, tableName string) ([]clickhouse.ColumnInfo, error)
}

// SchemaClientFactory creates a SchemaClient for a given cluster name.
type SchemaClientFactory func(clusterName string) (SchemaClient, error)

// ClusterProvider provides information about available ClickHouse clusters.
type ClusterProvider interface {
	// GetCluster returns cluster info by name.
	GetCluster(name string) (*clickhouse.ClusterInfo, bool)

	// ListClusters returns all available clusters.
	ListClusters() []*clickhouse.ClusterInfo
}

// clustersResponse is the JSON response for schema://clusters.
type clustersResponse struct {
	Clusters []clusterData `json:"clusters"`
}

type clusterData struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Host        string   `json:"host"`
	Networks    []string `json:"networks"`
}

// tablesResponse is the JSON response for schema://tables/{cluster}.
type tablesResponse struct {
	Cluster    string      `json:"cluster"`
	Database   string      `json:"database"`
	TableCount int         `json:"table_count"`
	Tables     []tableData `json:"tables"`
}

type tableData struct {
	Name       string `json:"name"`
	Engine     string `json:"engine"`
	TotalRows  string `json:"total_rows"`
	TotalBytes string `json:"total_bytes"`
	Comment    string `json:"comment"`
}

// tableSchemaResponse is the JSON response for schema://tables/{cluster}/{table}.
type tableSchemaResponse struct {
	Cluster      string       `json:"cluster"`
	Table        string       `json:"table"`
	Engine       string       `json:"engine"`
	TotalRows    string       `json:"total_rows"`
	TotalBytes   string       `json:"total_bytes"`
	Comment      string       `json:"comment"`
	PartitionKey string       `json:"partition_key"`
	SortingKey   string       `json:"sorting_key"`
	PrimaryKey   string       `json:"primary_key"`
	Columns      []columnData `json:"columns"`
}

type columnData struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	Comment           string `json:"comment,omitempty"`
	DefaultKind       string `json:"default_kind,omitempty"`
	DefaultExpression string `json:"default_expression,omitempty"`
	IsPartitionKey    bool   `json:"is_partition_key,omitempty"`
	IsSortingKey      bool   `json:"is_sorting_key,omitempty"`
	IsPrimaryKey      bool   `json:"is_primary_key,omitempty"`
}

// RegisterSchemaResources registers the schema:// resources with the registry.
func RegisterSchemaResources(
	log logrus.FieldLogger,
	reg Registry,
	provider ClusterProvider,
	clientFactory SchemaClientFactory,
) {
	log = log.WithField("resource", "schema")

	// Register static schema://clusters resource
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "schema://clusters",
			Name:        "ClickHouse Clusters",
			Description: "List of available ClickHouse clusters and their networks",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			clusters := provider.ListClusters()
			data := make([]clusterData, 0, len(clusters))

			for _, c := range clusters {
				data = append(data, clusterData{
					Name:        c.Name,
					Description: c.Description,
					Host:        c.Host,
					Networks:    c.Networks,
				})
			}

			response := clustersResponse{Clusters: data}
			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling clusters response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	// Pattern for schema://tables/{cluster}
	tablesPattern := regexp.MustCompile(`^schema://tables/([^/]+)$`)

	// Register template for schema://tables/{cluster}
	reg.RegisterTemplate(TemplateResource{
		Template: mcp.NewResourceTemplate(
			"schema://tables/{cluster}",
			"Cluster Tables",
			mcp.WithTemplateDescription("List all tables in a ClickHouse cluster. Cluster: xatu, xatu-experimental, xatu-cbt"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		Pattern: tablesPattern,
		Handler: func(ctx context.Context, uri string) (string, error) {
			matches := tablesPattern.FindStringSubmatch(uri)
			if len(matches) != 2 {
				return "", fmt.Errorf("invalid URI format: %s", uri)
			}

			clusterName := matches[1]

			cluster, ok := provider.GetCluster(clusterName)
			if !ok {
				available := getAvailableClusterNames(provider)
				return "", fmt.Errorf("unknown cluster: %s. Available clusters: %s", clusterName, available)
			}

			client, err := clientFactory(clusterName)
			if err != nil {
				return "", fmt.Errorf("creating client for cluster %s: %w", clusterName, err)
			}

			tables, err := client.ListTables(ctx)
			if err != nil {
				return "", fmt.Errorf("listing tables in cluster %s: %w", clusterName, err)
			}

			tableList := make([]tableData, 0, len(tables))
			for _, t := range tables {
				tableList = append(tableList, tableData{
					Name:       t.Name,
					Engine:     t.Engine,
					TotalRows:  t.TotalRows,
					TotalBytes: t.TotalBytes,
					Comment:    t.Comment,
				})
			}

			response := tablesResponse{
				Cluster:    clusterName,
				Database:   cluster.Database,
				TableCount: len(tableList),
				Tables:     tableList,
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling tables response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	// Pattern for schema://tables/{cluster}/{table}
	tableSchemaPattern := regexp.MustCompile(`^schema://tables/([^/]+)/([^/]+)$`)

	// Register template for schema://tables/{cluster}/{table}
	reg.RegisterTemplate(TemplateResource{
		Template: mcp.NewResourceTemplate(
			"schema://tables/{cluster}/{table}",
			"Table Schema",
			mcp.WithTemplateDescription("Detailed schema for a specific table including columns, types, and keys"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		Pattern: tableSchemaPattern,
		Handler: func(ctx context.Context, uri string) (string, error) {
			matches := tableSchemaPattern.FindStringSubmatch(uri)
			if len(matches) != 3 {
				return "", fmt.Errorf("invalid URI format: %s", uri)
			}

			clusterName := matches[1]
			tableName := matches[2]

			_, ok := provider.GetCluster(clusterName)
			if !ok {
				available := getAvailableClusterNames(provider)
				return "", fmt.Errorf("unknown cluster: %s. Available clusters: %s", clusterName, available)
			}

			client, err := clientFactory(clusterName)
			if err != nil {
				return "", fmt.Errorf("creating client for cluster %s: %w", clusterName, err)
			}

			tableInfo, err := client.GetTableInfo(ctx, tableName)
			if err != nil {
				return "", fmt.Errorf("getting table info for %s: %w", tableName, err)
			}
			if tableInfo == nil {
				return "", fmt.Errorf("table not found: %s in cluster %s", tableName, clusterName)
			}

			columns, err := client.GetTableSchema(ctx, tableName)
			if err != nil {
				return "", fmt.Errorf("getting table schema for %s: %w", tableName, err)
			}

			columnList := make([]columnData, 0, len(columns))
			for _, c := range columns {
				columnList = append(columnList, columnData{
					Name:              c.Name,
					Type:              c.Type,
					Comment:           c.Comment,
					DefaultKind:       c.DefaultKind,
					DefaultExpression: c.DefaultExpression,
					IsPartitionKey:    c.IsPartitionKey,
					IsSortingKey:      c.IsSortingKey,
					IsPrimaryKey:      c.IsPrimaryKey,
				})
			}

			response := tableSchemaResponse{
				Cluster:      clusterName,
				Table:        tableName,
				Engine:       tableInfo.Engine,
				TotalRows:    tableInfo.TotalRows,
				TotalBytes:   tableInfo.TotalBytes,
				Comment:      tableInfo.Comment,
				PartitionKey: tableInfo.PartitionKey,
				SortingKey:   tableInfo.SortingKey,
				PrimaryKey:   tableInfo.PrimaryKey,
				Columns:      columnList,
			}

			jsonData, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling table schema response: %w", err)
			}

			return string(jsonData), nil
		},
	})

	log.Debug("Registered schema resources")
}

// getAvailableClusterNames returns a comma-separated list of available cluster names.
func getAvailableClusterNames(provider ClusterProvider) string {
	clusters := provider.ListClusters()
	names := make([]string, 0, len(clusters))

	for _, c := range clusters {
		names = append(names, c.Name)
	}

	return strings.Join(names, ", ")
}
