package clickhouse

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// Client defines the interface for interacting with ClickHouse clusters.
type Client interface {
	// ListClusters returns all configured clusters.
	ListClusters() []ClusterInfo

	// GetCluster returns a cluster by name, and a boolean indicating if it was found.
	GetCluster(name string) (*ClusterInfo, bool)

	// ListTables returns all tables in the specified cluster's database.
	ListTables(ctx context.Context, clusterName string) ([]TableInfo, error)

	// GetTableSchema returns the column schema for a specific table.
	GetTableSchema(ctx context.Context, clusterName, tableName string) ([]ColumnInfo, error)

	// GetTableInfo returns metadata about a specific table.
	GetTableInfo(ctx context.Context, clusterName, tableName string) (*TableInfo, error)

	// Start initializes the client.
	Start(ctx context.Context) error

	// Stop shuts down the client and releases resources.
	Stop() error
}

// Ensure client implements Client interface.
var _ Client = (*client)(nil)

// client is the HTTP-based implementation of the Client interface.
type client struct {
	log        logrus.FieldLogger
	clusters   map[string]*ClusterInfo
	httpClient *http.Client
	mu         sync.RWMutex
}

// clusterDescriptions maps cluster names to their descriptions.
var clusterDescriptions = map[string]string{
	"xatu":              "Production raw data cluster for mainnet and testnets",
	"xatu-experimental": "Experimental cluster for devnet data",
	"xatu-cbt":          "Aggregated/CBT (Consensus Block Timing) tables",
}

// NewClient creates a new ClickHouse client.
// The client must be started with Start() before use.
func NewClient(log logrus.FieldLogger, clusterConfigs map[string]*config.ClusterConfig) Client {
	clusters := make(map[string]*ClusterInfo, len(clusterConfigs))

	for name, cfg := range clusterConfigs {
		if cfg == nil {
			continue
		}

		description := clusterDescriptions[name]
		if description == "" {
			description = fmt.Sprintf("ClickHouse cluster: %s", name)
		}

		clusters[name] = &ClusterInfo{
			Name:        name,
			Description: description,
			Host:        cfg.Host,
			Port:        cfg.Port,
			Protocol:    cfg.Protocol,
			User:        cfg.User,
			Password:    cfg.Password,
			Database:    cfg.Database,
			Networks:    cfg.Networks,
		}
	}

	return &client{
		log:      log.WithField("component", "clickhouse"),
		clusters: clusters,
	}
}

// Start initializes the HTTP client.
func (c *client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	c.log.WithField("cluster_count", len(c.clusters)).Info("ClickHouse client started")

	return nil
}

// Stop shuts down the HTTP client.
func (c *client) Stop() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.httpClient != nil {
		c.httpClient.CloseIdleConnections()
		c.httpClient = nil
	}

	c.log.Info("ClickHouse client stopped")

	return nil
}

// ListClusters returns all configured clusters.
func (c *client) ListClusters() []ClusterInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]ClusterInfo, 0, len(c.clusters))
	for _, cluster := range c.clusters {
		result = append(result, *cluster)
	}

	return result
}

// GetCluster returns a cluster by name.
func (c *client) GetCluster(name string) (*ClusterInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cluster, ok := c.clusters[name]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent modification
	clusterCopy := *cluster

	return &clusterCopy, true
}

// ListTables returns all tables in the specified cluster's database.
func (c *client) ListTables(ctx context.Context, clusterName string) ([]TableInfo, error) {
	cluster, ok := c.GetCluster(clusterName)
	if !ok {
		return nil, fmt.Errorf("cluster %q not found", clusterName)
	}

	query := `
		SELECT
			name,
			engine,
			toString(total_rows) as total_rows,
			toString(total_bytes) as total_bytes,
			comment,
			partition_key,
			sorting_key,
			primary_key
		FROM system.tables
		WHERE database = currentDatabase()
		AND name NOT LIKE '.%'
		ORDER BY name
	`

	rows, err := c.executeQuery(ctx, cluster, query)
	if err != nil {
		return nil, fmt.Errorf("listing tables for cluster %q: %w", clusterName, err)
	}

	tables := make([]TableInfo, 0, len(rows))

	for _, row := range rows {
		tables = append(tables, TableInfo{
			Name:         row["name"],
			Engine:       row["engine"],
			TotalRows:    row["total_rows"],
			TotalBytes:   row["total_bytes"],
			Comment:      row["comment"],
			PartitionKey: row["partition_key"],
			SortingKey:   row["sorting_key"],
			PrimaryKey:   row["primary_key"],
		})
	}

	c.log.WithFields(logrus.Fields{
		"cluster":     clusterName,
		"table_count": len(tables),
	}).Debug("Listed tables")

	return tables, nil
}

// GetTableSchema returns the column schema for a specific table.
func (c *client) GetTableSchema(ctx context.Context, clusterName, tableName string) ([]ColumnInfo, error) {
	cluster, ok := c.GetCluster(clusterName)
	if !ok {
		return nil, fmt.Errorf("cluster %q not found", clusterName)
	}

	if err := ValidateIdentifier(tableName, "table"); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
		SELECT
			name,
			type,
			comment,
			default_kind,
			default_expression,
			is_in_partition_key,
			is_in_sorting_key,
			is_in_primary_key
		FROM system.columns
		WHERE database = currentDatabase()
		AND table = '%s'
		ORDER BY position
	`, tableName)

	rows, err := c.executeQuery(ctx, cluster, query)
	if err != nil {
		return nil, fmt.Errorf("getting schema for table %q in cluster %q: %w", tableName, clusterName, err)
	}

	columns := make([]ColumnInfo, 0, len(rows))

	for _, row := range rows {
		columns = append(columns, ColumnInfo{
			Name:              row["name"],
			Type:              row["type"],
			Comment:           row["comment"],
			DefaultKind:       row["default_kind"],
			DefaultExpression: row["default_expression"],
			IsPartitionKey:    row["is_in_partition_key"] == "1",
			IsSortingKey:      row["is_in_sorting_key"] == "1",
			IsPrimaryKey:      row["is_in_primary_key"] == "1",
		})
	}

	c.log.WithFields(logrus.Fields{
		"cluster":      clusterName,
		"table":        tableName,
		"column_count": len(columns),
	}).Debug("Retrieved table schema")

	return columns, nil
}

// GetTableInfo returns metadata about a specific table.
func (c *client) GetTableInfo(ctx context.Context, clusterName, tableName string) (*TableInfo, error) {
	cluster, ok := c.GetCluster(clusterName)
	if !ok {
		return nil, fmt.Errorf("cluster %q not found", clusterName)
	}

	if err := ValidateIdentifier(tableName, "table"); err != nil {
		return nil, err
	}

	query := fmt.Sprintf(`
		SELECT
			name,
			engine,
			toString(total_rows) as total_rows,
			toString(total_bytes) as total_bytes,
			comment,
			partition_key,
			sorting_key,
			primary_key
		FROM system.tables
		WHERE database = currentDatabase()
		AND name = '%s'
		LIMIT 1
	`, tableName)

	rows, err := c.executeQuery(ctx, cluster, query)
	if err != nil {
		return nil, fmt.Errorf("getting info for table %q in cluster %q: %w", tableName, clusterName, err)
	}

	if len(rows) == 0 {
		return nil, fmt.Errorf("table %q not found in cluster %q", tableName, clusterName)
	}

	row := rows[0]
	tableInfo := &TableInfo{
		Name:         row["name"],
		Engine:       row["engine"],
		TotalRows:    row["total_rows"],
		TotalBytes:   row["total_bytes"],
		Comment:      row["comment"],
		PartitionKey: row["partition_key"],
		SortingKey:   row["sorting_key"],
		PrimaryKey:   row["primary_key"],
	}

	c.log.WithFields(logrus.Fields{
		"cluster": clusterName,
		"table":   tableName,
	}).Debug("Retrieved table info")

	return tableInfo, nil
}

// executeQuery executes a SQL query against a ClickHouse cluster and returns the results.
func (c *client) executeQuery(
	ctx context.Context,
	cluster *ClusterInfo,
	query string,
) ([]map[string]string, error) {
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()

	if httpClient == nil {
		return nil, fmt.Errorf("client not started: call Start() first")
	}

	// Append FORMAT JSONEachRow to get line-delimited JSON
	queryWithFormat := strings.TrimRight(strings.TrimSpace(query), ";") + " FORMAT JSONEachRow"

	url := cluster.URL()
	if cluster.Database != "" {
		url = fmt.Sprintf("%s?database=%s", url, cluster.Database)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader(queryWithFormat))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Content-Type", "text/plain")
	req.SetBasicAuth(cluster.User, cluster.Password)

	c.log.WithFields(logrus.Fields{
		"cluster": cluster.Name,
		"query":   truncateQuery(query, 100),
	}).Debug("Executing ClickHouse query")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf(
			"ClickHouse query failed with status %d: %s",
			resp.StatusCode,
			string(body),
		)
	}

	// Parse JSONEachRow format: one JSON object per line
	text := strings.TrimSpace(string(body))
	if text == "" {
		return []map[string]string{}, nil
	}

	lines := strings.Split(text, "\n")
	results := make([]map[string]string, 0, len(lines))

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			return nil, fmt.Errorf("parsing JSON row: %w", err)
		}

		// Convert all values to strings for consistent handling
		stringRow := make(map[string]string, len(row))
		for k, v := range row {
			stringRow[k] = fmt.Sprint(v)
		}

		results = append(results, stringRow)
	}

	return results, nil
}

// truncateQuery truncates a query string for logging purposes.
func truncateQuery(query string, maxLen int) string {
	// Normalize whitespace
	query = strings.Join(strings.Fields(query), " ")

	if len(query) <= maxLen {
		return query
	}

	return query[:maxLen] + "..."
}
