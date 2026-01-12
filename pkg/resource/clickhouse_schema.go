package resource

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ClickHouse/clickhouse-go/v2"
	"github.com/ClickHouse/clickhouse-go/v2/lib/driver"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// validIdentifier matches valid ClickHouse table/column identifiers.
var validIdentifier = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

const (
	// DefaultSchemaRefreshInterval is the refresh interval for schema discovery.
	DefaultSchemaRefreshInterval = 15 * time.Minute

	// DefaultSchemaQueryTimeout is the timeout for individual schema queries.
	DefaultSchemaQueryTimeout = 60 * time.Second

	// schemaQueryConcurrency limits concurrent schema queries per cluster.
	schemaQueryConcurrency = 5
)

// SchemaDiscoveryDatasource maps a ClickHouse cluster name to a logical cluster name.
type SchemaDiscoveryDatasource struct {
	Name    string
	Cluster string
}

// ClickHouseSchemaConfig holds configuration for schema discovery.
type ClickHouseSchemaConfig struct {
	RefreshInterval time.Duration
	QueryTimeout    time.Duration
	Datasources     []SchemaDiscoveryDatasource
}

// TableColumn represents a column in a ClickHouse table.
type TableColumn struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	Comment      string `json:"comment,omitempty"`
	DefaultType  string `json:"default_type,omitempty"`
	DefaultValue string `json:"default_value,omitempty"`
}

// TableSchema represents the full schema of a ClickHouse table.
type TableSchema struct {
	Name            string        `json:"name"`
	Engine          string        `json:"engine,omitempty"`
	Columns         []TableColumn `json:"columns"`
	Networks        []string      `json:"networks,omitempty"`
	HasNetworkCol   bool          `json:"has_network_column"`
	CreateStatement string        `json:"create_statement,omitempty"`
	Comment         string        `json:"comment,omitempty"`
}

// ClusterTables represents tables available in a ClickHouse cluster.
type ClusterTables struct {
	ClusterName string                  `json:"cluster_name"`
	Tables      map[string]*TableSchema `json:"tables"`
	LastUpdated time.Time               `json:"last_updated"`
}

// ClickHouseSchemaClient fetches and caches ClickHouse schema information.
type ClickHouseSchemaClient interface {
	// Start initializes the client and fetches initial schema data.
	Start(ctx context.Context) error
	// Stop stops background refresh.
	Stop() error
	// GetAllTables returns all tables across all clusters.
	GetAllTables() map[string]*ClusterTables
	// GetTable returns schema for a specific table (searches all clusters).
	GetTable(tableName string) (*TableSchema, string, bool)
	// GetTablesByCluster returns tables for a specific cluster.
	GetTablesByCluster(clusterName string) (*ClusterTables, bool)
	// GetClusters returns available cluster names.
	GetClusters() []string
}

// Compile-time interface compliance check.
var _ ClickHouseSchemaClient = (*clickhouseSchemaClient)(nil)

type clickhouseSchemaClient struct {
	log       logrus.FieldLogger
	cfg       ClickHouseSchemaConfig
	chConfigs []config.ClickHouseConfig

	mu          sync.RWMutex
	clusters    map[string]*ClusterTables
	connections map[string]driver.Conn // cluster name -> connection
	lastUpdated time.Time

	done chan struct{}
	wg   sync.WaitGroup
}

// NewClickHouseSchemaClient creates a new schema discovery client.
func NewClickHouseSchemaClient(
	log logrus.FieldLogger,
	cfg ClickHouseSchemaConfig,
	chConfigs []config.ClickHouseConfig,
) ClickHouseSchemaClient {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = DefaultSchemaRefreshInterval
	}

	if cfg.QueryTimeout == 0 {
		cfg.QueryTimeout = DefaultSchemaQueryTimeout
	}

	return &clickhouseSchemaClient{
		log:         log.WithField("component", "clickhouse_schema"),
		cfg:         cfg,
		chConfigs:   chConfigs,
		clusters:    make(map[string]*ClusterTables, 2),
		connections: make(map[string]driver.Conn, 2),
		done:        make(chan struct{}),
	}
}

// Start initializes the client and starts background refresh.
// The initial schema fetch runs asynchronously to avoid blocking server startup.
func (c *clickhouseSchemaClient) Start(ctx context.Context) error {
	c.log.WithField("refresh_interval", c.cfg.RefreshInterval).Info("Starting ClickHouse schema client")

	// Initialize connections for each configured datasource.
	if err := c.initConnections(); err != nil {
		return fmt.Errorf("initializing ClickHouse connections: %w", err)
	}

	// Start background refresh (includes initial fetch)
	c.wg.Add(1)

	go c.backgroundRefresh()

	// Trigger immediate initial fetch (tracked to prevent use-after-close)
	c.wg.Add(1)

	go func() {
		defer c.wg.Done()

		fetchCtx, cancel := context.WithTimeout(context.Background(), c.cfg.QueryTimeout*10)
		defer cancel()

		if err := c.refresh(fetchCtx); err != nil {
			c.log.WithError(err).Warn("Initial schema fetch failed, will retry on next refresh interval")
		} else {
			tableCount := 0

			c.mu.RLock()
			for _, cluster := range c.clusters {
				tableCount += len(cluster.Tables)
			}
			c.mu.RUnlock()

			c.log.WithFields(logrus.Fields{
				"cluster_count": len(c.clusters),
				"table_count":   tableCount,
			}).Info("Initial ClickHouse schema fetch completed")
		}
	}()

	c.log.Info("ClickHouse schema client started (fetching schema in background)")

	return nil
}

// initConnections initializes ClickHouse connections for configured datasources.
func (c *clickhouseSchemaClient) initConnections() error {
	// Build a map of ClickHouse configs by name.
	chConfigMap := make(map[string]config.ClickHouseConfig, len(c.chConfigs))
	for _, cfg := range c.chConfigs {
		chConfigMap[cfg.Name] = cfg
	}

	// Create connections for each configured schema discovery datasource.
	for _, ds := range c.cfg.Datasources {
		chCfg, ok := chConfigMap[ds.Name]
		if !ok {
			c.log.WithFields(logrus.Fields{
				"name":    ds.Name,
				"cluster": ds.Cluster,
			}).Warn("Schema discovery datasource not found in ClickHouse configs")

			continue
		}

		conn, err := c.createConnection(chCfg)
		if err != nil {
			c.log.WithError(err).WithField("cluster", ds.Cluster).Warn("Failed to create ClickHouse connection")

			continue
		}

		c.connections[ds.Cluster] = conn

		c.log.WithFields(logrus.Fields{
			"name":    ds.Name,
			"cluster": ds.Cluster,
		}).Debug("Created ClickHouse connection for schema discovery")
	}

	if len(c.connections) == 0 {
		return fmt.Errorf("no ClickHouse connections could be established")
	}

	return nil
}

// createConnection creates a ClickHouse connection from config.
func (c *clickhouseSchemaClient) createConnection(cfg config.ClickHouseConfig) (driver.Conn, error) {
	// Parse host:port using net.SplitHostPort for IPv6 compatibility.
	host, port, err := net.SplitHostPort(cfg.Host)
	if err != nil {
		// No port specified, use default.
		host = cfg.Host
		port = "9440" // Default secure port.
	}

	addr := net.JoinHostPort(host, port)

	opts := &clickhouse.Options{
		Addr: []string{addr},
		Auth: clickhouse.Auth{
			Database: cfg.Database,
			Username: cfg.Username,
			Password: cfg.Password,
		},
		Settings: clickhouse.Settings{
			"max_execution_time": 60,
		},
		DialTimeout: 30 * time.Second,
	}

	// Configure TLS.
	if cfg.IsSecure() {
		if cfg.SkipVerify {
			c.log.WithField("host", host).Warn("TLS certificate verification disabled (skip_verify=true) - vulnerable to MITM attacks")
		}

		opts.TLS = &tls.Config{
			MinVersion:         tls.VersionTLS12,
			InsecureSkipVerify: cfg.SkipVerify, //nolint:gosec // User-configured option.
		}
	}

	conn, err := clickhouse.Open(opts)
	if err != nil {
		return nil, fmt.Errorf("opening ClickHouse connection: %w", err)
	}

	// Test the connection with timeout.
	pingCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := conn.Ping(pingCtx); err != nil {
		return nil, fmt.Errorf("pinging ClickHouse: %w", err)
	}

	return conn, nil
}

// Stop stops the background refresh goroutine.
func (c *clickhouseSchemaClient) Stop() error {
	close(c.done)
	c.wg.Wait()

	// Close all connections.
	for cluster, conn := range c.connections {
		if err := conn.Close(); err != nil {
			c.log.WithError(err).WithField("cluster", cluster).Warn("Failed to close ClickHouse connection")
		}
	}

	c.log.Info("ClickHouse schema client stopped")

	return nil
}

// GetAllTables returns all tables across all clusters.
func (c *clickhouseSchemaClient) GetAllTables() map[string]*ClusterTables {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make(map[string]*ClusterTables, len(c.clusters))
	for k, v := range c.clusters {
		// Deep copy cluster tables.
		clusterCopy := &ClusterTables{
			ClusterName: v.ClusterName,
			Tables:      make(map[string]*TableSchema, len(v.Tables)),
			LastUpdated: v.LastUpdated,
		}

		for tableName, schema := range v.Tables {
			clusterCopy.Tables[tableName] = schema
		}

		result[k] = clusterCopy
	}

	return result
}

// GetTable returns schema for a specific table (searches all clusters).
func (c *clickhouseSchemaClient) GetTable(tableName string) (*TableSchema, string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	for clusterName, cluster := range c.clusters {
		if schema, ok := cluster.Tables[tableName]; ok {
			return schema, clusterName, true
		}
	}

	return nil, "", false
}

// GetTablesByCluster returns tables for a specific cluster.
func (c *clickhouseSchemaClient) GetTablesByCluster(clusterName string) (*ClusterTables, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	cluster, ok := c.clusters[clusterName]
	if !ok {
		return nil, false
	}

	// Return a copy.
	clusterCopy := &ClusterTables{
		ClusterName: cluster.ClusterName,
		Tables:      make(map[string]*TableSchema, len(cluster.Tables)),
		LastUpdated: cluster.LastUpdated,
	}

	for tableName, schema := range cluster.Tables {
		clusterCopy.Tables[tableName] = schema
	}

	return clusterCopy, true
}

// GetClusters returns available cluster names.
func (c *clickhouseSchemaClient) GetClusters() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	clusters := make([]string, 0, len(c.clusters))
	for name := range c.clusters {
		clusters = append(clusters, name)
	}

	sort.Strings(clusters)

	return clusters
}

// backgroundRefresh periodically refreshes the schema data.
func (c *clickhouseSchemaClient) backgroundRefresh() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cfg.RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			c.doRefresh()
		}
	}
}

// doRefresh performs a single schema refresh with proper context cleanup.
func (c *clickhouseSchemaClient) doRefresh() {
	ctx, cancel := context.WithTimeout(context.Background(), c.cfg.QueryTimeout*10)
	defer cancel()

	if err := c.refresh(ctx); err != nil {
		c.log.WithError(err).Warn("Failed to refresh ClickHouse schema data")

		return
	}

	tableCount := 0

	c.mu.RLock()
	for _, cluster := range c.clusters {
		tableCount += len(cluster.Tables)
	}
	c.mu.RUnlock()

	c.log.WithField("table_count", tableCount).Debug("Refreshed ClickHouse schema data")
}

// refresh fetches the latest schema from all configured clusters.
func (c *clickhouseSchemaClient) refresh(ctx context.Context) error {
	if len(c.connections) == 0 {
		c.log.Warn("No ClickHouse connections available for schema discovery")

		return nil
	}

	newClusters := make(map[string]*ClusterTables, len(c.connections))

	for clusterName, conn := range c.connections {
		tables, err := c.discoverClusterSchema(ctx, clusterName, conn)
		if err != nil {
			c.log.WithError(err).WithField("cluster", clusterName).Warn("Failed to discover cluster schema")

			continue
		}

		newClusters[clusterName] = tables
	}

	// Atomic update.
	c.mu.Lock()
	c.clusters = newClusters
	c.lastUpdated = time.Now()
	c.mu.Unlock()

	return nil
}

// discoverClusterSchema discovers schema for a single cluster.
func (c *clickhouseSchemaClient) discoverClusterSchema(
	ctx context.Context,
	clusterName string,
	conn driver.Conn,
) (*ClusterTables, error) {
	// Get table list.
	tables, err := c.fetchTableList(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("fetching table list: %w", err)
	}

	clusterTables := &ClusterTables{
		ClusterName: clusterName,
		Tables:      make(map[string]*TableSchema, len(tables)),
		LastUpdated: time.Now(),
	}

	// Get schema for each table with concurrency limit.
	sem := make(chan struct{}, schemaQueryConcurrency)

	var wg sync.WaitGroup

	var mu sync.Mutex

	for _, tableName := range tables {
		wg.Add(1)

		go func(name string) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				return
			}

			schema, err := c.fetchTableSchema(ctx, conn, name)
			if err != nil {
				c.log.WithError(err).WithField("table", name).Debug("Failed to fetch table schema")

				return
			}

			// Get networks if table has meta_network_name column.
			if schema.HasNetworkCol {
				networks, err := c.fetchTableNetworks(ctx, conn, name)
				if err != nil {
					c.log.WithError(err).WithField("table", name).Debug("Failed to fetch table networks")
				} else {
					schema.Networks = networks
				}
			}

			mu.Lock()
			clusterTables.Tables[name] = schema
			mu.Unlock()
		}(tableName)
	}

	wg.Wait()

	return clusterTables, nil
}

// fetchTableList fetches the list of tables from a ClickHouse connection.
func (c *clickhouseSchemaClient) fetchTableList(ctx context.Context, conn driver.Conn) ([]string, error) {
	rows, err := conn.Query(ctx, "SHOW TABLES")
	if err != nil {
		return nil, fmt.Errorf("executing SHOW TABLES: %w", err)
	}
	defer func() { _ = rows.Close() }()

	tables := make([]string, 0, 64)

	for rows.Next() {
		var tableName string
		if err := rows.Scan(&tableName); err != nil {
			continue
		}

		// Skip tables with _local suffix (internal ClickHouse distributed table shards).
		if strings.HasSuffix(tableName, "_local") {
			continue
		}

		tables = append(tables, tableName)
	}

	return tables, rows.Err()
}

// validateIdentifier validates a ClickHouse table/column identifier to prevent SQL injection.
func validateIdentifier(name string) error {
	if !validIdentifier.MatchString(name) {
		return fmt.Errorf("invalid identifier %q: must match [A-Za-z_][A-Za-z0-9_]*", name)
	}

	return nil
}

// fetchTableSchema fetches the schema for a specific table.
func (c *clickhouseSchemaClient) fetchTableSchema(
	ctx context.Context,
	conn driver.Conn,
	tableName string,
) (*TableSchema, error) {
	if err := validateIdentifier(tableName); err != nil {
		return nil, fmt.Errorf("validating table name: %w", err)
	}

	query := fmt.Sprintf("SHOW CREATE TABLE `%s`", tableName)

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("executing SHOW CREATE TABLE: %w", err)
	}
	defer func() { _ = rows.Close() }()

	var createStmt string

	if rows.Next() {
		if err := rows.Scan(&createStmt); err != nil {
			return nil, fmt.Errorf("scanning CREATE TABLE result: %w", err)
		}
	}

	if createStmt == "" {
		return nil, fmt.Errorf("empty CREATE TABLE statement for table %s", tableName)
	}

	return parseCreateTable(tableName, createStmt)
}

// fetchTableNetworks fetches distinct networks available in a table.
func (c *clickhouseSchemaClient) fetchTableNetworks(
	ctx context.Context,
	conn driver.Conn,
	tableName string,
) ([]string, error) {
	if err := validateIdentifier(tableName); err != nil {
		return nil, fmt.Errorf("validating table name: %w", err)
	}

	query := fmt.Sprintf(
		"SELECT DISTINCT meta_network_name FROM `%s` WHERE meta_network_name IS NOT NULL AND meta_network_name != '' LIMIT 1000",
		tableName,
	)

	rows, err := conn.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("executing network query: %w", err)
	}
	defer func() { _ = rows.Close() }()

	networks := make([]string, 0, 16)

	for rows.Next() {
		var network string
		if err := rows.Scan(&network); err != nil {
			continue
		}

		if network != "" {
			networks = append(networks, network)
		}
	}

	sort.Strings(networks)

	return networks, rows.Err()
}

// parseCreateTable parses SHOW CREATE TABLE output to extract schema info.
func parseCreateTable(tableName, createStmt string) (*TableSchema, error) {
	schema := &TableSchema{
		Name:            tableName,
		CreateStatement: createStmt,
		Columns:         make([]TableColumn, 0, 32),
	}

	// Extract engine.
	enginePattern := regexp.MustCompile(`ENGINE\s*=\s*(\w+)`)
	if matches := enginePattern.FindStringSubmatch(createStmt); len(matches) > 1 {
		schema.Engine = matches[1]
	}

	// Extract table comment.
	tableCommentPattern := regexp.MustCompile(`COMMENT\s+'([^']*)'`)
	if matches := tableCommentPattern.FindStringSubmatch(createStmt); len(matches) > 1 {
		schema.Comment = matches[1]
	}

	// Extract columns from the CREATE TABLE statement.
	// Find the content between the first ( and the matching ).
	startIdx := strings.Index(createStmt, "(")
	if startIdx == -1 {
		return schema, nil
	}

	// Find matching closing parenthesis.
	depth := 0
	endIdx := -1

outerLoop:
	for i := startIdx; i < len(createStmt); i++ {
		switch createStmt[i] {
		case '(':
			depth++
		case ')':
			depth--

			if depth == 0 {
				endIdx = i

				break outerLoop
			}
		}
	}

	if endIdx == -1 {
		return schema, nil
	}

	columnsSection := createStmt[startIdx+1 : endIdx]

	// Parse each column definition.
	// Column format: `name` Type [DEFAULT expr] [CODEC(...)] [COMMENT 'comment'].
	columnPattern := regexp.MustCompile("(?m)^\\s*`([^`]+)`\\s+([^,\\n]+)")
	commentPattern := regexp.MustCompile(`COMMENT\s+'([^']*)'`)
	defaultPattern := regexp.MustCompile(`(DEFAULT|MATERIALIZED|ALIAS)\s+([^,\n]+?)(?:\s+(?:CODEC|COMMENT|$))`)

	lines := strings.Split(columnsSection, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "INDEX") || strings.HasPrefix(line, "PROJECTION") {
			continue
		}

		colMatches := columnPattern.FindStringSubmatch(line)
		if len(colMatches) < 3 {
			continue
		}

		col := TableColumn{
			Name: colMatches[1],
			Type: strings.TrimSpace(colMatches[2]),
		}

		// Clean up the type - remove trailing commas and other clauses.
		col.Type = cleanColumnType(col.Type)

		// Extract comment.
		if commentMatches := commentPattern.FindStringSubmatch(line); len(commentMatches) > 1 {
			col.Comment = commentMatches[1]
		}

		// Extract default.
		if defaultMatches := defaultPattern.FindStringSubmatch(line); len(defaultMatches) > 2 {
			col.DefaultType = defaultMatches[1]
			col.DefaultValue = strings.TrimSpace(defaultMatches[2])
		}

		// Check for meta_network_name column.
		if col.Name == "meta_network_name" {
			schema.HasNetworkCol = true
		}

		schema.Columns = append(schema.Columns, col)
	}

	return schema, nil
}

// cleanColumnType removes trailing clauses from the column type.
func cleanColumnType(colType string) string {
	// Remove everything after DEFAULT, CODEC, COMMENT.
	for _, keyword := range []string{" DEFAULT", " CODEC", " COMMENT", " MATERIALIZED", " ALIAS"} {
		if idx := strings.Index(strings.ToUpper(colType), keyword); idx != -1 {
			colType = colType[:idx]
		}
	}

	// Remove trailing comma.
	colType = strings.TrimSuffix(strings.TrimSpace(colType), ",")

	return colType
}
