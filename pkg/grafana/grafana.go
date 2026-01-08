package grafana

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// DatasourceType represents the normalized type of a Grafana datasource.
type DatasourceType string

const (
	DatasourceTypeLoki       DatasourceType = "loki"
	DatasourceTypePrometheus DatasourceType = "prometheus"
	DatasourceTypeClickHouse DatasourceType = "clickhouse"
	DatasourceTypeUnknown    DatasourceType = "unknown"
)

// Datasource represents a Grafana datasource.
type Datasource struct {
	UID         string         `json:"uid"`
	Name        string         `json:"name"`
	Type        string         `json:"type"`
	TypeNorm    DatasourceType `json:"type_normalized"`
	Description string         `json:"description,omitempty"`
}

// Client defines the interface for interacting with Grafana.
type Client interface {
	// Start initializes the client and discovers datasources.
	Start(ctx context.Context) error

	// Stop shuts down the client and releases resources.
	Stop() error

	// ListDatasources returns all discovered datasources.
	ListDatasources() []Datasource

	// ListDatasourcesByType returns datasources filtered by type.
	ListDatasourcesByType(dsType DatasourceType) []Datasource

	// GetDatasource returns a datasource by UID.
	GetDatasource(uid string) (*Datasource, bool)

	// QueryClickHouse executes a SQL query against a ClickHouse datasource.
	QueryClickHouse(ctx context.Context, uid, sql string) (*QueryResult, error)

	// QueryPrometheus executes a PromQL query against a Prometheus datasource.
	QueryPrometheus(ctx context.Context, uid, query string, time time.Time) (*QueryResult, error)

	// QueryPrometheusRange executes a PromQL range query.
	QueryPrometheusRange(
		ctx context.Context, uid, query string,
		start, end time.Time, step time.Duration,
	) (*QueryResult, error)

	// QueryLoki executes a LogQL query against a Loki datasource.
	QueryLoki(
		ctx context.Context, uid, query string,
		start, end time.Time, limit int,
	) (*QueryResult, error)

	// GetLokiLabels returns available label names from a Loki datasource.
	GetLokiLabels(ctx context.Context, uid string, start, end time.Time) ([]string, error)

	// GetLokiLabelValues returns values for a specific label from a Loki datasource.
	GetLokiLabelValues(ctx context.Context, uid, label string, start, end time.Time) ([]string, error)

	// HealthCheck verifies the connection to Grafana.
	HealthCheck(ctx context.Context) error
}

// Ensure client implements Client interface.
var _ Client = (*client)(nil)

// client is the HTTP-based implementation of the Client interface.
type client struct {
	log         logrus.FieldLogger
	cfg         *Config
	httpClient  *http.Client
	datasources map[string]*Datasource
	allowedUIDs map[string]struct{}
	mu          sync.RWMutex
}

// QueryResult represents the result of a Grafana query.
type QueryResult struct {
	// Frames contains the data frames from the query.
	Frames []DataFrame `json:"frames"`
	// Raw contains the raw JSON response for inspection.
	Raw json.RawMessage `json:"raw,omitempty"`
}

// DataFrame represents a single data frame in a query result.
type DataFrame struct {
	Name   string         `json:"name,omitempty"`
	Fields []DataField    `json:"fields"`
	Meta   map[string]any `json:"meta,omitempty"`
}

// DataField represents a column/field in a data frame.
type DataField struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Values []any  `json:"values"`
}

// NewClient creates a new Grafana client.
// The client must be started with Start() before use.
func NewClient(log logrus.FieldLogger, cfg *Config) Client {
	allowedUIDs := make(map[string]struct{}, len(cfg.DatasourceUIDs))
	for _, uid := range cfg.DatasourceUIDs {
		allowedUIDs[uid] = struct{}{}
	}

	return &client{
		log:         log.WithField("component", "grafana"),
		cfg:         cfg,
		allowedUIDs: allowedUIDs,
	}
}

// Start initializes the HTTP client and discovers datasources.
func (c *client) Start(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.httpClient = &http.Client{
		Timeout: c.cfg.GetTimeout(),
		Transport: &http.Transport{
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 10,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Discover datasources
	if err := c.discoverDatasources(ctx); err != nil {
		return fmt.Errorf("discovering datasources: %w", err)
	}

	c.log.WithField("datasource_count", len(c.datasources)).Info("Grafana client started")

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

	c.log.Info("Grafana client stopped")

	return nil
}

// discoverDatasources fetches and filters datasources from Grafana.
// Caller must hold c.mu.
func (c *client) discoverDatasources(ctx context.Context) error {
	req, err := c.newRequest(ctx, http.MethodGet, "/api/datasources", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("failed to list datasources (status %d): %s", resp.StatusCode, string(body))
	}

	var rawDatasources []struct {
		UID  string `json:"uid"`
		Name string `json:"name"`
		Type string `json:"type"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawDatasources); err != nil {
		return fmt.Errorf("decoding datasources: %w", err)
	}

	c.datasources = make(map[string]*Datasource, len(rawDatasources))

	for _, raw := range rawDatasources {
		typeNorm := normalizeDatasourceType(raw.Type)
		if typeNorm == DatasourceTypeUnknown {
			continue // Skip unsupported datasource types
		}

		// Filter by allowed UIDs if configured
		if len(c.allowedUIDs) > 0 {
			if _, ok := c.allowedUIDs[raw.UID]; !ok {
				continue
			}
		}

		ds := &Datasource{
			UID:      raw.UID,
			Name:     raw.Name,
			Type:     raw.Type,
			TypeNorm: typeNorm,
		}
		c.datasources[raw.UID] = ds

		c.log.WithFields(logrus.Fields{
			"uid":  ds.UID,
			"name": ds.Name,
			"type": ds.TypeNorm,
		}).Debug("Discovered datasource")
	}

	return nil
}

// normalizeDatasourceType converts a Grafana datasource type to our normalized type.
func normalizeDatasourceType(dsType string) DatasourceType {
	dsTypeLower := strings.ToLower(dsType)

	switch {
	case strings.Contains(dsTypeLower, "loki"):
		return DatasourceTypeLoki
	case strings.Contains(dsTypeLower, "prometheus"):
		return DatasourceTypePrometheus
	case strings.Contains(dsTypeLower, "clickhouse"):
		return DatasourceTypeClickHouse
	default:
		return DatasourceTypeUnknown
	}
}

// ListDatasources returns all discovered datasources.
func (c *client) ListDatasources() []Datasource {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Datasource, 0, len(c.datasources))
	for _, ds := range c.datasources {
		result = append(result, *ds)
	}

	return result
}

// ListDatasourcesByType returns datasources filtered by type.
func (c *client) ListDatasourcesByType(dsType DatasourceType) []Datasource {
	c.mu.RLock()
	defer c.mu.RUnlock()

	result := make([]Datasource, 0)

	for _, ds := range c.datasources {
		if ds.TypeNorm == dsType {
			result = append(result, *ds)
		}
	}

	return result
}

// GetDatasource returns a datasource by UID.
func (c *client) GetDatasource(uid string) (*Datasource, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	ds, ok := c.datasources[uid]
	if !ok {
		return nil, false
	}

	// Return a copy to prevent modification
	dsCopy := *ds

	return &dsCopy, true
}

// HealthCheck verifies the connection to Grafana.
func (c *client) HealthCheck(ctx context.Context) error {
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()

	if httpClient == nil {
		return fmt.Errorf("client not started: call Start() first")
	}

	req, err := c.newRequest(ctx, http.MethodGet, "/api/user", nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusUnauthorized {
			return fmt.Errorf("authentication failed: check service token")
		}
		return fmt.Errorf("health check failed with status %d", resp.StatusCode)
	}

	return nil
}

// QueryClickHouse executes a SQL query via Grafana's unified query API.
func (c *client) QueryClickHouse(ctx context.Context, uid, sql string) (*QueryResult, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypeClickHouse {
		return nil, fmt.Errorf("datasource %q is not a ClickHouse datasource", uid)
	}

	now := time.Now()
	body := map[string]any{
		"from": strconv.FormatInt(now.Add(-time.Hour).UnixMilli(), 10),
		"to":   strconv.FormatInt(now.UnixMilli(), 10),
		"queries": []map[string]any{
			{
				"refId":         "A",
				"datasource":    map[string]string{"uid": uid, "type": ds.Type},
				"queryType":     "sql",
				"editorType":    "sql",
				"format":        1, // Table format
				"intervalMs":    1000,
				"maxDataPoints": 10000,
				"rawSql":        sql,
			},
		},
	}

	return c.executeUnifiedQuery(ctx, body)
}

// QueryPrometheus executes an instant PromQL query.
func (c *client) QueryPrometheus(ctx context.Context, uid, query string, t time.Time) (*QueryResult, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypePrometheus {
		return nil, fmt.Errorf("datasource %q is not a Prometheus datasource", uid)
	}

	params := url.Values{
		"query": {query},
		"time":  {strconv.FormatInt(t.Unix(), 10)},
	}

	path := fmt.Sprintf("/api/datasources/proxy/uid/%s/api/v1/query?%s", uid, params.Encode())

	return c.executeProxyGet(ctx, path)
}

// QueryPrometheusRange executes a range PromQL query.
func (c *client) QueryPrometheusRange(
	ctx context.Context, uid, query string,
	start, end time.Time, step time.Duration,
) (*QueryResult, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypePrometheus {
		return nil, fmt.Errorf("datasource %q is not a Prometheus datasource", uid)
	}

	params := url.Values{
		"query": {query},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.FormatInt(int64(step.Seconds()), 10)},
	}

	path := fmt.Sprintf("/api/datasources/proxy/uid/%s/api/v1/query_range?%s", uid, params.Encode())

	return c.executeProxyGet(ctx, path)
}

// QueryLoki executes a LogQL query.
func (c *client) QueryLoki(
	ctx context.Context, uid, query string,
	start, end time.Time, limit int,
) (*QueryResult, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypeLoki {
		return nil, fmt.Errorf("datasource %q is not a Loki datasource", uid)
	}

	if limit <= 0 {
		limit = 100
	}

	params := url.Values{
		"query": {query},
		"start": {strconv.FormatInt(start.UnixNano(), 10)},
		"end":   {strconv.FormatInt(end.UnixNano(), 10)},
		"limit": {strconv.Itoa(limit)},
	}

	path := fmt.Sprintf("/api/datasources/proxy/uid/%s/loki/api/v1/query_range?%s", uid, params.Encode())

	return c.executeProxyGet(ctx, path)
}

// GetLokiLabels returns available label names from a Loki datasource.
func (c *client) GetLokiLabels(ctx context.Context, uid string, start, end time.Time) ([]string, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypeLoki {
		return nil, fmt.Errorf("datasource %q is not a Loki datasource", uid)
	}

	params := url.Values{
		"start": {strconv.FormatInt(start.UnixNano(), 10)},
		"end":   {strconv.FormatInt(end.UnixNano(), 10)},
	}

	path := fmt.Sprintf("/api/datasources/proxy/uid/%s/loki/api/v1/labels?%s", uid, params.Encode())

	result, err := c.executeProxyGet(ctx, path)
	if err != nil {
		return nil, err
	}

	// Parse labels from Loki response format
	return c.parseLokiLabelsResponse(result.Raw)
}

// GetLokiLabelValues returns values for a specific label.
func (c *client) GetLokiLabelValues(
	ctx context.Context, uid, label string,
	start, end time.Time,
) ([]string, error) {
	ds, ok := c.GetDatasource(uid)
	if !ok {
		return nil, fmt.Errorf("datasource %q not found", uid)
	}

	if ds.TypeNorm != DatasourceTypeLoki {
		return nil, fmt.Errorf("datasource %q is not a Loki datasource", uid)
	}

	params := url.Values{
		"start": {strconv.FormatInt(start.UnixNano(), 10)},
		"end":   {strconv.FormatInt(end.UnixNano(), 10)},
	}

	path := fmt.Sprintf(
		"/api/datasources/proxy/uid/%s/loki/api/v1/label/%s/values?%s",
		uid, url.PathEscape(label), params.Encode(),
	)

	result, err := c.executeProxyGet(ctx, path)
	if err != nil {
		return nil, err
	}

	return c.parseLokiLabelsResponse(result.Raw)
}

// parseLokiLabelsResponse parses a Loki labels/values response.
func (c *client) parseLokiLabelsResponse(raw json.RawMessage) ([]string, error) {
	var resp struct {
		Status string   `json:"status"`
		Data   []string `json:"data"`
	}

	if err := json.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("parsing loki labels response: %w", err)
	}

	if resp.Status != "success" {
		return nil, fmt.Errorf("loki labels query failed with status: %s", resp.Status)
	}

	return resp.Data, nil
}

// executeUnifiedQuery executes a query via Grafana's unified query API (/api/ds/query).
func (c *client) executeUnifiedQuery(ctx context.Context, body map[string]any) (*QueryResult, error) {
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()

	if httpClient == nil {
		return nil, fmt.Errorf("client not started: call Start() first")
	}

	jsonBody, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshaling request body: %w", err)
	}

	req, err := c.newRequest(ctx, http.MethodPost, "/api/ds/query", bytes.NewReader(jsonBody))
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	return c.parseUnifiedQueryResponse(respBody)
}

// executeProxyGet executes a GET request via the datasource proxy.
func (c *client) executeProxyGet(ctx context.Context, path string) (*QueryResult, error) {
	c.mu.RLock()
	httpClient := c.httpClient
	c.mu.RUnlock()

	if httpClient == nil {
		return nil, fmt.Errorf("client not started: call Start() first")
	}

	req, err := c.newRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("query failed with status %d: %s", resp.StatusCode, string(respBody))
	}

	// Return raw response - let caller parse specific format
	return &QueryResult{Raw: respBody}, nil
}

// parseUnifiedQueryResponse parses a Grafana unified query API response.
func (c *client) parseUnifiedQueryResponse(body []byte) (*QueryResult, error) {
	var resp struct {
		Results map[string]struct {
			Status int `json:"status"`
			Frames []struct {
				Schema struct {
					Name   string `json:"name"`
					Fields []struct {
						Name string `json:"name"`
						Type string `json:"type"`
					} `json:"fields"`
				} `json:"schema"`
				Data struct {
					Values [][]any `json:"values"`
				} `json:"data"`
			} `json:"frames"`
			Error string `json:"error,omitempty"`
		} `json:"results"`
	}

	if err := json.Unmarshal(body, &resp); err != nil {
		return nil, fmt.Errorf("parsing unified query response: %w", err)
	}

	result := &QueryResult{
		Raw:    body,
		Frames: make([]DataFrame, 0),
	}

	for refID, r := range resp.Results {
		if r.Error != "" {
			return nil, fmt.Errorf("query %s failed: %s", refID, r.Error)
		}

		for _, frame := range r.Frames {
			df := DataFrame{
				Name:   frame.Schema.Name,
				Fields: make([]DataField, len(frame.Schema.Fields)),
			}

			for i, field := range frame.Schema.Fields {
				var values []any
				if i < len(frame.Data.Values) {
					values = frame.Data.Values[i]
				}

				df.Fields[i] = DataField{
					Name:   field.Name,
					Type:   field.Type,
					Values: values,
				}
			}

			result.Frames = append(result.Frames, df)
		}
	}

	return result, nil
}

// newRequest creates a new HTTP request with Grafana authentication.
func (c *client) newRequest(ctx context.Context, method, path string, body io.Reader) (*http.Request, error) {
	fullURL := strings.TrimSuffix(c.cfg.URL, "/") + path

	req, err := http.NewRequestWithContext(ctx, method, fullURL, body)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+c.cfg.ServiceToken)
	req.Header.Set("Content-Type", "application/json")

	return req, nil
}
