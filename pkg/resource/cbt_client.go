package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

const (
	// DefaultCBTCacheTTL is the default cache duration for CBT data.
	DefaultCBTCacheTTL = 5 * time.Minute

	// CBT API paths.
	cbtPathIntervalTypes   = "/api/v1/interval/types"
	cbtPathExternalModels  = "/api/v1/models/external"
	cbtPathTransformations = "/api/v1/models/transformations"

	// networkPlaceholder is the template placeholder for network names.
	networkPlaceholder = "{network}"
)

// CBTConfig holds configuration for the CBT client.
type CBTConfig struct {
	CacheTTL time.Duration
	Timeout  time.Duration
}

// CBTClient fetches and caches CBT metadata.
// Models are universal - the network is just which database to query.
type CBTClient interface {
	// Start initializes the client and fetches initial data.
	Start(ctx context.Context) error
	// Stop stops background refresh.
	Stop() error

	// Data access - models are universal.
	GetData() *CBTData
	GetNetworks() []string
	GetIntervalTypes() map[string][]IntervalConversion
	GetExternalModel(id string) *ExternalModel
	GetTransformation(id string) *TransformationModel
	GetDAG() *DAG
	GetModelDependencies(model string) *DependencyInfo
}

// CBTData holds all universal CBT data.
type CBTData struct {
	Networks        []string                        `json:"networks"`
	SourceNetwork   string                          `json:"source_network"`
	IntervalTypes   map[string][]IntervalConversion `json:"interval_types,omitempty"`
	ExternalModels  map[string]*ExternalModel       `json:"external_models,omitempty"`
	Transformations map[string]*TransformationModel `json:"transformations,omitempty"`
	DAG             *DAG                            `json:"dag,omitempty"`
	LastUpdated     time.Time                       `json:"last_updated"`
}

// IntervalConversion represents a single interval conversion option.
type IntervalConversion struct {
	Name       string `json:"name"`
	Format     string `json:"format,omitempty"`
	Expression string `json:"expression,omitempty"`
}

// ExternalModel represents a CBT external model (source table).
type ExternalModel struct {
	ID       string        `json:"id"`
	Database string        `json:"database"`
	Table    string        `json:"table"`
	Interval ModelInterval `json:"interval,omitempty"`
	Cache    ModelCache    `json:"cache,omitempty"`
	Lag      int           `json:"lag,omitempty"`
}

// DependsOn handles the polymorphic depends_on field which can be either:
// - []string: ["dep1", "dep2"] - all dependencies required
// - [][]string: [["dep1", "dep2"]] - any of the nested dependencies satisfies (OR)
// We flatten everything to []string for simplicity.
type DependsOn []string

// UnmarshalJSON handles both array of strings and array of arrays of strings.
func (d *DependsOn) UnmarshalJSON(data []byte) error {
	// Try array of strings first
	var simple []string
	if err := json.Unmarshal(data, &simple); err == nil {
		*d = simple

		return nil
	}

	// Try array of arrays of strings (OR dependencies)
	var nested [][]string
	if err := json.Unmarshal(data, &nested); err == nil {
		// Flatten nested arrays
		result := make([]string, 0, len(nested)*4)

		for _, group := range nested {
			result = append(result, group...)
		}

		*d = result

		return nil
	}

	// If both fail, return empty
	*d = nil

	return nil
}

// TransformationModel represents a CBT transformation model.
type TransformationModel struct {
	ID          string         `json:"id"`
	Database    string         `json:"database"`
	Table       string         `json:"table"`
	Type        string         `json:"type"`
	Content     string         `json:"content,omitempty"`
	ContentType string         `json:"content_type,omitempty"`
	DependsOn   DependsOn      `json:"depends_on,omitempty"`
	Interval    ModelInterval  `json:"interval,omitempty"`
	Schedules   ModelSchedules `json:"schedules,omitempty"`
	Schedule    string         `json:"schedule,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
}

// ModelInterval represents the interval configuration for a model.
type ModelInterval struct {
	Type string `json:"type,omitempty"`
	Min  *int   `json:"min,omitempty"`
	Max  *int   `json:"max,omitempty"`
}

// ModelCache represents cache configuration for external models.
type ModelCache struct {
	IncrementalScanInterval string `json:"incremental_scan_interval,omitempty"`
	FullScanInterval        string `json:"full_scan_interval,omitempty"`
}

// ModelSchedules represents schedule configuration for transformation models.
type ModelSchedules struct {
	ForwardFill string `json:"forwardfill,omitempty"`
	Backfill    string `json:"backfill,omitempty"`
}

// DAG is a pre-processed dependency graph (compact representation).
type DAG struct {
	Networks       []string            `json:"networks"`
	Roots          []string            `json:"roots"`
	Leaves         []string            `json:"leaves"`
	Nodes          map[string]*DAGNode `json:"nodes"`
	TotalExternal  int                 `json:"total_external"`
	TotalTransform int                 `json:"total_transformations"`
}

// DAGNode represents a node in the dependency graph.
type DAGNode struct {
	ID         string   `json:"id"`
	Type       string   `json:"type"`
	DependsOn  []string `json:"depends_on,omitempty"`
	DependedBy []string `json:"depended_by,omitempty"`
	Depth      int      `json:"depth"`
}

// DependencyInfo is a focused view for a single model (minimal context).
type DependencyInfo struct {
	Model        string   `json:"model"`
	Type         string   `json:"type"`
	Networks     []string `json:"networks"`
	DirectDeps   []string `json:"direct_dependencies"`
	AllDeps      []string `json:"all_dependencies"`
	DependedBy   []string `json:"depended_by"`
	ExternalDeps []string `json:"external_dependencies"`
}

// cbtClient implements CBTClient.
type cbtClient struct {
	log           logrus.FieldLogger
	cfg           CBTConfig
	client        *http.Client
	cartographoor CartographoorClient

	mu   sync.RWMutex
	data *CBTData

	done chan struct{}
	wg   sync.WaitGroup
}

// NewCBTClient creates a new CBT client.
func NewCBTClient(log logrus.FieldLogger, cfg CBTConfig, cartographoor CartographoorClient) CBTClient {
	if cfg.CacheTTL == 0 {
		cfg.CacheTTL = DefaultCBTCacheTTL
	}

	if cfg.Timeout == 0 {
		cfg.Timeout = DefaultHTTPTimeout
	}

	return &cbtClient{
		log:           log.WithField("component", "cbt"),
		cfg:           cfg,
		cartographoor: cartographoor,
		client: &http.Client{
			Timeout: cfg.Timeout,
		},
		done: make(chan struct{}),
	}
}

// Start initializes the client and starts background refresh.
func (c *cbtClient) Start(ctx context.Context) error {
	c.log.Info("Starting CBT client")

	// Initial fetch
	if err := c.refresh(ctx); err != nil {
		return fmt.Errorf("initial fetch failed: %w", err)
	}

	// Start background refresh
	c.wg.Add(1)

	go c.backgroundRefresh()

	c.mu.RLock()
	networkCount := len(c.data.Networks)
	c.mu.RUnlock()

	c.log.WithFields(logrus.Fields{
		"network_count": networkCount,
		"cache_ttl":     c.cfg.CacheTTL,
	}).Info("CBT client started")

	return nil
}

// Stop stops the background refresh goroutine.
func (c *cbtClient) Stop() error {
	close(c.done)
	c.wg.Wait()

	c.log.Info("CBT client stopped")

	return nil
}

// GetData returns a copy of all CBT data.
func (c *cbtClient) GetData() *CBTData {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return nil
	}

	// Return a shallow copy
	return &CBTData{
		Networks:        c.data.Networks,
		SourceNetwork:   c.data.SourceNetwork,
		IntervalTypes:   c.data.IntervalTypes,
		ExternalModels:  c.data.ExternalModels,
		Transformations: c.data.Transformations,
		DAG:             c.data.DAG,
		LastUpdated:     c.data.LastUpdated,
	}
}

// GetNetworks returns list of networks with CBT available.
func (c *cbtClient) GetNetworks() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return nil
	}

	result := make([]string, len(c.data.Networks))
	copy(result, c.data.Networks)

	return result
}

// GetIntervalTypes returns interval types.
func (c *cbtClient) GetIntervalTypes() map[string][]IntervalConversion {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return nil
	}

	return c.data.IntervalTypes
}

// GetExternalModel returns a specific external model.
func (c *cbtClient) GetExternalModel(id string) *ExternalModel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil || c.data.ExternalModels == nil {
		return nil
	}

	return c.data.ExternalModels[id]
}

// GetTransformation returns a specific transformation model.
func (c *cbtClient) GetTransformation(id string) *TransformationModel {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil || c.data.Transformations == nil {
		return nil
	}

	return c.data.Transformations[id]
}

// GetDAG returns the pre-processed DAG.
func (c *cbtClient) GetDAG() *DAG {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil {
		return nil
	}

	return c.data.DAG
}

// GetModelDependencies returns dependency info for a specific model.
func (c *cbtClient) GetModelDependencies(model string) *DependencyInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if c.data == nil || c.data.DAG == nil {
		return nil
	}

	node, ok := c.data.DAG.Nodes[model]
	if !ok {
		return nil
	}

	info := &DependencyInfo{
		Model:      model,
		Type:       node.Type,
		Networks:   c.data.Networks,
		DirectDeps: node.DependsOn,
		DependedBy: node.DependedBy,
	}

	// Compute transitive closure of dependencies
	visited := make(map[string]bool, len(c.data.DAG.Nodes))
	info.AllDeps = c.collectAllDependencies(c.data.DAG, model, visited)

	// Find external dependencies (leaf nodes)
	info.ExternalDeps = make([]string, 0, 8)

	for _, dep := range info.AllDeps {
		if depNode, exists := c.data.DAG.Nodes[dep]; exists && depNode.Type == "external" {
			info.ExternalDeps = append(info.ExternalDeps, dep)
		}
	}

	return info
}

// collectAllDependencies recursively collects all dependencies.
func (c *cbtClient) collectAllDependencies(dag *DAG, model string, visited map[string]bool) []string {
	if visited[model] {
		return nil
	}

	visited[model] = true

	node, ok := dag.Nodes[model]
	if !ok {
		return nil
	}

	result := make([]string, 0, len(node.DependsOn))

	for _, dep := range node.DependsOn {
		if !visited[dep] {
			result = append(result, dep)
			result = append(result, c.collectAllDependencies(dag, dep, visited)...)
		}
	}

	return result
}

// backgroundRefresh periodically refreshes CBT data.
func (c *cbtClient) backgroundRefresh() {
	defer c.wg.Done()

	ticker := time.NewTicker(c.cfg.CacheTTL)
	defer ticker.Stop()

	for {
		select {
		case <-c.done:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), c.cfg.Timeout*2)

			if err := c.refresh(ctx); err != nil {
				c.log.WithError(err).Warn("Failed to refresh CBT data")
			} else {
				c.mu.RLock()
				networkCount := len(c.data.Networks)
				c.mu.RUnlock()

				c.log.WithField("network_count", networkCount).Debug("Refreshed CBT data")
			}

			cancel()
		}
	}
}

// refresh fetches CBT data from a canonical source.
func (c *cbtClient) refresh(ctx context.Context) error {
	allNetworks := c.cartographoor.GetAllNetworks()

	// Collect networks with CBT URLs, prioritizing mainnet
	type networkURL struct {
		name string
		url  string
	}

	cbtNetworks := make([]networkURL, 0, 8)

	var mainnetURL string

	for name, network := range allNetworks {
		if network.ServiceURLs != nil && network.ServiceURLs.Cbt != "" {
			if name == "mainnet" {
				mainnetURL = network.ServiceURLs.Cbt
			}

			cbtNetworks = append(cbtNetworks, networkURL{name: name, url: network.ServiceURLs.Cbt})
		}
	}

	if len(cbtNetworks) == 0 {
		c.log.Debug("No networks with CBT configured")

		return nil
	}

	// Sort networks for consistent ordering
	sort.Slice(cbtNetworks, func(i, j int) bool {
		return cbtNetworks[i].name < cbtNetworks[j].name
	})

	// Determine which source to fetch from (mainnet preferred)
	var sourceNetwork string

	var sourceURL string

	if mainnetURL != "" {
		sourceNetwork = "mainnet"
		sourceURL = mainnetURL
	} else {
		sourceNetwork = cbtNetworks[0].name
		sourceURL = cbtNetworks[0].url
	}

	c.log.WithFields(logrus.Fields{
		"source":        sourceNetwork,
		"network_count": len(cbtNetworks),
	}).Debug("Fetching CBT data from canonical source")

	// Fetch from canonical source
	data, err := c.fetchCBTData(ctx, sourceNetwork, sourceURL)
	if err != nil {
		return fmt.Errorf("fetching from %s: %w", sourceNetwork, err)
	}

	// Set networks list (all networks with CBT, not just the source)
	data.Networks = make([]string, len(cbtNetworks))
	for i, net := range cbtNetworks {
		data.Networks[i] = net.name
	}

	// Update cache
	c.mu.Lock()
	c.data = data
	c.mu.Unlock()

	return nil
}

// fetchCBTData fetches all CBT data from a single endpoint.
func (c *cbtClient) fetchCBTData(ctx context.Context, sourceNetwork, baseURL string) (*CBTData, error) {
	data := &CBTData{
		SourceNetwork: sourceNetwork,
		LastUpdated:   time.Now(),
	}

	// Fetch interval types
	intervalTypes, err := c.fetchIntervalTypes(ctx, baseURL)
	if err != nil {
		return nil, fmt.Errorf("interval types: %w", err)
	}

	data.IntervalTypes = intervalTypes

	// Fetch external models
	externalModels, err := c.fetchExternalModels(ctx, baseURL, sourceNetwork)
	if err != nil {
		return nil, fmt.Errorf("external models: %w", err)
	}

	data.ExternalModels = externalModels

	// Fetch transformations
	transformations, err := c.fetchTransformations(ctx, baseURL, sourceNetwork)
	if err != nil {
		return nil, fmt.Errorf("transformations: %w", err)
	}

	data.Transformations = transformations

	// Build DAG
	data.DAG = buildDAG(data.Networks, externalModels, transformations)

	return data, nil
}

// fetchIntervalTypes fetches interval type definitions from CBT API.
func (c *cbtClient) fetchIntervalTypes(ctx context.Context, baseURL string) (map[string][]IntervalConversion, error) {
	url := baseURL + cbtPathIntervalTypes

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		IntervalTypes map[string][]IntervalConversion `json:"interval_types"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.IntervalTypes, nil
}

// fetchExternalModels fetches external models from CBT API and templates them.
func (c *cbtClient) fetchExternalModels(ctx context.Context, baseURL, sourceNetwork string) (map[string]*ExternalModel, error) {
	url := baseURL + cbtPathExternalModels

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Models []ExternalModel `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	models := make(map[string]*ExternalModel, len(result.Models))

	for i := range result.Models {
		model := &result.Models[i]

		// Template the model - strip network prefix from ID, replace in database
		model.ID = stripNetworkPrefix(model.ID, sourceNetwork)
		model.Database = templateDatabase(model.Database, sourceNetwork)

		models[model.ID] = model
	}

	return models, nil
}

// fetchTransformations fetches transformation models from CBT API and templates them.
func (c *cbtClient) fetchTransformations(ctx context.Context, baseURL, sourceNetwork string) (map[string]*TransformationModel, error) {
	url := baseURL + cbtPathTransformations

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var result struct {
		Models []TransformationModel `json:"models"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	models := make(map[string]*TransformationModel, len(result.Models))

	for i := range result.Models {
		model := &result.Models[i]

		// Template the model
		model.ID = stripNetworkPrefix(model.ID, sourceNetwork)
		model.Database = templateDatabase(model.Database, sourceNetwork)
		model.Content = templateContent(model.Content, sourceNetwork)
		model.DependsOn = templateDependencies(model.DependsOn, sourceNetwork)

		models[model.ID] = model
	}

	return models, nil
}

// stripNetworkPrefix removes the network prefix from a model ID.
// Example: "mainnet.fct_block" -> "fct_block"
func stripNetworkPrefix(id, sourceNetwork string) string {
	prefix := sourceNetwork + "."
	if strings.HasPrefix(id, prefix) {
		return strings.TrimPrefix(id, prefix)
	}

	return id
}

// templateDatabase replaces the network name with {network} placeholder.
func templateDatabase(database, sourceNetwork string) string {
	if database == sourceNetwork {
		return networkPlaceholder
	}

	return database
}

// templateContent replaces network-specific references in SQL content.
func templateContent(content, sourceNetwork string) string {
	if content == "" {
		return content
	}

	// Replace "mainnet." with "{network}." in SQL content
	prefix := sourceNetwork + "."

	return strings.ReplaceAll(content, prefix, networkPlaceholder+".")
}

// templateDependencies strips network prefix from all dependencies.
func templateDependencies(deps DependsOn, sourceNetwork string) DependsOn {
	if len(deps) == 0 {
		return deps
	}

	result := make(DependsOn, len(deps))

	for i, dep := range deps {
		result[i] = stripNetworkPrefix(dep, sourceNetwork)
	}

	return result
}

// buildDAG constructs a dependency graph from external models and transformations.
func buildDAG(networks []string, external map[string]*ExternalModel, transforms map[string]*TransformationModel) *DAG {
	dag := &DAG{
		Networks:       networks,
		Nodes:          make(map[string]*DAGNode, len(external)+len(transforms)),
		TotalExternal:  len(external),
		TotalTransform: len(transforms),
	}

	// Add all external models as nodes (depth 0, no dependencies)
	for id := range external {
		dag.Nodes[id] = &DAGNode{
			ID:         id,
			Type:       "external",
			Depth:      0,
			DependsOn:  nil,
			DependedBy: make([]string, 0, 4),
		}
	}

	// Add all transformations as nodes
	for id, t := range transforms {
		dag.Nodes[id] = &DAGNode{
			ID:         id,
			Type:       "transformation",
			DependsOn:  t.DependsOn,
			DependedBy: make([]string, 0, 4),
			Depth:      -1, // Will be computed
		}
	}

	// Build reverse dependencies (depended_by)
	for id, node := range dag.Nodes {
		for _, dep := range node.DependsOn {
			if depNode, ok := dag.Nodes[dep]; ok {
				depNode.DependedBy = append(depNode.DependedBy, id)
			}
		}
	}

	// Compute depths via BFS from roots
	computeDepths(dag)

	// Find roots (nodes with no dependencies)
	dag.Roots = make([]string, 0, len(external))

	for id, node := range dag.Nodes {
		if len(node.DependsOn) == 0 {
			dag.Roots = append(dag.Roots, id)
		}
	}

	sort.Strings(dag.Roots)

	// Find leaves (nodes with no dependents)
	dag.Leaves = make([]string, 0, 16)

	for id, node := range dag.Nodes {
		if len(node.DependedBy) == 0 {
			dag.Leaves = append(dag.Leaves, id)
		}
	}

	sort.Strings(dag.Leaves)

	return dag
}

// computeDepths computes the depth of each node in the DAG using BFS.
func computeDepths(dag *DAG) {
	// Initialize queue with root nodes
	queue := make([]string, 0, len(dag.Nodes))

	for id, node := range dag.Nodes {
		if len(node.DependsOn) == 0 {
			node.Depth = 0
			queue = append(queue, id)
		}
	}

	// BFS to compute depths
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		currentNode := dag.Nodes[current]

		for _, dependentID := range currentNode.DependedBy {
			dependent := dag.Nodes[dependentID]
			if dependent == nil {
				continue
			}

			newDepth := currentNode.Depth + 1
			if dependent.Depth < newDepth {
				dependent.Depth = newDepth
				queue = append(queue, dependentID)
			}
		}
	}

	// Set remaining unvisited nodes to depth -1 (circular or disconnected)
	for _, node := range dag.Nodes {
		if node.Depth == -1 {
			node.Depth = 0
		}
	}
}

// Ensure interface compliance at compile time.
var _ CBTClient = (*cbtClient)(nil)
