package resource

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// QueryExample represents a single query example.
type QueryExample struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Query       string `json:"query"`
	Cluster     string `json:"cluster"`
}

// QueryCategory represents a category of query examples.
type QueryCategory struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Examples    []QueryExample `json:"examples"`
}

// queryExamples contains common ClickHouse query patterns organized by use case.
//
//nolint:lll // SQL queries are naturally long.
var queryExamples = map[string]QueryCategory{
	"block_events": {
		Name:        "Block Events",
		Description: "Queries for beacon block events and propagation",
		Examples: []QueryExample{
			{
				Name:        "Recent blocks by network",
				Description: "Get the most recent blocks for a specific network",
				Query: `SELECT
    slot,
    block_root,
    proposer_index,
    meta_network_name,
    slot_start_date_time
FROM beacon_api_eth_v1_events_block
WHERE meta_network_name = 'mainnet'
ORDER BY slot DESC
LIMIT 100`,
				Cluster: "xatu",
			},
			{
				Name:        "Block propagation times",
				Description: "Analyze block propagation delay across sentries",
				Query: `SELECT
    slot,
    block_root,
    meta_client_name,
    propagation_slot_start_diff / 1000 as propagation_ms
FROM beacon_api_eth_v1_events_block
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 1 HOUR
ORDER BY slot DESC, propagation_ms ASC
LIMIT 1000`,
				Cluster: "xatu",
			},
		},
	},
	"attestations": {
		Name:        "Attestations",
		Description: "Queries for attestation data and analysis",
		Examples: []QueryExample{
			{
				Name:        "Attestation inclusion delay",
				Description: "Calculate average attestation inclusion delay by slot",
				Query: `SELECT
    slot,
    avg(inclusion_delay) as avg_inclusion_delay,
    count() as attestation_count
FROM beacon_api_eth_v1_events_attestation
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 1 HOUR
GROUP BY slot
ORDER BY slot DESC
LIMIT 100`,
				Cluster: "xatu",
			},
			{
				Name:        "Committee attestation performance",
				Description: "Attestation performance by committee",
				Query: `SELECT
    slot,
    committee_index,
    count() as attestation_count,
    uniqExact(aggregation_bits) as unique_aggregations
FROM beacon_api_eth_v1_events_attestation
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 1 HOUR
GROUP BY slot, committee_index
ORDER BY slot DESC, committee_index
LIMIT 500`,
				Cluster: "xatu",
			},
		},
	},
	"validators": {
		Name:        "Validators",
		Description: "Queries for validator state and performance",
		Examples: []QueryExample{
			{
				Name:        "Validator balance changes",
				Description: "Track validator balance changes over epochs",
				Query: `SELECT
    epoch,
    validator_index,
    balance / 1e9 as balance_eth,
    effective_balance / 1e9 as effective_balance_eth
FROM beacon_api_eth_v1_beacon_states_validators
WHERE meta_network_name = 'mainnet'
  AND validator_index = 12345
ORDER BY epoch DESC
LIMIT 100`,
				Cluster: "xatu",
			},
			{
				Name:        "Active validator count by epoch",
				Description: "Count active validators per epoch",
				Query: `SELECT
    epoch,
    countIf(status = 'active_ongoing') as active_validators
FROM beacon_api_eth_v1_beacon_states_validators
WHERE meta_network_name = 'mainnet'
  AND epoch >= toUInt64((toUnixTimestamp(now()) - 1606824000) / 384) - 100
GROUP BY epoch
ORDER BY epoch DESC
LIMIT 100`,
				Cluster: "xatu",
			},
		},
	},
	"consensus_timing": {
		Name:        "Consensus Timing (CBT)",
		Description: "Queries for consensus block timing analysis using aggregated tables",
		Examples: []QueryExample{
			{
				Name:        "Block timing distribution",
				Description: "Analyze block arrival times relative to slot start",
				Query: `SELECT
    slot,
    block_seen_p50_ms,
    block_seen_p90_ms,
    block_seen_p99_ms,
    block_first_seen_ms,
    proposer_index
FROM cbt_block_timing
WHERE network = 'mainnet'
ORDER BY slot DESC
LIMIT 100`,
				Cluster: "xatu-cbt",
			},
			{
				Name:        "Attestation timing percentiles",
				Description: "Get attestation timing percentiles by slot",
				Query: `SELECT
    slot,
    attestation_seen_p50_ms,
    attestation_seen_p90_ms,
    coverage_at_4s,
    coverage_at_8s
FROM cbt_attestation_timing
WHERE network = 'mainnet'
ORDER BY slot DESC
LIMIT 100`,
				Cluster: "xatu-cbt",
			},
		},
	},
	"blobs": {
		Name:        "Blob Data (Post-Dencun)",
		Description: "Queries for EIP-4844 blob sidecar data",
		Examples: []QueryExample{
			{
				Name:        "Recent blob sidecars",
				Description: "Get recent blob sidecars with their propagation times",
				Query: `SELECT
    slot,
    block_root,
    blob_index,
    kzg_commitment,
    propagation_slot_start_diff / 1000 as propagation_ms
FROM beacon_api_eth_v1_events_blob_sidecar
WHERE meta_network_name = 'mainnet'
ORDER BY slot DESC, blob_index
LIMIT 100`,
				Cluster: "xatu",
			},
			{
				Name:        "Blob count per block",
				Description: "Count blobs per block over recent slots",
				Query: `SELECT
    slot,
    block_root,
    count() as blob_count,
    avg(propagation_slot_start_diff) / 1000 as avg_propagation_ms
FROM beacon_api_eth_v1_events_blob_sidecar
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 1 HOUR
GROUP BY slot, block_root
ORDER BY slot DESC
LIMIT 100`,
				Cluster: "xatu",
			},
		},
	},
	"mempool": {
		Name:        "Mempool/Transaction Pool",
		Description: "Queries for mempool and pending transaction data",
		Examples: []QueryExample{
			{
				Name:        "Recent mempool transactions",
				Description: "Get recent pending transactions from the mempool",
				Query: `SELECT
    hash,
    from_address,
    to_address,
    value / 1e18 as value_eth,
    gas,
    gas_price / 1e9 as gas_price_gwei,
    meta_client_name
FROM mempool_transaction
WHERE meta_network_name = 'mainnet'
ORDER BY event_date_time DESC
LIMIT 100`,
				Cluster: "xatu",
			},
		},
	},
	"network_analysis": {
		Name:        "Network Analysis",
		Description: "Queries for analyzing network health and client diversity",
		Examples: []QueryExample{
			{
				Name:        "Client diversity by blocks",
				Description: "Analyze which clients are proposing blocks",
				Query: `SELECT
    meta_client_name,
    meta_client_version,
    count() as block_count
FROM beacon_api_eth_v1_events_block
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 24 HOUR
GROUP BY meta_client_name, meta_client_version
ORDER BY block_count DESC
LIMIT 50`,
				Cluster: "xatu",
			},
			{
				Name:        "Geographic distribution",
				Description: "Analyze geographic distribution of sentries",
				Query: `SELECT
    meta_client_geo_country,
    meta_client_geo_city,
    count() as event_count,
    uniqExact(meta_client_name) as unique_clients
FROM beacon_api_eth_v1_events_block
WHERE meta_network_name = 'mainnet'
  AND slot_start_date_time >= now() - INTERVAL 1 HOUR
GROUP BY meta_client_geo_country, meta_client_geo_city
ORDER BY event_count DESC
LIMIT 50`,
				Cluster: "xatu",
			},
		},
	},
}

// examplesResponse is the JSON response structure for the examples resource.
type examplesResponse struct {
	Description string                   `json:"description"`
	Categories  map[string]QueryCategory `json:"categories"`
}

// RegisterExamplesResources registers the examples:// resources with the registry.
func RegisterExamplesResources(log logrus.FieldLogger, reg Registry) {
	log = log.WithField("resource", "examples")

	// Register static examples://queries resource
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "examples://queries",
			Name:        "Query Examples",
			Description: "Common ClickHouse query patterns organized by use case",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			response := examplesResponse{
				Description: "Common ClickHouse query patterns for Xatu data analysis",
				Categories:  queryExamples,
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", err
			}

			return string(data), nil
		},
	})

	log.Debug("Registered examples resources")
}
