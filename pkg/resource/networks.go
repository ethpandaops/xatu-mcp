package resource

import (
	"context"
	"encoding/json"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// NetworkInfo contains information about an Ethereum network.
type NetworkInfo struct {
	Name                string   `json:"name"`
	DisplayName         string   `json:"display_name"`
	ChainID             int      `json:"chain_id"`
	Description         string   `json:"description"`
	Clusters            []string `json:"clusters"`
	GenesisTime         int64    `json:"genesis_time"`
	SlotDurationSeconds int      `json:"slot_duration_seconds"`
	SlotsPerEpoch       int      `json:"slots_per_epoch"`
	IsTestnet           bool     `json:"is_testnet"`
	IsDevnet            bool     `json:"is_devnet"`
	BeaconGenesisTime   int64    `json:"beacon_genesis_time"`
}

// networks contains information about all available Ethereum networks.
var networks = map[string]NetworkInfo{
	"mainnet": {
		Name:                "mainnet",
		DisplayName:         "Ethereum Mainnet",
		ChainID:             1,
		Description:         "The main Ethereum production network",
		Clusters:            []string{"xatu", "xatu-cbt"},
		GenesisTime:         1606824023,
		SlotDurationSeconds: 12,
		SlotsPerEpoch:       32,
		IsTestnet:           false,
		IsDevnet:            false,
		BeaconGenesisTime:   1606824023,
	},
	"sepolia": {
		Name:                "sepolia",
		DisplayName:         "Sepolia Testnet",
		ChainID:             11155111,
		Description:         "A permissioned testnet for application developers",
		Clusters:            []string{"xatu", "xatu-cbt"},
		GenesisTime:         1655733600,
		SlotDurationSeconds: 12,
		SlotsPerEpoch:       32,
		IsTestnet:           true,
		IsDevnet:            false,
		BeaconGenesisTime:   1655733600,
	},
	"holesky": {
		Name:                "holesky",
		DisplayName:         "Holesky Testnet",
		ChainID:             17000,
		Description:         "A public testnet for staking, infrastructure, and protocol development",
		Clusters:            []string{"xatu", "xatu-cbt"},
		GenesisTime:         1695902400,
		SlotDurationSeconds: 12,
		SlotsPerEpoch:       32,
		IsTestnet:           true,
		IsDevnet:            false,
		BeaconGenesisTime:   1695902400,
	},
	"hoodi": {
		Name:                "hoodi",
		DisplayName:         "Hoodi Testnet",
		ChainID:             560048,
		Description:         "A testnet for Pectra testing",
		Clusters:            []string{"xatu", "xatu-cbt"},
		GenesisTime:         1742212800,
		SlotDurationSeconds: 12,
		SlotsPerEpoch:       32,
		IsTestnet:           true,
		IsDevnet:            false,
		BeaconGenesisTime:   1742212800,
	},
}

// clusterNetworks maps cluster names to the networks they support.
var clusterNetworks = map[string][]string{
	"xatu":              {"mainnet", "sepolia", "holesky", "hoodi"},
	"xatu-experimental": {"devnets"},
	"xatu-cbt":          {"mainnet", "sepolia", "holesky", "hoodi"},
}

// usageNotes provides guidance on using network data.
var usageNotes = map[string]string{
	"querying": "Use meta_network_name = '<network>' in WHERE clauses to filter by network",
	"mainnet":  "Use 'mainnet' for production Ethereum data",
	"testnets": "Sepolia and Holesky are the primary testnets for most use cases",
	"devnets":  "Devnet data is only available on xatu-experimental cluster",
}

// networksResponse is the JSON response structure for the networks resource.
type networksResponse struct {
	Description     string                 `json:"description"`
	Networks        map[string]NetworkInfo `json:"networks"`
	ClusterNetworks map[string][]string    `json:"cluster_networks"`
	UsageNotes      map[string]string      `json:"usage_notes"`
}

// RegisterNetworksResources registers the networks:// resources with the registry.
func RegisterNetworksResources(log logrus.FieldLogger, reg Registry) {
	log = log.WithField("resource", "networks")

	// Register static networks://available resource
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "networks://available",
			Name:        "Available Networks",
			Description: "List of available Ethereum networks and their configurations",
			MIMEType:    "application/json",
		},
		Handler: func(_ context.Context, _ string) (string, error) {
			response := networksResponse{
				Description:     "Available Ethereum networks with their configurations and cluster mappings",
				Networks:        networks,
				ClusterNetworks: clusterNetworks,
				UsageNotes:      usageNotes,
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", err
			}

			return string(data), nil
		},
	})

	log.Debug("Registered networks resources")
}
