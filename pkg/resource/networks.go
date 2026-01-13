package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethpandaops/cartographoor/pkg/discovery"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// networkURIPattern matches networks://{name} URIs.
var networkURIPattern = regexp.MustCompile(`^networks://(.+)$`)

// CBTSummary provides a compact overview of CBT availability for a network.
// Models are universal across networks - see cbt:// resources for details.
type CBTSummary struct {
	Available bool   `json:"available"`
	ModelsURI string `json:"models_uri,omitempty"`
}

// NetworkSummary is a compact representation for the active networks list.
type NetworkSummary struct {
	Name     string      `json:"name"`
	ChainID  uint64      `json:"chain_id,omitempty"`
	Clusters []string    `json:"clusters"`
	Status   string      `json:"status"`
	CBT      *CBTSummary `json:"cbt,omitempty"`
}

// NetworksActiveResponse is the response for networks://active.
type NetworksActiveResponse struct {
	Networks []NetworkSummary `json:"networks"`
	Groups   []string         `json:"groups"`
	Usage    string           `json:"usage"`
}

// NetworkWithClusters wraps a discovery.Network with xatu-specific cluster info.
type NetworkWithClusters struct {
	discovery.Network
	Clusters []string `json:"clusters"`
}

// NetworksAllResponse is the response for networks://all.
type NetworksAllResponse struct {
	Networks map[string]NetworkWithClusters `json:"networks"`
	Groups   []string                       `json:"groups"`
}

// NetworkDetailResponse is the response for networks://{name} (single network).
type NetworkDetailResponse struct {
	Network NetworkWithClusters `json:"network"`
	CBT     *CBTSummary         `json:"cbt,omitempty"`
}

// GroupDetailResponse is the response for networks://{group} (devnet group).
type GroupDetailResponse struct {
	Group    string                         `json:"group"`
	Networks map[string]NetworkWithClusters `json:"networks"`
}

// RegisterNetworksResources registers all network-related resources with the registry.
// cbtClient can be nil if CBT is not available.
func RegisterNetworksResources(log logrus.FieldLogger, reg Registry, client CartographoorClient, cbtClient CBTClient) {
	log = log.WithField("resource", "networks")

	// Register networks://active - compact list of active networks
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "networks://active",
			Name:        "Active Networks",
			Description: "Compact list of active Ethereum networks and available devnet groups",
			MIMEType:    "application/json",
		},
		Handler: createActiveNetworksHandler(client, cbtClient),
	})

	// Register networks://all - all networks including inactive
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "networks://all",
			Name:        "All Networks",
			Description: "All Ethereum networks including inactive ones",
			MIMEType:    "application/json",
		},
		Handler: createAllNetworksHandler(client),
	})

	// Register networks://{name} - single network or devnet group
	reg.RegisterTemplate(TemplateResource{
		Template: mcp.NewResourceTemplate(
			"networks://{name}",
			"Network or Group Details",
			mcp.WithTemplateDescription("Get details for a specific network or all networks in a devnet group"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		Pattern: networkURIPattern,
		Handler: createNetworkDetailHandler(log, client, cbtClient),
	})

	log.Debug("Registered networks resources")
}

// createActiveNetworksHandler returns a handler for networks://active.
func createActiveNetworksHandler(client CartographoorClient, cbtClient CBTClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		networks := client.GetActiveNetworks()
		groups := client.GetGroups()

		summaries := make([]NetworkSummary, 0, len(networks))

		for _, network := range networks {
			summary := NetworkSummary{
				Name:     network.Name,
				ChainID:  network.ChainID,
				Clusters: client.GetClusters(network),
				Status:   network.Status,
			}

			// Add CBT summary if this network has CBT available
			if cbtClient != nil {
				cbtNetworks := cbtClient.GetNetworks()
				for _, cbtNet := range cbtNetworks {
					if cbtNet == network.Name {
						summary.CBT = &CBTSummary{
							Available: true,
							ModelsURI: "cbt://models",
						}

						break
					}
				}
			}

			summaries = append(summaries, summary)
		}

		response := NetworksActiveResponse{
			Networks: summaries,
			Groups:   groups,
			Usage:    "Use networks://{name} for full network details or networks://{group} for all networks in a devnet group",
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createAllNetworksHandler returns a handler for networks://all.
func createAllNetworksHandler(client CartographoorClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		networks := client.GetAllNetworks()
		groups := client.GetGroups()

		networksWithClusters := make(map[string]NetworkWithClusters, len(networks))

		for name, network := range networks {
			networksWithClusters[name] = NetworkWithClusters{
				Network:  network,
				Clusters: client.GetClusters(network),
			}
		}

		response := NetworksAllResponse{
			Networks: networksWithClusters,
			Groups:   groups,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createNetworkDetailHandler returns a handler for networks://{name}.
func createNetworkDetailHandler(log logrus.FieldLogger, client CartographoorClient, cbtClient CBTClient) ReadHandler {
	return func(_ context.Context, uri string) (string, error) {
		matches := networkURIPattern.FindStringSubmatch(uri)
		if len(matches) != 2 {
			return "", fmt.Errorf("invalid URI format: %s", uri)
		}

		name := matches[1]

		// Try exact network match first
		if network, ok := client.GetNetwork(name); ok {
			response := NetworkDetailResponse{
				Network: NetworkWithClusters{
					Network:  network,
					Clusters: client.GetClusters(network),
				},
			}

			// Add CBT summary if this network has CBT available
			if cbtClient != nil {
				cbtNetworks := cbtClient.GetNetworks()
				for _, cbtNet := range cbtNetworks {
					if cbtNet == name {
						response.CBT = &CBTSummary{
							Available: true,
							ModelsURI: "cbt://models",
						}

						break
					}
				}
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling response: %w", err)
			}

			return string(data), nil
		}

		// Try group match
		if networks, ok := client.GetGroup(name); ok {
			networksWithClusters := make(map[string]NetworkWithClusters, len(networks))

			for netName, network := range networks {
				networksWithClusters[netName] = NetworkWithClusters{
					Network:  network,
					Clusters: client.GetClusters(network),
				}
			}

			response := GroupDetailResponse{
				Group:    name,
				Networks: networksWithClusters,
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling response: %w", err)
			}

			return string(data), nil
		}

		// Not found - provide helpful error
		groups := client.GetGroups()
		allNetworks := client.GetAllNetworks()
		networkNames := make([]string, 0, len(allNetworks))

		for netName := range allNetworks {
			networkNames = append(networkNames, netName)
		}

		log.WithFields(logrus.Fields{
			"requested": name,
			"networks":  len(networkNames),
			"groups":    len(groups),
		}).Debug("Network or group not found")

		return "", fmt.Errorf(
			"network or group %q not found. Available groups: %s",
			name,
			strings.Join(groups, ", "),
		)
	}
}
