package resource

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

// CBT resource URI patterns.
var (
	cbtModelPattern     = regexp.MustCompile(`^cbt://models/([^/]+)$`)
	cbtModelDepsPattern = regexp.MustCompile(`^cbt://models/([^/]+)/dependencies$`)
)

// CBTOverviewResponse is the response for cbt://.
type CBTOverviewResponse struct {
	Description string   `json:"description"`
	Networks    []string `json:"networks"`
	Usage       string   `json:"usage"`
}

// CBTIntervalsResponse is the response for cbt://intervals.
type CBTIntervalsResponse struct {
	Description   string                          `json:"description"`
	IntervalTypes map[string][]IntervalConversion `json:"interval_types"`
}

// CBTModelsListResponse is the response for cbt://models.
type CBTModelsListResponse struct {
	ExternalModels  []string `json:"external_models"`
	Transformations []string `json:"transformations"`
	TotalCount      int      `json:"total_count"`
	Networks        []string `json:"networks"`
}

// CBTModelDetailResponse is the response for cbt://models/{model}.
type CBTModelDetailResponse struct {
	ID       string   `json:"id"`
	Type     string   `json:"type"`
	Model    any      `json:"model"`
	Networks []string `json:"networks"`
}

// RegisterCBTResources registers all CBT-related resources with the registry.
func RegisterCBTResources(log logrus.FieldLogger, reg Registry, client CBTClient) {
	log = log.WithField("resource", "cbt")

	// Register cbt:// - Overview
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "cbt://",
			Name:        "CBT Overview",
			Description: "Overview of CBT (ClickHouse Block Transformer) resources and available networks",
			MIMEType:    "application/json",
		},
		Handler: createCBTOverviewHandler(client),
	})

	// Register cbt://intervals - Interval type definitions
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "cbt://intervals",
			Name:        "CBT Interval Types",
			Description: "Interval type definitions and conversions (slot, epoch, block, etc.)",
			MIMEType:    "application/json",
		},
		Handler: createCBTIntervalsHandler(client),
	})

	// Register cbt://models - List all models
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "cbt://models",
			Name:        "CBT Models",
			Description: "List of all CBT models (external sources and transformations)",
			MIMEType:    "application/json",
		},
		Handler: createCBTModelsListHandler(client),
	})

	// Register cbt://dag - Universal DAG
	reg.RegisterStatic(StaticResource{
		Resource: mcp.Resource{
			URI:         "cbt://dag",
			Name:        "CBT Dependency DAG",
			Description: "Pre-processed dependency graph showing model relationships",
			MIMEType:    "application/json",
		},
		Handler: createCBTDAGHandler(client),
	})

	// Register cbt://models/{model} - Model details
	reg.RegisterTemplate(TemplateResource{
		Template: mcp.NewResourceTemplate(
			"cbt://models/{model}",
			"CBT Model Details",
			mcp.WithTemplateDescription("Detailed information about a specific CBT model"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		Pattern: cbtModelPattern,
		Handler: createCBTModelDetailHandler(log, client),
	})

	// Register cbt://models/{model}/dependencies - Model dependencies
	reg.RegisterTemplate(TemplateResource{
		Template: mcp.NewResourceTemplate(
			"cbt://models/{model}/dependencies",
			"CBT Model Dependencies",
			mcp.WithTemplateDescription("Dependency information for a specific model including transitive dependencies"),
			mcp.WithTemplateMIMEType("application/json"),
		),
		Pattern: cbtModelDepsPattern,
		Handler: createCBTModelDepsHandler(log, client),
	})

	log.Debug("Registered CBT resources")
}

// createCBTOverviewHandler returns a handler for cbt://.
func createCBTOverviewHandler(client CBTClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		networks := client.GetNetworks()

		response := CBTOverviewResponse{
			Description: "CBT (ClickHouse Block Transformer) provides data transformation metadata. " +
				"Models are universal - use {network} placeholder for network-specific queries.",
			Networks: networks,
			Usage: "Use cbt://models for model list, " +
				"cbt://models/{model} for details, " +
				"cbt://models/{model}/dependencies for dependencies, " +
				"cbt://dag for full dependency graph",
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createCBTIntervalsHandler returns a handler for cbt://intervals.
func createCBTIntervalsHandler(client CBTClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		intervalTypes := client.GetIntervalTypes()

		response := CBTIntervalsResponse{
			Description: "Interval types define how time-series data is partitioned. " +
				"Each type has conversion options for different representations.",
			IntervalTypes: intervalTypes,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createCBTModelsListHandler returns a handler for cbt://models.
func createCBTModelsListHandler(client CBTClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		cbtData := client.GetData()
		if cbtData == nil {
			return "", fmt.Errorf("CBT data not available")
		}

		// Build sorted lists of model IDs
		externalIDs := make([]string, 0, len(cbtData.ExternalModels))
		for id := range cbtData.ExternalModels {
			externalIDs = append(externalIDs, id)
		}

		sort.Strings(externalIDs)

		transformIDs := make([]string, 0, len(cbtData.Transformations))
		for id := range cbtData.Transformations {
			transformIDs = append(transformIDs, id)
		}

		sort.Strings(transformIDs)

		response := CBTModelsListResponse{
			ExternalModels:  externalIDs,
			Transformations: transformIDs,
			TotalCount:      len(externalIDs) + len(transformIDs),
			Networks:        cbtData.Networks,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createCBTDAGHandler returns a handler for cbt://dag.
func createCBTDAGHandler(client CBTClient) ReadHandler {
	return func(_ context.Context, _ string) (string, error) {
		dag := client.GetDAG()
		if dag == nil {
			return "", fmt.Errorf("CBT DAG not available")
		}

		data, err := json.MarshalIndent(dag, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// createCBTModelDetailHandler returns a handler for cbt://models/{model}.
func createCBTModelDetailHandler(log logrus.FieldLogger, client CBTClient) ReadHandler {
	return func(_ context.Context, uri string) (string, error) {
		matches := cbtModelPattern.FindStringSubmatch(uri)
		if len(matches) != 2 {
			return "", fmt.Errorf("invalid URI format: %s", uri)
		}

		modelID := matches[1]
		networks := client.GetNetworks()

		// Try external model first
		if external := client.GetExternalModel(modelID); external != nil {
			response := CBTModelDetailResponse{
				ID:       modelID,
				Type:     "external",
				Model:    external,
				Networks: networks,
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling response: %w", err)
			}

			return string(data), nil
		}

		// Try transformation model
		if transform := client.GetTransformation(modelID); transform != nil {
			response := CBTModelDetailResponse{
				ID:       modelID,
				Type:     "transformation",
				Model:    transform,
				Networks: networks,
			}

			data, err := json.MarshalIndent(response, "", "  ")
			if err != nil {
				return "", fmt.Errorf("marshaling response: %w", err)
			}

			return string(data), nil
		}

		return "", formatModelNotFoundError(modelID, client)
	}
}

// createCBTModelDepsHandler returns a handler for cbt://models/{model}/dependencies.
func createCBTModelDepsHandler(log logrus.FieldLogger, client CBTClient) ReadHandler {
	return func(_ context.Context, uri string) (string, error) {
		matches := cbtModelDepsPattern.FindStringSubmatch(uri)
		if len(matches) != 2 {
			return "", fmt.Errorf("invalid URI format: %s", uri)
		}

		modelID := matches[1]

		deps := client.GetModelDependencies(modelID)
		if deps == nil {
			return "", formatModelNotFoundError(modelID, client)
		}

		data, err := json.MarshalIndent(deps, "", "  ")
		if err != nil {
			return "", fmt.Errorf("marshaling response: %w", err)
		}

		return string(data), nil
	}
}

// formatModelNotFoundError formats an error when a model is not found.
func formatModelNotFoundError(modelID string, client CBTClient) error {
	cbtData := client.GetData()
	if cbtData == nil {
		return fmt.Errorf("model %q not found (CBT data not available)", modelID)
	}

	// Collect a sample of available models
	models := make([]string, 0, 10)

	for id := range cbtData.ExternalModels {
		models = append(models, id)

		if len(models) >= 5 {
			break
		}
	}

	for id := range cbtData.Transformations {
		models = append(models, id)

		if len(models) >= 10 {
			break
		}
	}

	sort.Strings(models)

	return fmt.Errorf(
		"model %q not found. Example models: %s (total: %d external, %d transformations)",
		modelID,
		strings.Join(models, ", "),
		len(cbtData.ExternalModels),
		len(cbtData.Transformations),
	)
}
