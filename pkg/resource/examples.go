package resource

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

//go:embed examples.yaml
var examplesYAML []byte

// QueryExample represents a single query example.
type QueryExample struct {
	Name        string `json:"name" yaml:"name"`
	Description string `json:"description" yaml:"description"`
	Query       string `json:"query" yaml:"query"`
	Cluster     string `json:"cluster" yaml:"cluster"`
}

// QueryCategory represents a category of query examples.
type QueryCategory struct {
	Name        string         `json:"name" yaml:"name"`
	Description string         `json:"description" yaml:"description"`
	Examples    []QueryExample `json:"examples" yaml:"examples"`
}

// queryExamples holds the parsed examples loaded from YAML.
var queryExamples map[string]QueryCategory

func init() {
	if err := yaml.Unmarshal(examplesYAML, &queryExamples); err != nil {
		panic(fmt.Sprintf("failed to parse examples.yaml: %v", err))
	}

	// Trim trailing whitespace from queries (YAML multiline strings may have trailing newlines)
	for key, category := range queryExamples {
		for i := range category.Examples {
			category.Examples[i].Query = strings.TrimSpace(category.Examples[i].Query)
		}

		queryExamples[key] = category
	}
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

// GetQueryExamples returns a copy of the query examples map.
// This allows tools to search through examples without modifying them.
func GetQueryExamples() map[string]QueryCategory {
	result := make(map[string]QueryCategory, len(queryExamples))
	for k, v := range queryExamples {
		result[k] = v
	}

	return result
}

// GetQueryCategories returns a list of available query category keys.
func GetQueryCategories() []string {
	categories := make([]string, 0, len(queryExamples))
	for k := range queryExamples {
		categories = append(categories, k)
	}

	return categories
}
