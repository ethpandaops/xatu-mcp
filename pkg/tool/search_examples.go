package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/resource"
)

const (
	SearchExamplesToolName = "search_examples"
	DefaultSearchLimit     = 3
	MaxSearchLimit         = 10
	MinSimilarityScore     = 0.3
)

const searchExamplesDescription = `Search ClickHouse query examples using semantic search.

Returns matching examples with full SQL queries. Each result includes target cluster (xatu vs xatu-cbt) - see mcp://getting-started for syntax differences.

Examples: search_examples(query="block"), search_examples(query="validator", category="validators")`

type SearchExampleResult struct {
	CategoryKey     string  `json:"category_key"`
	CategoryName    string  `json:"category_name"`
	ExampleName     string  `json:"example_name"`
	Description     string  `json:"description"`
	Query           string  `json:"query"`
	TargetCluster   string  `json:"target_cluster"`
	SimilarityScore float64 `json:"similarity_score"`
}

type SearchExamplesResponse struct {
	Query               string                 `json:"query"`
	CategoryFilter      string                 `json:"category_filter,omitempty"`
	TotalMatches        int                    `json:"total_matches"`
	Results             []*SearchExampleResult `json:"results"`
	AvailableCategories []string               `json:"available_categories"`
}

type searchExamplesHandler struct {
	log       logrus.FieldLogger
	index     *resource.ExampleIndex
	pluginReg *plugin.Registry
}

func NewSearchExamplesTool(log logrus.FieldLogger, index *resource.ExampleIndex, pluginReg *plugin.Registry) Definition {
	h := &searchExamplesHandler{
		log:       log.WithField("tool", SearchExamplesToolName),
		index:     index,
		pluginReg: pluginReg,
	}

	return Definition{
		Tool: mcp.Tool{
			Name:        SearchExamplesToolName,
			Description: searchExamplesDescription,
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Search term or phrase to find semantically similar examples",
					},
					"category": map[string]any{
						"type":        "string",
						"description": "Optional: filter to a specific category (e.g., 'attestations', 'block_events')",
					},
					"limit": map[string]any{
						"type":        "integer",
						"description": "Maximum results to return (default: 10, max: 50)",
						"minimum":     1,
						"maximum":     MaxSearchLimit,
					},
				},
				Required: []string{"query"},
			},
		},
		Handler: h.handle,
	}
}

func (h *searchExamplesHandler) handle(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	h.log.Debug("Handling search_examples request")

	query := request.GetString("query", "")
	if query == "" {
		return CallToolError(fmt.Errorf("query is required and cannot be empty")), nil
	}

	categoryFilter := request.GetString("category", "")

	limit := int(request.GetInt("limit", DefaultSearchLimit))
	if limit <= 0 {
		limit = DefaultSearchLimit
	}

	if limit > MaxSearchLimit {
		limit = MaxSearchLimit
	}

	examples := resource.GetQueryExamples(h.pluginReg)

	categories := make([]string, 0, len(examples))
	for k := range examples {
		categories = append(categories, k)
	}

	sort.Strings(categories)

	if categoryFilter != "" {
		if _, ok := examples[categoryFilter]; !ok {
			return CallToolError(fmt.Errorf(
				"unknown category: %q. Available categories: %s",
				categoryFilter,
				strings.Join(categories, ", "),
			)), nil
		}
	}

	results, err := h.index.Search(query, limit)
	if err != nil {
		return CallToolError(fmt.Errorf("search failed: %w", err)), nil
	}

	if categoryFilter != "" {
		filtered := make([]resource.SearchResult, 0)
		for _, r := range results {
			if r.CategoryKey == categoryFilter {
				filtered = append(filtered, r)
			}
		}

		results = filtered
	}

	searchResults := make([]*SearchExampleResult, 0, len(results))
	for _, r := range results {
		if r.Score < MinSimilarityScore {
			continue
		}

		searchResults = append(searchResults, &SearchExampleResult{
			CategoryKey:     r.CategoryKey,
			CategoryName:    r.CategoryName,
			ExampleName:     r.Example.Name,
			Description:     r.Example.Description,
			Query:           r.Example.Query,
			TargetCluster:   r.Example.Cluster,
			SimilarityScore: r.Score,
		})
	}

	response := &SearchExamplesResponse{
		Query:               query,
		CategoryFilter:      categoryFilter,
		TotalMatches:        len(searchResults),
		Results:             searchResults,
		AvailableCategories: categories,
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return CallToolError(fmt.Errorf("marshaling response: %w", err)), nil
	}

	h.log.WithFields(logrus.Fields{
		"query":   query,
		"matches": len(searchResults),
	}).Debug("Search completed")

	return CallToolSuccess(string(data)), nil
}
