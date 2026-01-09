package tool

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/ethpandaops/xatu-mcp/pkg/resource"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// SearchExamplesToolName is the name of the search_examples tool.
	SearchExamplesToolName = "search_examples"

	// DefaultSearchLimit is the default number of results to return.
	DefaultSearchLimit = 10

	// MaxSearchLimit is the maximum number of results allowed.
	MaxSearchLimit = 50
)

// searchExamplesDescription describes the search_examples tool.
const searchExamplesDescription = `Search through ClickHouse query examples by keyword, regex pattern, or category.

⚠️ TIP: Read xatu://getting-started resource for an overview of available tables and required filters.
Always search for examples BEFORE writing queries - they show correct table/column names and filters.

Searches across:
- Example names
- Example descriptions
- Query content (SQL)
- Category names and descriptions

Returns matching examples with their full context including category information.

Examples:
- search_examples(query="attestation") - Find all attestation-related examples
- search_examples(query="block_events", category="block_events") - Search within a category
- search_examples(query="slot.*propagation") - Regex search for patterns
- search_examples(query="blob", limit=5) - Limit results

If the regex pattern is invalid, it will be treated as a literal string search.`

// SearchExampleResult represents a single matching example with category context.
type SearchExampleResult struct {
	CategoryKey   string   `json:"category_key"`
	CategoryName  string   `json:"category_name"`
	ExampleName   string   `json:"example_name"`
	Description   string   `json:"description"`
	Query         string   `json:"query"`
	Cluster       string   `json:"cluster"`
	MatchedFields []string `json:"matched_fields"`
}

// SearchExamplesResponse is the complete search response.
type SearchExamplesResponse struct {
	Query               string                 `json:"query"`
	CategoryFilter      string                 `json:"category_filter,omitempty"`
	TotalMatches        int                    `json:"total_matches"`
	Results             []*SearchExampleResult `json:"results"`
	AvailableCategories []string               `json:"available_categories"`
}

// NewSearchExamplesTool creates the search_examples tool definition.
func NewSearchExamplesTool(log logrus.FieldLogger) Definition {
	return Definition{
		Tool: mcp.Tool{
			Name:        SearchExamplesToolName,
			Description: searchExamplesDescription,
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"query": map[string]any{
						"type":        "string",
						"description": "Search term: keyword, regex pattern, or category name",
					},
					"category": map[string]any{
						"type":        "string",
						"description": "Optional: filter to a specific category (e.g., 'attestations', 'block_events')",
					},
					"case_sensitive": map[string]any{
						"type":        "boolean",
						"description": "Enable case-sensitive matching (default: false)",
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
		Handler: newSearchExamplesHandler(log),
	}
}

// newSearchExamplesHandler creates the handler function for search_examples.
func newSearchExamplesHandler(log logrus.FieldLogger) Handler {
	handlerLog := log.WithField("tool", SearchExamplesToolName)

	return func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerLog.Debug("Handling search_examples request")

		// Extract parameters
		query := request.GetString("query", "")
		if query == "" {
			return CallToolError(fmt.Errorf("query is required and cannot be empty")), nil
		}

		categoryFilter := request.GetString("category", "")
		caseSensitive := request.GetBool("case_sensitive", false)

		limit := int(request.GetInt("limit", DefaultSearchLimit))
		if limit <= 0 {
			limit = DefaultSearchLimit
		}

		if limit > MaxSearchLimit {
			limit = MaxSearchLimit
		}

		// Validate category filter if provided
		examples := resource.GetQueryExamples()
		categories := resource.GetQueryCategories()

		if categoryFilter != "" {
			if _, ok := examples[categoryFilter]; !ok {
				return CallToolError(fmt.Errorf(
					"unknown category: %q. Available categories: %s",
					categoryFilter,
					strings.Join(categories, ", "),
				)), nil
			}
		}

		// Compile search pattern
		pattern, err := compileSearchPattern(query, caseSensitive)
		if err != nil {
			// This shouldn't happen since we fallback to literal search
			return CallToolError(fmt.Errorf("invalid search pattern: %w", err)), nil
		}

		// Perform search
		results := searchExamples(pattern, examples, categoryFilter, limit)

		// Sort categories for consistent output
		sort.Strings(categories)

		response := &SearchExamplesResponse{
			Query:               query,
			CategoryFilter:      categoryFilter,
			TotalMatches:        len(results),
			Results:             results,
			AvailableCategories: categories,
		}

		data, err := json.MarshalIndent(response, "", "  ")
		if err != nil {
			return CallToolError(fmt.Errorf("marshaling response: %w", err)), nil
		}

		handlerLog.WithFields(logrus.Fields{
			"query":   query,
			"matches": len(results),
		}).Debug("Search completed")

		return CallToolSuccess(string(data)), nil
	}
}

// compileSearchPattern compiles a search pattern with optional case sensitivity.
// If the pattern is invalid regex, it falls back to a literal string search.
func compileSearchPattern(query string, caseSensitive bool) (*regexp.Regexp, error) {
	pattern := query
	if !caseSensitive {
		pattern = "(?i)" + pattern
	}

	re, err := regexp.Compile(pattern)
	if err != nil {
		// Fallback: escape regex special chars and treat as literal
		escaped := regexp.QuoteMeta(query)
		if !caseSensitive {
			escaped = "(?i)" + escaped
		}

		return regexp.Compile(escaped)
	}

	return re, nil
}

// searchExamples searches through examples and returns matching results.
func searchExamples(
	pattern *regexp.Regexp,
	examples map[string]resource.QueryCategory,
	categoryFilter string,
	limit int,
) []*SearchExampleResult {
	results := make([]*SearchExampleResult, 0, limit)

	// Sort category keys for consistent ordering
	categoryKeys := make([]string, 0, len(examples))
	for k := range examples {
		categoryKeys = append(categoryKeys, k)
	}

	sort.Strings(categoryKeys)

	for _, categoryKey := range categoryKeys {
		category := examples[categoryKey]

		// Skip if category filter is set and doesn't match
		if categoryFilter != "" && categoryKey != categoryFilter {
			continue
		}

		// Check if category itself matches
		categoryMatches := pattern.MatchString(category.Name) || pattern.MatchString(category.Description)

		for _, example := range category.Examples {
			matchedFields := make([]string, 0, 4)

			// Check each searchable field
			if pattern.MatchString(example.Name) {
				matchedFields = append(matchedFields, "name")
			}

			if pattern.MatchString(example.Description) {
				matchedFields = append(matchedFields, "description")
			}

			if pattern.MatchString(example.Query) {
				matchedFields = append(matchedFields, "query")
			}

			if categoryMatches {
				matchedFields = append(matchedFields, "category")
			}

			if len(matchedFields) > 0 {
				results = append(results, &SearchExampleResult{
					CategoryKey:   categoryKey,
					CategoryName:  category.Name,
					ExampleName:   example.Name,
					Description:   example.Description,
					Query:         example.Query,
					Cluster:       example.Cluster,
					MatchedFields: matchedFields,
				})

				if len(results) >= limit {
					return results
				}
			}
		}
	}

	return results
}
