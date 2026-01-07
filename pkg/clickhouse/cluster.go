// Package clickhouse provides a client for querying ClickHouse schema information.
package clickhouse

import (
	"fmt"
	"regexp"
)

// ClusterInfo holds information about a ClickHouse cluster.
type ClusterInfo struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Host        string   `json:"host"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	User        string   `json:"user"`
	Password    string   `json:"-"` // Exclude from JSON for security
	Database    string   `json:"database"`
	Networks    []string `json:"networks"`
}

// TableInfo holds metadata about a ClickHouse table.
type TableInfo struct {
	Name         string `json:"name"`
	Engine       string `json:"engine"`
	TotalRows    string `json:"total_rows"`
	TotalBytes   string `json:"total_bytes"`
	Comment      string `json:"comment"`
	PartitionKey string `json:"partition_key,omitempty"`
	SortingKey   string `json:"sorting_key,omitempty"`
	PrimaryKey   string `json:"primary_key,omitempty"`
}

// ColumnInfo holds metadata about a ClickHouse column.
type ColumnInfo struct {
	Name              string `json:"name"`
	Type              string `json:"type"`
	Comment           string `json:"comment,omitempty"`
	DefaultKind       string `json:"default_kind,omitempty"`
	DefaultExpression string `json:"default_expression,omitempty"`
	IsPartitionKey    bool   `json:"is_partition_key,omitempty"`
	IsSortingKey      bool   `json:"is_sorting_key,omitempty"`
	IsPrimaryKey      bool   `json:"is_primary_key,omitempty"`
}

// validIdentifierPattern matches valid ClickHouse identifiers.
// Identifiers must start with a letter or underscore and contain only alphanumeric
// characters and underscores.
var validIdentifierPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// maxIdentifierLength is the maximum length for a ClickHouse identifier.
const maxIdentifierLength = 128

// ValidateIdentifier validates a ClickHouse identifier for safe use in SQL queries.
// It returns an error if the identifier is empty, contains invalid characters, or is too long.
func ValidateIdentifier(name, identifierType string) error {
	if name == "" {
		return fmt.Errorf("%s name cannot be empty", identifierType)
	}

	if !validIdentifierPattern.MatchString(name) {
		return fmt.Errorf(
			"invalid %s name %q: must contain only alphanumeric characters and underscores, "+
				"and must start with a letter or underscore",
			identifierType, name,
		)
	}

	if len(name) > maxIdentifierLength {
		return fmt.Errorf("%s name too long (max %d characters)", identifierType, maxIdentifierLength)
	}

	return nil
}

// URL returns the HTTP URL for the cluster.
func (c *ClusterInfo) URL() string {
	return fmt.Sprintf("%s://%s:%d", c.Protocol, c.Host, c.Port)
}
