package tool

import (
	"context"
	"fmt"
	"regexp"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/sirupsen/logrus"
)

const (
	// ListOutputFilesToolName is the name of the list_output_files tool.
	ListOutputFilesToolName = "list_output_files"
	// GetOutputFileToolName is the name of the get_output_file tool.
	GetOutputFileToolName = "get_output_file"
)

// safeFilenamePattern validates filenames to prevent path traversal attacks.
var safeFilenamePattern = regexp.MustCompile(`^[a-zA-Z0-9_\-][a-zA-Z0-9_\-\.]*$`)

const (
	maxFilenameLength = 255
)

// getOutputFileDescription describes the get_output_file tool.
const getOutputFileDescription = `Get information about how to retrieve output files.

Output files are uploaded from within sandbox code using xatu.storage:

` + "```python" + `
from xatu import storage

# Upload a file and get its URL
url = storage.upload("/workspace/chart.png")
print(f"Chart: {url}")
` + "```" + `

The URL is returned directly to stdout. This tool provides documentation
on how to use file storage in sandbox code.`

// listOutputFilesDescription describes the list_output_files tool.
const listOutputFilesDescription = `Get information about output file handling.

Output files should be uploaded from within sandbox code using xatu.storage.
This tool provides documentation on how files are handled.`

// NewListOutputFilesTool creates the list_output_files tool definition.
func NewListOutputFilesTool(log logrus.FieldLogger) Definition {
	return Definition{
		Tool: mcp.Tool{
			Name:        ListOutputFilesToolName,
			Description: listOutputFilesDescription,
			InputSchema: mcp.ToolInputSchema{
				Type:       "object",
				Properties: map[string]any{},
			},
		},
		Handler: newListOutputFilesHandler(log),
	}
}

// NewGetOutputFileTool creates the get_output_file tool definition.
func NewGetOutputFileTool(log logrus.FieldLogger) Definition {
	return Definition{
		Tool: mcp.Tool{
			Name:        GetOutputFileToolName,
			Description: getOutputFileDescription,
			InputSchema: mcp.ToolInputSchema{
				Type: "object",
				Properties: map[string]any{
					"filename": map[string]any{
						"type":        "string",
						"description": "Name of the file (for documentation purposes)",
					},
				},
				Required: []string{"filename"},
			},
		},
		Handler: newGetOutputFileHandler(log),
	}
}

// newListOutputFilesHandler creates the handler function for list_output_files.
func newListOutputFilesHandler(log logrus.FieldLogger) Handler {
	handlerLog := log.WithField("tool", ListOutputFilesToolName)

	return func(_ context.Context, _ mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerLog.Debug("Handling list_output_files request")

		response := `Output files are managed within sandbox code using xatu.storage.

Available functions:
- storage.upload(path) - Upload a file and get its public URL
- storage.upload(path, remote_name="custom.png") - Upload with custom name
- storage.list_files(prefix="") - List uploaded files
- storage.get_url(key) - Get URL for an existing file

Example workflow:
` + "```python" + `
from xatu import storage, clickhouse
import matplotlib.pyplot as plt

# Query data
df = clickhouse.query("mainnet", "SELECT * FROM beacon_api_eth_v1_events_block LIMIT 100")

# Create visualization
plt.figure(figsize=(10, 6))
plt.plot(df['slot'], df['block'])
plt.savefig('/workspace/blocks.png')

# Upload and get URL
url = storage.upload('/workspace/blocks.png')
print(f"Chart: {url}")
` + "```"

		return CallToolSuccess(response), nil
	}
}

// newGetOutputFileHandler creates the handler function for get_output_file.
func newGetOutputFileHandler(log logrus.FieldLogger) Handler {
	handlerLog := log.WithField("tool", GetOutputFileToolName)

	return func(_ context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handlerLog.Debug("Handling get_output_file request")

		// Extract and validate filename using mcp-go helper.
		filename := request.GetString("filename", "")

		if filename != "" {
			if err := validateFilename(filename); err != nil {
				return CallToolError(fmt.Errorf("invalid filename: %w", err)), nil
			}
		}

		response := `Output files should be uploaded from within sandbox code.

Example:
` + "```python" + `
from xatu import storage

# Save your file to /workspace
plt.savefig('/workspace/chart.png')

# Upload and get URL
url = storage.upload('/workspace/chart.png')
print(f"Chart URL: {url}")
` + "```" + `

The URL will be printed to stdout and visible in the execution results.`

		return CallToolSuccess(response), nil
	}
}

// validateFilename validates a filename to prevent path traversal attacks.
func validateFilename(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename cannot be empty")
	}

	// Check for path traversal attempts.
	if containsPathSeparator(filename) {
		return fmt.Errorf("filename cannot contain path separators")
	}

	if filename[0] == '.' {
		return fmt.Errorf("filename cannot start with '.'")
	}

	if containsDoubleDot(filename) {
		return fmt.Errorf("filename cannot contain '..'")
	}

	// Check against allowed pattern.
	if !safeFilenamePattern.MatchString(filename) {
		return fmt.Errorf(
			"filename must contain only alphanumeric characters, underscores, hyphens, and dots",
		)
	}

	// Length check.
	if len(filename) > maxFilenameLength {
		return fmt.Errorf("filename too long (max %d characters)", maxFilenameLength)
	}

	return nil
}

// containsPathSeparator checks if a string contains path separators.
func containsPathSeparator(s string) bool {
	for _, c := range s {
		if c == '/' || c == '\\' {
			return true
		}
	}

	return false
}

// containsDoubleDot checks if a string contains "..".
func containsDoubleDot(s string) bool {
	for i := 0; i < len(s)-1; i++ {
		if s[i] == '.' && s[i+1] == '.' {
			return true
		}
	}

	return false
}
