package loki

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/types"
)

type Plugin struct {
	cfg Config
}

func New() *Plugin { return &Plugin{} }

func (p *Plugin) Name() string { return "loki" }

func (p *Plugin) Init(rawConfig []byte) error {
	return yaml.Unmarshal(rawConfig, &p.cfg)
}

func (p *Plugin) ApplyDefaults() {
	for i := range p.cfg.Instances {
		if p.cfg.Instances[i].Timeout == 0 {
			p.cfg.Instances[i].Timeout = 60
		}
	}
}

func (p *Plugin) Validate() error {
	names := make(map[string]struct{}, len(p.cfg.Instances))
	for i, inst := range p.cfg.Instances {
		if inst.Name == "" {
			return fmt.Errorf("instances[%d].name is required", i)
		}
		if _, exists := names[inst.Name]; exists {
			return fmt.Errorf("instances[%d].name %q is duplicated", i, inst.Name)
		}
		names[inst.Name] = struct{}{}
		if inst.URL == "" {
			return fmt.Errorf("instances[%d].url is required", i)
		}
	}
	return nil
}

func (p *Plugin) SandboxEnv() (map[string]string, error) {
	if len(p.cfg.Instances) == 0 {
		return nil, nil
	}
	lokiConfigs, err := json.Marshal(p.cfg.Instances)
	if err != nil {
		return nil, fmt.Errorf("marshaling Loki configs: %w", err)
	}
	return map[string]string{
		"ETHPANDAOPS_LOKI_CONFIGS": string(lokiConfigs),
	}, nil
}

func (p *Plugin) DatasourceInfo() []types.DatasourceInfo {
	infos := make([]types.DatasourceInfo, 0, len(p.cfg.Instances))
	for _, inst := range p.cfg.Instances {
		infos = append(infos, types.DatasourceInfo{
			Type:        "loki",
			Name:        inst.Name,
			Description: inst.Description,
			Metadata: map[string]string{
				"url": inst.URL,
			},
		})
	}
	return infos
}

func (p *Plugin) Examples() map[string]types.ExampleCategory {
	result := make(map[string]types.ExampleCategory, len(queryExamples))
	for k, v := range queryExamples {
		result[k] = v
	}
	return result
}

// PythonAPIDocs with full Loki module docs
func (p *Plugin) PythonAPIDocs() map[string]types.ModuleDoc {
	return map[string]types.ModuleDoc{
		"loki": {
			Description: "Query Loki for log data",
			Functions: map[string]types.FunctionDoc{
				"list_datasources": {
					Signature:   "loki.list_datasources() -> list[dict]",
					Description: "List available Loki datasources. Prefer datasources://loki resource.",
					Returns:     "List of dicts with 'name', 'description', 'url' keys",
				},
				"query": {
					Signature:   "loki.query(datasource: str, logql: str, limit: int = 100, start: str = None, end: str = None, direction: str = 'backward') -> list[dict]",
					Description: "Execute LogQL range query",
					Parameters: map[string]string{
						"datasource": "Datasource name from datasources://loki",
						"logql":      "LogQL query string",
						"limit":      "Max entries to return (default: 100)",
						"start":      "Start time (default: now-1h)",
						"end":        "End time (default: now)",
						"direction":  "'forward' or 'backward' (default)",
					},
					Returns: "List of dicts with 'timestamp', 'labels', 'line' keys",
				},
				"query_instant": {
					Signature:   "loki.query_instant(datasource: str, logql: str, time: str = None, limit: int = 100, direction: str = 'backward') -> list[dict]",
					Description: "Execute instant LogQL query",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"logql":      "LogQL query string",
						"time":       "Evaluation timestamp (default: now)",
						"limit":      "Max entries (default: 100)",
						"direction":  "'forward' or 'backward'",
					},
					Returns: "List of dicts with 'timestamp', 'labels', 'line' keys",
				},
				"get_labels": {
					Signature:   "loki.get_labels(datasource: str, start: str = None, end: str = None) -> list[str]",
					Description: "Get all label names",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"start":      "Optional start time",
						"end":        "Optional end time",
					},
					Returns: "List of label names",
				},
				"get_label_values": {
					Signature:   "loki.get_label_values(datasource: str, label: str, start: str = None, end: str = None) -> list[str]",
					Description: "Get all values for a label",
					Parameters: map[string]string{
						"datasource": "Datasource name",
						"label":      "Label name",
						"start":      "Optional start time",
						"end":        "Optional end time",
					},
					Returns: "List of label values",
				},
			},
		},
	}
}

func (p *Plugin) GettingStartedSnippet() string                                           { return "" }
func (p *Plugin) RegisterResources(_ logrus.FieldLogger, _ plugin.ResourceRegistry) error { return nil }
func (p *Plugin) Start(_ context.Context) error                                           { return nil }
func (p *Plugin) Stop(_ context.Context) error                                            { return nil }
