// Package observability provides metrics capabilities for xatu-mcp.
package observability

import (
	"github.com/prometheus/client_golang/prometheus"
)

// Metrics namespace for all xatu-mcp metrics.
const metricsNamespace = "xatu_mcp"

// Tool call metrics.
var (
	// ToolCallsTotal counts the total number of tool calls by tool name and status.
	ToolCallsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "tool_calls_total",
			Help:      "Total number of tool calls",
		},
		[]string{"tool", "status"},
	)

	// ToolCallDuration measures the duration of tool calls in seconds.
	ToolCallDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "tool_call_duration_seconds",
			Help:      "Duration of tool calls in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.1, 2, 10),
		},
		[]string{"tool"},
	)
)

// Sandbox execution metrics.
var (
	// SandboxExecutions counts total sandbox executions by backend and status.
	SandboxExecutions = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "sandbox_executions_total",
			Help:      "Total sandbox executions",
		},
		[]string{"backend", "status"},
	)

	// SandboxDuration measures the duration of sandbox executions in seconds.
	SandboxDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "sandbox_duration_seconds",
			Help:      "Duration of sandbox executions in seconds",
			Buckets:   prometheus.ExponentialBuckets(1, 2, 10),
		},
		[]string{"backend"},
	)
)

// Connection metrics.
var (
	// ActiveConnections tracks the number of active MCP connections.
	ActiveConnections = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: metricsNamespace,
			Name:      "active_connections",
			Help:      "Number of active MCP connections",
		},
	)
)

// ClickHouse query metrics.
var (
	// ClickHouseQueriesTotal counts total ClickHouse queries by cluster and status.
	ClickHouseQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "clickhouse_queries_total",
			Help:      "Total ClickHouse queries executed",
		},
		[]string{"cluster", "status"},
	)

	// ClickHouseQueryDuration measures the duration of ClickHouse queries in seconds.
	ClickHouseQueryDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "clickhouse_query_duration_seconds",
			Help:      "Duration of ClickHouse queries in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.01, 2, 12),
		},
		[]string{"cluster"},
	)
)

// Request metrics.
var (
	// RequestsTotal counts total MCP requests by method and status.
	RequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "requests_total",
			Help:      "Total MCP requests processed",
		},
		[]string{"method", "status"},
	)

	// RequestDuration measures the duration of MCP requests in seconds.
	RequestDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Namespace: metricsNamespace,
			Name:      "request_duration_seconds",
			Help:      "Duration of MCP requests in seconds",
			Buckets:   prometheus.ExponentialBuckets(0.001, 2, 15),
		},
		[]string{"method"},
	)
)

// Error metrics.
var (
	// ErrorsTotal counts total errors by component and error type.
	ErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "errors_total",
			Help:      "Total errors encountered",
		},
		[]string{"component", "error_type"},
	)
)

func init() {
	// Register all metrics with the default registry.
	prometheus.MustRegister(
		// Tool call metrics
		ToolCallsTotal,
		ToolCallDuration,
		// Sandbox metrics
		SandboxExecutions,
		SandboxDuration,
		// Connection metrics
		ActiveConnections,
		// ClickHouse metrics
		ClickHouseQueriesTotal,
		ClickHouseQueryDuration,
		// Request metrics
		RequestsTotal,
		RequestDuration,
		// Error metrics
		ErrorsTotal,
	)
}
