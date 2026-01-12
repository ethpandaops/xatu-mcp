package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethpandaops/xatu-mcp/pkg/config"
	"github.com/ethpandaops/xatu-mcp/pkg/sandbox"
)

var testCmd = &cobra.Command{
	Use:   "test",
	Short: "Test sandbox execution",
	Long:  `Run a test Python script in the sandbox to verify everything works.`,
	RunE:  runTest,
}

var (
	testCode    string
	testTimeout int
)

func init() {
	rootCmd.AddCommand(testCmd)

	testCmd.Flags().StringVar(&testCode, "code", "", "Python code to execute (if not provided, runs a test script)")
	testCmd.Flags().IntVarP(&testTimeout, "timeout", "t", 30, "Execution timeout in seconds")
}

func runTest(cmd *cobra.Command, args []string) error {
	ctx := context.Background()

	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Create sandbox
	sandboxSvc, err := sandbox.New(cfg.Sandbox, log)
	if err != nil {
		return fmt.Errorf("creating sandbox: %w", err)
	}

	// Start sandbox
	if err := sandboxSvc.Start(ctx); err != nil {
		return fmt.Errorf("starting sandbox: %w", err)
	}

	defer func() {
		if stopErr := sandboxSvc.Stop(ctx); stopErr != nil {
			log.WithError(stopErr).Error("Failed to stop sandbox")
		}
	}()

	// Determine code to run
	code := testCode
	if code == "" {
		code = defaultTestCode()
	}

	fmt.Println("=== Executing Python code ===")
	fmt.Println(code)
	fmt.Println("=== Running... ===")

	// Build environment
	env, err := buildTestEnv(cfg)
	if err != nil {
		return fmt.Errorf("building test environment: %w", err)
	}

	// Execute
	result, err := sandboxSvc.Execute(ctx, sandbox.ExecuteRequest{
		Code:    code,
		Env:     env,
		Timeout: time.Duration(testTimeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	// Print results
	fmt.Println("\n=== STDOUT ===")
	fmt.Println(result.Stdout)

	if result.Stderr != "" {
		fmt.Println("\n=== STDERR ===")
		fmt.Println(result.Stderr)
	}

	if len(result.OutputFiles) > 0 {
		fmt.Println("\n=== OUTPUT FILES ===")
		for _, f := range result.OutputFiles {
			fmt.Printf("  - %s\n", f)
		}
	}

	fmt.Printf("\n=== Exit Code: %d | Duration: %.2fs | Execution ID: %s ===\n",
		result.ExitCode, result.DurationSeconds, result.ExecutionID)

	if result.ExitCode != 0 {
		os.Exit(result.ExitCode)
	}

	return nil
}

func defaultTestCode() string {
	return `import sys
print(f"Python version: {sys.version}")

# Test imports
print("\nTesting imports...")
import pandas as pd
import numpy as np
import polars as pl
import matplotlib
import seaborn as sns
import plotly
import altair as alt
import bokeh
import scipy

print(f"  pandas: {pd.__version__}")
print(f"  numpy: {np.__version__}")
print(f"  polars: {pl.__version__}")
print(f"  matplotlib: {matplotlib.__version__}")
print(f"  seaborn: {sns.__version__}")
print(f"  plotly: {plotly.__version__}")
print(f"  altair: {alt.__version__}")
print(f"  bokeh: {bokeh.__version__}")
print(f"  scipy: {scipy.__version__}")

# Test xatu library
print("\nTesting xatu library...")
from xatu import clickhouse, prometheus, loki, storage
print("  xatu library imported successfully")

# Test environment variables
import os
print("\nEnvironment variables:")
for key in sorted(os.environ.keys()):
    if key.startswith("XATU"):
        value = os.environ[key]
        if "PASSWORD" in key or "SECRET" in key:
            value = "***"
        print(f"  {key}={value}")

print("\nAll tests passed!")
`
}

func buildTestEnv(cfg *config.Config) (map[string]string, error) {
	env := make(map[string]string, 8)

	// ClickHouse configs as JSON array.
	if len(cfg.ClickHouse) > 0 {
		chConfigs, err := json.Marshal(cfg.ClickHouse)
		if err != nil {
			return nil, fmt.Errorf("marshaling ClickHouse configs: %w", err)
		}

		env["XATU_CLICKHOUSE_CONFIGS"] = string(chConfigs)
	}

	// Prometheus configs as JSON array.
	if len(cfg.Prometheus) > 0 {
		promConfigs, err := json.Marshal(cfg.Prometheus)
		if err != nil {
			return nil, fmt.Errorf("marshaling Prometheus configs: %w", err)
		}

		env["XATU_PROMETHEUS_CONFIGS"] = string(promConfigs)
	}

	// Loki configs as JSON array.
	if len(cfg.Loki) > 0 {
		lokiConfigs, err := json.Marshal(cfg.Loki)
		if err != nil {
			return nil, fmt.Errorf("marshaling Loki configs: %w", err)
		}

		env["XATU_LOKI_CONFIGS"] = string(lokiConfigs)
	}

	// S3 Storage.
	if cfg.Storage != nil {
		env["XATU_S3_ENDPOINT"] = cfg.Storage.Endpoint
		env["XATU_S3_ACCESS_KEY"] = cfg.Storage.AccessKey
		env["XATU_S3_SECRET_KEY"] = cfg.Storage.SecretKey
		env["XATU_S3_BUCKET"] = cfg.Storage.Bucket
		env["XATU_S3_REGION"] = cfg.Storage.Region

		if cfg.Storage.PublicURLPrefix != "" {
			env["XATU_S3_PUBLIC_URL_PREFIX"] = cfg.Storage.PublicURLPrefix
		}
	}

	return env, nil
}
