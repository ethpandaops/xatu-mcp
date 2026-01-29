package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/ethpandaops/mcp/pkg/config"
	"github.com/ethpandaops/mcp/pkg/plugin"
	"github.com/ethpandaops/mcp/pkg/sandbox"

	clickhouseplugin "github.com/ethpandaops/mcp/plugins/clickhouse"
	lokiplugin "github.com/ethpandaops/mcp/plugins/loki"
	prometheusplugin "github.com/ethpandaops/mcp/plugins/prometheus"
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

func runTest(_ *cobra.Command, _ []string) error {
	ctx := context.Background()

	// Load config.
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("loading config: %w", err)
	}

	// Build plugin registry to get env vars.
	pluginReg, err := buildTestPluginRegistry(cfg)
	if err != nil {
		return fmt.Errorf("building plugin registry: %w", err)
	}

	// Create sandbox.
	sandboxSvc, err := sandbox.New(cfg.Sandbox, log)
	if err != nil {
		return fmt.Errorf("creating sandbox: %w", err)
	}

	// Start sandbox.
	if err := sandboxSvc.Start(ctx); err != nil {
		return fmt.Errorf("starting sandbox: %w", err)
	}

	defer func() {
		if stopErr := sandboxSvc.Stop(ctx); stopErr != nil {
			log.WithError(stopErr).Error("Failed to stop sandbox")
		}
	}()

	// Determine code to run.
	code := testCode
	if code == "" {
		code = defaultTestCode()
	}

	fmt.Println("=== Executing Python code ===")
	fmt.Println(code)
	fmt.Println("=== Running... ===")

	// Build environment from plugin registry.
	env, err := buildTestEnv(cfg, pluginReg)
	if err != nil {
		return fmt.Errorf("building test environment: %w", err)
	}

	// Execute.
	result, err := sandboxSvc.Execute(ctx, sandbox.ExecuteRequest{
		Code:    code,
		Env:     env,
		Timeout: time.Duration(testTimeout) * time.Second,
	})
	if err != nil {
		return fmt.Errorf("execution failed: %w", err)
	}

	// Print results.
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

# Test ethpandaops library
print("\nTesting ethpandaops library...")
from ethpandaops import clickhouse, prometheus, loki, storage
print("  ethpandaops library imported successfully")

# Test environment variables
import os
print("\nEnvironment variables:")
for key in sorted(os.environ.keys()):
    if key.startswith("ETHPANDAOPS"):
        value = os.environ[key]
        if "PASSWORD" in key or "SECRET" in key:
            value = "***"
        print(f"  {key}={value}")

print("\nAll tests passed!")
`
}

func buildTestPluginRegistry(cfg *config.Config) (*plugin.Registry, error) {
	reg := plugin.NewRegistry(log)

	// Register all compiled-in plugins.
	reg.Add(clickhouseplugin.New())
	reg.Add(prometheusplugin.New())
	reg.Add(lokiplugin.New())

	// Initialize plugins that have config.
	for _, name := range reg.All() {
		rawYAML, err := cfg.PluginConfigYAML(name)
		if err != nil {
			return nil, fmt.Errorf("getting config for plugin %q: %w", name, err)
		}

		if rawYAML == nil {
			continue
		}

		if err := reg.InitPlugin(name, rawYAML); err != nil {
			return nil, fmt.Errorf("initializing plugin %q: %w", name, err)
		}
	}

	return reg, nil
}

func buildTestEnv(cfg *config.Config, pluginReg *plugin.Registry) (map[string]string, error) {
	// Get env vars from all initialized plugins.
	env, err := pluginReg.SandboxEnv()
	if err != nil {
		return nil, fmt.Errorf("getting sandbox env from plugins: %w", err)
	}

	// Add platform S3 vars.
	if cfg.Storage != nil {
		env["ETHPANDAOPS_S3_ENDPOINT"] = cfg.Storage.Endpoint
		env["ETHPANDAOPS_S3_ACCESS_KEY"] = cfg.Storage.AccessKey
		env["ETHPANDAOPS_S3_SECRET_KEY"] = cfg.Storage.SecretKey
		env["ETHPANDAOPS_S3_BUCKET"] = cfg.Storage.Bucket
		env["ETHPANDAOPS_S3_REGION"] = cfg.Storage.Region

		if cfg.Storage.PublicURLPrefix != "" {
			env["ETHPANDAOPS_S3_PUBLIC_URL_PREFIX"] = cfg.Storage.PublicURLPrefix
		}
	}

	return env, nil
}
