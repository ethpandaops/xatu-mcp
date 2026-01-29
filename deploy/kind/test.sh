#!/bin/bash
# Test script for KIND-based Kubernetes sandbox backend
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_URL="${MCP_URL:-http://localhost:30000}"

echo "============================================================"
echo "Testing MCP Server with Kubernetes Sandbox Backend"
echo "============================================================"
echo "MCP URL: ${MCP_URL}"
echo ""

# Check if server is reachable
echo "1. Checking server health..."
if ! curl -sf "${MCP_URL}/health" >/dev/null 2>&1; then
    echo "   ✗ MCP server is not reachable at ${MCP_URL}"
    echo "   Make sure the KIND cluster is running: make kind-setup"
    exit 1
fi
echo "   ✓ Server is healthy"

# Check Kubernetes backend is active
echo ""
echo "2. Verifying Kubernetes sandbox backend..."
if kubectl logs -n ethpandaops-mcp -l app.kubernetes.io/name=ethpandaops-mcp --tail=500 2>/dev/null | grep -q "Kubernetes sandbox backend started"; then
    echo "   ✓ Kubernetes sandbox backend is active"
else
    echo "   ⚠ Could not verify Kubernetes backend in logs"
fi

# Check sandbox namespace
echo ""
echo "3. Checking sandbox namespace..."
if kubectl get namespace mcp-sandboxes >/dev/null 2>&1; then
    echo "   ✓ Namespace mcp-sandboxes exists"
else
    echo "   ✗ Namespace mcp-sandboxes not found"
    exit 1
fi

# Check RBAC
echo ""
echo "4. Verifying RBAC permissions..."
if kubectl auth can-i create pods -n mcp-sandboxes --as=system:serviceaccount:ethpandaops-mcp:ethpandaops-mcp 2>/dev/null | grep -q "yes"; then
    echo "   ✓ Service account can create pods in sandbox namespace"
else
    echo "   ✗ RBAC permissions not configured correctly"
    exit 1
fi

# Check for sandbox pods
echo ""
echo "5. Checking for active sandbox pods..."
SANDBOX_PODS=$(kubectl get pods -n mcp-sandboxes -l app.kubernetes.io/managed-by=ethpandaops-mcp --no-headers 2>/dev/null | wc -l | tr -d ' ')
echo "   Active sandbox pods: ${SANDBOX_PODS}"

echo ""
echo "============================================================"
echo "All checks passed!"
echo "============================================================"
echo ""
echo "The Kubernetes sandbox backend is configured and ready."
echo ""
echo "To test code execution with an MCP client:"
echo "  cd tests/eval"
echo "  MCP_URL=${MCP_URL} uv run python -m scripts.repl"
echo ""
echo "Or configure Claude Code to connect to: ${MCP_URL}"
