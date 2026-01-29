#!/bin/bash
# Setup script for KIND-based Kubernetes testing
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
CLUSTER_NAME="${CLUSTER_NAME:-mcp-test}"

echo "==> Setting up KIND cluster for MCP testing"

# Check prerequisites
command -v kind >/dev/null 2>&1 || { echo "Error: kind is not installed"; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo "Error: kubectl is not installed"; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "Error: docker is not installed"; exit 1; }

# Check if cluster already exists
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "==> Cluster ${CLUSTER_NAME} already exists, using existing cluster"
else
    echo "==> Creating KIND cluster: ${CLUSTER_NAME}"
    kind create cluster --config "${SCRIPT_DIR}/kind-config.yaml" --name "${CLUSTER_NAME}"
fi

# Set kubectl context
kubectl cluster-info --context "kind-${CLUSTER_NAME}"

echo "==> Building Docker images"
cd "${PROJECT_ROOT}"

# Build MCP server image
echo "    Building ethpandaops-mcp:test"
docker build -t ethpandaops-mcp:test -f Dockerfile .

# Build sandbox image
echo "    Building ethpandaops-mcp-sandbox:test"
docker build -t ethpandaops-mcp-sandbox:test -f sandbox/Dockerfile .

echo "==> Loading images into KIND cluster"
kind load docker-image ethpandaops-mcp:test --name "${CLUSTER_NAME}"
kind load docker-image ethpandaops-mcp-sandbox:test --name "${CLUSTER_NAME}"

echo "==> Applying Kubernetes manifests"
kubectl apply -k "${SCRIPT_DIR}"

echo "==> Waiting for MCP server to be ready"
kubectl wait --for=condition=available --timeout=120s deployment/ethpandaops-mcp -n ethpandaops-mcp

echo ""
echo "==> Setup complete!"
echo ""
echo "MCP server is available at: http://localhost:30000"
echo ""
echo "Useful commands:"
echo "  kubectl logs -n ethpandaops-mcp -l app.kubernetes.io/name=ethpandaops-mcp -f"
echo "  kubectl get pods -n mcp-sandboxes"
echo "  kind delete cluster --name ${CLUSTER_NAME}"
