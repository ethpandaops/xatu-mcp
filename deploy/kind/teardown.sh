#!/bin/bash
# Teardown script for KIND cluster
set -euo pipefail

CLUSTER_NAME="${CLUSTER_NAME:-mcp-test}"

echo "==> Tearing down KIND cluster: ${CLUSTER_NAME}"

if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    kind delete cluster --name "${CLUSTER_NAME}"
    echo "    Cluster deleted"
else
    echo "    Cluster ${CLUSTER_NAME} does not exist"
fi

echo "==> Teardown complete"
