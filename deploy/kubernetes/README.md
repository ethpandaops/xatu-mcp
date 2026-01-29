# Kubernetes Deployment

This directory contains Kubernetes manifests for deploying ethpandaops-mcp with the Kubernetes sandbox backend.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        Ingress                              │
└───────────────────────────┬─────────────────────────────────┘
                            │
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌─────────┐         ┌─────────┐         ┌─────────┐
   │MCP Pod 1│         │MCP Pod 2│         │MCP Pod 3│   ◄── Stateless
   └────┬────┘         └────┬────┘         └────┬────┘
        │                   │                   │
        └───────────────────┼───────────────────┘
                            │ K8s API
                            ▼
              ┌──────────────────────────┐
              │     Kubernetes API       │  ◄── State lives here
              │  (etcd-backed, HA)       │
              └──────────────────────────┘
                            │
                            ▼
        ┌───────────────────┼───────────────────┐
        ▼                   ▼                   ▼
   ┌──────────┐        ┌──────────┐        ┌──────────┐
   │ Sandbox  │        │ Sandbox  │        │ Sandbox  │
   │  Pod A   │        │  Pod B   │        │  Pod C   │
   └──────────┘        └──────────┘        └──────────┘
         └─── mcp-sandboxes namespace ───┘
```

## Prerequisites

- Kubernetes 1.25+
- kubectl configured
- (Optional) Prometheus Operator for monitoring
- (Optional) gVisor for enhanced sandbox isolation

## Quick Start

1. **Create the secret** (copy and edit with real values):
   ```bash
   cp secret.yaml.example secret.yaml
   # Edit secret.yaml with your credentials
   kubectl apply -f secret.yaml
   ```

2. **Deploy using Kustomize**:
   ```bash
   kubectl apply -k .
   ```

3. **Verify deployment**:
   ```bash
   kubectl get pods -n ethpandaops-mcp
   kubectl get pods -n mcp-sandboxes
   ```

## Manifests

| File | Description |
|------|-------------|
| `namespace.yaml` | Creates `ethpandaops-mcp` and `mcp-sandboxes` namespaces |
| `rbac.yaml` | ServiceAccount, Role, and RoleBinding for sandbox management |
| `networkpolicy.yaml` | Network isolation for sandbox pods |
| `resourcequota.yaml` | Resource limits for sandbox namespace |
| `configmap.yaml` | MCP server configuration |
| `deployment.yaml` | MCP server deployment with PodDisruptionBudget |
| `service.yaml` | Service and Ingress definitions |
| `hpa.yaml` | HorizontalPodAutoscaler for automatic scaling |
| `monitoring.yaml` | ServiceMonitor and PrometheusRules (optional) |

## Security

### Pod Security Standards

The `mcp-sandboxes` namespace enforces the `restricted` Pod Security Standard:
- Pods run as non-root
- Read-only root filesystem (except volumes)
- No privilege escalation
- Dropped capabilities

### Network Policies

Sandbox pods are isolated:
- **Ingress**: Only from MCP server pods (for exec)
- **Egress**: Only to DNS and datasources (HTTPS)

### RBAC

The MCP server has minimal permissions:
- Create/delete pods in `mcp-sandboxes` namespace
- Execute commands in sandbox pods
- Read pod logs

## Configuration

### Environment Variables

Set in `secret.yaml`:

| Variable | Description |
|----------|-------------|
| `CLICKHOUSE_*` | ClickHouse connection details |
| `PROMETHEUS_*` | Prometheus connection details |
| `LOKI_*` | Loki connection details |
| `S3_*` | S3 storage configuration |
| `GITHUB_*` | GitHub OAuth (optional) |

### Sandbox Configuration

In `configmap.yaml`:

```yaml
sandbox:
  backend: kubernetes
  image: "ghcr.io/ethpandaops/mcp-sandbox:latest"
  kubernetes:
    namespace: "mcp-sandboxes"
    runtime_class: "gvisor"  # Optional, for extra isolation
    labels:
      app.kubernetes.io/part-of: ethpandaops-mcp
```

## gVisor Integration

For enhanced isolation, use gVisor:

1. Install gVisor on nodes:
   ```bash
   # See https://gvisor.dev/docs/user_guide/install/
   ```

2. Create RuntimeClass:
   ```yaml
   apiVersion: node.k8s.io/v1
   kind: RuntimeClass
   metadata:
     name: gvisor
   handler: runsc
   ```

3. Enable in config:
   ```yaml
   sandbox:
     kubernetes:
       runtime_class: "gvisor"
   ```

## Scaling

The deployment scales automatically based on CPU/memory usage:
- Minimum: 3 replicas
- Maximum: 10 replicas
- Scale up: +2 pods/minute when >70% CPU
- Scale down: -1 pod/minute after 5min stabilization

## Monitoring

If using Prometheus Operator:

```bash
kubectl apply -f monitoring.yaml
```

Alerts:
- `MCPServerDown`: Server unreachable for >1 minute
- `MCPHighSessionCount`: >15 active sessions
- `MCPHighExecutionLatency`: p95 latency >30s
- `MCPExecutionErrors`: Error rate >0.1/s

## Troubleshooting

### Check MCP server logs
```bash
kubectl logs -n ethpandaops-mcp -l app.kubernetes.io/name=ethpandaops-mcp -f
```

### Check sandbox pods
```bash
kubectl get pods -n mcp-sandboxes -l app.kubernetes.io/managed-by=ethpandaops-mcp
```

### Debug sandbox pod
```bash
kubectl describe pod -n mcp-sandboxes <pod-name>
kubectl logs -n mcp-sandboxes <pod-name>
```

### Check RBAC
```bash
kubectl auth can-i create pods -n mcp-sandboxes --as=system:serviceaccount:ethpandaops-mcp:ethpandaops-mcp
```
