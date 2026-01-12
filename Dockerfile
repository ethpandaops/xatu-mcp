# Xatu MCP Server Dockerfile
#
# Build:
#   docker build -t xatu-mcp:latest .
#
# Run:
#   docker run -p 2480:2480 -v /var/run/docker.sock:/var/run/docker.sock xatu-mcp:latest

# Build stage
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY internal/ internal/

# Build with version info
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/ethpandaops/xatu-mcp/internal/version.Version=${VERSION} \
    -X github.com/ethpandaops/xatu-mcp/internal/version.GitCommit=${GIT_COMMIT} \
    -X github.com/ethpandaops/xatu-mcp/internal/version.BuildTime=${BUILD_TIME}" \
    -o xatu-mcp ./cmd/xatu-mcp

# Runtime stage
FROM alpine:3.19

# Install runtime dependencies for Docker access and health checks
RUN apk add --no-cache ca-certificates docker-cli netcat-openbsd

# Create non-root user
RUN adduser -D -s /bin/sh xatu && \
    addgroup xatu docker 2>/dev/null || true

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/xatu-mcp /usr/local/bin/xatu-mcp

# Create directories
RUN mkdir -p /config /shared /output && \
    chown -R xatu:xatu /app /config /shared /output

# Expose ports
EXPOSE 2480 2490

# Health check - verify the MCP server port is accepting connections
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 2480 || exit 1

# Default command - start with SSE transport
ENTRYPOINT ["xatu-mcp"]
CMD ["serve", "--transport", "sse"]
