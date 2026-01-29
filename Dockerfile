# ethpandaops MCP Server Dockerfile
#
# Build:
#   docker build -t mcp:latest .
#
# Run:
#   docker run -p 2480:2480 -v /var/run/docker.sock:/var/run/docker.sock mcp:latest

# =============================================================================
# Stage 1: Build libllama_go.so for ARM64 (skipped on amd64)
# =============================================================================
FROM debian:bookworm-slim AS llama-builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake g++ make curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Only build on ARM64 - on amd64 we'll download the prebuilt
RUN if [ "$TARGETARCH" = "arm64" ]; then \
    echo "Building libllama_go.so for ARM64..." && \
    git clone --depth 1 --recurse-submodules https://github.com/kelindar/search.git && \
    cd search && \
    mkdir build && cd build && \
    cmake -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release \
        -DGGML_NATIVE=OFF \
        -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc .. && \
    cmake --build . --config Release && \
    find /build/search -name "libllama_go.so" -exec cp {} /build/libllama_go.so \; ; \
    else \
    echo "Skipping build on amd64 - will download prebuilt"; \
    fi

# =============================================================================
# Stage 2: Go builder
# =============================================================================
FROM golang:1.25-bookworm AS builder

ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy go mod files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ cmd/
COPY pkg/ pkg/
COPY plugins/ plugins/
COPY internal/ internal/
COPY runbooks/ runbooks/

# Build with version info (CGO_ENABLED=0 works because kelindar/search uses purego)
ARG VERSION=dev
ARG GIT_COMMIT=unknown
ARG BUILD_TIME=unknown

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w -X github.com/ethpandaops/mcp/internal/version.Version=${VERSION} \
    -X github.com/ethpandaops/mcp/internal/version.GitCommit=${GIT_COMMIT} \
    -X github.com/ethpandaops/mcp/internal/version.BuildTime=${BUILD_TIME}" \
    -o mcp ./cmd/mcp

# Download embedding model (same for all architectures)
RUN mkdir -p /assets && \
    curl -L -o /assets/MiniLM-L6-v2.Q8_0.gguf \
        https://huggingface.co/second-state/All-MiniLM-L6-v2-Embedding-GGUF/resolve/main/all-MiniLM-L6-v2-Q8_0.gguf

# Download prebuilt libllama_go.so for amd64, or copy from llama-builder for arm64
COPY --from=llama-builder /build/libllama_go.so* /tmp/
RUN if [ "$TARGETARCH" = "amd64" ]; then \
    echo "Downloading prebuilt libllama_go.so for amd64..." && \
    curl -L -o /assets/libllama_go.so \
        https://media.githubusercontent.com/media/kelindar/search/main/dist/linux-x64-avx/libllama_go.so; \
    else \
    echo "Using ARM64-built libllama_go.so..." && \
    cp /tmp/libllama_go.so /assets/libllama_go.so; \
    fi

# =============================================================================
# Stage 3: Runtime
# =============================================================================
FROM debian:bookworm-slim

# Install runtime dependencies for Docker access, health checks, and llama.cpp
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates docker.io netcat-openbsd libgomp1 && \
    rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -s /bin/bash mcp && \
    usermod -aG docker mcp 2>/dev/null || true

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/mcp /usr/local/bin/mcp

# Copy embedding model and llama.cpp shared library
COPY --from=builder /assets/MiniLM-L6-v2.Q8_0.gguf /usr/share/mcp/
COPY --from=builder /assets/libllama_go.so /lib/

# Create directories
RUN mkdir -p /config /shared /output && \
    chown -R mcp:mcp /app /config /shared /output

# Expose ports
EXPOSE 2480 2490

# Health check - verify the MCP server port is accepting connections
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD nc -z localhost 2480 || exit 1

# Default command - start with streamable-http transport
ENTRYPOINT ["mcp"]
CMD ["serve", "--transport", "streamable-http"]
