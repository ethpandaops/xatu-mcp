.PHONY: build test lint clean docker docker-push docker-sandbox test-sandbox run help

# Build variables
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u '+%Y-%m-%d_%H:%M:%S')
LDFLAGS := -s -w \
	-X github.com/ethpandaops/xatu-mcp/internal/version.Version=$(VERSION) \
	-X github.com/ethpandaops/xatu-mcp/internal/version.GitCommit=$(GIT_COMMIT) \
	-X github.com/ethpandaops/xatu-mcp/internal/version.BuildTime=$(BUILD_TIME)

# Docker variables
DOCKER_IMAGE ?= ethpandaops/xatu-mcp
DOCKER_TAG ?= $(VERSION)

# Go variables
GOBIN ?= $(shell go env GOPATH)/bin

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	go build -ldflags "$(LDFLAGS)" -o xatu-mcp ./cmd/xatu-mcp

build-linux: ## Build for Linux (amd64)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o xatu-mcp-linux-amd64 ./cmd/xatu-mcp

test: ## Run tests
	go test -race -v ./...

test-coverage: ## Run tests with coverage
	go test -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html

lint: ## Run linters
	@which golangci-lint > /dev/null || (echo "Installing golangci-lint..." && go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest)
	golangci-lint run ./...

lint-fix: ## Run linters and fix issues
	golangci-lint run --fix ./...

fmt: ## Format code
	go fmt ./...
	gofmt -s -w .

vet: ## Run go vet
	go vet ./...

tidy: ## Run go mod tidy
	go mod tidy

clean: ## Clean build artifacts
	rm -f xatu-mcp xatu-mcp-linux-amd64
	rm -f coverage.out coverage.html

docker: ## Build Docker image
	docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.

docker-push: docker ## Push Docker image
	docker push $(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_IMAGE):latest

docker-sandbox: ## Build sandbox Docker image
	docker build -t xatu-mcp-sandbox:latest ./sandbox

test-sandbox: build docker-sandbox ## Test sandbox execution (requires .env)
	@if [ -f .env ]; then \
		set -a && . .env && set +a && ./xatu-mcp test; \
	else \
		echo "Error: .env file not found. Copy .env.example and configure it."; \
		exit 1; \
	fi

run: build ## Run the server with stdio transport
	./xatu-mcp serve

run-sse: build ## Run the server with SSE transport
	./xatu-mcp serve --transport sse --port 8080

run-docker: docker ## Run with docker-compose
	docker-compose up -d

stop-docker: ## Stop docker-compose services
	docker-compose down

logs: ## View docker-compose logs
	docker-compose logs -f mcp-server

install: build ## Install binary to GOBIN
	cp xatu-mcp $(GOBIN)/xatu-mcp

version: ## Show version info
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"
