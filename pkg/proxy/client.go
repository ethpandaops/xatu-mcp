package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/mcp/pkg/auth/client"
	"github.com/ethpandaops/mcp/pkg/auth/store"
)

// Client connects to a proxy server and provides:
// - Datasource discovery from /datasources
// - Token/JWT management for sandbox authentication
// - Sandbox environment variable building
type Client interface {
	// Start starts the client and performs initial discovery.
	Start(ctx context.Context) error

	// Stop stops the client.
	Stop(ctx context.Context) error

	// URL returns the proxy URL for sandbox containers.
	URL() string

	// RegisterToken creates a new auth token for a sandbox execution.
	// For JWT-based auth, returns the user's JWT.
	// For token-based auth, this would require coordination with an embedded proxy (not supported by Client).
	RegisterToken(executionID string) string

	// RevokeToken revokes a token for an execution.
	// No-op for JWT-based auth where tokens expire naturally.
	RevokeToken(executionID string)

	// ClickHouseDatasources returns the discovered ClickHouse datasource names.
	ClickHouseDatasources() []string

	// PrometheusDatasources returns the discovered Prometheus datasource names.
	PrometheusDatasources() []string

	// LokiDatasources returns the discovered Loki datasource names.
	LokiDatasources() []string

	// S3Bucket returns the discovered S3 bucket name.
	S3Bucket() string

	// S3PublicURLPrefix returns the discovered S3 public URL prefix.
	S3PublicURLPrefix() string

	// Discover fetches datasource information from the proxy.
	Discover(ctx context.Context) error

	// EnsureAuthenticated checks if the user has valid credentials.
	EnsureAuthenticated(ctx context.Context) error
}

// ClientConfig configures the proxy client.
type ClientConfig struct {
	// URL is the base URL of the proxy server (e.g., http://localhost:18081).
	URL string

	// IssuerURL is the OIDC issuer URL for authentication.
	// If empty, the client will not use JWT authentication.
	IssuerURL string

	// ClientID is the OAuth client ID for authentication.
	ClientID string

	// DiscoveryInterval is how often to refresh datasource info (default: 5 minutes).
	// Set to 0 to disable background refresh.
	DiscoveryInterval time.Duration

	// HTTPTimeout is the timeout for HTTP requests (default: 30 seconds).
	HTTPTimeout time.Duration
}

// ApplyDefaults sets default values for the client config.
func (c *ClientConfig) ApplyDefaults() {
	if c.DiscoveryInterval == 0 {
		c.DiscoveryInterval = 5 * time.Minute
	}

	if c.HTTPTimeout == 0 {
		c.HTTPTimeout = 30 * time.Second
	}
}

// proxyClient implements Client for connecting to a proxy server.
type proxyClient struct {
	log        logrus.FieldLogger
	cfg        ClientConfig
	httpClient *http.Client
	authClient client.Client
	credStore  store.Store

	mu          sync.RWMutex
	datasources *DatasourcesResponse
	stopCh      chan struct{}
	stopped     bool
}

// Compile-time interface checks.
var (
	_ Client  = (*proxyClient)(nil)
	_ Service = (*proxyClient)(nil) // Client also implements Service for compatibility
)

// NewClient creates a new proxy client.
func NewClient(log logrus.FieldLogger, cfg ClientConfig) Client {
	cfg.ApplyDefaults()

	c := &proxyClient{
		log: log.WithField("component", "proxy-client"),
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: cfg.HTTPTimeout,
		},
		datasources: &DatasourcesResponse{},
		stopCh:      make(chan struct{}),
	}

	// Set up auth client and credential store if OIDC is configured.
	if cfg.IssuerURL != "" && cfg.ClientID != "" {
		c.authClient = client.New(log, client.Config{
			IssuerURL: cfg.IssuerURL,
			ClientID:  cfg.ClientID,
		})

		c.credStore = store.New(log, store.Config{
			AuthClient: c.authClient,
		})
	}

	return c
}

// Start starts the client and performs initial discovery.
func (c *proxyClient) Start(ctx context.Context) error {
	c.log.WithField("url", c.cfg.URL).Info("Starting proxy client")

	// Perform initial discovery.
	if err := c.Discover(ctx); err != nil {
		return fmt.Errorf("initial discovery failed: %w", err)
	}

	// Start background refresh if configured.
	if c.cfg.DiscoveryInterval > 0 {
		go c.backgroundRefresh()
	}

	return nil
}

// Stop stops the client.
func (c *proxyClient) Stop(_ context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.stopped {
		return nil
	}

	c.stopped = true
	close(c.stopCh)

	c.log.Info("Proxy client stopped")

	return nil
}

// URL returns the proxy URL.
func (c *proxyClient) URL() string {
	return c.cfg.URL
}

// RegisterToken returns the user's JWT for authentication.
// For Client-based architecture, the proxy uses JWT auth not per-execution tokens.
// When no auth is configured (local dev mode), returns a placeholder token.
func (c *proxyClient) RegisterToken(_ string) string {
	if c.credStore == nil {
		// No auth configured - return placeholder for proxy with auth.mode=none.
		return "none"
	}

	token, err := c.credStore.GetAccessToken()
	if err != nil {
		c.log.WithError(err).Error("Failed to get access token from credential store")

		return ""
	}

	return token
}

// RevokeToken is a no-op for JWT-based auth - JWTs expire naturally.
func (c *proxyClient) RevokeToken(_ string) {
	// No-op: JWTs are managed by the OIDC provider, not revoked per-execution
}

// ClickHouseDatasources returns the discovered ClickHouse datasource names.
func (c *proxyClient) ClickHouseDatasources() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.datasources.ClickHouse
}

// PrometheusDatasources returns the discovered Prometheus datasource names.
func (c *proxyClient) PrometheusDatasources() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.datasources.Prometheus
}

// LokiDatasources returns the discovered Loki datasource names.
func (c *proxyClient) LokiDatasources() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.datasources.Loki
}

// S3Bucket returns the discovered S3 bucket name.
func (c *proxyClient) S3Bucket() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.datasources.S3Bucket
}

// S3PublicURLPrefix returns the discovered S3 public URL prefix.
func (c *proxyClient) S3PublicURLPrefix() string {
	c.mu.RLock()
	defer c.mu.RUnlock()

	return c.datasources.S3PublicURLPrefix
}

// Discover fetches datasource information from the proxy's /datasources endpoint.
func (c *proxyClient) Discover(ctx context.Context) error {
	url := fmt.Sprintf("%s/datasources", c.cfg.URL)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("fetching datasources: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)

		return fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var datasources DatasourcesResponse
	if err := json.NewDecoder(resp.Body).Decode(&datasources); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}

	c.mu.Lock()
	c.datasources = &datasources
	c.mu.Unlock()

	c.log.WithFields(logrus.Fields{
		"clickhouse": len(datasources.ClickHouse),
		"prometheus": len(datasources.Prometheus),
		"loki":       len(datasources.Loki),
		"s3_bucket":  datasources.S3Bucket,
	}).Debug("Discovered datasources from proxy")

	return nil
}

// EnsureAuthenticated checks if the user has valid credentials.
func (c *proxyClient) EnsureAuthenticated(_ context.Context) error {
	if c.credStore == nil {
		// No auth required (e.g., local dev mode).
		return nil
	}

	if c.credStore.IsAuthenticated() {
		return nil
	}

	return fmt.Errorf(
		"not authenticated to proxy. Run 'mcp auth login --issuer %s --client-id %s' first",
		c.cfg.IssuerURL,
		c.cfg.ClientID,
	)
}

// backgroundRefresh periodically refreshes datasource information.
func (c *proxyClient) backgroundRefresh() {
	ticker := time.NewTicker(c.cfg.DiscoveryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-c.stopCh:
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(context.Background(), c.cfg.HTTPTimeout)

			if err := c.Discover(ctx); err != nil {
				c.log.WithError(err).Warn("Background datasource refresh failed")
			}

			cancel()
		}
	}
}
