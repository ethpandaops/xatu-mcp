// Package middleware provides authentication middleware for HTTP handlers.
package middleware

import (
	"net/http"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/ethpandaops/xatu-mcp/pkg/auth/oauth"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/session"
	"github.com/ethpandaops/xatu-mcp/pkg/auth/token"
	"github.com/ethpandaops/xatu-mcp/pkg/config"
)

// Middleware provides HTTP authentication middleware.
type Middleware struct {
	log                 logrus.FieldLogger
	enabled             bool
	store               session.Store
	tokenService        token.Service
	baseURL             string
	resourceMetadataURL string
}

// NewMiddleware creates a new authentication middleware.
func NewMiddleware(
	log logrus.FieldLogger,
	cfg config.AuthConfig,
	store session.Store,
	tokenService token.Service,
	baseURL string,
) *Middleware {
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &Middleware{
		log:                 log.WithField("component", "auth_middleware"),
		enabled:             cfg.Enabled,
		store:               store,
		tokenService:        tokenService,
		baseURL:             baseURL,
		resourceMetadataURL: baseURL + "/.well-known/oauth-protected-resource",
	}
}

// publicPaths are paths that don't require authentication.
var publicPaths = map[string]bool{
	"/":                                     true,
	"/health":                               true,
	"/ready":                                true,
	"/.well-known/oauth-protected-resource": true,
	"/.well-known/oauth-authorization-server": true,
	"/.well-known/openid-configuration":       true,
	"/auth/authorize":                         true,
	"/auth/github/callback":                   true,
	"/auth/token":                             true,
	"/auth/revoke":                            true,
	"/auth/login":                             true,
}

// publicPrefixes are path prefixes that don't require authentication.
var publicPrefixes = []string{
	"/auth/",
	"/.well-known/",
}

// isPublicPath checks if the path is public (doesn't require auth).
func (m *Middleware) isPublicPath(path string) bool {
	if publicPaths[path] {
		return true
	}

	for _, prefix := range publicPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}

	return false
}

// Handler returns the middleware handler function.
func (m *Middleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Skip auth for public paths.
		if m.isPublicPath(r.URL.Path) {
			next.ServeHTTP(w, r)

			return
		}

		// Skip auth if disabled.
		if !m.enabled {
			next.ServeHTTP(w, r)

			return
		}

		// Get Authorization header.
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			m.writeUnauthorized(w, "Missing Authorization header")

			return
		}

		if !strings.HasPrefix(authHeader, "Bearer ") {
			m.writeUnauthorized(w, "Authorization header must use Bearer scheme")

			return
		}

		tokenStr := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenStr == "" {
			m.writeUnauthorized(w, "Empty Bearer token")

			return
		}

		// Validate token.
		claims, err := m.tokenService.ValidateToken(r.Context(), tokenStr, m.baseURL, token.TokenTypeAccess)
		if err != nil {
			m.log.WithError(err).Debug("Token validation failed")
			m.writeUnauthorized(w, m.getErrorDescription(err))

			return
		}

		// Validate session.
		sess, err := m.store.GetSessionByAccessJTI(r.Context(), claims.ID)
		if err != nil {
			m.log.WithError(err).Debug("Session not found")
			m.writeUnauthorized(w, "Session not found")

			return
		}

		if !sess.IsValid() {
			m.writeUnauthorized(w, "Session has been revoked or expired")

			return
		}

		// Get user.
		user, err := m.store.GetUser(r.Context(), claims.Subject)
		if err != nil {
			m.log.WithError(err).Debug("User not found")
			m.writeUnauthorized(w, "User not found")

			return
		}

		// Create authenticated user context.
		scopes := claims.Scopes()

		authUser := &AuthUser{
			User:    user,
			Session: sess,
			Claims:  claims,
			Scopes:  scopes,
		}

		// Attach to request context.
		ctx := WithAuthUser(r.Context(), authUser)

		m.log.WithFields(logrus.Fields{
			"user_id":      user.ID,
			"github_login": user.GitHubLogin,
			"scopes":       scopes,
			"path":         r.URL.Path,
		}).Debug("Request authenticated")

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// getErrorDescription converts an error to a user-friendly description.
func (m *Middleware) getErrorDescription(err error) string {
	errMsg := err.Error()

	switch {
	case strings.Contains(errMsg, "expired"):
		return "Token has expired"
	case strings.Contains(errMsg, "audience"):
		return "Token audience mismatch"
	case strings.Contains(errMsg, "type mismatch"):
		return "Invalid token type"
	default:
		return "Invalid token"
	}
}

// writeUnauthorized writes an unauthorized response with proper headers.
func (m *Middleware) writeUnauthorized(w http.ResponseWriter, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", oauth.FormatWWWAuthenticate(
		m.resourceMetadataURL,
		"",
		"invalid_token",
		description,
	))
	w.WriteHeader(http.StatusUnauthorized)

	// Write JSON error response.
	_, _ = w.Write([]byte(`{"error":"invalid_token","error_description":"` + description + `"}`))
}

// RequireScope creates a middleware that requires a specific scope.
func RequireScopeMiddleware(scope string, resourceMetadataURL string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			authUser := GetAuthUser(r.Context())
			if authUser == nil {
				writeUnauthorizedResponse(w, resourceMetadataURL, "Authentication required")

				return
			}

			if !authUser.HasScope(scope) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+scope+`"`)
				w.WriteHeader(http.StatusForbidden)

				_, _ = w.Write([]byte(`{"error":"insufficient_scope","error_description":"Required scope: ` + scope + `"}`))

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeUnauthorizedResponse(w http.ResponseWriter, resourceMetadataURL, description string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", oauth.FormatWWWAuthenticate(
		resourceMetadataURL,
		"",
		"invalid_token",
		description,
	))
	w.WriteHeader(http.StatusUnauthorized)

	_, _ = w.Write([]byte(`{"error":"unauthorized","error_description":"` + description + `"}`))
}
