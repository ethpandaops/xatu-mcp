// Package oauth provides OAuth 2.1 authorization server functionality.
package oauth

import (
	"fmt"
	"strings"
)

// ProtectedResourceMetadata represents OAuth 2.0 Protected Resource Metadata (RFC 9728).
// This metadata document advertises the authorization servers that can be used
// to access this protected resource.
type ProtectedResourceMetadata struct {
	// Resource is the canonical URI of the protected resource.
	Resource string `json:"resource"`

	// AuthorizationServers contains the issuer URLs of authorization servers
	// that can issue tokens for this resource.
	AuthorizationServers []string `json:"authorization_servers"`

	// BearerMethodsSupported indicates how bearer tokens are transmitted.
	BearerMethodsSupported []string `json:"bearer_methods_supported"`

	// ScopesSupported lists the scopes available at this resource.
	ScopesSupported []string `json:"scopes_supported"`

	// ResourceDocumentation is an optional URL to documentation.
	ResourceDocumentation string `json:"resource_documentation,omitempty"`
}

// AuthorizationServerMetadata represents OAuth 2.0 Authorization Server Metadata (RFC 8414).
// Advertises the authorization server's capabilities and endpoints.
type AuthorizationServerMetadata struct {
	// Issuer is the authorization server's issuer identifier URL.
	Issuer string `json:"issuer"`

	// AuthorizationEndpoint is the URL of the authorization endpoint.
	AuthorizationEndpoint string `json:"authorization_endpoint"`

	// TokenEndpoint is the URL of the token endpoint.
	TokenEndpoint string `json:"token_endpoint"`

	// ResponseTypesSupported lists the OAuth response types supported.
	ResponseTypesSupported []string `json:"response_types_supported"`

	// GrantTypesSupported lists the OAuth grant types supported.
	GrantTypesSupported []string `json:"grant_types_supported"`

	// CodeChallengeMethodsSupported lists the PKCE code challenge methods.
	CodeChallengeMethodsSupported []string `json:"code_challenge_methods_supported"`

	// TokenEndpointAuthMethodsSupported lists the authentication methods.
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`

	// ScopesSupported lists the available scopes.
	ScopesSupported []string `json:"scopes_supported"`

	// RevocationEndpoint is the URL of the token revocation endpoint.
	RevocationEndpoint string `json:"revocation_endpoint,omitempty"`

	// UserinfoEndpoint is the URL of the userinfo endpoint.
	UserinfoEndpoint string `json:"userinfo_endpoint,omitempty"`

	// ClientIDMetadataDocumentSupported indicates MCP client metadata support.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported"`
}

// DefaultScopes returns the default scopes for the authorization server.
func DefaultScopes() []string {
	return []string{
		"execute_python",
		"get_output_file",
		"read_resources",
	}
}

// NewProtectedResourceMetadata creates protected resource metadata for the MCP server.
func NewProtectedResourceMetadata(baseURL string) *ProtectedResourceMetadata {
	resource := strings.TrimSuffix(baseURL, "/")

	return &ProtectedResourceMetadata{
		Resource:               resource,
		AuthorizationServers:   []string{resource}, // We are our own authorization server.
		BearerMethodsSupported: []string{"header"},
		ScopesSupported:        DefaultScopes(),
		ResourceDocumentation:  fmt.Sprintf("%s/docs", resource),
	}
}

// NewAuthorizationServerMetadata creates authorization server metadata.
func NewAuthorizationServerMetadata(baseURL string) *AuthorizationServerMetadata {
	issuer := strings.TrimSuffix(baseURL, "/")

	return &AuthorizationServerMetadata{
		Issuer:                            issuer,
		AuthorizationEndpoint:             fmt.Sprintf("%s/auth/authorize", issuer),
		TokenEndpoint:                     fmt.Sprintf("%s/auth/token", issuer),
		RevocationEndpoint:                fmt.Sprintf("%s/auth/revoke", issuer),
		UserinfoEndpoint:                  fmt.Sprintf("%s/auth/userinfo", issuer),
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		TokenEndpointAuthMethodsSupported: []string{"none"}, // Public clients.
		ScopesSupported:                   DefaultScopes(),
		ClientIDMetadataDocumentSupported: true,
	}
}

// FormatWWWAuthenticate formats the WWW-Authenticate header for 401/403 responses.
// Per RFC 9728 and RFC 6750, the WWW-Authenticate header should include
// the resource metadata URL and optionally scope/error info.
func FormatWWWAuthenticate(resourceMetadataURL, scope, oauthError, errorDescription string) string {
	var parts []string

	parts = append(parts, fmt.Sprintf(`Bearer resource_metadata="%s"`, resourceMetadataURL))

	if scope != "" {
		parts = append(parts, fmt.Sprintf(`scope="%s"`, scope))
	}

	if oauthError != "" {
		parts = append(parts, fmt.Sprintf(`error="%s"`, oauthError))
	}

	if errorDescription != "" {
		// Escape quotes in description.
		safeDesc := strings.ReplaceAll(errorDescription, `"`, `\"`)
		parts = append(parts, fmt.Sprintf(`error_description="%s"`, safeDesc))
	}

	return strings.Join(parts, ", ")
}
