// Package oauth provides OAuth 2.1 authorization server functionality.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
)

// VerifyPKCE verifies a PKCE code verifier against a code challenge.
// Only supports S256 method as required by OAuth 2.1.
func VerifyPKCE(codeVerifier, codeChallenge, codeChallengeMethod string) bool {
	if codeChallengeMethod != "S256" {
		return false
	}

	// Generate expected challenge from verifier using S256.
	hash := sha256.Sum256([]byte(codeVerifier))
	expected := base64.RawURLEncoding.EncodeToString(hash[:])

	// Constant-time comparison to prevent timing attacks.
	return subtle.ConstantTimeCompare([]byte(expected), []byte(codeChallenge)) == 1
}

// GenerateCodeVerifier generates a cryptographically secure PKCE code verifier.
// Returns a base64url-encoded string suitable for use as a code verifier.
func GenerateCodeVerifier() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("generating random bytes: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// GenerateCodeChallenge generates a PKCE code challenge from a code verifier.
// Uses S256 method as required by OAuth 2.1.
func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))

	return base64.RawURLEncoding.EncodeToString(hash[:])
}
