// Package github provides GitHub OAuth integration.
package github

// GitHubUser represents a GitHub user profile.
type GitHubUser struct {
	// ID is the GitHub user ID.
	ID int64 `json:"id"`

	// Login is the GitHub username.
	Login string `json:"login"`

	// Name is the user's display name.
	Name string `json:"name,omitempty"`

	// Email is the user's email address.
	Email string `json:"email,omitempty"`

	// AvatarURL is the URL to the user's avatar.
	AvatarURL string `json:"avatar_url,omitempty"`

	// Organizations is a list of organization logins the user belongs to.
	Organizations []string `json:"organizations,omitempty"`
}

// IsMemberOf checks if the user is a member of any of the allowed organizations.
// If allowedOrgs is empty, returns true (no restriction).
func (u *GitHubUser) IsMemberOf(allowedOrgs []string) bool {
	if len(allowedOrgs) == 0 {
		return true
	}

	for _, userOrg := range u.Organizations {
		for _, allowedOrg := range allowedOrgs {
			if userOrg == allowedOrg {
				return true
			}
		}
	}

	return false
}

// TokenResponse represents GitHub's OAuth token response.
type TokenResponse struct {
	// AccessToken is the GitHub access token.
	AccessToken string `json:"access_token"`

	// TokenType is the type of token (usually "bearer").
	TokenType string `json:"token_type"`

	// Scope contains the granted scopes.
	Scope string `json:"scope"`

	// Error is set if the request failed.
	Error string `json:"error,omitempty"`

	// ErrorDescription provides details about the error.
	ErrorDescription string `json:"error_description,omitempty"`
}

// githubUserResponse is the response from GitHub's /user API.
type githubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

// githubOrgResponse is an item in the response from GitHub's /user/orgs API.
type githubOrgResponse struct {
	Login string `json:"login"`
}
