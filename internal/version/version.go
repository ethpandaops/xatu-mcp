// Package version provides build version information.
package version

// These variables are set at build time via ldflags.
var (
	// Version is the semantic version of the build.
	Version = "dev"

	// GitCommit is the git commit hash of the build.
	GitCommit = "unknown"

	// BuildTime is the time the build was created.
	BuildTime = "unknown"
)

// Full returns the full version string including commit and build time.
func Full() string {
	return Version + " (" + GitCommit + ") built at " + BuildTime
}
