package main

// Build-time version information.
// These variables are set via -ldflags at build time:
//
//	go build -ldflags "-X main.version=v1.0.0 -X main.commit=abc1234 -X main.date=2026-01-01T00:00:00Z"
var (
	// version is the release version tag (e.g., "v1.0.0").
	// Defaults to "dev" when not set by ldflags.
	version = "dev"

	// commit is the abbreviated git commit hash of the build.
	// Defaults to "unknown" when not set by ldflags.
	commit = "unknown"

	// date is the build timestamp in RFC 3339 format.
	// Defaults to "unknown" when not set by ldflags.
	date = "unknown"
)

// buildVersion returns a formatted version string suitable for display.
// For release builds it returns "v1.0.0 (abc1234 2026-01-01T00:00:00Z)".
// For development builds it returns "dev".
func buildVersion() string {
	if version == "dev" {
		return version
	}
	return version + " (" + commit + " " + date + ")"
}
