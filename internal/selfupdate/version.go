// Package selfupdate provides self-update functionality for the yorishiro-proxy binary.
// It fetches the latest release from GitHub, compares versions, downloads the
// appropriate binary, verifies its checksum, and atomically replaces the running binary.
package selfupdate

import (
	"fmt"
	"strconv"
	"strings"
)

// semver represents a parsed semantic version (major.minor.patch with optional prerelease).
type semver struct {
	Major      int
	Minor      int
	Patch      int
	Prerelease string
}

// parseSemver parses a version string like "v1.2.3" or "v1.2.3-rc.1" into a semver.
// The leading "v" prefix is optional.
func parseSemver(s string) (semver, error) {
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return semver{}, fmt.Errorf("empty version string")
	}

	// Split off prerelease suffix.
	var pre string
	if idx := strings.IndexByte(s, '-'); idx >= 0 {
		pre = s[idx+1:]
		s = s[:idx]
	}

	parts := strings.Split(s, ".")
	if len(parts) != 3 {
		return semver{}, fmt.Errorf("invalid semver %q: expected major.minor.patch", s)
	}

	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return semver{}, fmt.Errorf("invalid major version %q: %w", parts[0], err)
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return semver{}, fmt.Errorf("invalid minor version %q: %w", parts[1], err)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		return semver{}, fmt.Errorf("invalid patch version %q: %w", parts[2], err)
	}

	return semver{
		Major:      major,
		Minor:      minor,
		Patch:      patch,
		Prerelease: pre,
	}, nil
}

// String returns the version in "major.minor.patch[-prerelease]" format (without "v" prefix).
func (v semver) String() string {
	s := fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
	if v.Prerelease != "" {
		s += "-" + v.Prerelease
	}
	return s
}

// compareSemver returns:
//
//	-1 if a < b
//	 0 if a == b
//	+1 if a > b
//
// Prerelease versions have lower precedence than their release counterparts
// (e.g. 1.0.0-rc.1 < 1.0.0). When both have prerelease identifiers, they
// are compared lexicographically.
func compareSemver(a, b semver) int {
	if a.Major != b.Major {
		return cmpInt(a.Major, b.Major)
	}
	if a.Minor != b.Minor {
		return cmpInt(a.Minor, b.Minor)
	}
	if a.Patch != b.Patch {
		return cmpInt(a.Patch, b.Patch)
	}

	// No prerelease on both means equal.
	if a.Prerelease == "" && b.Prerelease == "" {
		return 0
	}
	// A version without prerelease has higher precedence.
	if a.Prerelease == "" {
		return 1
	}
	if b.Prerelease == "" {
		return -1
	}
	// Both have prerelease: compare lexicographically.
	return strings.Compare(a.Prerelease, b.Prerelease)
}

// IsNewerThan returns true if the latest version string is newer than the current one.
// Both are expected in "vX.Y.Z" or "vX.Y.Z-pre" format.
// Returns false and nil error if current is "dev" (development builds always allow upgrade check
// but the caller should handle "dev" specially).
func IsNewerThan(latest, current string) (bool, error) {
	if current == "dev" {
		// Development builds: treat any release as newer.
		_, err := parseSemver(latest)
		if err != nil {
			return false, fmt.Errorf("parse latest version: %w", err)
		}
		return true, nil
	}

	latestV, err := parseSemver(latest)
	if err != nil {
		return false, fmt.Errorf("parse latest version: %w", err)
	}
	currentV, err := parseSemver(current)
	if err != nil {
		return false, fmt.Errorf("parse current version: %w", err)
	}

	return compareSemver(latestV, currentV) > 0, nil
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	return 1
}
