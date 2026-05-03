package fingerprint

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// Detector performs technology stack detection on HTTP responses.
// It is safe for concurrent use; all state is read-only after construction.
type Detector struct {
	rules []rule
}

// NewDetector creates a Detector with the default built-in rules.
func NewDetector() *Detector {
	return &Detector{rules: defaultRules}
}

// maxFingerprintBodySize is the maximum number of body bytes inspected for
// technology pattern matching. Technology signatures (meta tags, generator
// comments, etc.) typically appear in the first few kilobytes. Limiting the
// scan avoids CPU spikes on large response bodies.
const maxFingerprintBodySize = 64 * 1024 // 64KB

// Analyze inspects the given HTTP response headers and body to detect
// technologies. The body parameter should contain the response body content
// (or a prefix thereof — full body is not required).
// Both headers and body may be nil/empty.
func (d *Detector) Analyze(headers parser.RawHeaders, body []byte) *Result {
	seen := make(map[string]Detection) // key = "name|category" for dedup
	// Truncate body for pattern matching to avoid CPU spikes on large bodies.
	// Technology signatures typically appear early in the response.
	bodyForMatch := body
	if len(bodyForMatch) > maxFingerprintBodySize {
		bodyForMatch = bodyForMatch[:maxFingerprintBodySize]
	}
	bodyStr := string(bodyForMatch)
	cookieNames := extractCookieNames(headers)

	for _, r := range d.rules {
		switch r.target {
		case targetHeader:
			values := headers.Values(r.header)
			for _, v := range values {
				if m := r.pattern.FindStringSubmatch(v); m != nil {
					addDetection(seen, r, versionFromMatch(m))
				}
			}
		case targetCookieName:
			for _, cn := range cookieNames {
				if m := r.pattern.FindStringSubmatch(cn); m != nil {
					addDetection(seen, r, versionFromMatch(m))
				}
			}
		case targetBody:
			if len(bodyStr) > 0 {
				if m := r.pattern.FindStringSubmatch(bodyStr); m != nil {
					addDetection(seen, r, versionFromMatch(m))
				}
			}
		}
	}

	result := &Result{Detections: make([]Detection, 0, len(seen))}
	for _, det := range seen {
		result.Detections = append(result.Detections, det)
	}
	return result
}

// addDetection adds or updates a detection in the seen map.
// If the same name+category already exists, the higher-confidence entry wins.
// If confidence is equal, the entry with a version string wins.
func addDetection(seen map[string]Detection, r rule, version string) {
	key := r.name + "|" + string(r.category)
	existing, ok := seen[key]
	if !ok {
		seen[key] = Detection{
			Name:       r.name,
			Version:    version,
			Category:   r.category,
			Confidence: r.confidence,
		}
		return
	}
	// Prefer higher confidence; at equal confidence prefer version info.
	newRank := confidenceRank(r.confidence)
	existingRank := confidenceRank(existing.Confidence)
	if newRank > existingRank {
		seen[key] = Detection{
			Name:       r.name,
			Version:    version,
			Category:   r.category,
			Confidence: r.confidence,
		}
	} else if newRank == existingRank && existing.Version == "" && version != "" {
		seen[key] = Detection{
			Name:       r.name,
			Version:    version,
			Category:   r.category,
			Confidence: r.confidence,
		}
	} else if newRank < existingRank && existing.Version == "" && version != "" {
		// Lower confidence has version info — copy version only, keep high confidence.
		existing.Version = version
		seen[key] = existing
	}
}

// confidenceRank returns a numeric rank for confidence comparison.
func confidenceRank(c string) int {
	switch c {
	case "high":
		return 3
	case "medium":
		return 2
	case "low":
		return 1
	default:
		return 0
	}
}

// versionFromMatch extracts the version string from a regexp submatch.
// Returns empty string if no version capture group matched.
func versionFromMatch(m []string) string {
	if len(m) > 1 && m[1] != "" {
		return m[1]
	}
	return ""
}

// extractCookieNames parses Set-Cookie headers and returns cookie names.
func extractCookieNames(headers parser.RawHeaders) []string {
	values := headers.Values("Set-Cookie")
	if len(values) == 0 {
		return nil
	}
	names := make([]string, 0, len(values))
	for _, v := range values {
		// Cookie name is everything before the first '='.
		if idx := strings.IndexByte(v, '='); idx > 0 {
			names = append(names, strings.TrimSpace(v[:idx]))
		}
	}
	return names
}
