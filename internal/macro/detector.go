package macro

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MaxUnresolvedScanBytes bounds the body region scanned by
// DetectUnresolvedTemplates to keep detector cost bounded for large bodies.
// URL and header values are scanned in full (size-bounded by HTTP practical
// limits and CRLF anti-injection rules elsewhere in the engine).
const MaxUnresolvedScanBytes = 64 << 10

// maxSamplesPerLocation caps how many distinct matched patterns are surfaced
// in a single warning message. The remainder is summarised as "...(N more)".
const maxSamplesPerLocation = 5

// Pre-compiled regexes for foreign-templating syntaxes that operators
// occasionally use instead of the supported §var§ form. Each pattern requires
// an identifier-shaped interior — `[A-Za-z_][A-Za-z0-9_]{0,63}` — so that
// false positives such as URL percent-encoding (`%20`), arithmetic-style
// expressions (`${1+2}`), and CSS / framework directives whose interior is
// not a bare identifier (e.g. `{{ foo.bar }}` with dots, `{{- spaced -}}`) do
// not trigger the warning.
//
// False-positive policy (see help_macro.md): bodies that legitimately ship
// literal `{{name}}` / `${name}` / `%name%` (Liquid uploads, Bash heredocs,
// Postgres pg_format etc.) WILL trigger a warning. This is the documented
// tradeoff — surfacing a spurious warning is preferred over silently
// shipping an unresolved variable on the wire.
var (
	reHandlebars = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}`)
	reDollar     = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}`)
	rePercent    = regexp.MustCompile(`%([A-Za-z_][A-Za-z0-9_]{0,63})%`)
)

// DetectUnresolvedTemplates scans the substituted SendRequest for residual
// templating tokens that look like they were meant to be expanded but were
// not (because they used `{{var}}` / `${var}` / `%var%` instead of `§var§`).
//
// It operates on the post-substitution bytes only, after buildRequest has
// already applied §...§ expansion. This avoids false-positives on operator-
// authored substitutions that legitimately want literal `{{...}}` on the wire.
//
// Scan surface:
//   - URL (full)
//   - Header values (full; names are NOT scanned)
//   - Body (first MaxUnresolvedScanBytes bytes)
//
// Method is short and shape-constrained so it is not scanned.
//
// Returns a slice of human-readable warning messages, one per scan location
// where at least one residual token was found. Each message lists up to
// maxSamplesPerLocation distinct matches. A nil/empty return means the
// substituted request is clean.
func DetectUnresolvedTemplates(req *SendRequest) []string {
	if req == nil {
		return nil
	}

	var warnings []string

	// URL scan (full).
	if msg := scanForResiduals(req.URL); msg != "" {
		warnings = append(warnings, fmt.Sprintf("url: %s", msg))
	}

	// Header value scan (full; names are not scanned).
	// Order headers by name so the warning order is deterministic across calls.
	if len(req.Headers) > 0 {
		names := make([]string, 0, len(req.Headers))
		for name := range req.Headers {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, v := range req.Headers[name] {
				if msg := scanForResiduals(v); msg != "" {
					warnings = append(warnings, fmt.Sprintf("header:%s: %s", name, msg))
				}
			}
		}
	}

	// Body scan (first MaxUnresolvedScanBytes bytes).
	if len(req.Body) > 0 {
		body := req.Body
		if len(body) > MaxUnresolvedScanBytes {
			body = body[:MaxUnresolvedScanBytes]
		}
		if msg := scanForResiduals(string(body)); msg != "" {
			warnings = append(warnings, fmt.Sprintf("body: %s", msg))
		}
	}

	return warnings
}

// scanForResiduals runs the three compiled patterns against s and returns
// a human-readable description of matches, or "" if no patterns matched.
// Distinct matches across patterns are deduplicated.
func scanForResiduals(s string) string {
	if s == "" {
		return ""
	}

	seen := make(map[string]struct{})
	var samples []string

	collect := func(re *regexp.Regexp) {
		for _, m := range re.FindAllString(s, -1) {
			if _, ok := seen[m]; ok {
				continue
			}
			seen[m] = struct{}{}
			samples = append(samples, m)
		}
	}
	collect(reHandlebars)
	collect(reDollar)
	collect(rePercent)

	if len(samples) == 0 {
		return ""
	}

	total := len(samples)
	if total > maxSamplesPerLocation {
		samples = samples[:maxSamplesPerLocation]
	}
	msg := strings.Join(samples, ", ")
	if total > maxSamplesPerLocation {
		msg += fmt.Sprintf(", ...(%d more)", total-maxSamplesPerLocation)
	}
	return msg
}
