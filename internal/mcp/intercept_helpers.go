package mcp

import "fmt"

// intercept_helpers.go holds the small primitives shared by the intercept
// MCP tool and its sibling configure / query handlers: the release-mode
// string constants, the raw-bytes-override cap, and the base64 decoder
// used when callers supply RawOverrideBase64.
//
// Pre-USK-692 this file also held legacy rule-management helpers and the
// SafetyEngine fetch-and-revalidate path. Both were unwired by the
// HoldQueue-only migration: rule management now lives in configure_tool's
// per-protocol dispatch (see migrateInterceptRules), and SafetyStep runs
// in the Pipeline before InterceptStep — by hold time the matched
// envelope has already cleared safety.

// releaseMode is the per-call mode flag attached to the intercept tool's
// modify_and_forward and release actions.
type releaseMode string

const (
	// releaseModeStructured forwards the intercepted envelope using the
	// per-Message-type modify dispatch (default).
	releaseModeStructured releaseMode = "structured"
	// releaseModeRaw forwards the supplied RawOverrideBase64 bytes
	// verbatim, building a synthetic RawMessage envelope when the held
	// envelope is not already Raw (Decision R9).
	releaseModeRaw releaseMode = "raw"
)

// maxRawOverrideSize is the upper bound enforced on raw bytes supplied
// via the modify_and_forward path. Mirrors the legacy
// intercept.MaxRawBytesSize (CWE-770 — prevent memory exhaustion from
// excessively large client-supplied payloads). 10 MiB covers any
// legitimate HTTP/H2/WS payload while bounding abuse.
const maxRawOverrideSize = 10 * 1024 * 1024

// resolveReleaseMode converts a mode string from the MCP input into the
// canonical releaseMode constant. An empty string defaults to the
// structured path so existing callers that omit the field continue to
// route through the typed modify dispatch.
func resolveReleaseMode(mode string) (releaseMode, error) {
	switch mode {
	case "", "structured":
		return releaseModeStructured, nil
	case "raw":
		return releaseModeRaw, nil
	default:
		return "", fmt.Errorf("invalid mode %q: must be \"structured\" or \"raw\"", mode)
	}
}
