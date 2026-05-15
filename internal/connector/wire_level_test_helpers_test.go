//go:build e2e

package connector_test

// Shared test helpers for wire_level-aware e2e tests (USK-889 / USK-895).
// Lives under plain `e2e` so both the smoke tier (USK-895
// sse_h1_chunked_recording_integration_test.go) and the exhaustive tier
// (USK-889 wss_over_h2_frame_recording_integration_test.go +
// sse_over_h2_frame_recording_integration_test.go) compile.

import "github.com/usk6666/yorishiro-proxy/internal/flow"

// anyNonEmptyRaw reports whether any flow in flows carries non-empty
// RawBytes.
func anyNonEmptyRaw(flows []*flow.Flow) bool {
	for _, f := range flows {
		if f == nil {
			continue
		}
		if len(f.RawBytes) > 0 {
			return true
		}
	}
	return false
}

// flowsByWireLevel filters flows by wire_level + direction. Empty
// WireLevel reads as the semantic default for backward compatibility
// with pre-schemaV14 stores.
func flowsByWireLevel(flows []*flow.Flow, wireLevel, direction string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range flows {
		if f == nil {
			continue
		}
		fl := f.WireLevel
		if fl == "" {
			fl = flow.WireLevelSemantic
		}
		if fl != wireLevel {
			continue
		}
		if direction != "" && f.Direction != direction {
			continue
		}
		out = append(out, f)
	}
	return out
}

// sharesStreamID reports whether at least one row from a and one row
// from b share the same StreamID.
func sharesStreamID(a, b []*flow.Flow) bool {
	seen := make(map[string]struct{}, len(a))
	for _, f := range a {
		if f == nil {
			continue
		}
		seen[f.StreamID] = struct{}{}
	}
	for _, f := range b {
		if f == nil {
			continue
		}
		if _, ok := seen[f.StreamID]; ok {
			return true
		}
	}
	return false
}

// streamIDs collects the StreamID values from flows for diagnostic logs.
func streamIDs(flows []*flow.Flow) []string {
	out := make([]string, 0, len(flows))
	for _, f := range flows {
		if f == nil {
			continue
		}
		out = append(out, f.StreamID)
	}
	return out
}
