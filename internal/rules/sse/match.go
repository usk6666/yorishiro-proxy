package sse

import (
	"fmt"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// RuleDirection specifies which envelope direction a rule applies to.
//
// SSE is half-duplex Receive-only on the live wire (`relaySSEEvent`
// always builds Direction=Receive envelopes). The string set is retained
// for cross-protocol schema parity with WS / gRPC, but the MCP
// configure_tool rejects "send" at compile time so a misconfigured rule
// cannot silently match nothing.
type RuleDirection string

const (
	// DirectionReceive matches server-to-client SSE events.
	DirectionReceive RuleDirection = "receive"
	// DirectionBoth matches events regardless of direction. Retained for
	// cross-protocol template parity even though SSE only observes Receive
	// envelopes today.
	DirectionBoth RuleDirection = "both"
)

// directionAllowed reports whether a rule with the given Direction setting
// matches an envelope observed in direction d. Empty rule direction is
// treated as DirectionBoth so callers may omit the field.
func directionAllowed(rule RuleDirection, d envelope.Direction) bool {
	if rule == "" || rule == DirectionBoth {
		return true
	}
	// SSE-on-the-wire is always Receive; rule == DirectionReceive matches
	// when the envelope is Receive. Anything else (e.g. a stale Send rule
	// that bypassed compile-time validation) returns false.
	switch d {
	case envelope.Receive:
		return rule == DirectionReceive
	default:
		return false
	}
}

// containsCRLF reports whether s contains a CR or LF character. Used by
// the transform compile-time guards to reject action values that would
// inject SSE-protocol framing bytes.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// containsCR reports whether s contains a CR character. SetData permits
// `\n` (multi-line data is legal per RFC 8895) but still rejects `\r` so
// operators cannot smuggle an unrelated event terminator.
func containsCR(s string) bool {
	return strings.ContainsRune(s, '\r')
}

// ValidateModifyFields is the shared CRLF-guard predicate used by both
// the engine's compile-time validator (validateActionForCRLF in
// transform.go) and the MCP intercept tool's applySSEModify path. It
// encodes the RFC 8895 asymmetry: CR or LF are rejected on `event` and
// `id` because both must occupy a single wire line; on `data` only CR is
// rejected because multi-line `data:` is a legal wire form (one `data:`
// line per `\n`-split chunk).
//
// Each parameter is a nil-tolerant pointer so callers can pass only the
// fields they actually intend to mutate. The returned error matches the
// historical error text shape of both sites so existing tests continue
// to assert against the same string contents.
//
// Centralising the predicate keeps the engine's auto-transform path and
// the intercept tool's operator-driven modify_and_forward path in lock-
// step: a future tightening (e.g. rejecting other control characters)
// lands in one place and propagates to both surfaces.
func ValidateModifyFields(event, id, data *string) error {
	if event != nil && containsCRLF(*event) {
		return fmt.Errorf("event: value must not contain CR or LF")
	}
	if id != nil && containsCRLF(*id) {
		return fmt.Errorf("id: value must not contain CR or LF")
	}
	if data != nil && containsCR(*data) {
		return fmt.Errorf("data: value must not contain CR (LF is permitted for multi-line data)")
	}
	return nil
}

// matchAnomalies returns true when the rule's Anomalies list is empty or
// when any envelope anomaly's Type equals any rule entry (OR / any-of).
// Mirrors the HTTP `Methods` whitelist semantic from rules/http.
func matchAnomalies(ruleAnomalies []string, evAnomalies []envelope.Anomaly) bool {
	if len(ruleAnomalies) == 0 {
		return true
	}
	for _, want := range ruleAnomalies {
		for _, a := range evAnomalies {
			if string(a.Type) == want {
				return true
			}
		}
	}
	return false
}

// matchRetryRange returns true when the event's Retry field falls within
// the inclusive [min, max] window. Nil bounds are unbounded on that side.
// An event with Retry == 0 (unset on the wire) skips the rule whenever
// either bound is set — a 0 retry means the field was not present and
// matching it against a numeric range would be misleading.
func matchRetryRange(retryMs int64, minMs, maxMs *int64) bool {
	if minMs == nil && maxMs == nil {
		return true
	}
	if retryMs == 0 {
		return false
	}
	if minMs != nil && retryMs < *minMs {
		return false
	}
	if maxMs != nil && retryMs > *maxMs {
		return false
	}
	return true
}
