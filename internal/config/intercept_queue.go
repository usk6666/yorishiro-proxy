package config

import (
	"fmt"
	"sort"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// MinInterceptQueueTimeoutMs is the inclusive lower bound on a configured
// intercept-queue timeout. Matches the floor used by the MCP configure
// tool (configure_tool.go::applyInterceptQueueConfig); a future Issue can
// relax this if needed but the floor is shared across both surfaces so
// they reject the same sub-floor values with the same error message.
const MinInterceptQueueTimeoutMs = 1000

// InterceptQueueConfig holds the intercept-queue file-config block. It
// configures both the global hold timeout / timeout-behavior (mirroring
// the MCP configure_tool's existing shape) and per-protocol overrides
// (USK-855: USK-851 follow-up B).
//
// Per-protocol overrides take precedence over the global. A protocol
// override entry with TimeoutMs == 0 means "inherit global timeout"; an
// entry with TimeoutBehavior == "" means "inherit global behavior". This
// per-field inherit semantics matches the HoldQueue's
// protocolTimeoutSetting shape.
//
// Valid protocol-overrides keys are the canonical envelope.Protocol
// string values:
//   - "http"          (HTTP/1.x and HTTP/2 — both aggregate into HTTPMessage)
//   - "ws"            (WebSocket)
//   - "grpc"          (native gRPC)
//   - "grpc-web"      (gRPC-Web)
//   - "sse"           (Server-Sent Events)
//   - "raw"           (Raw TCP pass-through)
//   - "tls-handshake" (TLS handshake observation envelopes)
//
// Note: "http2" is NOT a valid key — HTTP/1 and HTTP/2 share the "http"
// envelope Protocol. The validator rejects unknown keys with an error
// listing the canonical set.
type InterceptQueueConfig struct {
	// TimeoutMs sets the global hold timeout in milliseconds. Zero
	// (or omitted) leaves the built-in default (5 minutes) in place.
	// Validation rejects positive values below MinInterceptQueueTimeoutMs
	// so the file-config and MCP-tool floors stay aligned.
	TimeoutMs int64 `json:"timeout_ms,omitempty"`

	// TimeoutBehavior sets the global timeout-expiry behavior. Empty
	// (or omitted) leaves the built-in default (auto_release) in place.
	// Valid values: "auto_release", "auto_drop".
	TimeoutBehavior string `json:"timeout_behavior,omitempty"`

	// ProtocolOverrides maps a canonical envelope.Protocol string to a
	// per-protocol hold-timeout / timeout-behavior override. Keys not in
	// the canonical set are rejected by the validator.
	ProtocolOverrides map[string]*InterceptQueueProtocolOverride `json:"protocol_overrides,omitempty"`
}

// InterceptQueueProtocolOverride holds a per-protocol hold-timeout
// override. Zero/empty fields inherit the global per-field — both
// fields are independent, so {timeout_ms: 1500} keeps the global
// timeout_behavior intact, and vice versa.
type InterceptQueueProtocolOverride struct {
	// TimeoutMs is the per-protocol hold timeout in milliseconds.
	// Zero (or omitted) inherits the global TimeoutMs. Validation
	// rejects positive values below MinInterceptQueueTimeoutMs.
	TimeoutMs int64 `json:"timeout_ms,omitempty"`

	// TimeoutBehavior is the per-protocol timeout-expiry behavior.
	// Empty (or omitted) inherits the global TimeoutBehavior. Valid
	// values: "auto_release", "auto_drop".
	TimeoutBehavior string `json:"timeout_behavior,omitempty"`
}

// canonicalInterceptQueueProtocols enumerates every valid map key for
// InterceptQueueConfig.ProtocolOverrides. The slice form is used to
// produce a deterministic error message listing accepted keys.
var canonicalInterceptQueueProtocols = []envelope.Protocol{
	envelope.ProtocolHTTP,
	envelope.ProtocolWebSocket,
	envelope.ProtocolGRPC,
	envelope.ProtocolGRPCWeb,
	envelope.ProtocolSSE,
	envelope.ProtocolRaw,
	envelope.ProtocolTLSHandshake,
}

// isCanonicalInterceptQueueProtocol reports whether p is one of the
// canonical envelope.Protocol string values. Shared between the
// file-config validator and the MCP configure tool's input validator so
// both surfaces reject identical key sets.
func isCanonicalInterceptQueueProtocol(p envelope.Protocol) bool {
	for _, c := range canonicalInterceptQueueProtocols {
		if c == p {
			return true
		}
	}
	return false
}

// canonicalProtocolKeysList returns the canonical protocol keys joined
// with ", " for use in error messages. Stable order (sorted) so users
// see the same list across runs.
func canonicalProtocolKeysList() string {
	keys := make([]string, 0, len(canonicalInterceptQueueProtocols))
	for _, p := range canonicalInterceptQueueProtocols {
		keys = append(keys, string(p))
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// validInterceptQueueBehavior reports whether b is a recognised
// timeout-expiry behavior string. Empty is accepted (means "inherit").
func validInterceptQueueBehavior(b string) bool {
	switch b {
	case "", "auto_release", "auto_drop":
		return true
	default:
		return false
	}
}

// validateInterceptQueue validates the ProxyConfig.InterceptQueue
// substruct. A nil InterceptQueue is treated as "use built-in defaults"
// and causes no error.
func (c *ProxyConfig) validateInterceptQueue() error {
	if c == nil || c.InterceptQueue == nil {
		return nil
	}
	iq := c.InterceptQueue

	if iq.TimeoutMs < 0 {
		return fmt.Errorf("intercept_queue.timeout_ms must be >= 0, got %d", iq.TimeoutMs)
	}
	if iq.TimeoutMs > 0 && iq.TimeoutMs < MinInterceptQueueTimeoutMs {
		return fmt.Errorf("intercept_queue.timeout_ms must be >= %d, got %d", MinInterceptQueueTimeoutMs, iq.TimeoutMs)
	}
	if !validInterceptQueueBehavior(iq.TimeoutBehavior) {
		return fmt.Errorf("intercept_queue.timeout_behavior %q is not valid (expected %q or %q)",
			iq.TimeoutBehavior, "auto_release", "auto_drop")
	}

	for key, ov := range iq.ProtocolOverrides {
		proto := envelope.Protocol(key)
		if !isCanonicalInterceptQueueProtocol(proto) {
			return fmt.Errorf("intercept_queue.protocol_overrides[%q]: unknown protocol key (valid keys: %s)",
				key, canonicalProtocolKeysList())
		}
		if ov == nil {
			// A null value in JSON is permitted at the MCP tool layer
			// (it means "clear the override"). On the file-config side
			// a null override is meaningless, but we treat it as
			// equivalent to "no override" rather than rejecting it so
			// the JSON shape stays symmetric.
			continue
		}
		if ov.TimeoutMs < 0 {
			return fmt.Errorf("intercept_queue.protocol_overrides[%q].timeout_ms must be >= 0, got %d",
				key, ov.TimeoutMs)
		}
		if ov.TimeoutMs > 0 && ov.TimeoutMs < MinInterceptQueueTimeoutMs {
			return fmt.Errorf("intercept_queue.protocol_overrides[%q].timeout_ms must be >= %d, got %d",
				key, MinInterceptQueueTimeoutMs, ov.TimeoutMs)
		}
		if !validInterceptQueueBehavior(ov.TimeoutBehavior) {
			return fmt.Errorf("intercept_queue.protocol_overrides[%q].timeout_behavior %q is not valid (expected %q or %q)",
				key, ov.TimeoutBehavior, "auto_release", "auto_drop")
		}
	}
	return nil
}
