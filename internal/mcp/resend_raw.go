// Package mcp resend_raw.go implements the RFC-001 N8 protocol-typed
// resend_raw MCP tool. Schema fields mirror envelope.RawMessage so AI
// agents address arbitrary TCP / TLS-passthrough payloads by raw byte
// content (with optional offset-based patches) instead of a typed L7
// shape. This is the smuggling-and-anomaly-test surface — the wire
// bytes ARE the message, and the proxy is forbidden from normalising
// them anywhere on the path.
//
// resend_raw coexists with the legacy `resend_raw_h2` and other legacy
// raw-resend entry points. Those keep working until RFC-001 N9 retires
// them. This new tool restricts itself to a flow_id-driven recovery
// path; from-scratch raw injection (no recorded flow) belongs to
// fuzz_raw (USK-680) which composes overrides per fuzz iteration.
//
// Pipeline placement (RFC §9.3 D1): resend traverses
//
//	PluginStepPost → RecordStep
//
// — PluginStepPre and InterceptStep are excluded so signing and last-
// mile post-mutation hooks fire exactly once on the resent envelope
// while pre_pipeline annotation hooks (which observe pristine wire-
// fresh data) stay quiet on resends.
//
// Wire fidelity invariant: NEVER apply CR/LF guards or any other
// content-level normalization to override_bytes / patches[].data. Raw
// is the wire — analysts run smuggling, dual-CL/TE, and other anomaly
// tests through this tool. Schema-level guards apply ONLY to
// target_addr / sni (where a CR/LF would smuggle a second TCP-layer
// "request" through any intermediate that reads them line-oriented).
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// resendRawInput is the typed input for the resend_raw tool.
//
// flow_id is REQUIRED. Unlike resend_http / resend_ws / resend_grpc
// which support a from-scratch path, raw resend always recovers the
// original wire bytes from a recorded RawMessage Flow. Ad-hoc byte
// injection without a recorded flow is fuzz_raw (USK-680) territory.
//
// override_bytes and patches are mutually exclusive at the schema
// boundary (validation rejects requests supplying both before the flow
// store is touched). When neither is supplied, the recovered Flow's
// RawBytes are sent verbatim.
type resendRawInput struct {
	FlowID                string        `json:"flow_id" jsonschema:"recorded raw stream id; REQUIRED — resend_raw has no from-scratch path"`
	TargetAddr            string        `json:"target_addr" jsonschema:"upstream host:port; REQUIRED. Explicit port required (no defaulting — raw is protocol-agnostic)"`
	UseTLS                bool          `json:"use_tls,omitempty" jsonschema:"true to upgrade the dialed connection to TLS via tlslayer.Client"`
	SNI                   string        `json:"sni,omitempty" jsonschema:"SNI server name; defaults to target_addr host portion when use_tls=true"`
	OverrideBytes         string        `json:"override_bytes,omitempty" jsonschema:"replacement payload interpreted per override_bytes_encoding; mutually exclusive with patches"`
	OverrideBytesEncoding string        `json:"override_bytes_encoding,omitempty" jsonschema:"text|base64; defaults to text. base64 required for binary smuggling payloads"`
	OverrideBytesSet      bool          `json:"override_bytes_set,omitempty" jsonschema:"set true to replace with empty bytes; otherwise an empty override_bytes string is treated as no override"`
	Patches               []resendRawBP `json:"patches,omitempty" jsonschema:"offset-based byte patches applied to the recovered bytes; mutually exclusive with override_bytes"`
	InsecureSkipVerify    bool          `json:"insecure_skip_verify,omitempty" jsonschema:"skip TLS server certificate verification when use_tls=true"`
	TLSFingerprint        string        `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	TimeoutMs             *int          `json:"timeout_ms,omitempty" jsonschema:"per-call timeout in milliseconds covering dial+handshake+send+receive; default 30000"`
	Tag                   string        `json:"tag,omitempty" jsonschema:"tag stored on the new flow's Tags map"`
}

// resendRawBP is the schema shape of an offset-based byte patch.
// The data field is interpreted per data_encoding; defaults to text.
type resendRawBP struct {
	Offset       int    `json:"offset" jsonschema:"zero-based byte offset in the recovered payload"`
	Data         string `json:"data" jsonschema:"replacement bytes interpreted per data_encoding"`
	DataEncoding string `json:"data_encoding,omitempty" jsonschema:"text|base64; defaults to text"`
}

// resendRawTypedResult is the structured response of the resend_raw tool.
//
// stream_id is the new Stream record holding the resend-time send Flow
// plus every received chunk Flow. response_bytes is the concatenated
// payload across all received bytechunk envelopes (always base64 since
// raw bytes are binary by definition); response_chunks exposes the
// envelope count for callers that want the segmentation shape without
// a per-chunk schema. truncated is true when the receive loop hit the
// per-call response cap before the upstream closed.
type resendRawTypedResult struct {
	StreamID       string `json:"stream_id"`
	ResponseBytes  string `json:"response_bytes"`
	ResponseSize   int    `json:"response_size"`
	ResponseChunks int    `json:"response_chunks,omitempty"`
	Truncated      bool   `json:"truncated,omitempty"`
	DurationMs     int64  `json:"duration_ms"`
	Tag            string `json:"tag,omitempty"`
}

// registerResendRaw wires the resend_raw tool into the MCP server.
func (s *Server) registerResendRaw() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend_raw",
		Description: "Resend a recorded raw byte payload via a freshly dialled TCP (or TLS) upstream connection. " +
			"flow_id is REQUIRED — resend_raw has no from-scratch path (use fuzz_raw for ad-hoc injection). " +
			"override_bytes replaces the payload entirely; patches apply offset-based byte replacements; the two are mutually exclusive. " +
			"target_addr requires an explicit port (raw is protocol-agnostic; no port defaulting). " +
			"PluginStepPost fires once on the resend; PluginStepPre is bypassed (RFC-001 §9.3). " +
			"Wire bytes (override_bytes, patches[].data, recovered Flow.RawBytes) are NEVER normalized — they reach the wire verbatim. " +
			"This is the smuggling-and-anomaly-test surface; analysts use it to send dual-CL/TE, malformed framing, and other deliberate wire anomalies. " +
			"Legacy `resend_raw_h2` and other raw entry points coexist in parallel.",
	}, s.handleResendRaw)
}

// handleResendRaw is the top-level handler. It coordinates: input
// validation → byte payload recovery (flow_id) → optional override /
// patches → defense-in-depth checks → upstream dial (TCP + optional
// TLS) → bytechunk Layer wrap → resend pipeline construction → send
// envelope through pipeline → write to wire → receive loop → result
// formatting. The pipeline itself fires PluginStepPost and RecordStep
// on every envelope both directions; this handler only assembles the
// inputs.
func (s *Server) handleResendRaw(ctx context.Context, _ *gomcp.CallToolRequest, input resendRawInput) (*gomcp.CallToolResult, *resendRawTypedResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "resend_raw",
		"flow_id", input.FlowID,
		"target_addr", input.TargetAddr,
		"use_tls", input.UseTLS,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "resend_raw",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateResendRawInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildResendRawPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkResendRawScope(plan); err != nil {
		return nil, nil, err
	}
	// Safety filter: feed the full payload as the body input. URL is empty
	// (no L7 view), headers nil — raw bytes carry the entire wire surface
	// so the body argument exhaustively represents the request. Mirrors
	// the legacy resend_raw safety check at internal/mcp/resend_multiproto.go.
	if v := s.checkSafetyInput(plan.payload, "", nil); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	if input.TLSFingerprint != "" {
		// U2 deferral: per-call fingerprint isn't wired in v1. Surface the
		// field so users notice it had no effect rather than silently
		// ignoring it. Mirrors resend_http U2 / resend_ws U2 / resend_grpc U2.
		if !input.UseTLS {
			slog.WarnContext(ctx, "resend_raw: tls_fingerprint supplied with use_tls=false; field is informational v1 and will be ignored",
				"supplied", input.TLSFingerprint)
		} else {
			slog.WarnContext(ctx, "resend_raw: tls_fingerprint is informational v1; using server-configured fingerprint",
				"supplied", input.TLSFingerprint)
		}
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}
	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	encoders := buildResendRawEncoderRegistry()
	pipe := s.buildResendRawPipeline(encoders)

	respBytes, chunks, truncated, err := s.runResendRaw(rtCtx, plan, pipe)
	if err != nil {
		return nil, nil, fmt.Errorf("resend_raw: %w", err)
	}

	if input.Tag != "" && s.flowStore.store != nil {
		s.applyResendRawTag(ctx, plan.streamID, input.Tag)
	}

	duration := time.Since(start)
	return nil, formatResendRawResult(plan.streamID, respBytes, chunks, truncated, input.Tag, duration), nil
}
