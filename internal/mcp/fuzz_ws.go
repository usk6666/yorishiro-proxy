// Package mcp fuzz_ws.go implements the RFC-001 N8 protocol-typed
// fuzz_ws MCP tool. Builds on top of resend_ws: the same validation /
// flow-recovery / upgrade-dance / pipeline machinery, iterated N times
// with per-position payload substitution against the WSMessage envelope.
//
// fuzz_ws coexists with the legacy `fuzz` tool. Legacy continues to
// work unchanged for fuzz jobs that need the full async runner
// (concurrency / rate limit / overload monitor / job registry). This
// new tool is a *synchronous* per-call fuzzer suitable for small to
// medium variant counts (≤ maxFuzzWSVariants=1000); larger jobs should
// still use the legacy tool until N9 retires it.
//
// Pipeline placement (RFC §9.3 D1): each variant traverses
//
//	PluginStepPost → RecordStep
//
// — same self-contained pipeline as resend_ws. PluginStepPre and
// InterceptStep are excluded so signing and last-mile post-mutation
// hooks fire exactly once per variant, while pre_pipeline annotation
// hooks (which observe pristine wire-fresh data) stay quiet on fuzzed
// variants.
//
// Position path syntax (WSMessage-typed):
//
//	"payload"       → WSMessage.Payload (interpreted per encoding)
//	"close_reason"  → WSMessage.CloseReason
//
// Variant generation: cartesian product across positions (full N-way
// product). Total variant count is capped at maxFuzzWSVariants=1000
// to keep the synchronous tool bounded; callers that need more should
// either chain multiple invocations or use the legacy `fuzz` tool.
//
// Per variant: one WebSocket frame to a freshly dialled + upgraded
// upstream. Each variant gets its own TCP connection, upgrade dance,
// and Stream row. Auto-Pong replies for incoming Pings are emitted by
// the receive loop (mirroring resend_ws); the variant terminates on
// the first non-control frame OR a Close frame OR ctx timeout.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// fuzzWSInput is the typed input for the fuzz_ws tool.
//
// flow_id behaves identically to resend_ws: when set, the upgrade
// Stream's send/receive Flows seed the upgrade-dance URL/headers and
// the negotiated Sec-WebSocket-Extensions value used by deflate. When
// flow_id is empty, target_addr + path are required up-front (and
// compressed=true is rejected because no extension was negotiated).
//
// positions is REQUIRED and must contain at least one entry. Each
// position has a typed path into the WSMessage (payload or
// close_reason) and a list of payloads. The cartesian product of all
// positions × payloads produces the variant sequence; total variant
// count is capped at maxFuzzWSVariants.
type fuzzWSInput struct {
	// Inherits resend_ws fields verbatim.
	FlowID         string `json:"flow_id,omitempty" jsonschema:"recorded WebSocket stream id; when set, the upgrade dance inherits URL/headers/extensions from the recorded flow"`
	TargetAddr     string `json:"target_addr,omitempty" jsonschema:"upstream host:port. Overrides the dial target while preserving the recovered :authority. Required when flow_id is empty"`
	Scheme         string `json:"scheme,omitempty" jsonschema:"ws or wss; required when flow_id is empty (defaults to ws)"`
	Path           string `json:"path,omitempty" jsonschema:"upgrade request path; required when flow_id is empty"`
	RawQuery       string `json:"raw_query,omitempty" jsonschema:"upgrade request raw query string without the leading '?'"`
	Opcode         string `json:"opcode" jsonschema:"frame opcode: text|binary|close|ping|pong"`
	Fin            *bool  `json:"fin,omitempty" jsonschema:"FIN bit; defaults to true"`
	Payload        string `json:"payload,omitempty" jsonschema:"base frame payload interpreted per body_encoding; positions can target payload"`
	BodyEncoding   string `json:"body_encoding,omitempty" jsonschema:"text|base64; defaults to text — applies to base payload"`
	PayloadSet     bool   `json:"payload_set,omitempty" jsonschema:"set true to send an empty base payload; otherwise an empty payload field is treated as no override"`
	Masked         *bool  `json:"masked,omitempty" jsonschema:"informational; the upstream-facing layer auto-masks per RFC 6455 §5.3 regardless of this value"`
	Mask           string `json:"mask,omitempty" jsonschema:"informational 4-byte mask key (base64); ignored on Send for client→server frames"`
	CloseCode      *int   `json:"close_code,omitempty" jsonschema:"RFC 6455 status code for Close frames"`
	CloseReason    string `json:"close_reason,omitempty" jsonschema:"base UTF-8 reason for Close frames; positions can target close_reason"`
	Compressed     *bool  `json:"compressed,omitempty" jsonschema:"per-message-deflate (RFC 7692); requires the upgrade to negotiate deflate via flow_id"`
	TimeoutMs      *int   `json:"timeout_ms,omitempty" jsonschema:"per-variant timeout in milliseconds; default 30000"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	Tag            string `json:"tag,omitempty" jsonschema:"tag stored on every variant Stream's Tags map"`

	// Fuzz-specific fields below.

	Positions   []fuzzWSPosition `json:"positions" jsonschema:"REQUIRED ordered position list; each describes a typed path into WSMessage and the payloads to substitute"`
	StopOnClose bool             `json:"stop_on_close,omitempty" jsonschema:"when true, abort the remaining variants once any variant receives a Close frame"`
}

// fuzzWSPosition describes one fuzz position. Path is a typed reference
// into the WSMessage struct (see file-level comment for the supported
// syntax). Payloads is the list of values to substitute at this
// position; the cartesian product across all positions yields the
// variant sequence.
//
// Encoding: each payload is interpreted per encoding ("text" or
// "base64"); defaults to "text".
type fuzzWSPosition struct {
	Path     string   `json:"path" jsonschema:"typed path into WSMessage: payload | close_reason"`
	Payloads []string `json:"payloads" jsonschema:"REQUIRED list of payload values to substitute at this path; at least one element"`
	Encoding string   `json:"encoding,omitempty" jsonschema:"text|base64 — applies to every payload; default text"`
}

// fuzzWSResult is the structured response of the fuzz_ws tool.
type fuzzWSResult struct {
	TotalVariants     int                `json:"total_variants"`
	CompletedVariants int                `json:"completed_variants"`
	StoppedReason     string             `json:"stopped_reason,omitempty"`
	Variants          []fuzzWSVariantRow `json:"variants"`
	DurationMs        int64              `json:"duration_ms"`
	Tag               string             `json:"tag,omitempty"`
}

// fuzzWSVariantRow is one variant's compact result row. Opcode + Payload
// describe the upstream's terminating frame (the first non-control
// frame OR a Close frame); empty when the variant errored before send.
type fuzzWSVariantRow struct {
	Index           int               `json:"index"`
	StreamID        string            `json:"stream_id"`
	Opcode          string            `json:"opcode,omitempty"`
	Fin             bool              `json:"fin,omitempty"`
	Payload         string            `json:"payload,omitempty"`
	PayloadEncoding string            `json:"payload_encoding,omitempty"`
	Compressed      bool              `json:"compressed,omitempty"`
	CloseCode       uint16            `json:"close_code,omitempty"`
	CloseReason     string            `json:"close_reason,omitempty"`
	Payloads        map[string]string `json:"payloads"`
	Error           string            `json:"error,omitempty"`
	DurationMs      int64             `json:"duration_ms"`
}

// registerFuzzWS wires the fuzz_ws tool into the MCP server.
func (s *Server) registerFuzzWS() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz_ws",
		Description: "Synchronously fuzz a WebSocket frame with WSMessage-typed positions. Schema mirrors resend_ws " +
			"(flow_id + target_addr + opcode + base payload + close_code/reason + compressed + tag) plus a positions[] list — " +
			"each position is a typed path into the WSMessage (payload | close_reason) with a payloads[] list. The cartesian " +
			"product of all positions yields the variant sequence (capped at 1000 variants per call). Each variant traverses " +
			"the same self-contained PluginStepPost → RecordStep pipeline as resend_ws (PluginStepPre is bypassed per " +
			"RFC-001 §9.3) on a freshly dialled + upgraded WebSocket connection. Variants are executed sequentially; legacy " +
			"`fuzz` tool with concurrency / rate limit / overload monitor coexists in parallel. stop_on_close aborts " +
			"remaining variants once any variant receives a Close frame from upstream.",
	}, s.handleFuzzWS)
}

// handleFuzzWS is the top-level handler. It coordinates: input
// validation → base plan resolution (delegates to resend_ws helpers) →
// variant enumeration (cartesian product, capped) → per-variant dial +
// upgrade + pipeline execution → result aggregation.
func (s *Server) handleFuzzWS(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzWSInput) (*gomcp.CallToolResult, *fuzzWSResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_ws",
		"flow_id", input.FlowID,
		"opcode", input.Opcode,
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_ws",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateFuzzWSInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildFuzzWSPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}

	rows, completed, stopReason, err := s.runFuzzWSVariants(ctx, plan, timeout, input.StopOnClose, input.Tag)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz_ws: %w", err)
	}

	duration := time.Since(start)
	return nil, &fuzzWSResult{
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
