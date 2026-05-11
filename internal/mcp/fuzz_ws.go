// Package mcp fuzz_ws.go implements the protocol-typed fuzz_ws MCP tool.
// Builds on top of resend_ws: the same validation / flow-recovery /
// upgrade-dance / pipeline machinery, iterated N times with per-position
// payload substitution against the WSMessage envelope. This is a
// *synchronous* per-call fuzzer suitable for small to medium variant
// counts (≤ maxFuzzWSVariants=1000).
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
// chain multiple invocations.
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

	"github.com/google/uuid"
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
//
// fuzz_id is the UUID PK of the corresponding fuzz_jobs row (USK-831,
// mirrors USK-827). AI agents chain this with
// `query { resource: "fuzz_results", filter: { fuzz_id: ..., outliers_only:
// true } }` to surface per-run outlier variants without re-running the
// fuzz job.
type fuzzWSResult struct {
	FuzzID            string             `json:"fuzz_id"`
	TotalVariants     int                `json:"total_variants"`
	CompletedVariants int                `json:"completed_variants"`
	StoppedReason     string             `json:"stopped_reason,omitempty"`
	Variants          []fuzzWSVariantRow `json:"variants"`
	DurationMs        int64              `json:"duration_ms"`
	Tag               string             `json:"tag,omitempty"`
}

// fuzzWSVariantRow is one variant's compact result row. Opcode + scalar
// metadata describe the upstream's terminating frame (the first non-
// control frame OR a Close frame); the full payload is intentionally
// NOT stored on the row — analysts retrieve it via the `query` MCP
// tool against the variant's StreamID. Storing the full payload would
// let a malicious upstream amplify memory use up to maxFuzzWSVariants
// (1000) × the 16 MiB per-frame Layer cap (CWE-770); mirrors fuzz_http
// which only stores BodySize. CloseReason stays on the row because RFC
// 6455 §5.5.1 caps Close payloads at 125 bytes (no DoS surface).
type fuzzWSVariantRow struct {
	Index       int               `json:"index"`
	StreamID    string            `json:"stream_id"`
	Opcode      string            `json:"opcode,omitempty"`
	Fin         bool              `json:"fin,omitempty"`
	PayloadSize int               `json:"payload_size,omitempty"`
	Compressed  bool              `json:"compressed,omitempty"`
	CloseCode   uint16            `json:"close_code,omitempty"`
	CloseReason string            `json:"close_reason,omitempty"`
	Payloads    map[string]string `json:"payloads"`
	Error       string            `json:"error,omitempty"`
	DurationMs  int64             `json:"duration_ms"`
}

// registerFuzzWS wires the fuzz_ws tool into the MCP server.
func (s *Server) registerFuzzWS() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz_ws",
		Description: "Synchronously fuzz a WebSocket frame. Schema mirrors resend_ws plus a positions[] list — " +
			"each position is a typed path (payload | close_reason) with payloads[]. The cartesian product " +
			"of positions yields the variant sequence (capped at 1000 per call). Variants run sequentially over " +
			"a freshly dialled and upgraded connection. stop_on_close aborts on the first upstream Close frame. " +
			"See yorishiro://help/fuzz_ws.",
	}, s.handleFuzzWS)
}

// handleFuzzWS is the top-level handler. It coordinates: input
// validation → base plan resolution (delegates to resend_ws helpers) →
// variant enumeration (cartesian product, capped) → per-variant dial +
// upgrade + pipeline execution → result aggregation.
func (s *Server) handleFuzzWS(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzWSInput) (*gomcp.CallToolResult, *fuzzWSResult, error) {
	start := time.Now()
	fuzzID := uuid.NewString()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_ws",
		"flow_id", input.FlowID,
		"fuzz_id", fuzzID,
		"opcode", input.Opcode,
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_ws",
			"fuzz_id", fuzzID,
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

	// USK-831: insert fuzz_jobs row before the variant loop so any
	// concurrent `query fuzz_jobs` observes the run. Use a fresh
	// background ctx so caller-side cancel cannot prevent the row from
	// being created — the finalize UPDATE below relies on this row.
	s.saveFuzzWSJob(context.Background(), fuzzID, &input, plan)

	rows, completed, stopReason, runErr := s.runFuzzWSVariants(ctx, plan, timeout, input.StopOnClose, input.Tag, fuzzID)

	// Use a fresh background ctx so the closing UPDATE always lands,
	// even on caller-side ctx cancel.
	s.finalizeFuzzWSJob(context.Background(), fuzzID, rows, completed, stopReason, runErr)

	if runErr != nil {
		return nil, nil, fmt.Errorf("fuzz_ws: %w", runErr)
	}

	duration := time.Since(start)
	return nil, &fuzzWSResult{
		FuzzID:            fuzzID,
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
