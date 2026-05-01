// Package mcp fuzz_grpc.go implements the RFC-001 N8 protocol-typed
// fuzz_grpc MCP tool. Builds on top of resend_grpc: the same
// validation / plan / dial / pipeline machinery, iterated N times with
// per-position payload substitution against the GRPCStart / GRPCData
// envelopes that compose one gRPC unary RPC.
//
// fuzz_grpc coexists with the legacy `fuzz` tool. Each variant becomes
// one independent gRPC stream — fresh ConnID, fresh StreamID, fresh
// dial — so per-variant state observed by analysts (Stream rows,
// PluginStepPost firing) is symmetric with the resend_grpc surface.
//
// Pipeline placement (RFC §9.3 D1): each variant traverses
//
//	PluginStepPost → RecordStep
//
// — same self-contained pipeline as resend_grpc. PluginStepPre and
// InterceptStep are excluded so signing and last-mile post-mutation
// hooks fire exactly once per Start + per Data envelope while
// pre_pipeline annotation hooks (which observe pristine wire-fresh
// data) stay quiet on fuzzed variants.
//
// Position path syntax (typed reference into the GRPCStart + GRPCData
// envelope shape):
//
//	"service"               → GRPCStartMessage.Service
//	"method"                → GRPCStartMessage.Method
//	"metadata[N].name"      → GRPCStartMessage.Metadata[N].Name
//	"metadata[N].value"     → GRPCStartMessage.Metadata[N].Value
//	"messages[N].payload"   → GRPCDataMessage.Payload (variant N)
//
// scheme / target_addr / encoding are intentionally NOT fuzz positions —
// they affect connection setup and would change the dial target rather
// than the on-wire envelope content. Callers that need to fuzz across
// schemes should issue separate fuzz_grpc calls.
//
// Variant generation: cartesian product across positions (full N-way
// product). Total variant count is capped at maxFuzzGRPCVariants=1000
// to keep the synchronous tool bounded.
//
// AC#5: PluginStepPost fires per Start + per Data envelope per variant.
// End is observation-only — the surface table marks
// ("grpc","on_end") = PhaseSupportNone (RFC §9.3).
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// fuzzGRPCInput is the typed input for the fuzz_grpc tool.
//
// flow_id behaves identically to resend_grpc: when set, the recorded
// Send-direction GRPCStart Flow seeds the per-variant base envelope;
// user-supplied fields override before any positions apply. When
// flow_id is empty, target_addr + service + method are required
// up-front and no encoding state is inherited.
//
// positions is REQUIRED and must contain at least one entry. Each
// position has a typed path into the GRPCStart / GRPCData shape and a
// list of payloads. The cartesian product of all positions × payloads
// produces the variant sequence; total variant count is capped at
// maxFuzzGRPCVariants.
type fuzzGRPCInput struct {
	// Inherits resend_grpc fields verbatim. Documented inline rather than
	// embedded so the JSON schema stays explicit at the boundary.

	FlowID          string           `json:"flow_id,omitempty" jsonschema:"recorded gRPC stream id; when set, omitted Start fields and the encoding hint are inherited from the original RPC"`
	TargetAddr      string           `json:"target_addr,omitempty" jsonschema:"upstream host:port. Required when flow_id is empty"`
	Scheme          string           `json:"scheme,omitempty" jsonschema:"http or https; defaults to https. http selects plaintext h2c"`
	Service         string           `json:"service,omitempty" jsonschema:"gRPC service name (e.g. pkg.Greeter); required when flow_id is empty"`
	Method          string           `json:"method,omitempty" jsonschema:"gRPC method name (e.g. SayHello); required when flow_id is empty"`
	Metadata        []headerKV       `json:"metadata,omitempty" jsonschema:"ordered metadata list; preserves wire case, order and duplicates"`
	Encoding        string           `json:"encoding,omitempty" jsonschema:"grpc-encoding for outgoing messages (identity or gzip)"`
	AcceptEncoding  []string         `json:"accept_encoding,omitempty" jsonschema:"grpc-accept-encoding list (e.g. [\"gzip\",\"identity\"])"`
	Messages        []resendGRPCData `json:"messages,omitempty" jsonschema:"request-side LPM list; at least one element required (positions can target messages[N].payload)"`
	TrailerMetadata []headerKV       `json:"trailer_metadata,omitempty" jsonschema:"optional Send-direction trailer HEADERS; when supplied, the request terminates via a trailer frame instead of END_STREAM on the last DATA"`
	TimeoutMs       *int             `json:"timeout_ms,omitempty" jsonschema:"per-variant timeout in milliseconds covering dial+handshake+send+receive; default 30000"`
	TLSFingerprint  string           `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred"`
	Tag             string           `json:"tag,omitempty" jsonschema:"tag stored on every variant Stream's Tags map"`

	// Fuzz-specific fields below.

	Positions   []fuzzGRPCPosition `json:"positions" jsonschema:"REQUIRED ordered position list; each describes a typed path into the GRPCStart/GRPCData shape and the payloads to substitute"`
	StopOnNonOK bool               `json:"stop_on_non_ok,omitempty" jsonschema:"when true, abort the remaining variants once any variant returns a non-OK gRPC status (or terminates without a trailer)"`
}

// fuzzGRPCPosition describes one fuzz position. Path is a typed
// reference into the GRPCStart / GRPCData envelope shape (see
// file-level comment for the supported syntax). Payloads is the list
// of values to substitute at this position; the cartesian product
// across all positions yields the variant sequence.
//
// Encoding: each payload is interpreted per encoding ("text" or
// "base64"); defaults to "text".
type fuzzGRPCPosition struct {
	Path     string   `json:"path" jsonschema:"typed path: service | method | metadata[N].name | metadata[N].value | messages[N].payload"`
	Payloads []string `json:"payloads" jsonschema:"REQUIRED list of payload values to substitute at this path; at least one element"`
	Encoding string   `json:"encoding,omitempty" jsonschema:"text|base64 — applies to every payload; default text"`
}

// fuzzGRPCResult is the structured response of the fuzz_grpc tool.
type fuzzGRPCResult struct {
	TotalVariants     int                  `json:"total_variants"`
	CompletedVariants int                  `json:"completed_variants"`
	StoppedReason     string               `json:"stopped_reason,omitempty"`
	Variants          []fuzzGRPCVariantRow `json:"variants"`
	DurationMs        int64                `json:"duration_ms"`
	Tag               string               `json:"tag,omitempty"`
}

// fuzzGRPCVariantRow is one variant's compact result row. Status is
// the gRPC status code (0 = OK); StatusMessage carries the gRPC
// status message when non-empty. ResponseMessages / ResponseTotalBytes
// summarise the receive-direction Data envelopes without ferrying full
// response payloads into the result (analyst can fetch them via the
// query tool keyed by stream_id).
type fuzzGRPCVariantRow struct {
	Index                int               `json:"index"`
	StreamID             string            `json:"stream_id"`
	Status               uint32            `json:"status"`
	StatusMessage        string            `json:"status_message,omitempty"`
	ResponseMessageCount int               `json:"response_message_count,omitempty"`
	ResponseTotalBytes   int               `json:"response_total_bytes,omitempty"`
	Payloads             map[string]string `json:"payloads"`
	Error                string            `json:"error,omitempty"`
	DurationMs           int64             `json:"duration_ms"`
}

// registerFuzzGRPC wires the fuzz_grpc tool into the MCP server.
func (s *Server) registerFuzzGRPC() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz_grpc",
		Description: "Synchronously fuzz a gRPC unary RPC with GRPCStart/Data-typed positions. Schema mirrors resend_grpc " +
			"(flow_id + target_addr + service/method + metadata + messages + trailer_metadata + tag) plus a positions[] list — " +
			"each position is a typed path (service | method | metadata[N].name | metadata[N].value | messages[N].payload) " +
			"with a payloads[] list. The cartesian product of all positions yields the variant sequence (capped at 1000 " +
			"variants per call). Each variant traverses the same self-contained PluginStepPost → RecordStep pipeline as " +
			"resend_grpc (PluginStepPre is bypassed per RFC-001 §9.3) and is dialed as a fresh independent stream. Legacy " +
			"`fuzz` tool with concurrency / rate limit / overload monitor coexists in parallel. stop_on_non_ok aborts " +
			"remaining variants once any variant returns a non-OK gRPC status.",
	}, s.handleFuzzGRPC)
}

// handleFuzzGRPC is the top-level handler. It coordinates: input
// validation → base plan resolution (delegates to resend_grpc helpers)
// → variant enumeration (cartesian product, capped) → per-variant
// pipeline execution with per-variant fresh stream → result aggregation.
func (s *Server) handleFuzzGRPC(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzGRPCInput) (*gomcp.CallToolResult, *fuzzGRPCResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_grpc",
		"flow_id", input.FlowID,
		"target_addr", input.TargetAddr,
		"service", input.Service,
		"method", input.Method,
		"messages", len(input.Messages),
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_grpc",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateFuzzGRPCInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildFuzzGRPCPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkResendGRPCScope(plan.basePlan); err != nil {
		return nil, nil, err
	}

	if input.TLSFingerprint != "" {
		// U2 deferral: per-call fingerprint isn't wired in v1. Mirrors
		// resend_grpc U2 / fuzz_http behavior.
		slog.WarnContext(ctx, "fuzz_grpc: tls_fingerprint is informational v1; using server-configured fingerprint",
			"supplied", input.TLSFingerprint)
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}

	rows, completed, stopReason, err := s.runFuzzGRPCVariants(ctx, plan, timeout, input.StopOnNonOK, input.Tag)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz_grpc: %w", err)
	}

	duration := time.Since(start)
	return nil, &fuzzGRPCResult{
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
