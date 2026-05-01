// Package mcp resend_grpc.go implements the RFC-001 N8 protocol-typed
// resend_grpc MCP tool. Schema fields mirror envelope.GRPCStartMessage /
// envelope.GRPCDataMessage / envelope.GRPCEndMessage so AI agents address
// gRPC RPCs by structured event (Start headers, Data LPMs, optional End
// trailers) instead of round-tripping an opaque message_sequence index.
//
// resend_grpc coexists with the legacy `resend` tool. The legacy tool
// remains the entry point for HTTP, gRPC, gRPC-Web, raw, and WebSocket
// resends until RFC-001 N9 retires it. This new tool restricts itself
// to native gRPC flows; non-gRPC flow_ids are rejected with an explicit
// pointer to the matching protocol-typed tool (resend_http / resend_ws /
// resend_raw).
//
// Pipeline placement (RFC §9.3 D1): resend traverses
//
//	PluginStepPost → RecordStep
//
// — PluginStepPre and InterceptStep are excluded so signing and last-mile
// post-mutation hooks fire exactly once per envelope on the resent RPC
// while pre_pipeline annotation hooks (which observe pristine wire-fresh
// data) stay quiet on resends.
//
// Upstream connection: a fresh TCP (+ TLS for grpcs / scheme=https) dial
// → HTTP/2 Layer in ClientRole (no net/http) → http2.Layer.OpenStream →
// grpclayer.Wrap (RoleClient, synthetic firstHeaders=nil per D5). The
// gRPC Layer's Send path translates GRPCStart/Data/End envelopes into
// the underlying H2 HEADERS / DATA / TRAILERS frames.
//
// End semantics:
//
//   - When trailer_metadata is omitted (the common case): the trailing
//     GRPCDataMessage carries EndStream=true and the request-side stream
//     terminates via END_STREAM on the last DATA frame. This matches the
//     standard gRPC client convention.
//   - When trailer_metadata is supplied: the trailing GRPCDataMessage
//     keeps EndStream=false and a GRPCEndMessage envelope is sent
//     afterwards. The Layer emits the trailer HEADERS frame (with
//     END_STREAM) — a non-standard but diagnostic-useful Send-direction
//     trailer (see envelope.GRPCEndMessage doc; recorded as Direction=Send
//     under AnomalyUnexpectedGRPCWebRequestTrailer in normal observation).
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// resendGRPCInput is the typed input for the resend_grpc tool.
//
// flow_id is optional. When set, the original RPC's send-direction GRPCStart
// Flow supplies the Service / Method / Metadata / Encoding fields the user
// omits; the receive-direction GRPCStart Flow supplies the negotiated
// upstream encoding hint for accept_encoding defaulting. When flow_id is
// empty, target_addr + service + method are required up-front and no
// encoding state is inherited.
//
// messages is the request-side Data list. Each element is one
// length-prefixed message (LPM) on the gRPC stream. Empty messages list
// is rejected (an RPC with zero DATA frames is not well-formed).
//
// trailer_metadata is the optional override; when present, the request
// stream terminates via a Send-direction trailer HEADERS frame instead
// of END_STREAM on the last DATA. Useful for diagnostic round-tripping
// of unusual server-style trailer behaviour from a client position.
type resendGRPCInput struct {
	FlowID          string           `json:"flow_id,omitempty" jsonschema:"recorded gRPC stream id; when set, omitted Start fields and the encoding hint are inherited from the original RPC"`
	TargetAddr      string           `json:"target_addr,omitempty" jsonschema:"upstream host:port. Required when flow_id is empty. When supplied with flow_id, redirects the dial target while preserving the recovered :authority"`
	Scheme          string           `json:"scheme,omitempty" jsonschema:"http or https; defaults to https. http selects plaintext h2c"`
	Service         string           `json:"service,omitempty" jsonschema:"gRPC service name (e.g. pkg.Greeter); required when flow_id is empty"`
	Method          string           `json:"method,omitempty" jsonschema:"gRPC method name (e.g. SayHello); required when flow_id is empty"`
	Metadata        []headerKV       `json:"metadata,omitempty" jsonschema:"ordered metadata list; preserves wire case, order and duplicates"`
	Encoding        string           `json:"encoding,omitempty" jsonschema:"grpc-encoding for outgoing messages (identity or gzip)"`
	AcceptEncoding  []string         `json:"accept_encoding,omitempty" jsonschema:"grpc-accept-encoding list (e.g. [\"gzip\",\"identity\"])"`
	Messages        []resendGRPCData `json:"messages,omitempty" jsonschema:"request-side LPM list; at least one element required"`
	TrailerMetadata []headerKV       `json:"trailer_metadata,omitempty" jsonschema:"optional Send-direction trailer HEADERS; when supplied, the request terminates via a trailer frame instead of END_STREAM on the last DATA"`
	TimeoutMs       *int             `json:"timeout_ms,omitempty" jsonschema:"per-call timeout in milliseconds covering dial+handshake+send+receive; default 30000"`
	TLSFingerprint  string           `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	Tag             string           `json:"tag,omitempty" jsonschema:"tag stored on the new flow's Tags map"`
}

// resendGRPCData is one LPM input. Payload is interpreted per
// body_encoding (text → UTF-8 passthrough, base64 → decoded). Compressed
// flips the LPM compression byte; the underlying gRPC Layer applies the
// negotiated grpc-encoding (gzip) when sending. Setting compressed=true
// without an Encoding (recovered or user-supplied) is rejected at the
// schema boundary.
type resendGRPCData struct {
	Payload      string `json:"payload" jsonschema:"LPM payload interpreted per body_encoding"`
	BodyEncoding string `json:"body_encoding,omitempty" jsonschema:"text|base64; defaults to text"`
	Compressed   bool   `json:"compressed,omitempty" jsonschema:"set the LPM compression flag; requires Encoding to be set"`
}

// resendGRPCResult is the structured response of the resend_grpc tool.
//
// stream_id is the new Stream record holding the resend-time send Flows
// (Start + Data*) and receive Flows (Start + Data* + End). end may be nil
// when the upstream terminated the stream without a trailer HEADERS frame
// — diagnostic callers should treat that case as "abnormal termination
// observed; no trailer received".
type resendGRPCResult struct {
	StreamID      string                 `json:"stream_id"`
	StartMetadata []headerKV             `json:"start_metadata"`
	Messages      []resendGRPCDataResult `json:"messages"`
	End           *resendGRPCEndResult   `json:"end,omitempty"`
	DurationMs    int64                  `json:"duration_ms"`
	Tag           string                 `json:"tag,omitempty"`
}

// resendGRPCDataResult is one decoded response-side LPM in the result.
// Payload is the decompressed bytes (the gRPC Layer always decompresses
// for inspection convenience); the original wire bytes are preserved
// on the recorded Flow.RawBytes for analysts that need them.
type resendGRPCDataResult struct {
	Payload         string `json:"payload"`
	PayloadEncoding string `json:"payload_encoding"`
	Compressed      bool   `json:"compressed,omitempty"`
}

// resendGRPCEndResult is the structured trailer summary of the result.
// Status is the gRPC status code (0 = OK). Trailers excludes grpc-status,
// grpc-message, and grpc-status-details-bin (already projected on the
// dedicated fields).
type resendGRPCEndResult struct {
	Status   uint32     `json:"status"`
	Message  string     `json:"message,omitempty"`
	Trailers []headerKV `json:"trailers,omitempty"`
}

// registerResendGRPC wires the resend_grpc tool into the MCP server.
func (s *Server) registerResendGRPC() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend_grpc",
		Description: "Resend a gRPC RPC via a freshly dialled HTTP/2 upstream connection with GRPCStart/Data/End-typed schema. " +
			"messages[] is the request-side LPM list (at least one element required). When flow_id is set, Service/Method/Metadata/Encoding " +
			"are inherited from the recorded send and overridden by user-supplied fields. When flow_id is empty, target_addr + service + " +
			"method are required. metadata is an ordered list of {name, value} pairs preserving wire case/order/duplicates. " +
			"trailer_metadata is optional; when omitted the request terminates via END_STREAM on the last DATA, when supplied a " +
			"Send-direction trailer HEADERS frame is sent. " +
			"PluginStepPost fires once per Start + per Data envelope (End is observation-only per RFC §9.3 surface table); PluginStepPre is bypassed (RFC-001 §9.3). " +
			"target_addr redirects the dial target while preserving the recovered :authority. " +
			"For non-gRPC flows use resend_http / resend_ws / resend_raw (legacy resend tool also remains).",
	}, s.handleResendGRPC)
}

// handleResendGRPC is the top-level handler. It coordinates: input
// validation → flow recovery → plan resolution → defense-in-depth checks
// → upstream dial + HTTP/2 Layer + open stream → gRPC Layer wrap → resend
// pipeline construction → request envelope sequence (Start + Data* +
// optional End) → response envelope receive loop → result formatting.
// The pipeline itself is what fires PluginStepPost and RecordStep on
// every envelope both directions; this handler only assembles the inputs.
func (s *Server) handleResendGRPC(ctx context.Context, _ *gomcp.CallToolRequest, input resendGRPCInput) (*gomcp.CallToolResult, *resendGRPCResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "resend_grpc",
		"flow_id", input.FlowID,
		"target_addr", input.TargetAddr,
		"service", input.Service,
		"method", input.Method,
		"messages", len(input.Messages),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "resend_grpc",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateResendGRPCInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildResendGRPCPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkResendGRPCScope(plan); err != nil {
		return nil, nil, err
	}
	if v := s.checkSafetyInput(concatResendGRPCPayloads(plan), plan.canonicalURL.String(), keyValuesToExchangeKV(plan.metadata)); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	if input.TLSFingerprint != "" {
		// U2 deferral: per-call fingerprint isn't wired in v1. Surface
		// the field so users notice it had no effect rather than
		// silently ignoring it. Mirrors resend_http U2 / resend_ws U2.
		slog.WarnContext(ctx, "resend_grpc: tls_fingerprint is informational v1; using server-configured fingerprint",
			"supplied", input.TLSFingerprint)
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}
	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	encoders := buildResendGRPCEncoderRegistry()
	pipe := s.buildResendGRPCPipeline(encoders)

	endEnv, recvData, recvStartMeta, err := s.runResendGRPC(rtCtx, plan, pipe)
	if err != nil {
		return nil, nil, fmt.Errorf("resend_grpc: %w", err)
	}

	if input.Tag != "" && s.flowStore.store != nil {
		s.applyResendGRPCTag(ctx, plan.streamID, input.Tag)
	}

	duration := time.Since(start)
	return nil, s.formatResendGRPCResult(plan.streamID, recvStartMeta, recvData, endEnv, input.Tag, duration), nil
}
