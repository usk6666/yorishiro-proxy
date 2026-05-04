// Package mcp resend_ws.go implements the RFC-001 N8 protocol-typed
// resend_ws MCP tool. Schema fields mirror envelope.WSMessage
// (opcode/fin/payload/close_code/close_reason/compressed) so AI agents
// address WebSocket frames by structured field instead of round-tripping
// an opaque message_sequence index.
//
// resend_ws coexists with the legacy `resend` tool. The legacy tool
// remains the entry point for HTTP, gRPC, gRPC-Web, raw, and WebSocket
// resends until RFC-001 N9 retires it. This new tool restricts itself
// to WebSocket flows; non-WS flow_ids are rejected with an explicit
// pointer to the matching protocol-typed tool.
//
// Pipeline placement (RFC §9.3 D1): resend traverses
//
//	PluginStepPost → RecordStep
//
// — PluginStepPre and InterceptStep are excluded so signing and last-mile
// post-mutation hooks fire exactly once on the resent envelope while
// pre_pipeline annotation hooks (which observe pristine wire-fresh data)
// stay quiet on resends.
//
// Upstream connection: a fresh TCP (+ TLS for wss) dial → HTTP/1.1
// Upgrade dance via the http1 Layer (no net/http) → DetachStream → ws
// Layer in RoleClient. The Layer regenerates a fresh per-frame mask key
// for client→server frames per RFC 6455 §5.3, so the schema's `mask`
// and `masked` fields are informational only on Send.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// resendWSInput is the typed input for the resend_ws tool.
//
// flow_id is optional. When set, the original WS upgrade Stream is looked
// up and its first send-direction Flow's URL + Headers populate the
// upgrade dance (Sec-WebSocket-Protocol echo, Cookie, Authorization,
// etc.); the receive-direction Flow at sequence 1 supplies the
// negotiated Sec-WebSocket-Extensions value used to enable
// permessage-deflate. When flow_id is empty, target_addr + path are
// required up-front and no extension negotiation happens (compressed
// frames cannot round-trip in the from-scratch path).
//
// opcode is required (text|binary|close|ping|pong) and validated at the
// schema boundary so AI agents always express the frame kind they intend.
type resendWSInput struct {
	FlowID         string `json:"flow_id,omitempty" jsonschema:"recorded WebSocket stream id; when set, the upgrade dance inherits URL/headers/extensions from the recorded flow"`
	TargetAddr     string `json:"target_addr,omitempty" jsonschema:"upstream host:port. Overrides the dial target while preserving the recovered :authority. Required when flow_id is empty"`
	Scheme         string `json:"scheme,omitempty" jsonschema:"ws or wss; required when flow_id is empty (defaults to ws)"`
	Path           string `json:"path,omitempty" jsonschema:"upgrade request path; required when flow_id is empty"`
	RawQuery       string `json:"raw_query,omitempty" jsonschema:"upgrade request raw query string without the leading '?'"`
	Opcode         string `json:"opcode" jsonschema:"frame opcode: text|binary|close|ping|pong"`
	Fin            *bool  `json:"fin,omitempty" jsonschema:"FIN bit; defaults to true"`
	Payload        string `json:"payload,omitempty" jsonschema:"frame payload interpreted per body_encoding"`
	BodyEncoding   string `json:"body_encoding,omitempty" jsonschema:"text|base64; defaults to text"`
	PayloadSet     bool   `json:"payload_set,omitempty" jsonschema:"set true to send an empty payload; otherwise an empty payload field is treated as no override"`
	Masked         *bool  `json:"masked,omitempty" jsonschema:"informational; the upstream-facing layer auto-masks per RFC 6455 §5.3 regardless of this value"`
	Mask           string `json:"mask,omitempty" jsonschema:"informational 4-byte mask key (hex or base64 per body_encoding); ignored on Send for client→server frames"`
	CloseCode      *int   `json:"close_code,omitempty" jsonschema:"RFC 6455 status code for Close frames"`
	CloseReason    string `json:"close_reason,omitempty" jsonschema:"optional UTF-8 reason for Close frames"`
	Compressed     *bool  `json:"compressed,omitempty" jsonschema:"per-message-deflate (RFC 7692); requires the upgrade to negotiate deflate via flow_id"`
	TimeoutMs      *int   `json:"timeout_ms,omitempty" jsonschema:"per-call timeout in milliseconds covering dial+upgrade+send+receive; default 30000"`
	TLSFingerprint string `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	Tag            string `json:"tag,omitempty" jsonschema:"tag stored on the new flow's Tags map"`
}

// resendWSResult is the structured response of the resend_ws tool.
//
// stream_id is the new Stream record holding the resend-time send Flow
// plus every received frame (auto-Pong replies are recorded as their own
// Flows on the same Stream). The result frame is the first non-control
// frame (text / binary / close) the upstream sent OR a Close frame
// terminating the conversation.
type resendWSResult struct {
	StreamID        string `json:"stream_id"`
	Opcode          string `json:"opcode"`
	Fin             bool   `json:"fin"`
	Payload         string `json:"payload"`
	PayloadEncoding string `json:"payload_encoding"`
	Compressed      bool   `json:"compressed,omitempty"`
	CloseCode       uint16 `json:"close_code,omitempty"`
	CloseReason     string `json:"close_reason,omitempty"`
	DurationMs      int64  `json:"duration_ms"`
	Tag             string `json:"tag,omitempty"`
}

// registerResendWS wires the resend_ws tool into the MCP server.
func (s *Server) registerResendWS() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend_ws",
		Description: "Resend a single WebSocket frame via a freshly dialled upstream connection with WSMessage-typed schema fields " +
			"(opcode/fin/payload/close_code/close_reason/compressed). When flow_id is set, the upgrade dance inherits URL, " +
			"request headers, and the negotiated permessage-deflate extension from the recorded flow; when flow_id is empty, " +
			"target_addr + path are required and no compressed-frame round-trip is possible. " +
			"PluginStepPost fires once on the resend; PluginStepPre is bypassed (RFC-001 §9.3). " +
			"target_addr redirects the dial target while preserving the recovered :authority. " +
			"For non-WebSocket flows use resend_http / resend_grpc / resend_raw (legacy resend tool also remains).",
	}, s.handleResendWS)
}

// handleResendWS is the top-level handler. It coordinates: input
// validation → flow recovery + extension negotiation → upstream dial +
// upgrade dance → envelope construction → defense-in-depth checks →
// resend pipeline construction → frame send + receive loop → result
// formatting. The pipeline itself is what fires PluginStepPost and
// RecordStep on every frame both directions; this handler only assembles
// the inputs.
func (s *Server) handleResendWS(ctx context.Context, _ *gomcp.CallToolRequest, input resendWSInput) (*gomcp.CallToolResult, *resendWSResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "resend_ws",
		"flow_id", input.FlowID,
		"target_addr", input.TargetAddr,
		"opcode", input.Opcode,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "resend_ws",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateResendWSInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildResendWSPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkResendWSScope(plan); err != nil {
		return nil, nil, err
	}
	if v := s.checkSafetyInput(plan.payload, plan.upgradeURL.String(), plan.upgradeHeaders); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	if input.TLSFingerprint != "" {
		// U2 deferral: per-call fingerprint isn't wired in v1. Surface
		// the field so users notice it had no effect rather than
		// silently ignoring it. Mirrors resend_http U2.
		slog.WarnContext(ctx, "resend_ws: tls_fingerprint is informational v1; using server-configured fingerprint",
			"supplied", input.TLSFingerprint)
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}
	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	encoders, sendEnv, rawBytes, err := s.buildResendWSEnvelope(plan)
	if err != nil {
		return nil, nil, err
	}
	sendEnv.Raw = rawBytes
	pipe := s.buildResendWSPipeline(encoders)

	respEnv, err := s.runResendWS(rtCtx, plan, sendEnv, pipe)
	if err != nil {
		return nil, nil, fmt.Errorf("resend_ws: %w", err)
	}

	if input.Tag != "" && s.flowStore.store != nil {
		s.applyResendWSTag(ctx, sendEnv.StreamID, input.Tag)
	}

	duration := time.Since(start)
	return nil, s.formatResendWSResult(sendEnv.StreamID, respEnv, input.Tag, duration), nil
}
