// Package mcp resend_http.go implements the RFC-001 N8 protocol-typed
// resend_http MCP tool. Schema fields mirror envelope.HTTPMessage
// (method/scheme/authority/path/raw_query/headers/body) so AI agents address
// HTTP fields by name instead of round-tripping a single opaque URL string.
//
// resend_http coexists with the legacy `resend` tool. The legacy tool stays
// the entry point for HTTP, gRPC, gRPC-Web, WebSocket, and raw resends until
// RFC-001 N9 retires it. The new tool restricts itself to plain HTTP/1.x and
// HTTP/2 flows; non-HTTP flow_ids are rejected with an explicit error
// pointing at the matching protocol-typed tool (resend_ws / resend_grpc /
// resend_raw — added in successive N8 issues).
//
// Pipeline placement (RFC §9.3 D1): resend traverses
//
//	PluginStepPost → RecordStep
//
// — PluginStepPre and InterceptStep are excluded so signing and last-mile
// post-mutation hooks fire exactly once on the resent envelope while
// pre_pipeline annotation hooks (which observe pristine wire-fresh data)
// stay quiet on resends. This is the "Send 直前の最終形を 1 回見る"
// semantics from the OQ#3 resolution.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// resendHTTPInput is the typed input for the resend_http tool.
//
// flow_id is optional. When set, a Stream lookup populates fields the user
// omits (method/scheme/authority/path/raw_query/headers/body). When empty,
// method/scheme/authority/path are all required up-front. body_set
// distinguishes "omit body — keep original" from "override to empty body";
// without it, a missing body field on a flow_id-less call yields an error.
type resendHTTPInput struct {
	FlowID          string      `json:"flow_id,omitempty" jsonschema:"recorded stream id; when set, omitted fields are inherited from the original send"`
	Method          string      `json:"method,omitempty" jsonschema:"HTTP method (GET, POST, ...); required when flow_id is empty"`
	Scheme          string      `json:"scheme,omitempty" jsonschema:"http or https; required when flow_id is empty"`
	Authority       string      `json:"authority,omitempty" jsonschema:"Host header / :authority value; required when flow_id is empty"`
	Path            string      `json:"path,omitempty" jsonschema:"request path including leading slash; required when flow_id is empty"`
	RawQuery        string      `json:"raw_query,omitempty" jsonschema:"raw query string without the leading '?'"`
	Headers         []headerKV  `json:"headers,omitempty" jsonschema:"ordered header list; preserves wire case, order and duplicates"`
	Body            string      `json:"body,omitempty" jsonschema:"request body interpreted per body_encoding"`
	BodyEncoding    string      `json:"body_encoding,omitempty" jsonschema:"text|base64; default text"`
	BodySet         bool        `json:"body_set,omitempty" jsonschema:"set true to override body to empty; otherwise omitting body inherits the original"`
	BodyPatches     []BodyPatch `json:"body_patches,omitempty" jsonschema:"applied on top of any body replacement"`
	OverrideHost    string      `json:"override_host,omitempty" jsonschema:"redirect the dial target while preserving the request's Host/:authority (host:port)"`
	FollowRedirects *bool       `json:"follow_redirects,omitempty" jsonschema:"unsupported; setting true returns an error"`
	TimeoutMs       *int        `json:"timeout_ms,omitempty" jsonschema:"per-request timeout in milliseconds; default 30000"`
	TLSFingerprint  string      `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	Tag             string      `json:"tag,omitempty" jsonschema:"tag stored on the new flow's Tags map"`
}

// resendHTTPResult is the structured response of the resend_http tool.
//
// stream_id is the new Stream record holding the resend-time send + receive
// flows (and any modified-variant rows produced by the pipeline). headers is
// preserved as an ordered list — the same wire-fidelity contract the input
// schema enforces — so callers can round-trip case-sensitive duplicates.
type resendHTTPResult struct {
	StreamID     string     `json:"stream_id"`
	StatusCode   int        `json:"status_code"`
	Headers      []headerKV `json:"headers"`
	Body         string     `json:"body"`
	BodyEncoding string     `json:"body_encoding"`
	DurationMs   int64      `json:"duration_ms"`
	Tag          string     `json:"tag,omitempty"`
}

// registerResendHTTP wires the resend_http tool into the MCP server.
func (s *Server) registerResendHTTP() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "resend_http",
		Description: "Resend or construct an HTTP request via the RFC-001 layer stack with HTTPMessage-typed schema fields " +
			"(method/scheme/authority/path/raw_query/headers/body). When flow_id is set, omitted fields are inherited from " +
			"the recorded send; when flow_id is empty, method/scheme/authority/path are required. headers is an ordered list " +
			"of {name, value} pairs preserving wire case/order/duplicates. body is text or base64 per body_encoding. " +
			"PluginStepPost fires once on the resend; PluginStepPre is bypassed (RFC-001 §9.3). " +
			"override_host redirects the dial target while preserving the request's :authority. " +
			"For non-HTTP flows use resend_ws / resend_grpc / resend_raw (legacy resend tool also remains).",
	}, s.handleResendHTTP)
}

// handleResendHTTP is the top-level handler. It coordinates: input validation
// → envelope construction → dial-target resolution → defense-in-depth checks
// → resend pipeline construction → request/response exchange → result
// formatting. The pipeline itself is what fires PluginStepPost and
// RecordStep; this handler only assembles the inputs.
func (s *Server) handleResendHTTP(ctx context.Context, _ *gomcp.CallToolRequest, input resendHTTPInput) (*gomcp.CallToolResult, *resendHTTPResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "resend_http",
		"flow_id", input.FlowID,
		"override_host", input.OverrideHost,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "resend_http",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateResendHTTPInput(&input); err != nil {
		return nil, nil, err
	}

	env, err := s.buildResendHTTPEnvelope(ctx, &input)
	if err != nil {
		return nil, nil, err
	}
	msg := env.Message.(*envelope.HTTPMessage)

	addr, useTLS, sni, err := resolveResendHTTPDial(msg, input.OverrideHost)
	if err != nil {
		return nil, nil, err
	}
	if err := s.checkResendHTTPScope(msg, addr, input.OverrideHost); err != nil {
		return nil, nil, err
	}
	if v := s.checkSafetyInput(msg.Body, resendHTTPRequestURL(msg).String(), keyValuesToExchangeKV(msg.Headers)); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	if input.TLSFingerprint != "" {
		// U2 deferral: per-call fingerprint isn't wired in v1. Surface
		// the field so users notice it had no effect rather than
		// silently ignoring it.
		slog.WarnContext(ctx, "resend_http: tls_fingerprint is informational v1; using server-configured fingerprint",
			"supplied", input.TLSFingerprint)
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}
	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	pipe := s.buildResendHTTPPipeline()
	dial := buildResendHTTPDialFunc(s.connector.tlsTransport, addr, useTLS, sni)

	respEnv, err := runResendHTTP(rtCtx, env, dial, pipe)
	if err != nil {
		return nil, nil, fmt.Errorf("resend_http: %w", err)
	}

	if input.Tag != "" && s.flowStore.store != nil {
		s.applyResendHTTPTag(ctx, env.StreamID, input.Tag)
	}

	duration := time.Since(start)
	return nil, s.formatResendHTTPResult(env.StreamID, respEnv, input.Tag, duration), nil
}
