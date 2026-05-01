// Package mcp fuzz_http.go implements the RFC-001 N8 protocol-typed
// fuzz_http MCP tool. Builds on top of resend_http: the same
// validation / dial / pipeline machinery, iterated N times with per-
// position payload substitution against the HTTPMessage envelope.
//
// fuzz_http coexists with the legacy `fuzz` tool. Legacy continues to
// work unchanged for HTTP fuzz jobs that need the full async runner
// (concurrency / rate limit / overload monitor / job registry). This
// new tool is a *synchronous* per-call fuzzer suitable for small to
// medium variant counts (≤ maxFuzzHTTPVariants=1000); larger jobs
// should still use the legacy tool until N9 retires it.
//
// Pipeline placement (RFC §9.3 D1): each variant traverses
//
//	PluginStepPost → RecordStep
//
// — same self-contained pipeline as resend_http. PluginStepPre and
// InterceptStep are excluded so signing and last-mile post-mutation
// hooks fire exactly once per variant, while pre_pipeline annotation
// hooks (which observe pristine wire-fresh data) stay quiet on fuzzed
// variants.
//
// Position path syntax (HTTPMessage-typed):
//
//	"method"           → HTTPMessage.Method
//	"scheme"           → HTTPMessage.Scheme
//	"authority"        → HTTPMessage.Authority
//	"path"             → HTTPMessage.Path
//	"raw_query"        → HTTPMessage.RawQuery
//	"body"             → HTTPMessage.Body (string interpretation)
//	"headers[N].name"  → HTTPMessage.Headers[N].Name
//	"headers[N].value" → HTTPMessage.Headers[N].Value
//
// Variant generation: cartesian product across positions (full N-way
// product). Total variant count is capped at maxFuzzHTTPVariants=1000
// to keep the synchronous tool bounded; callers that need more should
// either chain multiple invocations or use the legacy `fuzz` tool.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// fuzzHTTPInput is the typed input for the fuzz_http tool.
//
// flow_id behaves identically to resend_http: when set, the recorded
// Send Flow seeds the per-variant base envelope; user-supplied fields
// (method/scheme/authority/path/etc.) override before any positions
// apply. When flow_id is empty, the from-scratch HTTPMessage fields
// are required (same rule as resend_http).
//
// positions is REQUIRED and must contain at least one entry. Each
// position has a typed path into the HTTPMessage and a list of
// payloads. The cartesian product of all positions × payloads
// produces the variant sequence; total variant count is capped at
// maxFuzzHTTPVariants.
type fuzzHTTPInput struct {
	// Inherits resend_http fields verbatim (FlowID / Method / Scheme /
	// Authority / Path / RawQuery / Headers / Body / BodyEncoding /
	// BodySet / BodyPatches / OverrideHost / TLSFingerprint / TimeoutMs /
	// Tag). Documented inline rather than embedded so the JSON schema
	// stays explicit at the boundary.

	FlowID         string      `json:"flow_id,omitempty" jsonschema:"recorded HTTP stream id; when set, omitted base fields are inherited"`
	Method         string      `json:"method,omitempty" jsonschema:"HTTP method base; required when flow_id is empty"`
	Scheme         string      `json:"scheme,omitempty" jsonschema:"http or https; required when flow_id is empty"`
	Authority      string      `json:"authority,omitempty" jsonschema:"Host / :authority; required when flow_id is empty"`
	Path           string      `json:"path,omitempty" jsonschema:"request path; required when flow_id is empty"`
	RawQuery       string      `json:"raw_query,omitempty" jsonschema:"raw query string without leading '?'"`
	Headers        []headerKV  `json:"headers,omitempty" jsonschema:"ordered base header list; positions can target headers[N].value / .name"`
	Body           string      `json:"body,omitempty" jsonschema:"base body interpreted per body_encoding"`
	BodyEncoding   string      `json:"body_encoding,omitempty" jsonschema:"text|base64; default text"`
	BodySet        bool        `json:"body_set,omitempty" jsonschema:"set true to override body to empty; otherwise omitting body inherits the original"`
	BodyPatches    []BodyPatch `json:"body_patches,omitempty" jsonschema:"applied to base body before positions"`
	OverrideHost   string      `json:"override_host,omitempty" jsonschema:"redirect dial target while preserving the request's Host/:authority"`
	TLSFingerprint string      `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred"`
	TimeoutMs      *int        `json:"timeout_ms,omitempty" jsonschema:"per-variant timeout in milliseconds; default 30000"`
	Tag            string      `json:"tag,omitempty" jsonschema:"tag stored on every variant Stream's Tags map"`

	// Fuzz-specific fields below.

	Positions []fuzzHTTPPosition `json:"positions" jsonschema:"REQUIRED ordered position list; each describes a typed path into HTTPMessage and the payloads to substitute"`
	StopOn5xx bool               `json:"stop_on_5xx,omitempty" jsonschema:"when true, abort the remaining variants once any variant returns a 5xx response"`
}

// fuzzHTTPPosition describes one fuzz position. Path is a typed
// reference into the HTTPMessage struct (see file-level comment for
// the supported syntax). Payloads is the list of values to substitute
// at this position; the cartesian product across all positions yields
// the variant sequence.
//
// Encoding: each payload is interpreted per encoding ("text" or
// "base64"); defaults to "text".
type fuzzHTTPPosition struct {
	Path     string   `json:"path" jsonschema:"typed path into HTTPMessage: method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value"`
	Payloads []string `json:"payloads" jsonschema:"REQUIRED list of payload values to substitute at this path; at least one element"`
	Encoding string   `json:"encoding,omitempty" jsonschema:"text|base64 — applies to every payload; default text"`
}

// fuzzHTTPResult is the structured response of the fuzz_http tool.
//
// variants is the per-variant outcome list, in execution order. Each
// entry includes the position payload tuple that produced it (so a
// caller can correlate results without re-deriving the cartesian
// product index), the response status code, the body byte length, and
// the new Stream.ID under which RecordStep persisted the variant's
// Flows.
type fuzzHTTPResult struct {
	TotalVariants     int                  `json:"total_variants"`
	CompletedVariants int                  `json:"completed_variants"`
	StoppedReason     string               `json:"stopped_reason,omitempty"`
	Variants          []fuzzHTTPVariantRow `json:"variants"`
	DurationMs        int64                `json:"duration_ms"`
	Tag               string               `json:"tag,omitempty"`
}

// fuzzHTTPVariantRow is one variant's compact result row.
type fuzzHTTPVariantRow struct {
	Index      int               `json:"index"`
	StreamID   string            `json:"stream_id"`
	StatusCode int               `json:"status_code,omitempty"`
	BodySize   int               `json:"body_size,omitempty"`
	Payloads   map[string]string `json:"payloads"`
	Error      string            `json:"error,omitempty"`
	DurationMs int64             `json:"duration_ms"`
}

// registerFuzzHTTP wires the fuzz_http tool into the MCP server.
func (s *Server) registerFuzzHTTP() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz_http",
		Description: "Synchronously fuzz an HTTP request with HTTPMessage-typed positions. Schema mirrors resend_http " +
			"(flow_id + base fields + override_host + tag) plus a positions[] list — each position is a typed path into " +
			"the HTTPMessage (method | scheme | authority | path | raw_query | body | headers[N].name | headers[N].value) " +
			"with a payloads[] list. The cartesian product of all positions yields the variant sequence (capped at " +
			"1000 variants per call). Each variant traverses the same self-contained PluginStepPost → RecordStep " +
			"pipeline as resend_http (PluginStepPre is bypassed per RFC-001 §9.3). Variants are executed sequentially " +
			"with a fresh dial per variant; legacy `fuzz` tool with concurrency / rate limit / overload monitor coexists " +
			"in parallel. stop_on_5xx aborts remaining variants once any variant gets a 5xx response.",
	}, s.handleFuzzHTTP)
}

// handleFuzzHTTP is the top-level handler. It coordinates: input
// validation → base envelope construction (delegates to resend_http
// helpers) → variant enumeration (cartesian product, capped) →
// per-variant pipeline execution with shared dial path → result
// aggregation.
func (s *Server) handleFuzzHTTP(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzHTTPInput) (*gomcp.CallToolResult, *fuzzHTTPResult, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_http",
		"flow_id", input.FlowID,
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_http",
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateFuzzHTTPInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildFuzzHTTPPlan(ctx, &input)
	if err != nil {
		return nil, nil, err
	}

	timeout := defaultReplayTimeout
	if input.TimeoutMs != nil && *input.TimeoutMs > 0 {
		timeout = time.Duration(*input.TimeoutMs) * time.Millisecond
	}

	rows, completed, stopReason, err := s.runFuzzHTTPVariants(ctx, plan, timeout, input.StopOn5xx, input.Tag)
	if err != nil {
		return nil, nil, fmt.Errorf("fuzz_http: %w", err)
	}

	duration := time.Since(start)
	return nil, &fuzzHTTPResult{
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
