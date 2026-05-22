// Package mcp fuzz_http.go implements the protocol-typed fuzz_http MCP
// tool. Builds on top of resend_http: the same validation / dial /
// pipeline machinery, iterated N times with per-position payload
// substitution against the HTTPMessage envelope. This is a *synchronous*
// per-call fuzzer suitable for small to medium variant counts
// (≤ maxFuzzHTTPVariants=1000).
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
// chain multiple invocations.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/uuid"
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
	Path           string      `json:"path,omitempty" jsonschema:"request path; required when flow_id is empty. A literal '?' splits this into path + raw_query automatically; supplying both raw_query AND a '?' in path returns an error"`
	RawQuery       string      `json:"raw_query,omitempty" jsonschema:"raw query string without leading '?'. Mutually exclusive with embedding a query in path"`
	Headers        []headerKV  `json:"headers,omitempty" jsonschema:"ordered base header list; positions can target headers[N].value / .name (headers[N] indexes the input array; Host auto-injected from authority is not addressable here — use the authority path to fuzz Host)"`
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

	UpstreamProxy *UpstreamProxyConfig `json:"upstream_proxy,omitempty" jsonschema:"optional upstream proxy override applied per variant. url_template is re-expanded once per variant against §__iteration§ (variant index) and §__nonce§ (per-variant UUID), and the parsed URL tunnels the variant's dial via HTTP CONNECT or SOCKS5. Used for residential proxy IP rotation: each variant exits from a distinct upstream IP"`

	// PreMacro / PostMacro: pre/post macro hooks (USK-960 per-iteration,
	// USK-961 per-job + mix-scope). scope="iteration" (default) shares a
	// per-variant KV Store with the variant's pipeline so reserved keys
	// §__iteration§ / §__nonce§, pre extracts, and (for post) reserved
	// __response_* keys are visible to template expansion. scope="job"
	// runs the hook exactly once outside the variant loop against a
	// job-scoped KV Store that is merged into each iteration's store
	// before per-iteration reserved keys are seeded — so pre=job extracts
	// flow into every variant's request templating. mix-scope (pre and
	// post with independent scope) is supported.
	PreMacro  *fuzzHTTPMacroConfig `json:"pre_macro,omitempty" jsonschema:"pre macro hook executed before a variant's send. scope=iteration (default; fires once per variant) | job (fires once before the variant loop; extracts shared with every variant). on_error: skip|abort|continue (default skip). For scope=job, skip returns a successful job result with completed_variants=0 and stopped_reason set"`
	PostMacro *fuzzHTTPMacroConfig `json:"post_macro,omitempty" jsonschema:"post macro hook executed after a variant's response. scope=iteration (default; fires once per variant against __response_* reserved keys) | job (fires once after the variant loop completes; no __response_* keys, since there is no single response). on_error: skip|abort|continue (default skip). For scope=iteration, pass_response is forced on so __response_status / __response_body / __response_headers__<lower(name)>__ are visible to the macro's template expansion"`
}

// fuzzHTTPMacroConfig is the pre/post macro hook configuration for
// fuzz_http (USK-960 per-iteration, USK-961 per-job + mix-scope).
//
// scope="iteration" (default) fires once per variant; the per-iteration
// KV Store is allocated fresh in the variant loop with reserved keys
// §__iteration§ / §__nonce§ seeded and (for post) reserved __response_*
// keys injected before the macro runs.
//
// scope="job" fires exactly once outside the variant loop against a
// separate job-scoped KV Store that is merged into each iteration's
// store before per-iteration reserved keys are seeded — so pre=job
// extracts flow into every variant's request templating, and post=job
// summarises after the loop completes. Reserved keys (§__iteration§,
// §__nonce§, __response_*) are NOT visible to job-scope macros (the
// loop has not started for pre-job, and is over with discarded per-
// iteration kvStores for post-job). run_interval is rejected when
// scope="job" (single-fire by construction).
type fuzzHTTPMacroConfig struct {
	// Name is the stored macro name (defined via macro.define).
	Name string `json:"name" jsonschema:"REQUIRED stored macro name"`

	// Scope: "iteration" (default) or "job". Mix-scope is supported —
	// pre and post may independently select their scope. Empty defaults
	// to "iteration".
	Scope string `json:"scope,omitempty" jsonschema:"iteration (default; fires once per variant) | job (fires once outside the variant loop; KV Store is shared across the whole job and merged into each iteration's per-variant store)"`

	// OnError selects the iteration's behaviour when the hook errors.
	//   "skip"     (default) — record the iteration as skipped, do not send
	//                          the fuzz request, do not run the post hook,
	//                          continue to the next variant.
	//   "abort"    — abort the fuzz run with an error.
	//   "continue" — log the error, persist a fuzz_macro_results row, and
	//                continue to the variant's send (templates may carry
	//                unresolved §var§ literals — recorded in
	//                fuzz_results.error).
	OnError string `json:"on_error,omitempty" jsonschema:"skip (default) | abort | continue"`

	// Vars is a static map of kvStore overrides injected before the macro
	// runs. Keys with the reserved prefix ("__") are silently dropped at
	// injection time (matches internal/job/job.go:mergeKVStore precedent)
	// so a Vars entry cannot shadow runtime-populated reserved keys such
	// as __iteration / __nonce / __response_* (USK-981 Q2).
	//
	// scope="iteration": Vars is injected into every variant's per-
	// iteration kvStore after the job-store copy and before
	// SeedIterationKV — so the operator's static overrides are visible to
	// §var§ template expansion on the variant request but cannot shadow
	// per-iteration reserved keys.
	//
	// scope="job": Vars is injected once into the job kvStore at job
	// start. The job-store is then naturally merged into every per-
	// iteration kvStore via the existing copy at iteration setup.
	Vars map[string]string `json:"vars,omitempty" jsonschema:"static kvStore overrides injected before the macro runs. Keys with the '__' reserved prefix are silently dropped (USK-981)"`

	// RunInterval gates when the hook fires across iterations. Only valid
	// for scope="iteration" — scope="job" hooks fire exactly once by
	// construction and the validator rejects scope="job" + non-empty
	// RunInterval (USK-961 Q10).
	//
	// pre_macro legal values: "always" (default) | "once" | "every_n" |
	// "on_error". post_macro legal values: "always" (default) |
	// "on_status" | "on_match". Pre and post have disjoint legal sets;
	// validation runs per-direction via the underlying hooks.go
	// validators (USK-981 Q7).
	RunInterval string `json:"run_interval,omitempty" jsonschema:"hook firing cadence (scope=iteration only). pre_macro: always (default) | once | every_n | on_error. post_macro: always (default) | on_status | on_match. Rejected when scope='job'"`

	// N is the interval count for RunInterval="every_n". Required when
	// RunInterval="every_n"; ignored otherwise.
	N int `json:"n,omitempty" jsonschema:"iteration cadence for RunInterval='every_n' (>= 1)"`

	// StatusCodes is the list of response status codes that gate
	// post_macro firing for RunInterval="on_status". Required when
	// RunInterval="on_status"; ignored otherwise. post_macro only.
	StatusCodes []int `json:"status_codes,omitempty" jsonschema:"response status codes for post_macro RunInterval='on_status'"`

	// MatchPattern is the regex pattern matched against the response body
	// for post_macro RunInterval="on_match". Required when
	// RunInterval="on_match"; ignored otherwise. post_macro only.
	MatchPattern string `json:"match_pattern,omitempty" jsonschema:"response body regex pattern for post_macro RunInterval='on_match'"`

	// compiledPattern is the pre-compiled MatchPattern, set during
	// validation so the hook executor reuses it across iterations rather
	// than recompiling. Not serialised — internal to the validator/
	// executor handoff. Matches the precedent on hookConfig.compiledPattern.
	compiledPattern *regexp.Regexp `json:"-"`
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
//
// fuzz_id is the UUID PK of the corresponding fuzz_jobs row (USK-827).
// AI agents chain this with `query { resource: "fuzz_results", filter:
// { fuzz_id: ..., outliers_only: true } }` to surface per-run outlier
// variants without re-running the fuzz job.
type fuzzHTTPResult struct {
	FuzzID            string               `json:"fuzz_id"`
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
		Description: "Synchronously fuzz an HTTP request. Schema mirrors resend_http plus a positions[] list — " +
			"each position is a typed path (method | scheme | authority | path | raw_query | body | " +
			"headers[N].name | headers[N].value) with payloads[]. The cartesian product of positions yields " +
			"the variant sequence (capped at 1000 per call). Variants run sequentially with a fresh dial each. " +
			"Base path may carry a literal '?' (auto-split into path + raw_query); supplying both raw_query " +
			"AND a '?' in path is rejected. " +
			"stop_on_5xx aborts on the first 5xx response. See yorishiro://help/fuzz_http.",
	}, s.handleFuzzHTTP)
}

// handleFuzzHTTP is the top-level handler. It coordinates: input
// validation → base envelope construction (delegates to resend_http
// helpers) → variant enumeration (cartesian product, capped) →
// per-variant pipeline execution with shared dial path → result
// aggregation.
func (s *Server) handleFuzzHTTP(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzHTTPInput) (*gomcp.CallToolResult, *fuzzHTTPResult, error) {
	start := time.Now()
	fuzzID := uuid.NewString()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_http",
		"flow_id", input.FlowID,
		"fuzz_id", fuzzID,
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_http",
			"fuzz_id", fuzzID,
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

	// Insert the fuzz_jobs row at status="running" BEFORE the variant
	// loop so any concurrent `query fuzz_jobs` observes the run.
	//
	// Use a fresh background context so a caller-side cancel landing
	// AFTER plan-build but BEFORE the first variant cannot prevent the
	// row from being created — the finalize UPDATE below relies on this
	// row existing. Mirrors applyResendHTTPTag's precedent for store
	// writes that must not be cancelled by the request context.
	s.saveFuzzHTTPJob(context.Background(), fuzzID, &input, plan)

	rows, completed, stopReason, runErr := s.runFuzzHTTPVariants(ctx, plan, timeout, input.StopOn5xx, input.Tag, fuzzID, input.UpstreamProxy, input.PreMacro, input.PostMacro)

	// Use a fresh background ctx so the closing UPDATE always lands,
	// even on caller-side ctx cancel. The store-write is best-effort:
	// the per-variant Flow rows persisted via RecordStep are the source
	// of truth; fuzz_jobs is the aggregation layer.
	s.finalizeFuzzHTTPJob(context.Background(), fuzzID, rows, completed, stopReason, runErr)

	if runErr != nil {
		return nil, nil, fmt.Errorf("fuzz_http: %w", runErr)
	}

	duration := time.Since(start)
	return nil, &fuzzHTTPResult{
		FuzzID:            fuzzID,
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
