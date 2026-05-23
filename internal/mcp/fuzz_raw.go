// Package mcp fuzz_raw.go implements the RFC-001 N8 protocol-typed
// fuzz_raw MCP tool. Builds on top of resend_raw: the same validation
// / dial / pipeline machinery, iterated N times with per-position
// payload substitution against the RawMessage byte payload.
//
// fuzz_raw is the central tool for HTTP request smuggling and other
// byte-level fuzz scenarios — it is the only fuzz_* sibling that lets
// users vary arbitrary bytes anywhere in the wire payload, not just
// typed L7 fields. The tool inherits resend_raw's wire-fidelity
// invariant: payload bytes (substituted via positions or carried via
// override_bytes / patches) are NEVER normalised on the proxy side.
//
// Unlike resend_raw, fuzz_raw makes flow_id OPTIONAL and owns the
// from-scratch byte-injection path that resend_raw deferred. Callers
// can either:
//   - supply flow_id (recovered RawMessage seeds the base bytes), or
//   - supply override_bytes (the entire base payload), or
//   - have a "payload" position with payloads listed (the variant
//     payload itself defines the bytes — base bytes can be empty).
//
// fuzz_raw is a *synchronous* per-call fuzzer suitable for small to
// medium variant counts (≤ maxFuzzRawVariants=1000).
//
// Pipeline placement (RFC §9.3 D1): each variant traverses
//
//	PluginStepPost → RecordStep
//
// — same self-contained pipeline as resend_raw. PluginStepPre and
// InterceptStep are excluded so signing and last-mile post-mutation
// hooks fire exactly once per variant, while pre_pipeline annotation
// hooks (which observe pristine wire-fresh data) stay quiet on fuzzed
// variants.
//
// Position path syntax (RawMessage-typed):
//
//	"payload"           → replace the entire RawMessage.Bytes for the variant
//	"patches[N].data"   → replace patch N's data field for the variant (N ∈ [0, len(patches)))
//
// "payload" wins over the recovered/override base bytes when both are
// present (the position payload becomes the variant bytes wholesale).
// "patches[N].data" mutates the input.Patches[N].Data field for the
// variant, then base+patches assembly proceeds as in resend_raw.
//
// Variant generation: cartesian product across positions (full N-way
// product). Total variant count is capped at maxFuzzRawVariants=1000
// to keep the synchronous tool bounded; callers that need more should
// chain multiple invocations.
package mcp

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/google/uuid"
)

// fuzzRawInput is the typed input for the fuzz_raw tool.
//
// flow_id is OPTIONAL (unlike resend_raw where it is REQUIRED) — fuzz_raw
// owns the ad-hoc-bytes path. When flow_id is empty, callers must
// either supply override_bytes or include a "payload" position so each
// variant carries its own bytes.
//
// override_bytes / override_bytes_set / patches behave identically to
// resend_raw at base-payload assembly time. positions are applied on
// top of the assembled base, per variant.
type fuzzRawInput struct {
	FlowID                string        `json:"flow_id,omitempty" jsonschema:"recorded raw stream id; OPTIONAL — when empty, override_bytes or a 'payload' position must supply the variant bytes"`
	TargetAddr            string        `json:"target_addr" jsonschema:"upstream host:port; REQUIRED. Explicit port required (no defaulting — raw is protocol-agnostic)"`
	UseTLS                bool          `json:"use_tls,omitempty" jsonschema:"true to upgrade the dialed connection to TLS via tlslayer.Client"`
	SNI                   string        `json:"sni,omitempty" jsonschema:"SNI server name; defaults to target_addr host portion when use_tls=true"`
	OverrideBytes         string        `json:"override_bytes,omitempty" jsonschema:"replacement payload interpreted per override_bytes_encoding; mutually exclusive with patches"`
	OverrideBytesEncoding string        `json:"override_bytes_encoding,omitempty" jsonschema:"text|base64; defaults to text. base64 required for binary smuggling payloads"`
	OverrideBytesSet      bool          `json:"override_bytes_set,omitempty" jsonschema:"set true to replace with empty bytes; otherwise an empty override_bytes string is treated as no override"`
	Patches               []resendRawBP `json:"patches,omitempty" jsonschema:"offset-based byte patches applied to the base bytes; mutually exclusive with override_bytes. Used as a base for 'patches[N].data' positions"`
	InsecureSkipVerify    bool          `json:"insecure_skip_verify,omitempty" jsonschema:"skip TLS server certificate verification when use_tls=true"`
	TLSFingerprint        string        `json:"tls_fingerprint,omitempty" jsonschema:"informational v1; per-call selection deferred — server uses its configured fingerprint"`
	TimeoutMs             *int          `json:"timeout_ms,omitempty" jsonschema:"per-variant timeout in milliseconds; default 30000"`
	Tag                   string        `json:"tag,omitempty" jsonschema:"tag stored on every variant Stream's Tags map"`

	// Fuzz-specific fields below.

	Positions   []fuzzRawPosition `json:"positions" jsonschema:"REQUIRED ordered position list; each describes a typed path into the payload and the payloads to substitute"`
	StopOnError bool              `json:"stop_on_error,omitempty" jsonschema:"when true, abort the remaining variants once any variant fails (network error, timeout, or pipeline drop)"`

	// PreMacro / PostMacro: pre/post macro hooks (USK-986; sibling of
	// USK-960 / USK-961 / USK-983 for fuzz_http). scope="iteration"
	// (default) shares a per-variant KV Store with the variant's pipeline
	// so reserved keys §__iteration§ / §__nonce§, pre extracts, and (for
	// post) the raw-specific __response_* keys (__response_body /
	// __response_chunks / __response_truncated) are visible to template
	// expansion. scope="job" runs the hook exactly once outside the
	// variant loop against a job-scoped KV Store that is merged into
	// each iteration's store before per-iteration reserved keys are
	// seeded.
	//
	// Raw-specific constraint: post_macro run_interval="on_status" is
	// REJECTED at validation because raw has no L7 status concept (only
	// a byte stream and chunk count). Use run_interval="on_match"
	// against the received bytes via __response_body instead.
	PreMacro  *MacroConfig `json:"pre_macro,omitempty" jsonschema:"pre macro hook executed before a variant's dial. scope=iteration (default; fires once per variant) | job (fires once before the variant loop; extracts shared with every variant). on_error: skip|abort|continue (default skip). run_interval='on_status' is rejected (raw has no L7 status)"`
	PostMacro *MacroConfig `json:"post_macro,omitempty" jsonschema:"post macro hook executed after a variant's receive loop ends (EOF or response cap). scope=iteration (default; fires once per variant against __response_body / __response_chunks / __response_truncated reserved keys — no __response_status / __response_headers, raw has no L7 status concept) | job (fires once after the variant loop completes; no __response_* keys). on_error: skip|abort|continue (default skip). run_interval='on_status' is rejected; use run_interval='on_match' against __response_body bytes"`
}

// fuzzRawPosition describes one fuzz position. Path is one of:
//   - "payload"           — substitute the entire RawMessage.Bytes
//   - "patches[N].data"   — substitute patch N's data field (requires patches[N] in input)
//
// Encoding: each payload is interpreted per encoding ("text" or
// "base64"); defaults to "text". base64 is required for binary
// payloads (smuggling templates often contain control bytes).
type fuzzRawPosition struct {
	Path     string   `json:"path" jsonschema:"typed path into the payload: payload | patches[N].data"`
	Payloads []string `json:"payloads" jsonschema:"REQUIRED list of payload values to substitute at this path; at least one element"`
	Encoding string   `json:"encoding,omitempty" jsonschema:"text|base64 — applies to every payload; default text"`
}

// fuzzRawResult is the structured response of the fuzz_raw tool.
//
// variants is the per-variant outcome list, in execution order. Each
// entry includes the position payload tuple that produced it (so a
// caller can correlate results without re-deriving the cartesian
// product index), the response body byte length, and the new Stream.ID
// under which RecordStep persisted the variant's Flows.
//
// fuzz_id is the UUID PK of the corresponding fuzz_jobs row (USK-837,
// parity with USK-827 for fuzz_http). AI agents chain this with
// `query { resource: "fuzz_results", filter: { fuzz_id: ...,
// outliers_only: true } }` to surface per-run outlier variants without
// re-running the fuzz job.
type fuzzRawResult struct {
	FuzzID            string              `json:"fuzz_id"`
	TotalVariants     int                 `json:"total_variants"`
	CompletedVariants int                 `json:"completed_variants"`
	StoppedReason     string              `json:"stopped_reason,omitempty"`
	Variants          []fuzzRawVariantRow `json:"variants"`
	DurationMs        int64               `json:"duration_ms"`
	Tag               string              `json:"tag,omitempty"`
}

// fuzzRawVariantRow is one variant's compact result row. Raw has no
// status code so the row exposes response_size + response_chunks +
// truncated for shape diagnostics.
type fuzzRawVariantRow struct {
	Index          int               `json:"index"`
	StreamID       string            `json:"stream_id"`
	ResponseSize   int               `json:"response_size,omitempty"`
	ResponseChunks int               `json:"response_chunks,omitempty"`
	Truncated      bool              `json:"truncated,omitempty"`
	Payloads       map[string]string `json:"payloads"`
	Error          string            `json:"error,omitempty"`
	DurationMs     int64             `json:"duration_ms"`
}

// registerFuzzRaw wires the fuzz_raw tool into the MCP server.
func (s *Server) registerFuzzRaw() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "fuzz_raw",
		Description: "Synchronously fuzz a raw byte payload — the central HTTP smuggling fuzzing surface. " +
			"Schema mirrors resend_raw plus a positions[] list (typed path: payload | patches[N].data) with payloads[]. " +
			"flow_id is OPTIONAL; when empty, override_bytes or a 'payload' position must supply the variant bytes. " +
			"The cartesian product of positions yields the variant sequence (capped at 1000 per call). " +
			"Wire bytes are NEVER normalized — they reach the wire verbatim. " +
			"stop_on_error aborts on the first failure. " +
			"pre_macro / post_macro hooks dispatch around each variant (scope=iteration) or once per job (scope=job); " +
			"raw has no L7 status concept so post_macro run_interval='on_status' is rejected — use 'on_match' against __response_body. " +
			"See yorishiro://help/fuzz_raw.",
	}, s.handleFuzzRaw)
}

// handleFuzzRaw is the top-level handler. It coordinates: input
// validation → base-bytes resolution (delegates to resend_raw helpers
// when flow_id present) → variant enumeration (cartesian product,
// capped) → per-variant pipeline execution with shared dial path →
// result aggregation.
func (s *Server) handleFuzzRaw(ctx context.Context, _ *gomcp.CallToolRequest, input fuzzRawInput) (*gomcp.CallToolResult, *fuzzRawResult, error) {
	start := time.Now()
	fuzzID := uuid.NewString()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "fuzz_raw",
		"flow_id", input.FlowID,
		"target_addr", input.TargetAddr,
		"use_tls", input.UseTLS,
		"fuzz_id", fuzzID,
		"positions", len(input.Positions),
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "fuzz_raw",
			"fuzz_id", fuzzID,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateFuzzRawInput(&input); err != nil {
		return nil, nil, err
	}

	plan, err := s.buildFuzzRawPlan(ctx, &input)
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
	// row existing. Mirrors fuzz_http (USK-827) precedent.
	s.saveFuzzRawJob(context.Background(), fuzzID, &input, plan)

	rows, completed, stopReason, runErr := s.runFuzzRawVariants(ctx, plan, timeout, input.StopOnError, input.Tag, fuzzID, input.PreMacro, input.PostMacro)

	// Use a fresh background ctx so the closing UPDATE always lands,
	// even on caller-side ctx cancel. The store-write is best-effort:
	// the per-variant Flow rows persisted via RecordStep are the source
	// of truth; fuzz_jobs is the aggregation layer.
	s.finalizeFuzzRawJob(context.Background(), fuzzID, rows, completed, stopReason, runErr)

	if runErr != nil {
		return nil, nil, fmt.Errorf("fuzz_raw: %w", runErr)
	}

	duration := time.Since(start)
	return nil, &fuzzRawResult{
		FuzzID:            fuzzID,
		TotalVariants:     plan.totalVariants,
		CompletedVariants: completed,
		StoppedReason:     stopReason,
		Variants:          rows,
		DurationMs:        duration.Milliseconds(),
		Tag:               input.Tag,
	}, nil
}
