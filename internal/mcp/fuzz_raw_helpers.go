// Package mcp fuzz_raw_helpers.go holds the building blocks used by
// fuzz_raw.go: input validation, base-bytes resolution (via flow_id
// recovery or override_bytes), variant enumeration (cartesian product
// with hard cap), per-variant payload application against the
// RawMessage byte payload, the dial / pipeline factory (reused from
// resend_raw), the per-variant run loop, and result formatting.
//
// # Payload passthrough — by design (MITM principle)
//
// Position payloads substituted into the variant byte sequence via
// applyFuzzRawPositions are written verbatim, including CR/LF, NUL,
// and other control characters. This is intentional: fuzz_raw is the
// central tool for HTTP request smuggling, dual-CL/TE fuzz, malformed
// framing, and other byte-level wire anomalies. Adding a CRLF guard at
// substitution time would defeat the purpose of the tool — payloads
// are the wire.
//
// This is consistent with the project-wide MITM Implementation Principle
// "Do not normalize what the wire did not normalize" (CLAUDE.md). CRLF
// guards apply ONLY to user-supplied URL components (target_addr, sni)
// — never to payload bytes, override_bytes, patches[].data, position
// payloads, or recovered Flow.RawBytes.
//
// SafetyFilter input gating still runs per-variant inside
// runFuzzRawSingleVariant (after position application, before the
// upstream dial), so the destructive-sql / destructive-os-command
// presets continue to apply to the substituted payload — fuzzing CRLF
// is allowed; sending `rm -rf /` is not, when the configured rules say
// so.
package mcp

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/job"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzRawVariants caps the cartesian product across all positions.
// Mirrors maxFuzzHTTPVariants — 1000 variants is a balance between
// meaningful synchronous fuzz runs and bounded server-side resource
// use; callers that need more should chain calls.
const maxFuzzRawVariants = 1000

// maxFuzzRawPositions caps the number of positions per call. Mirrors
// maxFuzzHTTPPositions. Practical raw fuzz jobs use 1-2 positions
// (e.g. one "payload" or two "patches[N].data" against a smuggling
// template).
const maxFuzzRawPositions = 32

// maxFuzzRawPayloadSize caps the *decoded* size of a single position
// payload. Mirrors maxFuzzHTTPPayloadSize. Without a cap, a 16 MiB
// payload * maxFuzzRawVariants (1000) would queue up 16 GiB of
// allocated payload bytes (sequential, not concurrent — but still a
// footgun). 1 MiB is generous for smuggling fuzz cases (smuggling
// templates rarely exceed a few KiB).
const maxFuzzRawPayloadSize = 1 << 20

// fuzzRawHeadersPathRE matches "patches[N].data" where N is a non-
// negative decimal integer. Captures the index.
var fuzzRawHeadersPathRE = regexp.MustCompile(`^patches\[(\d+)\]\.data$`)

// validateFuzzRawInput rejects malformed inputs at the schema
// boundary before any expensive lookups (flow store, dial) run.
//
// Validation rules:
//   - target_addr required + valid host:port
//   - CRLF rejected in target_addr / sni (NEVER in payload bytes)
//   - override_bytes_encoding / patches[].data_encoding allowlist
//   - override_bytes vs patches mutex (mirrors resend_raw rule)
//   - patches: offset >= 0, offset <= cap, data non-empty, encoding ok
//   - positions: non-empty, within positions cap
//   - each position: path resolves, payloads non-empty, encoding ok,
//     decoded payload size within cap
//   - cartesian product within variants cap
//   - "patches[N].data" path: N within [0, len(input.Patches))
//   - payload source: at least one of {flow_id, override_bytes_set,
//     "payload" position} so each variant has bytes to send
//
// Split into per-section helpers to keep cyclomatic complexity below
// the project lint threshold (15).
func validateFuzzRawInput(input *fuzzRawInput) error {
	if err := validateFuzzRawTargetAndSNI(input); err != nil {
		return err
	}
	if err := validateFuzzRawOverrideAndPatches(input); err != nil {
		return err
	}
	hasPayloadPosition, err := validateFuzzRawPositionsList(input)
	if err != nil {
		return err
	}
	hasOverride := input.OverrideBytes != "" || input.OverrideBytesSet
	if input.FlowID == "" && !hasOverride && !hasPayloadPosition {
		return errors.New("fuzz_raw: at least one of flow_id, override_bytes, or a 'payload' position must supply the variant bytes")
	}
	if err := validateFuzzRawMacroConfig(input); err != nil {
		return err
	}
	return nil
}

// validateFuzzRawMacroConfig validates the per-iteration / per-job
// macro hook configs (USK-986). Raw is the "+1 adaptor" in USK-980's
// N-1 uniform + 1 adaptor pattern — raw has no L7 status concept, so
// run_interval="on_status" is REJECTED upfront with the documented
// verbatim error message before delegating to the shared
// ValidateMacroConfig for the rest of the cross-field rules.
//
// The shared validator (fuzz_macro_common.go:ValidateMacroConfig) stays
// protocol-neutral; the raw-specific reject lives here as a thin pre-
// check wrapper so the shared seam does not have to grow a protocol-
// aware branch.
func validateFuzzRawMacroConfig(input *fuzzRawInput) error {
	if input.PreMacro != nil && input.PreMacro.RunInterval == "on_status" {
		return errors.New(`fuzz_raw: pre_macro run_interval="on_status" not supported (raw has no L7 status)`)
	}
	if input.PostMacro != nil && input.PostMacro.RunInterval == "on_status" {
		return errors.New(`fuzz_raw: post_macro run_interval="on_status" not supported (raw has no L7 status)`)
	}
	if err := ValidateMacroConfig("pre_macro", input.PreMacro, true); err != nil {
		return err
	}
	if err := ValidateMacroConfig("post_macro", input.PostMacro, false); err != nil {
		return err
	}
	return nil
}

// validateFuzzRawTargetAndSNI checks target_addr (required, host:port,
// no CRLF) and SNI (no CRLF).
func validateFuzzRawTargetAndSNI(input *fuzzRawInput) error {
	if input.TargetAddr == "" {
		return errors.New("target_addr is required (host:port — explicit port mandatory)")
	}
	if err := validateFuzzRawNoCRLF("target_addr", input.TargetAddr); err != nil {
		return err
	}
	if err := validateFuzzRawNoCRLF("sni", input.SNI); err != nil {
		return err
	}
	if _, _, splitErr := net.SplitHostPort(input.TargetAddr); splitErr != nil {
		return fmt.Errorf("invalid target_addr %q: must be host:port (%v)", input.TargetAddr, splitErr)
	}
	return nil
}

// validateFuzzRawOverrideAndPatches checks override_bytes_encoding,
// the override_bytes vs patches mutex, and each patch's shape (mirrors
// resend_raw's per-patch rules).
func validateFuzzRawOverrideAndPatches(input *fuzzRawInput) error {
	if input.OverrideBytesEncoding != "" && input.OverrideBytesEncoding != "text" && input.OverrideBytesEncoding != "base64" {
		return fmt.Errorf("unsupported override_bytes_encoding %q: must be text or base64", input.OverrideBytesEncoding)
	}
	hasOverride := input.OverrideBytes != "" || input.OverrideBytesSet
	if hasOverride && len(input.Patches) > 0 {
		return errors.New("override_bytes and patches are mutually exclusive")
	}
	for i, p := range input.Patches {
		if err := validateResendRawPatch(i, p); err != nil {
			return err
		}
	}
	return nil
}

// validateFuzzRawPositionsList walks the positions list, validating
// each entry, enforcing the per-call positions cap and the cartesian
// product variants cap, and reporting whether any position targets the
// "payload" path (signal needed for the payload-source rule).
//
// Duplicate `path` entries across positions are rejected: the per-variant
// payload map in decodeFuzzRawPayloads is keyed by path, so two positions
// sharing the same path would silently lose the earlier substitution while
// still expanding the cartesian product. Reject up-front so callers see the
// misconfiguration instead of running ~N redundant variants.
func validateFuzzRawPositionsList(input *fuzzRawInput) (bool, error) {
	if len(input.Positions) == 0 {
		return false, errors.New("positions must contain at least one entry")
	}
	if len(input.Positions) > maxFuzzRawPositions {
		return false, fmt.Errorf("positions has %d entries; max %d per call", len(input.Positions), maxFuzzRawPositions)
	}
	hasPayloadPosition := false
	totalVariants := 1
	seenPaths := make(map[string]int, len(input.Positions))
	for i, p := range input.Positions {
		if err := validateFuzzRawPosition(i, p, len(input.Patches)); err != nil {
			return false, err
		}
		if prev, ok := seenPaths[p.Path]; ok {
			return false, fmt.Errorf("positions[%d]: duplicate path %q (already declared at positions[%d]); each path may appear at most once", i, p.Path, prev)
		}
		seenPaths[p.Path] = i
		if p.Path == "payload" {
			hasPayloadPosition = true
		}
		totalVariants *= len(p.Payloads)
		if totalVariants > maxFuzzRawVariants {
			return false, fmt.Errorf("positions cartesian product exceeds %d variants (computed at position %d); reduce payload counts or split into multiple calls", maxFuzzRawVariants, i)
		}
	}
	return hasPayloadPosition, nil
}

// validateFuzzRawNoCRLF rejects CR/LF in user-supplied URL
// components. Wire bytes (payload / patches data / position payloads)
// are NOT subject to this guard — see file-level comment.
func validateFuzzRawNoCRLF(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains CR/LF characters", field)
	}
	return nil
}

// validateFuzzRawPosition validates one position entry: the path must
// resolve to a known payload-byte field, the payloads list must be
// non-empty, and the encoding must be in the allowlist. For
// "patches[N].data" paths, N must be a valid index into input.Patches.
func validateFuzzRawPosition(index int, p fuzzRawPosition, patchCount int) error {
	if p.Path == "" {
		return fmt.Errorf("positions[%d]: path must not be empty", index)
	}
	if !isValidFuzzRawPath(p.Path, patchCount) {
		return fmt.Errorf("positions[%d]: unsupported path %q (valid: payload, patches[N].data with N < %d)", index, p.Path, patchCount)
	}
	if len(p.Payloads) == 0 {
		return fmt.Errorf("positions[%d]: payloads must contain at least one element", index)
	}
	if p.Encoding != "" && p.Encoding != "text" && p.Encoding != "base64" {
		return fmt.Errorf("positions[%d]: unsupported encoding %q: must be text or base64", index, p.Encoding)
	}
	return nil
}

// isValidFuzzRawPath reports whether path resolves to a supported
// payload-byte field. "payload" is the wholesale-replacement path.
// "patches[N].data" is the per-patch substitution path; N must be a
// valid index into input.Patches (otherwise caller's request is
// nonsensical — they have no patches[N] to substitute).
func isValidFuzzRawPath(path string, patchCount int) bool {
	if path == "payload" {
		return true
	}
	if matches := fuzzRawHeadersPathRE.FindStringSubmatch(path); matches != nil {
		idx, err := strconv.Atoi(matches[1])
		if err != nil {
			return false
		}
		return idx >= 0 && idx < patchCount
	}
	return false
}

// fuzzRawPlan is the resolved base bytes + dial parameters + variant
// enumeration. baseBytes is the post-recovery / post-override starting
// point; positions modify it per variant. basePatches is the cloned
// input.Patches list — variant patches are derived from this clone
// after "patches[N].data" position substitutions are applied.
type fuzzRawPlan struct {
	connID string

	// useTLS, dialAddr, sni resolve the upstream dial target.
	useTLS   bool
	dialAddr string
	sni      string

	// baseBytes is the post-recovery / post-override starting point.
	// nil is allowed when no flow_id + no override_bytes (every
	// variant must then carry a "payload" position).
	baseBytes []byte

	// basePatches is a clone of input.Patches (with already-decoded
	// data fields). Per-variant: variantPatches := clone(basePatches),
	// apply "patches[N].data" substitutions, then ApplyPatches.
	basePatches []job.BytePatch

	insecureSkipVerify bool

	positions     []fuzzRawPosition
	totalVariants int
}

// buildFuzzRawPlan resolves the base bytes (via flow_id recovery or
// override_bytes), decodes input.Patches data fields, computes the
// dial target, and counts the total variants.
func (s *Server) buildFuzzRawPlan(ctx context.Context, input *fuzzRawInput) (*fuzzRawPlan, error) {
	baseBytes, err := s.resolveFuzzRawBase(ctx, input)
	if err != nil {
		return nil, err
	}
	if len(baseBytes) > maxResendRawPayload {
		return nil, fmt.Errorf("fuzz_raw: base payload too large: %d > %d", len(baseBytes), maxResendRawPayload)
	}

	basePatches, err := decodeFuzzRawBasePatches(input.Patches)
	if err != nil {
		return nil, err
	}

	plan := &fuzzRawPlan{
		connID:             uuid.NewString(),
		useTLS:             input.UseTLS,
		dialAddr:           input.TargetAddr,
		baseBytes:          baseBytes,
		basePatches:        basePatches,
		insecureSkipVerify: input.InsecureSkipVerify,
		positions:          input.Positions,
	}
	if input.UseTLS {
		host, _, _ := net.SplitHostPort(input.TargetAddr)
		plan.sni = input.SNI
		if plan.sni == "" {
			plan.sni = host
		}
	}

	// Enforce TargetScope on the dial address before any per-variant
	// work. Mirrors resend_raw's checkResendRawScope.
	scheme := ""
	if plan.useTLS {
		scheme = "https"
	}
	if err := s.checkTargetScopeAddr(scheme, plan.dialAddr); err != nil {
		return nil, err
	}

	plan.totalVariants = 1
	for _, p := range input.Positions {
		plan.totalVariants *= len(p.Payloads)
	}
	return plan, nil
}

// resolveFuzzRawBase produces the post-recovery / post-override base
// bytes. flow_id wins over override_bytes when both are supplied
// (recovered bytes are the canonical seed; override_bytes is the
// from-scratch fallback for ad-hoc fuzz). When neither is supplied,
// nil is returned and per-variant "payload" positions must supply the
// bytes (validation enforces this).
func (s *Server) resolveFuzzRawBase(ctx context.Context, input *fuzzRawInput) ([]byte, error) {
	if input.FlowID != "" {
		if s.flowStore.store == nil {
			return nil, errors.New("fuzz_raw: flow store is not initialized")
		}
		stream, err := s.flowStore.store.GetStream(ctx, input.FlowID)
		if err != nil {
			return nil, fmt.Errorf("fuzz_raw: get stream %s: %w", input.FlowID, err)
		}
		if !resendRawSupportedProtocols[stream.Protocol] {
			return nil, fmt.Errorf("fuzz_raw: protocol %q not supported by this tool — use fuzz_http for non-raw flows", stream.Protocol)
		}
		// Recover with no overrides — base patches and overrides are
		// applied per-variant by runFuzzRawSingleVariant so that
		// "patches[N].data" position substitutions can mutate them.
		source := job.NewRawResendSource(s.flowStore.store, input.FlowID, job.RawResendOverrides{})
		srcEnv, err := source.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("fuzz_raw: recover bytes: %w", err)
		}
		rawMsg, ok := srcEnv.Message.(*envelope.RawMessage)
		if !ok {
			return nil, fmt.Errorf("fuzz_raw: source returned %T, expected *RawMessage", srcEnv.Message)
		}
		return rawMsg.Bytes, nil
	}
	if input.OverrideBytes != "" || input.OverrideBytesSet {
		decoded, err := decodeBodyEncoded(input.OverrideBytes, input.OverrideBytesEncoding, "override_bytes")
		if err != nil {
			return nil, err
		}
		return decoded, nil
	}
	return nil, nil
}

// decodeFuzzRawBasePatches decodes each input patch's data field once
// and returns a job.BytePatch slice ready for per-variant cloning. The
// returned slice carries decoded bytes; per-variant substitutions
// replace the .Data field of a copy of this slice.
func decodeFuzzRawBasePatches(in []resendRawBP) ([]job.BytePatch, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]job.BytePatch, 0, len(in))
	for i, p := range in {
		data, err := decodeBodyEncoded(p.Data, p.DataEncoding, fmt.Sprintf("patches[%d].data", i))
		if err != nil {
			return nil, err
		}
		out = append(out, job.BytePatch{Offset: p.Offset, Data: data})
	}
	return out, nil
}

// runFuzzRawVariants iterates the cartesian product of all positions,
// running each variant through the fuzz_raw pipeline + dial path.
// Returns the per-variant rows, the count of completed variants, and
// an optional stop reason ("" when all variants ran to completion).
//
// USK-837: persists one fuzz_results row per variant via
// FuzzStore.SaveFuzzResult so `query fuzz_results { fuzz_id }` is
// populated for both successful and error variants. Store-write
// failures are non-fatal (slog.Warn + continue) — the wire data is on
// disk via RecordStep and remains the source of truth.
//
// USK-986: scope="job" hooks fire exactly once outside the variant
// loop against a separate job-scoped kvStore that is merged into each
// iteration's per-variant store. pre-job runs between loop-state setup
// and the for-variant loop; post-job runs after the loop body exits
// (including the stop_on_error terminal path, but NOT on ctx cancel
// or pre-job abort).
func (s *Server) runFuzzRawVariants(ctx context.Context, plan *fuzzRawPlan, timeout time.Duration, stopOnError bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) ([]fuzzRawVariantRow, int, string, error) {
	loop := buildFuzzRawVariantLoop(s, plan, timeout, stopOnError, tag, fuzzID, preMacro, postMacro)

	// USK-986 pre-job: fire once before the variant loop. Abort short-
	// circuits the whole job; skip returns success with stopped_reason;
	// continue records the error and proceeds with whatever jobKVStore
	// captured. Mirrors the fuzz_http pattern (USK-961).
	if IsJobScope(preMacro) {
		jobAction, stopReason, retErr := loop.runPreJobMacro(ctx)
		if retErr != nil {
			return loop.rows, loop.completed, "", retErr
		}
		if jobAction == fuzzRawPreJobSkipAll {
			return loop.rows, loop.completed, stopReason, nil
		}
	}

	completedNormally, earlyStopReason, retErr := loop.runVariantLoop(ctx)
	if retErr != nil {
		return loop.rows, loop.completed, "", retErr
	}

	// USK-986 post-job: fire after the variant loop exits. post-job
	// fires on natural exhaustion or stop_on_error exit, but NOT on
	// ctx cancel (mirrors fuzz_http Q5).
	if completedNormally && IsJobScope(postMacro) {
		loop.runPostJobMacro(ctx)
	}

	return loop.rows, loop.completed, earlyStopReason, nil
}

// fuzzRawVariantLoop bundles the per-run state shared across iterations
// so the inner loop body (runOne) is a method on a small struct instead
// of a wide free function. Mirrors fuzzHTTPVariantLoop's shape (USK-961)
// adapted for raw's simpler dial / receive-loop semantics: no upstream-
// proxy rotation, no template expansion on the base bytes (raw is a
// byte stream — template expansion happens on the position payloads
// only via §var§ tokens that are then assembled into the variant bytes).
type fuzzRawVariantLoop struct {
	s             *Server
	plan          *fuzzRawPlan
	timeout       time.Duration
	stopOnError   bool
	tag           string
	fuzzID        string
	preMacro      *MacroConfig
	postMacro     *MacroConfig
	pipe          *pipeline.Pipeline
	hookExec      *hookExecutor
	jobHookExec   *hookExecutor
	jobKVStore    map[string]string
	rateLimitHost string

	rows      []fuzzRawVariantRow
	indices   []int
	completed int
}

// buildFuzzRawVariantLoop assembles the per-run state container shared
// by all variants. Split out of runFuzzRawVariants to keep that function
// below the gocyclo threshold and mirror the fuzz_http construction
// pattern.
func buildFuzzRawVariantLoop(s *Server, plan *fuzzRawPlan, timeout time.Duration, stopOnError bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) *fuzzRawVariantLoop {
	loop := &fuzzRawVariantLoop{
		s:           s,
		plan:        plan,
		timeout:     timeout,
		stopOnError: stopOnError,
		tag:         tag,
		fuzzID:      fuzzID,
		preMacro:    preMacro,
		postMacro:   postMacro,
	}

	encoders := buildResendRawEncoderRegistry()
	loop.pipe = s.buildFuzzRawPipeline(encoders)

	loop.rateLimitHost, _, _ = net.SplitHostPort(plan.dialAddr)

	loop.hookExec = BuildIterationHookExecutor(s, preMacro, postMacro)
	// USK-986 adaptor: raw post_macro injects its own __response_body /
	// __response_chunks / __response_truncated via injectRawResponseVars
	// — we do NOT want the HTTP-shaped injectResponseVars (status + body
	// + headers) to fire and overwrite with stale / hypothetical fields.
	// BuildIterationHookExecutor hard-codes PassResponse=true for the
	// HTTP path; for raw we flip it back off so the post-macro engine
	// uses ONLY the keys we explicitly injected. shouldRunPostMacro's
	// on_match gate still receives the raw bytes via executePostMacro's
	// responseBody argument (independent of PassResponse).
	if loop.hookExec != nil && loop.hookExec.hooks != nil && loop.hookExec.hooks.PostMacro != nil {
		loop.hookExec.hooks.PostMacro.PassResponse = false
	}
	loop.jobHookExec, loop.jobKVStore = BuildJobHookExecutor(s, preMacro, postMacro)

	loop.rows = make([]fuzzRawVariantRow, 0, plan.totalVariants)
	loop.indices = make([]int, len(plan.positions))
	return loop
}

// runVariantLoop drives the variant loop body and returns
// (completedNormally, earlyStopReason, retErr). completedNormally is
// true when the loop reached the post-job firing path (natural
// exhaustion or stop_on_error); it is false on ctx cancel. retErr
// non-nil propagates an unrecoverable failure (e.g. per-variant payload
// size cap exceeded) up to the MCP tool boundary as an IsError result.
// Mirrors fuzz_http's runVariantLoop pattern.
func (l *fuzzRawVariantLoop) runVariantLoop(ctx context.Context) (bool, string, error) {
	for variantIdx := 0; variantIdx < l.plan.totalVariants; variantIdx++ {
		select {
		case <-ctx.Done():
			return false, fmt.Sprintf("ctx cancelled: %v", ctx.Err()), nil
		default:
		}

		// TODO(USK-817 sibling: budget counter, P5-19)
		if err := l.s.waitRateLimit(ctx, l.rateLimitHost); err != nil {
			return true, fmt.Sprintf("rate limit: %v", err), nil
		}

		stop, retErr := l.runOne(ctx, variantIdx)
		if retErr != nil {
			return false, "", retErr
		}
		if stop != "" {
			// stop_on_error exit. Mirrors fuzz_http's Q5: post-job fires
			// on stop_on_error.
			return true, stop, nil
		}
	}
	return true, "", nil
}

// runOne executes a single iteration of the variant loop. Returns
// (stopReason, retErr). stopReason "" means continue; non-empty signals
// an early loop stop (e.g. stop_on_error / pre_macro abort). retErr
// non-nil aborts the whole run with a hard error (e.g. payload decode
// cap exceeded — mirrors the pre-refactor behaviour).
func (l *fuzzRawVariantLoop) runOne(ctx context.Context, variantIdx int) (string, error) {
	payloads, err := decodeFuzzRawPayloads(l.plan.positions, l.indices)
	if err != nil {
		return "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
	}

	// USK-986: build the per-iteration kvStore (job-store merge +
	// iteration-scope Vars + reserved __iteration / __nonce). pre_macro
	// extracts and the response __response_* keys (post path) land here.
	kvStore := PrepareIteration(l.jobKVStore, l.preMacro, l.postMacro, variantIdx)

	// pre_macro (iteration-scope only). When pre is scope="job", the
	// executor was invoked once outside the loop by runPreJobMacro.
	if IsIterationScope(l.preMacro) {
		preOutcome := l.runPreMacro(ctx, variantIdx, payloads, kvStore)
		switch preOutcome {
		case fuzzRawPreSkipped:
			// USK-989: counter-only bump — the skip path never reached
			// the wire so there is no wire result to record. The previous
			// wire-completed iteration's lastError remains in place, so
			// an on_error gate on the next iteration still reacts to the
			// most recent real outcome. Mirrors fuzz_http's prep.skipped
			// path (PR #60 / USK-982).
			BumpHookIterationCount(l.hookExec)
			nextFuzzRawIndices(l.indices, l.plan.positions)
			return "", nil
		case fuzzRawPreAborted:
			// on_error=abort: row recorded with row.Error set by
			// runPreMacro; halt the loop with a documented stop reason.
			// USK-989: counter-only bump — abort is also a pre-wire path
			// (the macro errored before any upstream dial), so there is
			// no wire result to record. lastError carries over from the
			// previous wire-completed iteration.
			BumpHookIterationCount(l.hookExec)
			nextFuzzRawIndices(l.indices, l.plan.positions)
			return fmt.Sprintf("pre_macro abort: variant %d failed", variantIdx), nil
		}
	}

	variantStart := time.Now()
	row, respBytes, chunks, truncated, runErr := l.s.runFuzzRawSingleVariantWithResponse(ctx, l.plan, l.pipe, l.timeout, variantIdx, payloads, l.tag)
	row.DurationMs = time.Since(variantStart).Milliseconds()

	if runErr != nil {
		row.Error = runErr.Error()
	}
	l.rows = append(l.rows, row)
	l.completed++

	// USK-837: persist per-variant fuzz_results row so the aggregation
	// view is populated. Save failures are non-fatal.
	l.s.saveFuzzRawResult(ctx, l.fuzzID, variantIdx, row, payloads)

	// post_macro (iteration-scope only). scope="job" post fires once
	// outside the loop. Suppress post on transport error / pre-iteration
	// short-circuit — mirrors fuzz_http's "errored variant" gate.
	if IsIterationScope(l.postMacro) && runErr == nil {
		l.runPostMacro(ctx, variantIdx, row, respBytes, chunks, truncated, kvStore)
	}

	// USK-981 / USK-989: record the iteration's wire result so the next
	// runOne call's shouldRunPreMacro sees the correct lastError for the
	// on_error gate, AND advance the iteration counter for the every_n
	// gate. updateState bumps requestCount and records
	// (statusCode, runErr != nil) atomically — replacing the counter-
	// only BumpHookIterationCount used during USK-981.
	//
	// statusCode is fixed at 0 because raw has no L7 status concept —
	// the on_error gate's `lastStatusCode >= 400` branch in
	// shouldRunPreMacro will therefore never fire on raw; only the
	// `lastError` (transport-error) branch applies. This matches the
	// raw adaptor contract (USK-986 + help_fuzz_raw.md: "raw has no L7
	// status"). The 0 is NOT a bug.
	//
	// Note the per-call-site distinction: only this normal-path branch
	// has wire-result information. The pre-wire abort branches above
	// (pre-macro skip, pre-macro abort) keep BumpHookIterationCount
	// since they never reached the wire and have no wire result to
	// record — leaving lastError unchanged so the previous wire-
	// completed iteration's outcome carries over to the next on_error
	// evaluation. Mirrors PR #60 / USK-982 for fuzz_http.
	l.hookExec.updateState(0, runErr != nil)
	nextFuzzRawIndices(l.indices, l.plan.positions)

	if l.stopOnError && runErr != nil {
		return fmt.Sprintf("stop_on_error: variant %d failed: %v", variantIdx, runErr), nil
	}
	return "", nil
}

// recordVariantError appends a synthetic error-row to the variant rows
// (no upstream send happened) and persists the matching fuzz_results
// row. Used by short-circuit paths (payload decode failure) where the
// variant never reached runFuzzRawSingleVariant. Mirrors the fuzz_http
// pattern.
func (l *fuzzRawVariantLoop) recordVariantError(ctx context.Context, variantIdx int, payloads map[string]string, msg string) {
	row := fuzzRawVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
		Error:    msg,
	}
	l.rows = append(l.rows, row)
	l.completed++
	l.s.saveFuzzRawResult(ctx, l.fuzzID, variantIdx, row, payloads)
}

// fuzzRawPreMacroOutcome marks whether the variant loop should proceed
// with the upstream send after pre_macro resolution.
type fuzzRawPreMacroOutcome int

const (
	// fuzzRawPreOK = pre macro ran successfully (or was not configured);
	// continue to the variant send.
	fuzzRawPreOK fuzzRawPreMacroOutcome = iota
	// fuzzRawPreSkipped = pre macro failed under on_error=skip; the
	// caller has already recorded the skipped row, do NOT send the
	// variant, do NOT fire post_macro.
	fuzzRawPreSkipped
	// fuzzRawPreAborted = pre macro failed under on_error=abort; the
	// caller must terminate the entire variant loop. The row was
	// already recorded with row.Error set.
	fuzzRawPreAborted
)

// runPreMacro dispatches the pre_macro hook for this iteration and
// translates the OnError policy into a pre-macro outcome. Mirrors
// fuzz_http's runPreMacro structure. The kvStore parameter is the
// per-iteration store owned by runOne — pre_macro extracts land here
// so runPostMacro can resolve §var§ tokens that reference them.
func (l *fuzzRawVariantLoop) runPreMacro(ctx context.Context, variantIdx int, payloads map[string]string, kvStore map[string]string) fuzzRawPreMacroOutcome {
	if l.preMacro == nil {
		return fuzzRawPreOK
	}
	_, hookErr := l.hookExec.executePreMacro(ctx, kvStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "ok", 0, "")
		return fuzzRawPreOK
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		// fuzz_raw abort: record the variant as errored AND signal the
		// caller to terminate the whole loop. Mirrors fuzz_http's abort
		// path (which propagates as retErr); fuzz_raw expresses the same
		// intent via a distinct outcome value so the variant loop's
		// stop_on_error-style halt covers both transport errors and
		// pre-hook aborts uniformly.
		l.recordVariantError(ctx, variantIdx, payloads, fmt.Sprintf("pre_macro hook abort: %v", hookErr))
		return fuzzRawPreAborted
	case "continue":
		slog.WarnContext(ctx, "fuzz_raw: pre_macro hook error (on_error=continue)",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		return fuzzRawPreOK
	default: // skip
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "skipped", 0, hookErr.Error())
		row := fuzzRawVariantRow{
			Index:    variantIdx,
			Payloads: payloads,
			Error:    fmt.Sprintf("pre_macro hook failed (on_error=skip): %v", hookErr),
		}
		l.rows = append(l.rows, row)
		l.completed++
		l.s.saveFuzzRawResult(ctx, l.fuzzID, variantIdx, row, payloads)
		return fuzzRawPreSkipped
	}
}

// runPostMacro fires the post_macro hook against the shared kvStore.
// Raw injects __response_body / __response_chunks / __response_truncated
// directly via injectRawResponseVars (NOT __response_status /
// __response_headers — raw has no L7 status concept; USK-986 adaptor).
//
// PassResponse is forced OFF on the raw hookExec (see
// buildFuzzRawVariantLoop) so the HTTP-shaped injectResponseVars
// (status + body + headers) does NOT fire and overwrite our raw inject.
// respBytes is still threaded into executePostMacro so the
// shouldRunPostMacro gate (on_match against responseBody) sees the
// real wire bytes. run_interval="on_status" is REJECTED upfront for
// raw, so statusCode is irrelevant here.
func (l *fuzzRawVariantLoop) runPostMacro(ctx context.Context, variantIdx int, row fuzzRawVariantRow, respBytes []byte, chunks int, truncated bool, kvStore map[string]string) {
	injectRawResponseVars(kvStore, respBytes, chunks, truncated)
	hookErr := l.hookExec.executePostMacro(ctx, 0, respBytes, nil, kvStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_raw: post_macro hook error",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "error", 0, hookErr.Error())
		_ = row
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "ok", 0, "")
}

// fuzzRawJobPreOutcome marks the pre-job hook's effect on the
// surrounding job loop.
type fuzzRawJobPreOutcome int

const (
	// fuzzRawPreJobOK = pre-job ran successfully (or under
	// on_error=continue): proceed with the variant loop.
	fuzzRawPreJobOK fuzzRawJobPreOutcome = iota
	// fuzzRawPreJobSkipAll = pre-job failed under on_error=skip: skip
	// the entire job. fuzz_raw returns a successful result with
	// CompletedVariants=0 and stopped_reason set. Mirrors fuzz_http U1.
	fuzzRawPreJobSkipAll
)

// runPreJobMacro fires the pre_macro hook ONCE outside the variant loop
// (scope="job"). Mirrors fuzz_http's runPreJobMacro structure. Failure
// policies: abort → wrapped error; continue → log+record+proceed; skip
// → record + short-circuit whole job via fuzzRawPreJobSkipAll.
//
// fuzz_macro_results.index_num=-1 is the documented sentinel for
// job-scope hook rows.
func (l *fuzzRawVariantLoop) runPreJobMacro(ctx context.Context) (fuzzRawJobPreOutcome, string, error) {
	if l.jobHookExec == nil || l.preMacro == nil || !IsJobScope(l.preMacro) {
		return fuzzRawPreJobOK, "", nil
	}
	_, hookErr := l.jobHookExec.executePreMacro(ctx, l.jobKVStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "ok", 0, "")
		return fuzzRawPreJobOK, "", nil
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzRawPreJobOK, "", fmt.Errorf("pre_macro hook abort (scope=job): %w", hookErr)
	case "continue":
		slog.WarnContext(ctx, "fuzz_raw: pre_macro hook error (scope=job, on_error=continue)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzRawPreJobOK, "", nil
	default: // skip — short-circuit the whole job with stopped_reason
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "skipped", 0, hookErr.Error())
		stopReason := fmt.Sprintf("pre_macro hook skipped (scope=job, on_error=skip): %v", hookErr)
		return fuzzRawPreJobSkipAll, stopReason, nil
	}
}

// runPostJobMacro fires the post_macro hook ONCE after the variant loop
// completes (scope="job"). post-job fires on natural exhaustion or
// stop_on_error, but NOT on ctx cancel (the caller gates on
// completedNormally). post-job sees ONLY the jobKVStore — per-iteration
// __response_* keys are not available because each iteration's kvStore
// was discarded. Mirrors fuzz_http Q5 / Q21.
func (l *fuzzRawVariantLoop) runPostJobMacro(ctx context.Context) {
	if l.jobHookExec == nil || l.postMacro == nil || !IsJobScope(l.postMacro) {
		return
	}
	hookErr := l.jobHookExec.executePostMacro(ctx, 0, nil, nil, l.jobKVStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_raw: post_macro hook error (scope=job)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "error", 0, hookErr.Error())
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "ok", 0, "")
}

// runFuzzRawSingleVariantWithResponse executes one variant: assembles
// variant bytes from the base + per-variant patches + per-variant
// "payload" position, runs the safety filter, dials, sends, receives,
// and returns the row PLUS the response bytes + chunk count + truncated
// flag so the caller can inject the raw-specific __response_* keys
// into the post_macro kvStore (USK-986).
//
// Per-variant SafetyFilter input gating runs after variant assembly
// and before the upstream dial (mirroring fuzz_http per-variant
// semantics). On a violation the variant is recorded with row.Error
// set and returns nil error so the run loop continues; a single
// blocked variant does not abort the whole run. respBytes is nil /
// chunks=0 / truncated=false on a safety-filter violation or pre-
// network short-circuit — the caller's gate (runErr != nil OR row.Error
// set OR fuzzRawPreSkipped on the pre side) keeps post_macro
// suppressed in those paths.
func (s *Server) runFuzzRawSingleVariantWithResponse(ctx context.Context, plan *fuzzRawPlan, p *pipeline.Pipeline, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzRawVariantRow, []byte, int, bool, error) {
	row := fuzzRawVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantBytes, err := assembleFuzzRawVariantBytes(plan, payloads)
	if err != nil {
		return row, nil, 0, false, fmt.Errorf("assemble variant bytes: %w", err)
	}
	if len(variantBytes) > maxResendRawPayload {
		return row, nil, 0, false, fmt.Errorf("variant payload too large: %d > %d", len(variantBytes), maxResendRawPayload)
	}

	row.StreamID = uuid.NewString()

	// SafetyFilter input gating: run AFTER variant assembly so the
	// destructive-sql / destructive-os-command presets see the substituted
	// payload (matches fuzz_http per-variant semantics). On a violation we
	// record the variant with row.Error and return nil err — the run loop
	// continues to the next variant.
	if v := s.checkSafetyInput(variantBytes, "", nil); v != nil {
		row.Error = safetyViolationError(v)
		return row, nil, 0, false, nil
	}

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	respBytes, chunks, truncated, err := s.runFuzzRawSingleExchange(rtCtx, plan, row.StreamID, variantBytes, p)
	if err != nil {
		return row, nil, 0, false, err
	}
	row.ResponseSize = len(respBytes)
	row.ResponseChunks = chunks
	row.Truncated = truncated

	// Tag persistence uses the parent ctx (not the per-variant rtCtx) so
	// the tag write is not bound to the variant's request timeout —
	// matches fuzz_http behaviour.
	if tag != "" && s.flowStore.store != nil {
		s.applyResendRawTag(ctx, row.StreamID, tag)
	}
	return row, respBytes, chunks, truncated, nil
}

// runFuzzRawSingleExchange runs one variant's send/receive cycle and
// returns (responseBytes, chunkCount, truncated, error). Mirrors
// runResendRaw but takes the already-assembled variant bytes and the
// pre-built pipeline.
//
// Drop / Respond on the receive side is intentionally ignored (mirror
// resend_raw): the diagnostic caller sees what the upstream actually
// sent.
func (s *Server) runFuzzRawSingleExchange(ctx context.Context, plan *fuzzRawPlan, streamID string, payload []byte, p *pipeline.Pipeline) ([]byte, int, bool, error) {
	sendEnv := buildFuzzRawSendEnvelope(plan, streamID, payload)
	postSend, action, custom := p.Run(ctx, sendEnv)
	switch action {
	case pipeline.Drop:
		return nil, 0, false, errors.New("send envelope dropped by pipeline")
	case pipeline.Respond:
		if custom == nil {
			return nil, 0, false, errors.New("pipeline returned Respond with nil response envelope")
		}
		custom.StreamID = postSend.StreamID
		custom.Sequence = 1
		_, _, _ = p.Run(ctx, custom)
		respMsg, ok := custom.Message.(*envelope.RawMessage)
		if !ok {
			return nil, 0, false, fmt.Errorf("pipeline Respond envelope has %T, expected *RawMessage", custom.Message)
		}
		return respMsg.Bytes, 1, false, nil
	}

	conn, err := dialFuzzRawUpstream(ctx, plan)
	if err != nil {
		return nil, 0, false, err
	}
	l := bytechunk.New(conn, streamID, envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	if err := ch.Send(ctx, postSend); err != nil {
		return nil, 0, false, fmt.Errorf("upstream send: %w", err)
	}

	return runFuzzRawReceiveLoop(ctx, streamID, ch, p)
}

// runFuzzRawReceiveLoop reads bytechunk envelopes until io.EOF /
// ctx.Done() / response cap. Mirrors runResendRawReceiveLoop. Each
// envelope is pinned to streamID + monotonic Sequence and run through
// the pipeline (so PluginStepPost fires per chunk).
func runFuzzRawReceiveLoop(ctx context.Context, streamID string, ch interface {
	Next(context.Context) (*envelope.Envelope, error)
}, p *pipeline.Pipeline) ([]byte, int, bool, error) {
	var (
		out       []byte
		chunks    int
		truncated bool
		recvSeq   int
	)
	for {
		respEnv, err := ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return out, chunks, truncated, nil
			}
			if chunks == 0 {
				return nil, 0, false, fmt.Errorf("upstream receive: %w", err)
			}
			slog.WarnContext(ctx, "fuzz_raw: receive loop terminated abnormally; returning partial results",
				"stream_id", streamID,
				"chunks", chunks,
				"error", err,
			)
			return out, chunks, truncated, nil
		}
		respEnv.StreamID = streamID
		respEnv.Sequence = recvSeq
		recvSeq++
		respEnv, _, _ = p.Run(ctx, respEnv)
		chunks++
		respMsg, ok := respEnv.Message.(*envelope.RawMessage)
		if !ok {
			continue
		}
		if len(out)+len(respMsg.Bytes) > maxResendRawResponse {
			remaining := maxResendRawResponse - len(out)
			if remaining > 0 {
				out = append(out, respMsg.Bytes[:remaining]...)
			}
			truncated = true
			return out, chunks, truncated, nil
		}
		out = append(out, respMsg.Bytes...)
	}
}

// dialFuzzRawUpstream is a thin wrapper around connector.DialUpstreamRaw
// that builds the same DialRawOpts as resend_raw. Inlined rather than
// reused via dialResendRawUpstream because the latter takes a
// resendRawPlan argument; the shared helper would require a wider
// refactor for ~10 lines of code reuse.
func dialFuzzRawUpstream(ctx context.Context, plan *fuzzRawPlan) (net.Conn, error) {
	opts := connector.DialRawOpts{
		DialTimeout: defaultReplayTimeout,
	}
	if plan.useTLS {
		opts.TLSConfig = &tls.Config{
			ServerName: plan.sni,
			MinVersion: tls.VersionTLS12,
		}
		opts.InsecureSkipVerify = plan.insecureSkipVerify
		opts.OfferALPN = []string{"http/1.1"}
	}
	conn, _, err := connector.DialUpstreamRaw(ctx, plan.dialAddr, opts)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", plan.dialAddr, err)
	}
	return conn, nil
}

// buildFuzzRawSendEnvelope synthesises the Send-side RawMessage
// envelope for a variant. Mirrors buildResendRawSendEnvelope but
// stamps the variant's own streamID + payload directly.
func buildFuzzRawSendEnvelope(plan *fuzzRawPlan, streamID string, payload []byte) *envelope.Envelope {
	bytesCopy := make([]byte, len(payload))
	copy(bytesCopy, payload)
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Raw:       bytesCopy,
		Message:   &envelope.RawMessage{Bytes: bytesCopy},
		Context: envelope.EnvelopeContext{
			ConnID: plan.connID,
		},
	}
}

// assembleFuzzRawVariantBytes computes the variant's send-side bytes:
//
//  1. Start from plan.baseBytes (recovered Flow.RawBytes or
//     decoded(override_bytes) or nil).
//  2. Clone plan.basePatches; for each "patches[N].data" position
//     active for this variant, replace variantPatches[N].Data with
//     the position payload.
//  3. ApplyPatches(base, variantPatches).
//  4. If a "payload" position is active for this variant, REPLACE
//     the result wholesale with the position payload.
//
// The "payload" wholesale-override is applied last so callers can
// combine "patches[N].data" positions (modifying intermediate
// variants) with a "payload" override on top — though in practice
// they are typically used independently.
func assembleFuzzRawVariantBytes(plan *fuzzRawPlan, payloads map[string]string) ([]byte, error) {
	variantPatches, err := buildFuzzRawVariantPatches(plan.basePatches, payloads)
	if err != nil {
		return nil, err
	}

	var bytes []byte
	if len(variantPatches) > 0 {
		bytes = job.ApplyPatches(plan.baseBytes, variantPatches)
	} else {
		bytes = make([]byte, len(plan.baseBytes))
		copy(bytes, plan.baseBytes)
	}

	if payload, ok := payloads["payload"]; ok {
		// Wholesale override — ignore base + patches.
		out := []byte(payload)
		return out, nil
	}
	return bytes, nil
}

// buildFuzzRawVariantPatches clones plan.basePatches and applies any
// "patches[N].data" position substitutions for this variant. Callers
// that have no such positions get a clean clone (so ApplyPatches
// doesn't see an aliased slice).
func buildFuzzRawVariantPatches(base []job.BytePatch, payloads map[string]string) ([]job.BytePatch, error) {
	if len(base) == 0 {
		return nil, nil
	}
	out := make([]job.BytePatch, len(base))
	copy(out, base)
	for path, payload := range payloads {
		if path == "payload" {
			continue
		}
		matches := fuzzRawHeadersPathRE.FindStringSubmatch(path)
		if matches == nil {
			continue
		}
		idx, err := strconv.Atoi(matches[1])
		if err != nil {
			return nil, fmt.Errorf("invalid patch index %q", matches[1])
		}
		if idx < 0 || idx >= len(out) {
			return nil, fmt.Errorf("patches index %d out of range [0, %d)", idx, len(out))
		}
		out[idx].Data = []byte(payload)
	}
	return out, nil
}

// nextFuzzRawIndices increments the variant index counter. Treats
// indices[i] like a digit in a mixed-radix counter where the radix at
// position i is len(positions[i].Payloads). Position 0 is the
// least-significant digit; carries propagate upward. Mirrors fuzz_http's
// nextIndices.
func nextFuzzRawIndices(indices []int, positions []fuzzRawPosition) {
	for i := 0; i < len(indices); i++ {
		indices[i]++
		if indices[i] < len(positions[i].Payloads) {
			return
		}
		indices[i] = 0
	}
}

// decodeFuzzRawPayloads materialises the per-position payload values
// for the current variant index combination into a path → decoded
// payload string map. Decoding follows the position's encoding
// ("text" or "base64").
//
// Each decoded payload is rejected if it exceeds maxFuzzRawPayloadSize
// — see the constant doc for the rationale. The cap applies post-decode
// so a 1.4 MiB base64 string that decodes to 1 MiB is allowed.
func decodeFuzzRawPayloads(positions []fuzzRawPosition, indices []int) (map[string]string, error) {
	out := make(map[string]string, len(positions))
	for i, pos := range positions {
		raw := pos.Payloads[indices[i]]
		decoded, err := decodeBodyEncoded(raw, pos.Encoding, fmt.Sprintf("positions[%d].payloads[%d]", i, indices[i]))
		if err != nil {
			return nil, err
		}
		if len(decoded) > maxFuzzRawPayloadSize {
			return nil, fmt.Errorf("positions[%d].payloads[%d]: decoded length %d exceeds %d byte cap", i, indices[i], len(decoded), maxFuzzRawPayloadSize)
		}
		out[pos.Path] = string(decoded)
	}
	return out, nil
}

// fuzzRawJobConfig is the JSON payload persisted to fuzz_jobs.config.
// Intentionally records only structural metadata: position paths,
// payload counts, encoding labels, and the stop_on_error flag. Raw
// payload values are deliberately excluded — they can be re-derived
// from each Stream's recorded Flow, and including them here would
// inflate the row by O(positions × payloads × payload-size) and
// surface potentially-sensitive payloads (smuggling templates, auth
// tokens) in the aggregation table. Mirrors fuzz_http (USK-827).
type fuzzRawJobConfig struct {
	Positions     []fuzzRawJobPosition `json:"positions"`
	StopOnError   bool                 `json:"stop_on_error"`
	TotalVariants int                  `json:"total_variants"`
}

// fuzzRawJobPosition is one position entry inside fuzz_jobs.config.
// Only structural metadata is recorded — see fuzzRawJobConfig for the
// payload-omission rationale.
type fuzzRawJobPosition struct {
	Path         string `json:"path"`
	PayloadCount int    `json:"payload_count"`
	Encoding     string `json:"encoding,omitempty"`
}

// saveFuzzRawJob persists the initial fuzz_jobs row at status="running".
// Called once before the variant loop starts. Store-write failures are
// logged at slog.Warn and ignored — the fuzz run itself is not blocked
// because aggregation persistence is best-effort.
//
// fuzz_jobs.stream_id is set from input.FlowID when the caller seeded
// the run from a recorded flow; otherwise it is left empty (fuzz_raw
// supports from-scratch runs where flow_id is unset — see fuzz_raw.go
// "Three operating modes").
func (s *Server) saveFuzzRawJob(ctx context.Context, fuzzID string, input *fuzzRawInput, plan *fuzzRawPlan) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}

	cfg := fuzzRawJobConfig{
		Positions:     make([]fuzzRawJobPosition, 0, len(input.Positions)),
		StopOnError:   input.StopOnError,
		TotalVariants: plan.totalVariants,
	}
	for _, p := range input.Positions {
		cfg.Positions = append(cfg.Positions, fuzzRawJobPosition{
			Path:         p.Path,
			PayloadCount: len(p.Payloads),
			Encoding:     p.Encoding,
		})
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		// Should never fail for this structure; degrade to a minimal payload
		// so the row still inserts rather than blocking the run.
		cfgJSON = []byte("{}")
	}

	job := &flow.FuzzJob{
		ID:             fuzzID,
		StreamID:       input.FlowID, // seed stream when replaying a recorded flow; empty for from-scratch
		Config:         string(cfgJSON),
		Status:         "running",
		Tag:            input.Tag,
		CreatedAt:      time.Now().UTC(),
		Total:          plan.totalVariants,
		CompletedCount: 0,
		ErrorCount:     0,
	}
	if err := s.jobRunner.fuzzStore.SaveFuzzJob(ctx, job); err != nil {
		slog.WarnContext(ctx, "fuzz_raw: save fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"error", err,
		)
	}
}

// finalizeFuzzRawJob updates the fuzz_jobs row at end of run with the
// final status / completed_at / counts. Called with a fresh background
// context so caller-side ctx cancel does not prevent the closing
// UPDATE from landing.
//
// Status rule (USK-837 parity with USK-827): "completed" when the
// variant loop ran to natural exhaustion OR when stop_on_error
// triggered (a documented exit, not a failure). "error" only when the
// run aborted before completion due to a non-stop_on_error runErr.
//
// error_count counts per-variant errors observed in the rows
// (row.Error != ""); store-write failures intentionally do NOT bump
// this counter — they are observability gaps, not request failures.
func (s *Server) finalizeFuzzRawJob(ctx context.Context, fuzzID string, rows []fuzzRawVariantRow, completed int, stopReason string, runErr error) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}

	now := time.Now().UTC()
	errorCount := 0
	for _, r := range rows {
		if r.Error != "" {
			errorCount++
		}
	}

	status := "completed"
	if runErr != nil {
		status = "error"
	}

	// UpdateFuzzJob's SQL overwrites total / completed_count / error_count
	// (config / created_at / tag / stream_id are preserved by WHERE id = ?).
	// Fetch the existing row first so we preserve the planned Total when
	// stop_on_error aborts early (completed < total).
	existing, err := s.jobRunner.fuzzStore.GetFuzzJob(ctx, fuzzID)
	if err != nil {
		slog.WarnContext(ctx, "fuzz_raw: load fuzz_jobs row for finalize failed",
			"fuzz_id", fuzzID,
			"error", err,
		)
		return
	}
	existing.Status = status
	existing.CompletedAt = &now
	existing.CompletedCount = completed
	existing.ErrorCount = errorCount
	if err := s.jobRunner.fuzzStore.UpdateFuzzJob(ctx, existing); err != nil {
		slog.WarnContext(ctx, "fuzz_raw: update fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"status", status,
			"error", err,
		)
	}
	_ = stopReason // stop_reason is recorded in the response payload; no fuzz_jobs column today
}

// saveFuzzRawResult persists a single per-variant fuzz_results row.
// Called from the variant loop after each variant completes (success
// or error). Save failures are logged at slog.Warn and ignored — the
// per-variant Flow rows persisted via RecordStep are the source of
// truth for forensic drill-down.
//
// StatusCode is always 0 for Raw: the protocol has no L7 status
// concept — Raw is a byte-stream view, not a request/response
// transaction. Outlier triage on fuzz_raw runs therefore relies on
// response_length / duration / error distributions (status_code is a
// flat 0 baseline across the run).
//
// ResponseLength = row.ResponseSize (total bytes received before
// truncation cap). Error variants are recorded with response_length=0
// + error=<msg>; this matches the in-memory variants[] list which
// already surfaces error variants to the caller. Without this, the
// aggregation table would under-count by exactly the error-variant
// population.
func (s *Server) saveFuzzRawResult(ctx context.Context, fuzzID string, index int, row fuzzRawVariantRow, payloads map[string]string) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}
	result := &flow.FuzzResult{
		FuzzID:         fuzzID,
		IndexNum:       index,
		StreamID:       row.StreamID,
		Payloads:       flow.PayloadsToJSON(payloads),
		StatusCode:     0, // Raw has no L7 status — see function-level comment
		ResponseLength: row.ResponseSize,
		DurationMs:     int(row.DurationMs),
		Error:          row.Error,
	}
	if err := s.jobRunner.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
		slog.WarnContext(ctx, "fuzz_raw: save fuzz_results row failed",
			"fuzz_id", fuzzID,
			"index", index,
			"stream_id", row.StreamID,
			"error", err,
		)
	}
}

// buildFuzzRawPipeline constructs the per-variant pipeline shared
// across the fuzz run. Mirrors buildResendRawPipeline (PluginStepPost
// + RecordStep per RFC §9.3 D1) but stamps the RecordStep Origin with
// flow.OriginFuzz so `query flows { filter.origin: "fuzz" }` filters
// fuzz-originated traffic away from live capture and resend views.
//
// USK-837: a dedicated pipeline (rather than mutating
// buildResendRawPipeline) keeps the resend-vs-fuzz origin attribution
// honest — a recorded flow that was actually replayed via resend_raw
// must continue to carry OriginResend, while a fuzz_raw variant must
// carry OriginFuzz.
func (s *Server) buildFuzzRawPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		// USK-818: BudgetStep at position #1 — each fuzz variant Send
		// counts toward the budget; over-budget variants short-circuit
		// before dial. Mirrors buildResendRawPipeline ordering.
		pipeline.NewBudgetStep(s.misc.budgetManager),
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(
			s.flowStore.store,
			slog.Default(),
			pipeline.WithWireEncoderRegistry(encoders),
			pipeline.WithOrigin(flow.OriginFuzz),
		),
	}
	return pipeline.New(steps...)
}
