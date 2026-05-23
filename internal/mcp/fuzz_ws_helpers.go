// Package mcp fuzz_ws_helpers.go holds the building blocks used by
// fuzz_ws.go: input validation, base-plan construction (reusing
// resend_ws helpers), variant enumeration (cartesian product with
// hard cap), per-variant payload application against the WSMessage
// envelope, the dial / pipeline factory (reused from resend_ws), the
// per-variant run loop, and result formatting.
//
// # Payload passthrough — by design (MITM principle)
//
// Position payloads substituted into the WSMessage envelope via
// applyFuzzWSPosition are written verbatim, including arbitrary bytes
// after base64 decoding. This is intentional: fuzz_ws is the path most
// useful for WebSocket payload smuggling, framing-level abuse, and
// other deliberate wire anomalies. The base-headers / URL path still
// goes through validateResendWSInput's CRLF guards (target_addr,
// scheme, path, raw_query); only payload substitutions bypass — the
// asymmetry mirrors fuzz_http and is intentional.
//
// SafetyFilter input gating still runs per-variant inside
// runFuzzWSSingleVariant (after position application, before the
// upstream dial), so the destructive-sql / destructive-os-command
// presets continue to apply to the substituted payload.
package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzWSVariants caps the cartesian product across all positions.
// 1000 variants is a balance between meaningful synchronous fuzz runs
// and bounded server-side resource use; callers that need more should
// chain calls.
const maxFuzzWSVariants = 1000

// maxFuzzWSPositions caps the number of positions per call. WS fuzz
// positions are limited (payload, close_reason) so 32 is generous and
// almost never bites in practice.
const maxFuzzWSPositions = 32

// maxFuzzWSPayloadSize caps the *decoded* size of a single position
// payload. Without a cap, a 16 MiB payload * maxFuzzWSVariants (1000)
// could allocate up to 16 GiB sequentially — still a footgun. 1 MiB
// matches fuzz_http and is well below the per-frame 16 MiB cap that
// resend_ws enforces.
const maxFuzzWSPayloadSize = 1 << 20

// validFuzzWSRoots lists the WSMessage root field paths that fuzz_ws
// accepts. payload and close_reason cover the user-mutable fields;
// opcode/fin/close_code are enum-like and excluded by design — they
// would mostly fail validation as fuzz inputs.
var validFuzzWSRoots = map[string]bool{
	"payload":      true,
	"close_reason": true,
}

// validateFuzzWSInput rejects malformed inputs at the schema boundary
// before any expensive lookups (flow store, dial) run. Inherits all of
// resend_ws's validation discipline (CRLF guards on user-supplied URL
// components, opcode allowlist, etc.) by delegating to validateResendWSInput;
// fuzz-specific validation is layered on top:
//   - positions list non-empty and within the per-call cap
//   - each path resolves to a known WSMessage field
//   - each payloads list non-empty
//   - cartesian product within maxFuzzWSVariants
func validateFuzzWSInput(input *fuzzWSInput) error {
	rw := fuzzWSInputToResendWS(input)
	if err := validateResendWSInput(&rw); err != nil {
		return err
	}
	if len(input.Positions) == 0 {
		return errors.New("positions must contain at least one entry")
	}
	if len(input.Positions) > maxFuzzWSPositions {
		return fmt.Errorf("positions has %d entries; max %d per call", len(input.Positions), maxFuzzWSPositions)
	}
	totalVariants := 1
	for i, p := range input.Positions {
		if err := validateFuzzWSPosition(i, p); err != nil {
			return err
		}
		totalVariants *= len(p.Payloads)
		if totalVariants > maxFuzzWSVariants {
			return fmt.Errorf("positions cartesian product exceeds %d variants (computed at position %d); reduce payload counts or split into multiple calls", maxFuzzWSVariants, i)
		}
	}
	if err := ValidateMacroConfig("pre_macro", input.PreMacro, true); err != nil {
		return err
	}
	if err := ValidateMacroConfig("post_macro", input.PostMacro, false); err != nil {
		return err
	}
	return nil
}

// validateFuzzWSPosition validates one position entry: the path must
// resolve to a known WSMessage field, the payloads list must be
// non-empty, and the encoding must be in the allowlist.
func validateFuzzWSPosition(index int, p fuzzWSPosition) error {
	if p.Path == "" {
		return fmt.Errorf("positions[%d]: path must not be empty", index)
	}
	if !validFuzzWSRoots[p.Path] {
		return fmt.Errorf("positions[%d]: unsupported path %q (valid: payload, close_reason)", index, p.Path)
	}
	if len(p.Payloads) == 0 {
		return fmt.Errorf("positions[%d]: payloads must contain at least one element", index)
	}
	if p.Encoding != "" && p.Encoding != "text" && p.Encoding != "base64" {
		return fmt.Errorf("positions[%d]: unsupported encoding %q: must be text or base64", index, p.Encoding)
	}
	return nil
}

// fuzzWSInputToResendWS projects fuzz_ws base fields onto a
// resendWSInput so we can reuse resend_ws's validation and base-plan
// helpers without copy-paste. Fuzz-specific fields (Positions,
// StopOnClose) are not part of the projection.
func fuzzWSInputToResendWS(input *fuzzWSInput) resendWSInput {
	return resendWSInput{
		FlowID:         input.FlowID,
		TargetAddr:     input.TargetAddr,
		Scheme:         input.Scheme,
		Path:           input.Path,
		RawQuery:       input.RawQuery,
		Opcode:         input.Opcode,
		Fin:            input.Fin,
		Payload:        input.Payload,
		BodyEncoding:   input.BodyEncoding,
		PayloadSet:     input.PayloadSet,
		Masked:         input.Masked,
		Mask:           input.Mask,
		CloseCode:      input.CloseCode,
		CloseReason:    input.CloseReason,
		Compressed:     input.Compressed,
		TimeoutMs:      input.TimeoutMs,
		TLSFingerprint: input.TLSFingerprint,
		Tag:            input.Tag,
	}
}

// fuzzWSPlan is the resolved base plan + variant enumeration. The
// embedded *resendWSPlan provides the dial target, upgrade headers,
// extension header, and base frame fields; positions/totalVariants are
// the fuzz-specific overlay.
type fuzzWSPlan struct {
	base          *resendWSPlan
	encoder       func(*envelope.Envelope) ([]byte, error)
	encoders      *pipeline.WireEncoderRegistry
	positions     []fuzzWSPosition
	totalVariants int
}

// buildFuzzWSPlan resolves the base plan (delegating to resend_ws's
// buildResendWSPlan) and computes the total variant count. Builds the
// shared WireEncoderRegistry (one per call, reused across variants).
func (s *Server) buildFuzzWSPlan(ctx context.Context, input *fuzzWSInput) (*fuzzWSPlan, error) {
	rw := fuzzWSInputToResendWS(input)
	base, err := s.buildResendWSPlan(ctx, &rw)
	if err != nil {
		return nil, err
	}
	if err := s.checkResendWSScope(base); err != nil {
		return nil, err
	}

	totalVariants := 1
	for _, p := range input.Positions {
		totalVariants *= len(p.Payloads)
	}

	encoder := ws.NewResendWireEncoder(base.extensionHeader)
	encoders := pipeline.NewWireEncoderRegistry()
	encoders.Register(envelope.ProtocolWebSocket, encoder)

	return &fuzzWSPlan{
		base:          base,
		encoder:       encoder,
		encoders:      encoders,
		positions:     input.Positions,
		totalVariants: totalVariants,
	}, nil
}

// runFuzzWSVariants iterates the cartesian product of all positions,
// running each variant through a fresh dial + upgrade dance and the
// shared resend_ws pipeline. Returns the per-variant rows, the count
// of completed variants, and an optional stop reason ("" when all
// variants ran to completion).
//
// USK-831: persists one fuzz_results row per variant via
// FuzzStore.SaveFuzzResult so `query fuzz_results { fuzz_id }` is
// populated for both successful and error variants. Store-write
// failures are non-fatal (slog.Warn + continue) — the wire data is on
// disk via RecordStep and remains the source of truth.
//
// USK-984: per-iteration and per-job macro hooks plumb through the
// shared fuzzWSVariantLoop. The pure refactor preserves the prior
// behaviour when preMacro / postMacro are nil — the only structural
// change is moving the inline loop body into methods on
// *fuzzWSVariantLoop so the macro wiring sits where fuzz_http's does.
//
// scope="job" hooks fire exactly once outside the variant loop against
// a separate job-scoped kvStore that is merged into each iteration's
// per-variant store. pre-job runs between loop-state setup and the
// for-variant loop; post-job runs after the loop body exits (including
// the stop_on_close terminal path, but NOT on ctx cancel or pre-job
// abort).
func (s *Server) runFuzzWSVariants(ctx context.Context, plan *fuzzWSPlan, timeout time.Duration, stopOnClose bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) ([]fuzzWSVariantRow, int, string, error) {
	loop := buildFuzzWSVariantLoop(s, plan, timeout, stopOnClose, tag, fuzzID, preMacro, postMacro)

	// USK-984 pre-job: fire once before the variant loop. Abort short-
	// circuits the whole job; skip returns success with stopped_reason;
	// continue records the error and proceeds with whatever jobKVStore
	// captured.
	if IsJobScope(preMacro) {
		jobAction, stopReason, retErr := loop.runPreJobMacro(ctx)
		if retErr != nil {
			return loop.rows, loop.completed, "", retErr
		}
		if jobAction == fuzzWSPreJobSkipAll {
			return loop.rows, loop.completed, stopReason, nil
		}
	}

	completedNormally, earlyStopReason, retErr := loop.runVariantLoop(ctx)
	if retErr != nil {
		return loop.rows, loop.completed, "", retErr
	}

	// USK-984 post-job: fire after the variant loop exits. post-job fires
	// on natural exhaustion or stop_on_close exit, but NOT on ctx cancel.
	// completedNormally captures "we reached the post-job firing path
	// through a non-cancel exit".
	if completedNormally && IsJobScope(postMacro) {
		loop.runPostJobMacro(ctx)
	}

	return loop.rows, loop.completed, earlyStopReason, nil
}

// fuzzWSVariantLoop bundles the per-run state shared across iterations
// so the inner loop body (runOne) is a method on a small struct instead
// of an N-argument free function. Mirrors fuzzHTTPVariantLoop in
// fuzz_http_helpers.go; the macro hook wiring (USK-984) plugs into the
// same seam.
//
// USK-984 adds jobKVStore + jobHookExec for scope="job" hooks. The two
// kvStores (per-iteration + job) are deliberately separate: per-
// iteration reserved keys (§__iteration§ / §__nonce§ / __response_*)
// overwrite any conflicting keys from the job store at iteration start
// ("iteration wins" — matches the existing "caller wins" precedent in
// executePreMacro / executePostMacro's vars-merge dance).
type fuzzWSVariantLoop struct {
	s           *Server
	plan        *fuzzWSPlan
	timeout     time.Duration
	stopOnClose bool
	tag         string
	fuzzID      string
	preMacro    *MacroConfig
	postMacro   *MacroConfig
	pipe        *pipeline.Pipeline
	hookExec    *hookExecutor
	// jobHookExec is the executor for scope="job" hooks. Distinct from
	// hookExec so the iteration-side hookState.preMacroExecuted state is
	// not flipped by the job-side single-fire call. Nil when no hook is
	// scope="job".
	jobHookExec *hookExecutor
	// jobKVStore is the kvStore shared across all variants for scope="job"
	// hooks. pre-job extracts land here; iteration runs copy this into a
	// fresh per-iteration kvStore before seeding reserved keys; post-job
	// reads back what pre-job wrote. Nil when no hook is scope="job".
	jobKVStore    map[string]string
	rateLimitHost string

	rows      []fuzzWSVariantRow
	indices   []int
	completed int
}

// buildFuzzWSVariantLoop assembles the per-run state container shared by
// all variants. Split out of runFuzzWSVariants to keep that function
// below the gocyclo threshold; the construction logic is mechanical
// (mirror of buildFuzzHTTPVariantLoop) and has no branch fan-out outside
// the rate-limit host parse.
func buildFuzzWSVariantLoop(s *Server, plan *fuzzWSPlan, timeout time.Duration, stopOnClose bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) *fuzzWSVariantLoop {
	loop := &fuzzWSVariantLoop{
		s:           s,
		plan:        plan,
		timeout:     timeout,
		stopOnClose: stopOnClose,
		tag:         tag,
		fuzzID:      fuzzID,
		preMacro:    preMacro,
		postMacro:   postMacro,
	}
	loop.pipe = s.buildFuzzWSPipeline(plan.encoders)

	// Strip the port to align rate-limit bucket keys with the live data path
	// (connector/connect_handler.go, http1_forward_handler.go, socks5.go) and
	// with target_scope matching, both of which key on host only. Falling
	// back to the raw host on SplitHostPort error mirrors the connector's
	// behaviour for entries without an explicit port.
	rateLimitHost, _, err := net.SplitHostPort(plan.base.upgradeURL.Host)
	if err != nil {
		rateLimitHost = plan.base.upgradeURL.Host
	}
	loop.rateLimitHost = rateLimitHost

	loop.hookExec = BuildIterationHookExecutor(s, preMacro, postMacro)
	loop.jobHookExec, loop.jobKVStore = BuildJobHookExecutor(s, preMacro, postMacro)

	loop.rows = make([]fuzzWSVariantRow, 0, plan.totalVariants)
	loop.indices = make([]int, len(plan.positions))
	return loop
}

// runVariantLoop drives the variant loop body and returns
// (completedNormally, earlyStopReason, retErr). completedNormally is
// true when the loop reached the post-job firing path (natural
// exhaustion or stop_on_close); it is false on ctx cancel. retErr
// non-nil signals an unrecoverable abort and post-job MUST NOT fire.
//
// Mirrors fuzzHTTPVariantLoop.runVariantLoop — ctx-cancel detection
// bubbles up through retErr wrapped with %w so errors.Is(retErr,
// context.Canceled) drives the post-job gate.
func (l *fuzzWSVariantLoop) runVariantLoop(ctx context.Context) (bool, string, error) {
	for variantIdx := 0; variantIdx < l.plan.totalVariants; variantIdx++ {
		stop, retErr := l.runOne(ctx, variantIdx)
		if retErr != nil {
			if errors.Is(retErr, context.Canceled) || errors.Is(retErr, context.DeadlineExceeded) {
				// post-job does NOT fire on ctx cancel. Surface the cancel
				// reason via stopped_reason for parity with the pre-USK-984
				// string-sentinel path; do NOT propagate as retErr so the
				// caller still finalizes the fuzz_jobs row normally.
				return false, fmt.Sprintf("ctx cancelled: %v", retErr), nil
			}
			// pre-iteration abort or other unrecoverable error.
			return false, "", retErr
		}
		if stop == "" {
			continue
		}
		// stop_on_close reaches here.
		return true, stop, nil
	}
	return true, "", nil
}

// runOne executes a single iteration of the variant loop. Returns
// (stopReason, retErr): stopReason "" means continue; non-empty means
// stop with that reason (e.g., stop_on_close); retErr propagates an
// abort up the call stack. ctx cancel is surfaced via retErr wrapped
// with %w so the caller can distinguish via errors.Is(context.Canceled)
// / errors.Is(context.DeadlineExceeded) instead of string-matching the
// stop reason.
func (l *fuzzWSVariantLoop) runOne(ctx context.Context, variantIdx int) (string, error) {
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("variant %d: %w", variantIdx, ctx.Err())
	default:
	}

	payloads, err := decodeFuzzWSPayloads(l.plan.positions, l.indices)
	if err != nil {
		return "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
	}

	// USK-984: prepare per-iteration kvStore (jobKVStore copy + Vars +
	// reserved keys) and dispatch pre_macro (scope=iteration only). The
	// skipped path mirrors fuzz_http: record the row and short-circuit
	// before the upstream dial.
	prep, retErr := l.prepareIteration(ctx, variantIdx, payloads)
	if retErr != nil {
		return "", retErr
	}
	if prep.skipped {
		// USK-981 parity: bump the iteration counter even on skip so
		// RunInterval engine gates (every_n) treat skipped iterations as
		// consuming their slot.
		//
		// USK-987: stay on counter-only Bump here — the skip path never
		// reached the wire so there is no wire result to record. The
		// previous wire-completed iteration's lastStatusCode / lastError
		// remain in place, so an on_error gate on the next iteration
		// still reacts to the most recent real outcome.
		BumpHookIterationCount(l.hookExec)
		nextIndicesWS(l.indices, l.plan.positions)
		return "", nil
	}
	kvStore := prep.kvStore

	// TODO(USK-817 sibling: budget counter, P5-19)
	if err := l.s.waitRateLimit(ctx, l.rateLimitHost); err != nil {
		return fmt.Sprintf("rate limit: %v", err), nil
	}

	// Template-expand the per-position payloads against the populated
	// kvStore so pre_macro extracts (or job-scope extracts) can flow into
	// the variant frame via §var§ tokens. Unknown tokens are left literal;
	// the diagnostic surfacing happens at the fuzz_http parity point —
	// for WS we just send what the template produced.
	expandedPayloads, expandErr := expandFuzzWSPayloads(payloads, kvStore)
	if expandErr != nil {
		l.recordVariantError(ctx, variantIdx, payloads, fmt.Sprintf("template expansion: %v", expandErr))
		// USK-987: counter-only bump — like prep.skipped, template-
		// expansion failures never reached the wire, so lastStatusCode /
		// lastError carry over from the previous wire-completed iter.
		BumpHookIterationCount(l.hookExec)
		nextIndicesWS(l.indices, l.plan.positions)
		return "", nil
	}

	variantStart := time.Now()
	row, gotClose, runErr := l.s.runFuzzWSSingleVariant(ctx, l.plan, l.pipe, l.timeout, variantIdx, expandedPayloads, l.tag)
	row.DurationMs = time.Since(variantStart).Milliseconds()
	// Keep row.Payloads aligned with what saveFuzzWSResult persists to
	// fuzz_results.payloads — the operator-supplied (un-expanded) payload
	// map, NOT the post-template-expansion form. Matches fuzz_http parity:
	// the wire-actual bytes are preserved via the per-variant Flow rows
	// under row.StreamID; fuzz_results.payloads is the replay-input view.
	row.Payloads = payloads
	if runErr != nil {
		row.Error = runErr.Error()
	}
	l.rows = append(l.rows, row)
	l.completed++

	// USK-831: persist per-variant fuzz_results row so the aggregation
	// view (`query fuzz_results { fuzz_id }` + USK-278 outliers_only)
	// is populated. Save failures are non-fatal — wire data on disk via
	// RecordStep is the source of truth.
	l.s.saveFuzzWSResult(ctx, l.fuzzID, variantIdx, row, payloads)

	// USK-984: gate post-iteration on scope="iteration" (or empty —
	// defaults to iteration). scope="job" post runs once after the
	// variant loop completes. Mirrors fuzz_http: fire post on both error
	// and success paths so iteration-scope post still runs on transport-
	// level errors; on error, runPostMacro passes zero values to
	// injectWSResponseVars and a 0 status to executePostMacro.
	if IsIterationScope(l.postMacro) {
		l.runPostMacro(ctx, variantIdx, row, kvStore)
	}

	// USK-981 / USK-987: record the iteration's wire result so the next
	// runOne call's shouldRunPreMacro sees the correct lastStatusCode /
	// lastError for the on_error gate, AND advance the iteration counter
	// for the every_n gate. updateState bumps requestCount and records
	// (statusCode, runErr != nil) atomically — replacing the counter-
	// only BumpHookIterationCount used during USK-981.
	//
	// Pass statusCode=0 unconditionally: WS close frame codes (RFC 6455
	// §7.4) are L7 graceful-shutdown signals, not error signals. Passing
	// int(row.CloseCode) would make a normal closure (Close=1000) trip
	// the on_error gate (1000 >= 400). Only the transport-error signal
	// (runErr != nil) drives on_error for WS. Close-code-driven on_error
	// is deferred — file a follow-up Issue when a concrete operator
	// scenario emerges (YAGNI / MITM Principle #6).
	//
	// Note the per-call-site distinction: only this normal-path branch
	// has wire-result information. The pre-wire abort branches above
	// (prep.skipped, template-expansion error) keep BumpHookIterationCount
	// since they never reached the wire and have no wire result to
	// record — leaving lastStatusCode / lastError unchanged so the
	// previous wire-completed iteration's outcome carries over to the
	// next on_error evaluation.
	l.hookExec.updateState(0, runErr != nil)

	nextIndicesWS(l.indices, l.plan.positions)

	if l.stopOnClose && gotClose {
		return fmt.Sprintf("stop_on_close: variant %d received Close frame", variantIdx), nil
	}
	return "", nil
}

// fuzzWSIterationPrep holds the per-iteration state produced by
// prepareIteration: the kvStore (merged from jobKVStore + reserved
// iteration keys) and the skipped flag set when pre-iteration's
// on_error=skip short-circuited the variant.
type fuzzWSIterationPrep struct {
	kvStore map[string]string
	skipped bool
}

// prepareIteration handles the per-variant kvStore setup and pre-
// iteration hook dispatch. Returns (prep, retErr): retErr non-nil aborts
// the run; prep.skipped means the iteration was short-circuited and the
// caller should advance indices and continue to the next variant.
//
// Mirrors fuzzHTTPVariantLoop.prepareIteration. The upstream-proxy
// rotation branch in fuzz_http is not applicable to fuzz_ws (no proxy
// rotation knob on the WS schema today).
func (l *fuzzWSVariantLoop) prepareIteration(ctx context.Context, variantIdx int, payloads map[string]string) (fuzzWSIterationPrep, error) {
	// USK-983: per-iteration kvStore build uses the shared
	// PrepareIteration helper so the Vars / reserved-key seeding order
	// matches fuzz_http exactly.
	kvStore := PrepareIteration(l.jobKVStore, l.preMacro, l.postMacro, variantIdx)

	// USK-984: pre-iteration only fires when pre is configured at
	// scope="iteration" (empty defaults to iteration). When pre is
	// scope="job", the executor was invoked once outside the loop.
	if !IsIterationScope(l.preMacro) {
		return fuzzWSIterationPrep{kvStore: kvStore}, nil
	}
	outcome, retErr := l.runPreMacro(ctx, variantIdx, payloads, kvStore)
	if retErr != nil {
		return fuzzWSIterationPrep{}, retErr
	}
	if outcome == fuzzWSPreSkipped {
		return fuzzWSIterationPrep{skipped: true}, nil
	}
	return fuzzWSIterationPrep{kvStore: kvStore}, nil
}

// fuzzWSPreMacroOutcome marks whether the variant loop should proceed
// with the upstream send after pre_macro resolution. Mirrors
// fuzzHTTPPreMacroOutcome.
type fuzzWSPreMacroOutcome int

const (
	// fuzzWSPreOK = pre macro ran successfully, or was not configured;
	// continue to body send.
	fuzzWSPreOK fuzzWSPreMacroOutcome = iota
	// fuzzWSPreSkipped = pre macro failed under on_error=skip; the caller
	// has already recorded the skipped row, do NOT send the variant, do
	// NOT fire post_macro.
	fuzzWSPreSkipped
)

// runPreMacro dispatches the pre_macro hook for this iteration and
// translates the OnError policy into a pre-macro outcome. Returns
// (outcome, retErr): retErr non-nil aborts the whole fuzz run; outcome
// drives the caller's decision to send or short-circuit.
//
// Mirrors fuzzHTTPVariantLoop.runPreMacro.
func (l *fuzzWSVariantLoop) runPreMacro(ctx context.Context, variantIdx int, payloads map[string]string, kvStore map[string]string) (fuzzWSPreMacroOutcome, error) {
	if l.preMacro == nil {
		return fuzzWSPreOK, nil
	}
	_, hookErr := l.hookExec.executePreMacro(ctx, kvStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "ok", 0, "")
		return fuzzWSPreOK, nil
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		return fuzzWSPreOK, fmt.Errorf("variant %d pre_macro hook abort: %w", variantIdx, hookErr)
	case "continue":
		slog.WarnContext(ctx, "fuzz_ws: pre_macro hook error (on_error=continue)",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		return fuzzWSPreOK, nil
	default: // skip
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "skipped", 0, hookErr.Error())
		row := fuzzWSVariantRow{
			Index:    variantIdx,
			Payloads: payloads,
			Error:    fmt.Sprintf("pre_macro hook failed (on_error=skip): %v", hookErr),
		}
		l.rows = append(l.rows, row)
		l.completed++
		l.s.saveFuzzWSResult(ctx, l.fuzzID, variantIdx, row, payloads)
		return fuzzWSPreSkipped, nil
	}
}

// runPostMacro fires the post_macro hook against the same kvStore that
// pre_macro shared. Post failures NEVER abort the run — record a
// fuzz_macro_results row and return.
//
// WS-specific reserved keys (__response_opcode / __response_payload /
// __response_close_code / __response_close_reason) are injected into
// kvStore FIRST so the macro's template expansion sees them. Then
// executePostMacro is called with statusCode=int(row.CloseCode) and
// nil body / nil headers — the shared HTTP-shaped injectResponseVars
// inside executePostMacro becomes a benign no-op writing only
// __response_status (already populated from close_code as a numeric
// proxy for L7 status).
//
// The terminating frame's payload bytes are not carried on
// fuzzWSVariantRow (deliberately omitted by USK-836's CWE-770 cap) so we
// fetch the last receive Flow's body from the store via
// fetchFuzzWSVariantPayload. On a missing / lookup error we treat the
// payload as empty — the macro then sees __response_payload="" which is
// the expected error-path semantic (matches fuzz_http's behaviour on a
// missing receive flow).
func (l *fuzzWSVariantLoop) runPostMacro(ctx context.Context, variantIdx int, row fuzzWSVariantRow, kvStore map[string]string) {
	payload := l.s.fetchFuzzWSVariantPayload(ctx, row.StreamID)
	injectWSResponseVars(kvStore, row.Opcode, payload, row.CloseCode, row.CloseReason)
	statusCode := int(row.CloseCode)
	hookErr := l.hookExec.executePostMacro(ctx, statusCode, nil, nil, kvStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_ws: post_macro hook error",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "error", statusCode, hookErr.Error())
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "ok", statusCode, "")
}

// fetchFuzzWSVariantPayload reads the recorded receive Flow body for the
// variant's stream so runPostMacro can inject __response_payload into
// the shared kvStore. Returns nil on any lookup failure — the post
// macro then sees an empty __response_payload, which matches the
// "no response captured" semantics for the on_error=continue path
// where the upstream may not have responded. Mirrors
// fetchFuzzVariantResponse for fuzz_http but returns only the body
// (WS frames have no header surface in the macro path).
//
// The last (most recent) receive Flow is the terminating frame's
// envelope — auto-Pong replies fire control-bypass via runResendWSReceiveLoop
// and do NOT count as the terminating frame. Reading the last entry
// pairs with the row metadata (opcode / close_code) produced inside
// runFuzzWSSingleVariant.
func (s *Server) fetchFuzzWSVariantPayload(ctx context.Context, streamID string) []byte {
	if streamID == "" || s.flowStore.store == nil {
		return nil
	}
	flows, err := s.flowStore.store.GetFlows(ctx, streamID, flow.FlowListOptions{Direction: "receive"})
	if err != nil || len(flows) == 0 {
		return nil
	}
	return flows[len(flows)-1].Body
}

// fuzzWSJobPreOutcome marks the pre-job hook's effect on the surrounding
// job loop. Mirrors fuzzHTTPJobPreOutcome.
type fuzzWSJobPreOutcome int

const (
	// fuzzWSPreJobOK = pre-job ran successfully (or under on_error=
	// continue): proceed with the variant loop.
	fuzzWSPreJobOK fuzzWSJobPreOutcome = iota
	// fuzzWSPreJobSkipAll = pre-job failed under on_error=skip: skip the
	// entire job. fuzz_ws returns a successful result with
	// CompletedVariants=0 and stopped_reason set.
	fuzzWSPreJobSkipAll
)

// runPreJobMacro fires the pre_macro hook ONCE outside the variant loop
// (scope="job"). Mirrors fuzzHTTPVariantLoop.runPreJobMacro.
func (l *fuzzWSVariantLoop) runPreJobMacro(ctx context.Context) (fuzzWSJobPreOutcome, string, error) {
	if l.jobHookExec == nil || l.preMacro == nil || !IsJobScope(l.preMacro) {
		return fuzzWSPreJobOK, "", nil
	}
	_, hookErr := l.jobHookExec.executePreMacro(ctx, l.jobKVStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "ok", 0, "")
		return fuzzWSPreJobOK, "", nil
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzWSPreJobOK, "", fmt.Errorf("pre_macro hook abort (scope=job): %w", hookErr)
	case "continue":
		slog.WarnContext(ctx, "fuzz_ws: pre_macro hook error (scope=job, on_error=continue)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzWSPreJobOK, "", nil
	default: // skip — short-circuit the whole job with stopped_reason
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "skipped", 0, hookErr.Error())
		stopReason := fmt.Sprintf("pre_macro hook skipped (scope=job, on_error=skip): %v", hookErr)
		return fuzzWSPreJobSkipAll, stopReason, nil
	}
}

// runPostJobMacro fires the post_macro hook ONCE after the variant loop
// completes (scope="job"). Mirrors fuzzHTTPVariantLoop.runPostJobMacro:
// fires on natural exhaustion or stop_on_close exit, but NOT on ctx
// cancel (the caller gates the call on completedNormally). Post-job sees
// only the jobKVStore — per-iteration response keys (__response_*) are
// NOT available because each iteration's kvStore was discarded.
func (l *fuzzWSVariantLoop) runPostJobMacro(ctx context.Context) {
	if l.jobHookExec == nil || l.postMacro == nil || !IsJobScope(l.postMacro) {
		return
	}
	// Post-job has no per-iteration response to inject. Pass zero values
	// for status / body / headers so executePostMacro's PassResponse
	// branch is a no-op (the jobHookExec.hooks.PostMacro config leaves
	// PassResponse=false; defensively pass zero values anyway).
	hookErr := l.jobHookExec.executePostMacro(ctx, 0, nil, nil, l.jobKVStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_ws: post_macro hook error (scope=job)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "error", 0, hookErr.Error())
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "ok", 0, "")
}

// recordVariantError appends a synthetic error-row to the variant rows
// (no upstream send happened) and persists the matching fuzz_results
// row. Used by short-circuit paths (template expansion failure) where
// the variant never reached runFuzzWSSingleVariant.
//
// Mirrors fuzzHTTPVariantLoop.recordVariantError.
func (l *fuzzWSVariantLoop) recordVariantError(ctx context.Context, variantIdx int, payloads map[string]string, msg string) {
	row := fuzzWSVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
		Error:    msg,
	}
	l.rows = append(l.rows, row)
	l.completed++
	l.s.saveFuzzWSResult(ctx, l.fuzzID, variantIdx, row, payloads)
}

// expandFuzzWSPayloads applies macro.ExpandTemplate to each per-position
// payload against the shared per-iteration kvStore. Unknown §var§ tokens
// are left literal (ExpandTemplate's natural behaviour). Returns a new
// map; does NOT mutate the input. Mirrors expandFuzzHTTPPayloads.
func expandFuzzWSPayloads(payloads map[string]string, kvStore map[string]string) (map[string]string, error) {
	out := make(map[string]string, len(payloads))
	for path, payload := range payloads {
		expanded, err := macro.ExpandTemplate(payload, kvStore)
		if err != nil {
			return nil, fmt.Errorf("position %q: %w", path, err)
		}
		out[path] = expanded
	}
	return out, nil
}

// macroResponseOpcodeKey / macroResponseCloseCodeKey / macroResponseClose-
// ReasonKey / macroResponsePayloadKey are the WS-specific reserved kvStore
// keys injected into the per-iteration kvStore before post_macro runs
// (USK-984). The "__" prefix matches the existing __response_status /
// __response_body / __response_headers__ convention so user-supplied
// macros cannot shadow them via the macro.IsReservedKey filter applied
// at every KV-store merge site.
const (
	// macroResponseOpcodeKey carries the terminating frame's opcode
	// name ("text", "binary", "close", etc.). Distinct from
	// __response_status / __response_close_code which carry the close-
	// code numeric values — opcode is the symbolic identifier.
	macroResponseOpcodeKey = macro.ReservedKeyPrefix + "response_opcode"

	// macroResponseCloseCodeKey carries the terminating frame's RFC 6455
	// close status code as a base-10 decimal string. 0 when the
	// terminating frame is NOT a Close frame (text / binary echo etc.).
	macroResponseCloseCodeKey = macro.ReservedKeyPrefix + "response_close_code"

	// macroResponseCloseReasonKey carries the Close frame's UTF-8 reason
	// text (RFC 6455 §5.5.1 caps reason at 125 bytes — no DoS surface;
	// reused as-is without truncation).
	macroResponseCloseReasonKey = macro.ReservedKeyPrefix + "response_close_reason"

	// macroResponsePayloadKey carries the terminating frame's payload
	// bytes (truncated to maxResponseBodyKVBytes — 64 KiB — to bound
	// per-iteration kvStore growth; same cap and CWE-770 rationale as
	// __response_body for HTTP).
	macroResponsePayloadKey = macro.ReservedKeyPrefix + "response_payload"
)

// injectWSResponseVars writes the WS-specific terminating-frame reserved
// keys into kvStore for consumption by post_macro template expansion.
// Called from runPostMacro BEFORE executePostMacro so the shared HTTP-
// shaped injectResponseVars (gated on PassResponse=true) sees a fresh
// __response_payload-equivalent already in place.
//
// CWE-770 cap: __response_payload is truncated at maxResponseBodyKVBytes
// (64 KiB — reused from hooks.go; semantically WS-frame-specific) so an
// attacker-controlled 16 MiB terminating frame cannot amplify per-
// iteration kvStore growth × the maxFuzzWSVariants cap.
//
// Empty / zero values are still written so the macro template sees
// deterministic keys even on the transport-error path (parity with the
// fuzz_http error-path behaviour of writing __response_status=0).
func injectWSResponseVars(kvStore map[string]string, opcode string, payload []byte, closeCode uint16, closeReason string) {
	if kvStore == nil {
		return
	}
	kvStore[macroResponseOpcodeKey] = opcode
	body := payload
	if len(body) > maxResponseBodyKVBytes {
		body = body[:maxResponseBodyKVBytes]
	}
	kvStore[macroResponsePayloadKey] = string(body)
	kvStore[macroResponseCloseCodeKey] = strconv.FormatUint(uint64(closeCode), 10)
	kvStore[macroResponseCloseReasonKey] = closeReason
}

// fuzzWSJobConfig is the JSON payload persisted to fuzz_jobs.config.
// Intentionally records only structural metadata: position paths,
// payload counts, encoding labels, and the stop_on_close flag. Raw
// payload values are deliberately excluded — they can be re-derived
// from each Stream's recorded Flow, and including them here would
// inflate the row and surface potentially-sensitive payloads in the
// aggregation table.
type fuzzWSJobConfig struct {
	Positions     []fuzzWSJobPosition `json:"positions"`
	StopOnClose   bool                `json:"stop_on_close"`
	TotalVariants int                 `json:"total_variants"`
}

// fuzzWSJobPosition is one position entry inside fuzz_jobs.config.
// Only structural metadata is recorded — see fuzzWSJobConfig for the
// payload-omission rationale.
type fuzzWSJobPosition struct {
	Path         string `json:"path"`
	PayloadCount int    `json:"payload_count"`
	Encoding     string `json:"encoding,omitempty"`
}

// saveFuzzWSJob persists the initial fuzz_jobs row at status="running".
// Called once before the variant loop starts. Store-write failures are
// logged at slog.Warn and ignored — the fuzz run itself is not blocked
// because aggregation persistence is best-effort.
//
// fuzz_jobs.stream_id is set from input.FlowID when the caller seeded
// the run from a recorded flow; otherwise it is left empty.
func (s *Server) saveFuzzWSJob(ctx context.Context, fuzzID string, input *fuzzWSInput, plan *fuzzWSPlan) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}

	cfg := fuzzWSJobConfig{
		Positions:     make([]fuzzWSJobPosition, 0, len(input.Positions)),
		StopOnClose:   input.StopOnClose,
		TotalVariants: plan.totalVariants,
	}
	for _, p := range input.Positions {
		cfg.Positions = append(cfg.Positions, fuzzWSJobPosition{
			Path:         p.Path,
			PayloadCount: len(p.Payloads),
			Encoding:     p.Encoding,
		})
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		cfgJSON = []byte("{}")
	}

	job := &flow.FuzzJob{
		ID:             fuzzID,
		StreamID:       input.FlowID, // seed stream when replaying a recorded flow
		Config:         string(cfgJSON),
		Status:         "running",
		Tag:            input.Tag,
		CreatedAt:      time.Now().UTC(),
		Total:          plan.totalVariants,
		CompletedCount: 0,
		ErrorCount:     0,
	}
	if err := s.jobRunner.fuzzStore.SaveFuzzJob(ctx, job); err != nil {
		slog.WarnContext(ctx, "fuzz_ws: save fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"error", err,
		)
	}
}

// finalizeFuzzWSJob updates the fuzz_jobs row at end of run with the
// final status / completed_at / counts. Called with a fresh background
// context so caller-side ctx cancel does not prevent the closing
// UPDATE from landing.
//
// Status rule (mirrors USK-827): "completed" when the variant loop ran
// to natural exhaustion OR when stop_on_close triggered (a documented
// exit, not a failure). "error" only when the run aborted before
// completion due to a non-stop_on_close runErr.
func (s *Server) finalizeFuzzWSJob(ctx context.Context, fuzzID string, rows []fuzzWSVariantRow, completed int, stopReason string, runErr error) {
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

	existing, err := s.jobRunner.fuzzStore.GetFuzzJob(ctx, fuzzID)
	if err != nil {
		slog.WarnContext(ctx, "fuzz_ws: load fuzz_jobs row for finalize failed",
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
		slog.WarnContext(ctx, "fuzz_ws: update fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"status", status,
			"error", err,
		)
	}
	_ = stopReason // stop_reason is recorded in the response payload; no fuzz_jobs column today
}

// saveFuzzWSResult persists a single per-variant fuzz_results row.
// Called from the variant loop after each variant completes (success
// or error). Save failures are logged at slog.Warn and ignored — the
// per-variant Flow rows persisted via RecordStep are the source of
// truth for forensic drill-down.
//
// Per-protocol StatusCode mapping (USK-831): WebSocket variant rows
// have no HTTP-style status code; the closest analogue is the Close
// frame's status code (RFC 6455 §7.4). Map row.CloseCode (uint16, 0 when
// the terminating frame is not a Close) into FuzzResult.StatusCode (int).
// ResponseLength gets row.PayloadSize (terminating frame payload byte
// length).
func (s *Server) saveFuzzWSResult(ctx context.Context, fuzzID string, index int, row fuzzWSVariantRow, payloads map[string]string) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}
	result := &flow.FuzzResult{
		FuzzID:         fuzzID,
		IndexNum:       index,
		StreamID:       row.StreamID,
		Payloads:       flow.PayloadsToJSON(payloads),
		StatusCode:     int(row.CloseCode),
		ResponseLength: row.PayloadSize,
		DurationMs:     int(row.DurationMs),
		Error:          row.Error,
	}
	if err := s.jobRunner.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
		slog.WarnContext(ctx, "fuzz_ws: save fuzz_results row failed",
			"fuzz_id", fuzzID,
			"index", index,
			"stream_id", row.StreamID,
			"error", err,
		)
	}
}

// buildFuzzWSPipeline constructs the per-variant pipeline for fuzz_ws.
// Mirrors buildResendWSPipeline but stamps variant Streams with
// flow.OriginFuzz so `query flows { filter.origin: "fuzz" }` filters
// fuzz-originated traffic away from live capture views (parity with
// fuzz_http's OriginFuzz stamping).
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass).
func (s *Server) buildFuzzWSPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		// USK-818: BudgetStep at position #1. The synthetic Send envelope
		// is a WSMessage, which BudgetStep filters out as "post-Upgrade".
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

// runFuzzWSSingleVariant executes one variant: clones the base plan,
// applies all position payloads, runs the pre-send pipeline pass,
// dials a fresh upstream, performs the upgrade dance, sends the
// variant frame, receives until the first non-control frame OR Close
// OR ctx timeout. Returns the row + a flag indicating whether the
// terminating frame was a Close.
//
// Per-variant SafetyFilter input gating runs after position application
// and before the upstream dial (mirroring fuzz_http per-variant
// semantics). On a violation the variant is recorded with row.Error
// set; the run loop continues iterating.
func (s *Server) runFuzzWSSingleVariant(ctx context.Context, plan *fuzzWSPlan, p *pipeline.Pipeline, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzWSVariantRow, bool, error) {
	row := fuzzWSVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantPlan := cloneResendWSPlanForFuzz(plan.base)
	for _, pos := range plan.positions {
		payload, ok := payloads[pos.Path]
		if !ok {
			continue
		}
		applyFuzzWSPosition(variantPlan, pos.Path, payload)
	}

	row.StreamID = variantPlan.streamID

	// SafetyFilter input gating after position application, before
	// dial. Mirrors fuzz_http per-variant semantics.
	if v := s.checkSafetyInput(variantPlan.payload, variantPlan.upgradeURL.String(), variantPlan.upgradeHeaders); v != nil {
		row.Error = safetyViolationError(v)
		return row, false, nil
	}

	variantMsg := &envelope.WSMessage{
		Opcode:      variantPlan.opcode,
		Fin:         variantPlan.fin,
		Masked:      variantPlan.masked,
		Mask:        variantPlan.mask,
		Payload:     variantPlan.payload,
		CloseCode:   variantPlan.closeCode,
		CloseReason: variantPlan.closeReason,
		Compressed:  variantPlan.compressed,
	}
	sendEnv := &envelope.Envelope{
		StreamID:  variantPlan.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   variantMsg,
		Context: envelope.EnvelopeContext{
			ConnID:       variantPlan.connID,
			UpgradePath:  variantPlan.upgradeURL.Path,
			UpgradeQuery: variantPlan.upgradeURL.RawQuery,
		},
	}
	rawBytes, err := plan.encoder(sendEnv)
	if err != nil {
		return row, false, fmt.Errorf("pre-encode: %w", err)
	}
	sendEnv.Raw = rawBytes

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	respEnv, err := s.runResendWS(rtCtx, variantPlan, sendEnv, p)
	// USK-882 (parity with USK-789 for resend_ws + USK-832 for fuzz_http):
	// fuzz_ws bypasses session.RunSession so the proxy-path's OnComplete-
	// driven Stream finalisation never fires. Without this, the per-variant
	// Stream created by RecordStep stays pinned at State="active" forever.
	// Use the parent ctx (not rtCtx) so the terminal UPDATE lands even when
	// the per-variant request timeout expired — matches the
	// applyResendWSTag precedent below.
	finalizeResendStream(ctx, s.flowStore.store, variantPlan.streamID, err)
	if err != nil {
		return row, false, err
	}

	gotClose := false
	if respMsg, ok := respEnv.Message.(*envelope.WSMessage); ok {
		row.Opcode = wsOpcodeName(respMsg.Opcode)
		row.Fin = respMsg.Fin
		row.Compressed = respMsg.Compressed
		row.CloseCode = respMsg.CloseCode
		row.CloseReason = respMsg.CloseReason
		row.PayloadSize = len(respMsg.Payload)
		if respMsg.Opcode == envelope.WSClose {
			gotClose = true
		}
	}

	// Tag persistence uses the parent ctx (not the per-variant rtCtx)
	// so the tag write is not bound to the variant's request timeout —
	// matches resend_ws / fuzz_http behaviour.
	if tag != "" && s.flowStore.store != nil {
		s.applyResendWSTag(ctx, variantPlan.streamID, tag)
	}
	return row, gotClose, nil
}

// cloneResendWSPlanForFuzz returns a per-variant copy of base with a
// fresh streamID/connID and an isolated payload byte slice. The
// upgradeURL is preserved by reference because it is treated as
// read-only by every downstream helper; positions never touch it.
func cloneResendWSPlanForFuzz(base *resendWSPlan) *resendWSPlan {
	out := *base
	out.streamID = uuid.NewString()
	out.connID = uuid.NewString()
	if base.payload != nil {
		out.payload = append([]byte(nil), base.payload...)
	}
	if base.upgradeHeaders != nil {
		out.upgradeHeaders = append([]envelope.KeyValue(nil), base.upgradeHeaders...)
	}
	if base.upgradeURL != nil {
		copyURL := *base.upgradeURL
		out.upgradeURL = &copyURL
	} else {
		out.upgradeURL = &url.URL{}
	}
	return &out
}

// applyFuzzWSPosition writes payload at the given typed path on the
// variant plan. Caller has already validated the path via
// validFuzzWSRoots, so the path is guaranteed to be one of the known
// scalar paths.
//
// All scalar substitutions pass through verbatim — see the
// package-level "Payload passthrough" note for the rationale (CRLF /
// smuggling fuzz is the point).
func applyFuzzWSPosition(plan *resendWSPlan, path, payload string) {
	switch path {
	case "payload":
		plan.payload = []byte(payload)
	case "close_reason":
		plan.closeReason = payload
	}
}

// nextIndicesWS increments the variant index counter. Treats indices[i]
// like a digit in a mixed-radix counter where the radix at position i
// is len(positions[i].Payloads). Position 0 is the least-significant
// digit; carries propagate upward.
func nextIndicesWS(indices []int, positions []fuzzWSPosition) {
	for i := 0; i < len(indices); i++ {
		indices[i]++
		if indices[i] < len(positions[i].Payloads) {
			return
		}
		indices[i] = 0
	}
}

// decodeFuzzWSPayloads materialises the per-position payload values for
// the current variant index combination into a path → decoded payload
// string map. Decoding follows the position's encoding ("text" or
// "base64").
//
// Each decoded payload is rejected if it exceeds maxFuzzWSPayloadSize —
// see the constant doc for the rationale. The cap applies post-decode
// so a 1.4 MiB base64 string that decodes to 1 MiB is allowed.
func decodeFuzzWSPayloads(positions []fuzzWSPosition, indices []int) (map[string]string, error) {
	out := make(map[string]string, len(positions))
	for i, pos := range positions {
		raw := pos.Payloads[indices[i]]
		decoded, err := decodeBodyEncoded(raw, pos.Encoding, fmt.Sprintf("positions[%d].payloads[%d]", i, indices[i]))
		if err != nil {
			return nil, err
		}
		if len(decoded) > maxFuzzWSPayloadSize {
			return nil, fmt.Errorf("positions[%d].payloads[%d]: decoded length %d exceeds %d byte cap", i, indices[i], len(decoded), maxFuzzWSPayloadSize)
		}
		out[pos.Path] = string(decoded)
	}
	return out, nil
}
