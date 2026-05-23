// Package mcp fuzz_grpc_helpers.go holds the building blocks used by
// fuzz_grpc.go: input validation, base-plan resolution (reusing
// resend_grpc helpers), variant enumeration (cartesian product with
// hard cap), per-variant payload application against the GRPCStart /
// GRPCData envelope shape, the dial / pipeline factory (reused from
// resend_grpc), the per-variant run loop, and result formatting.
//
// # Payload passthrough — by design (MITM principle)
//
// Position payloads substituted via applyFuzzGRPCPosition are written
// verbatim, including CR/LF and other control characters. This is
// intentional: fuzz_grpc is the path most useful for testing
// upstream-side gRPC parsers / metadata handlers / payload validation
// layers. Adding a CRLF guard at substitution time would defeat the
// purpose of the tool.
//
// This is consistent with the project-wide MITM Implementation Principle
// "Do not normalize what the wire did not normalize" (CLAUDE.md). Note
// that this is asymmetric with the base-fields path:
// validateResendGRPCInput (called via fuzzGRPCInputToResendGRPC) does
// reject CR/LF in user-supplied service / method / scheme / target_addr
// — those guards apply only to base fields. Per-position payloads on
// service / method / metadata bypass that guard by design. Callers that
// need a strict (no-CRLF) mode should pre-filter their payload lists.
//
// SafetyFilter input gating still runs per-variant inside
// runFuzzGRPCSingleVariant (after position application, before the
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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzGRPCVariants caps the cartesian product across all positions.
// 1000 variants is a balance between meaningful synchronous fuzz runs
// and bounded server-side resource use; callers that need more should
// chain calls.
const maxFuzzGRPCVariants = 1000

// maxFuzzGRPCPositions caps the number of positions per call. The cap
// is generous (32) so it almost never bites; practical fuzz jobs use
// 1-3 positions.
const maxFuzzGRPCPositions = 32

// maxFuzzGRPCPayloadSize caps the *decoded* size of a single position
// payload. Without a cap, a 16 MiB payload * maxFuzzGRPCVariants (1000)
// would queue up 16 GiB of allocated payload bytes (sequential, not
// concurrent — but still a footgun). 1 MiB is generous for metadata /
// service-name / payload fuzz cases and matches fuzz_http.
const maxFuzzGRPCPayloadSize = 1 << 20

// maxFuzzGRPCResponseBodyCapture caps the per-variant concatenated DATA
// payload retained in-memory for the post_macro __response_body kvStore
// key (USK-985). 64 KiB matches maxResponseBodyKVBytes (the HTTP fuzz
// cap on __response_body) — the gRPC LPM Layer does not bound message
// size on its own, so capping at capture time avoids loading multi-MiB
// streaming responses into memory just to discard them at template
// expansion (CWE-770).
const maxFuzzGRPCResponseBodyCapture = 64 * 1024

// validFuzzGRPCRoots lists the GRPCStart scalar field paths that
// fuzz_grpc accepts. metadata[N].* and messages[N].payload paths are
// matched separately via regex; this set covers the scalar fields.
var validFuzzGRPCRoots = map[string]bool{
	"service": true,
	"method":  true,
}

// fuzzGRPCMetadataPathRE matches "metadata[N].name" or "metadata[N].value"
// where N is a non-negative decimal integer. Captures the index and
// the field name.
var fuzzGRPCMetadataPathRE = regexp.MustCompile(`^metadata\[(\d+)\]\.(name|value)$`)

// fuzzGRPCMessagePathRE matches "messages[N].payload" where N is a
// non-negative decimal integer. Captures the index.
var fuzzGRPCMessagePathRE = regexp.MustCompile(`^messages\[(\d+)\]\.payload$`)

// fuzzGRPCMessageJSONPathRE matches
// "messages[N].payload.FFFF:OOOO:type" — a JSON-path position into a
// proto-schemaless-json payload (USK-925). Captures the message index and
// the proto field key.
//
// The remainder after `payload.` is intentionally permissive (`(.+)`) —
// it can include spaces (the protobuf "embedded message" / "32-bit" /
// "64-bit" wire-type names) and colons (the `field:ordinal:type`
// separators). Strict parsing against parseKeyParts happens in
// validateFuzzGRPCPositionAgainstPlan once the targeted message's JSON
// has been resolved.
var fuzzGRPCMessageJSONPathRE = regexp.MustCompile(`^messages\[(\d+)\]\.payload\.(.+)$`)

// fuzzGRPCSupportedJSONFieldTypes lists the proto wire-type names a
// JSON-path position may target. Composite types ("repeated",
// "embedded message") are intentionally excluded for v1 — they require
// a structurally-typed payload (array / object) but the fuzz iterator
// supplies a single string per position. Callers that need to mutate
// nested fields can supply the entire embedded-message subtree via the
// `messages[N].payload` (root) path with body_encoding="proto-schemaless-json".
var fuzzGRPCSupportedJSONFieldTypes = map[string]bool{
	"String": true,
	"Varint": true,
	"32-bit": true,
	"64-bit": true,
	"bytes":  true,
}

// validateFuzzGRPCInput rejects malformed inputs at the schema boundary
// before any expensive lookups (flow store, dial) run.
//
// Inherits all of resend_grpc's validation discipline (CRLF guards on
// user-supplied URL components via the underlying resend_grpc helpers);
// fuzz-specific validation is layered on top:
// - positions list non-empty and within the per-call cap
// - each path resolves to a known field (regex-matched for indexed paths)
// - each payloads list non-empty
// - cartesian product within maxFuzzGRPCVariants
//
// Index-range validation against the resolved base plan happens later
// (after buildFuzzGRPCPlan) since it depends on the recovered metadata
// / messages length.
func validateFuzzGRPCInput(input *fuzzGRPCInput) error {
	rg := fuzzGRPCInputToResendGRPC(input)
	if err := validateResendGRPCInput(&rg); err != nil {
		return err
	}
	if len(input.Positions) == 0 {
		return errors.New("positions must contain at least one entry")
	}
	if len(input.Positions) > maxFuzzGRPCPositions {
		return fmt.Errorf("positions has %d entries; max %d per call", len(input.Positions), maxFuzzGRPCPositions)
	}
	totalVariants := 1
	for i, p := range input.Positions {
		if err := validateFuzzGRPCPosition(i, p); err != nil {
			return err
		}
		totalVariants *= len(p.Payloads)
		if totalVariants > maxFuzzGRPCVariants {
			return fmt.Errorf("positions cartesian product exceeds %d variants (computed at position %d); reduce payload counts or split into multiple calls", maxFuzzGRPCVariants, i)
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

// validateFuzzGRPCPosition validates one position entry: the path must
// resolve to a known field, the payloads list must be non-empty, and
// the encoding must be in the allowlist.
func validateFuzzGRPCPosition(index int, p fuzzGRPCPosition) error {
	if p.Path == "" {
		return fmt.Errorf("positions[%d]: path must not be empty", index)
	}
	if !isValidFuzzGRPCPath(p.Path) {
		return fmt.Errorf("positions[%d]: unsupported path %q (valid: service, method, metadata[N].name, metadata[N].value, messages[N].payload, messages[N].payload.<FFFF:OOOO:type>)", index, p.Path)
	}
	if len(p.Payloads) == 0 {
		return fmt.Errorf("positions[%d]: payloads must contain at least one element", index)
	}
	if p.Encoding != "" && p.Encoding != "text" && p.Encoding != "base64" {
		return fmt.Errorf("positions[%d]: unsupported encoding %q: must be text or base64", index, p.Encoding)
	}
	return nil
}

// isValidFuzzGRPCPath reports whether path resolves to a supported
// field. Scalar paths are exact-match against validFuzzGRPCRoots;
// indexed paths are regex-matched. The JSON-path form
// `messages[N].payload.<key>` (USK-925) is recognised here at the
// schema-shape layer; deeper validation (parseable key, supported wire
// type, json-path target message uses proto-schemaless-json) happens in
// validateFuzzGRPCPositionAgainstPlan once the base plan is resolved.
func isValidFuzzGRPCPath(path string) bool {
	if validFuzzGRPCRoots[path] {
		return true
	}
	if fuzzGRPCMetadataPathRE.MatchString(path) {
		return true
	}
	if fuzzGRPCMessagePathRE.MatchString(path) {
		return true
	}
	return fuzzGRPCMessageJSONPathRE.MatchString(path)
}

// fuzzGRPCInputToResendGRPC projects fuzz_grpc base fields onto a
// resendGRPCInput so we can reuse resend_grpc's validation and plan
// helpers without copy-paste. Fuzz-specific fields (Positions,
// StopOnNonOK) are not part of the projection.
func fuzzGRPCInputToResendGRPC(input *fuzzGRPCInput) resendGRPCInput {
	return resendGRPCInput{
		FlowID:          input.FlowID,
		TargetAddr:      input.TargetAddr,
		Scheme:          input.Scheme,
		Service:         input.Service,
		Method:          input.Method,
		Metadata:        input.Metadata,
		Encoding:        input.Encoding,
		AcceptEncoding:  input.AcceptEncoding,
		Messages:        input.Messages,
		TrailerMetadata: input.TrailerMetadata,
		TimeoutMs:       input.TimeoutMs,
		TLSFingerprint:  input.TLSFingerprint,
		Tag:             input.Tag,
	}
}

// fuzzGRPCPlan is the resolved base plan + variant enumeration.
// basePlan is the resend_grpc plan built once with from-scratch /
// flow_id-recovered fields; per-variant plans are deep-cloned and
// position-mutated.
type fuzzGRPCPlan struct {
	basePlan      *resendGRPCPlan
	positions     []fuzzGRPCPosition
	totalVariants int
}

// buildFuzzGRPCPlan resolves the base plan (delegating to resend_grpc's
// buildResendGRPCPlan) and computes the total variant count. Index-
// range checks for indexed positions (metadata[N], messages[N]) run
// here because they need the resolved plan length.
func (s *Server) buildFuzzGRPCPlan(ctx context.Context, input *fuzzGRPCInput) (*fuzzGRPCPlan, error) {
	rg := fuzzGRPCInputToResendGRPC(input)
	basePlan, err := s.buildResendGRPCPlan(ctx, &rg)
	if err != nil {
		return nil, err
	}

	for i, pos := range input.Positions {
		if err := validateFuzzGRPCPositionAgainstPlan(i, pos, basePlan); err != nil {
			return nil, err
		}
	}
	if err := validateFuzzGRPCMessagePathConflicts(input.Positions); err != nil {
		return nil, err
	}

	totalVariants := 1
	for _, p := range input.Positions {
		totalVariants *= len(p.Payloads)
	}

	return &fuzzGRPCPlan{
		basePlan:      basePlan,
		positions:     input.Positions,
		totalVariants: totalVariants,
	}, nil
}

// validateFuzzGRPCPositionAgainstPlan runs the index-range checks for
// indexed paths (metadata[N], messages[N], messages[N].payload.<key>)
// against the resolved base plan. Scalar paths (service, method) need
// no plan-side check.
//
// For JSON-path positions (USK-925) the targeted message must have been
// supplied with body_encoding="proto-schemaless-json"; otherwise the
// JSON source string isn't available for mutation. The proto field key
// must parse, must reference a field present in the input JSON, and
// must point at a supported scalar wire type (String / Varint / 32-bit
// / 64-bit / bytes).
func validateFuzzGRPCPositionAgainstPlan(idx int, pos fuzzGRPCPosition, plan *resendGRPCPlan) error {
	if matches := fuzzGRPCMetadataPathRE.FindStringSubmatch(pos.Path); matches != nil {
		return validateFuzzGRPCMetadataIndex(idx, matches[1], plan)
	}
	if matches := fuzzGRPCMessageJSONPathRE.FindStringSubmatch(pos.Path); matches != nil {
		return validateFuzzGRPCJSONPathTarget(idx, pos.Path, matches[1], matches[2], plan)
	}
	if matches := fuzzGRPCMessagePathRE.FindStringSubmatch(pos.Path); matches != nil {
		return validateFuzzGRPCMessageIndex(idx, matches[1], plan)
	}
	return nil
}

// validateFuzzGRPCMetadataIndex pins the index-range check for
// metadata[N].name|value paths. Extracted from
// validateFuzzGRPCPositionAgainstPlan to keep cyclomatic complexity low.
func validateFuzzGRPCMetadataIndex(idx int, rawIdx string, plan *resendGRPCPlan) error {
	mIdx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("positions[%d]: invalid metadata index %q: %w", idx, rawIdx, err)
	}
	if mIdx < 0 || mIdx >= len(plan.metadata) {
		return fmt.Errorf("positions[%d]: metadata index %d out of range [0, %d) — base plan has %d metadata entries", idx, mIdx, len(plan.metadata), len(plan.metadata))
	}
	return nil
}

// validateFuzzGRPCMessageIndex pins the index-range check for the
// bytes-level messages[N].payload path. Mirror helper of
// validateFuzzGRPCMetadataIndex.
func validateFuzzGRPCMessageIndex(idx int, rawIdx string, plan *resendGRPCPlan) error {
	mIdx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("positions[%d]: invalid messages index %q: %w", idx, rawIdx, err)
	}
	if mIdx < 0 || mIdx >= len(plan.messages) {
		return fmt.Errorf("positions[%d]: messages index %d out of range [0, %d) — base plan has %d messages", idx, mIdx, len(plan.messages), len(plan.messages))
	}
	return nil
}

// validateFuzzGRPCJSONPathTarget runs the layered checks for
// messages[N].payload.<key>: index range, body_encoding requirement,
// key parseability, supported wire type, and presence-in-source.
// USK-925 introduces this path; the validator block is extracted to
// keep validateFuzzGRPCPositionAgainstPlan under the lint cyclomatic
// cap.
func validateFuzzGRPCJSONPathTarget(idx int, path, rawIdx, key string, plan *resendGRPCPlan) error {
	mIdx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("positions[%d]: invalid messages index %q: %w", idx, rawIdx, err)
	}
	if mIdx < 0 || mIdx >= len(plan.messages) {
		return fmt.Errorf("positions[%d]: messages index %d out of range [0, %d) — base plan has %d messages", idx, mIdx, len(plan.messages), len(plan.messages))
	}
	if plan.messages[mIdx].bodyEncoding != "proto-schemaless-json" {
		return fmt.Errorf("positions[%d]: JSON-path %q requires messages[%d].body_encoding=\"proto-schemaless-json\" (got %q)", idx, path, mIdx, plan.messages[mIdx].bodyEncoding)
	}
	parts := parseProtoKeyParts(key)
	if parts == nil {
		return fmt.Errorf("positions[%d]: invalid proto field key %q in JSON path (expected FFFF:OOOO:type)", idx, key)
	}
	if !fuzzGRPCSupportedJSONFieldTypes[parts[2]] {
		return fmt.Errorf("positions[%d]: unsupported proto wire type %q in JSON path %q (supported: String, Varint, 32-bit, 64-bit, bytes)", idx, parts[2], path)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal([]byte(plan.messages[mIdx].jsonPayload), &m); err != nil {
		return fmt.Errorf("positions[%d]: messages[%d].payload is not valid proto-schemaless-json: %w", idx, mIdx, err)
	}
	if _, ok := m[key]; !ok {
		return fmt.Errorf("positions[%d]: proto field key %q not present in messages[%d].payload — fuzz JSON-path positions cannot add new fields", idx, key, mIdx)
	}
	return nil
}

// validateFuzzGRPCMessagePathConflicts rejects the (bytes, JSON-path)
// pair targeting the same message index. The bytes-level
// messages[N].payload position overwrites the LPM payload outright,
// which would silently lose any same-message JSON-path mutation
// (JSON commit re-derives from plan.messages[N].jsonPayload, not the
// just-overwritten bytes), so we surface the conflict up-front rather
// than have the AI agent debug a missing mutation.
func validateFuzzGRPCMessagePathConflicts(positions []fuzzGRPCPosition) error {
	bytesPos := make(map[int]int)
	jsonPos := make(map[int]int)
	for i, p := range positions {
		if matches := fuzzGRPCMessagePathRE.FindStringSubmatch(p.Path); matches != nil {
			idx, _ := strconv.Atoi(matches[1])
			bytesPos[idx] = i
			continue
		}
		if matches := fuzzGRPCMessageJSONPathRE.FindStringSubmatch(p.Path); matches != nil {
			idx, _ := strconv.Atoi(matches[1])
			jsonPos[idx] = i
		}
	}
	for idx, bi := range bytesPos {
		if ji, ok := jsonPos[idx]; ok {
			return fmt.Errorf("positions[%d] and positions[%d]: cannot combine messages[%d].payload (bytes-level) and messages[%d].payload.<key> (JSON-path) on the same message — pick one", bi, ji, idx, idx)
		}
	}
	return nil
}

// parseProtoKeyParts mirrors internal/encoding/protobuf parseKeyParts —
// duplicated here because that helper is package-private. Splits
// "FFFF:OOOO:type" into [fieldNumber, ordinal, type]; returns nil on
// malformed input.
func parseProtoKeyParts(key string) []string {
	i1 := strings.Index(key, ":")
	if i1 < 0 {
		return nil
	}
	rest := key[i1+1:]
	i2 := strings.Index(rest, ":")
	if i2 < 0 {
		return nil
	}
	return []string{key[:i1], rest[:i2], rest[i2+1:]}
}

// runFuzzGRPCVariants iterates the cartesian product of all positions,
// running each variant through a fresh resend_grpc-style upstream RPC.
// The pipeline is shared across variants (PluginStepPost + RecordStep
// fire on every variant's envelopes); each variant gets a fresh
// streamID + connID + dial.
//
// Returns the per-variant rows, the count of completed variants, and
// an optional stop reason ("" when all variants ran to completion).
//
// USK-831: persists one fuzz_results row per variant via
// FuzzStore.SaveFuzzResult so `query fuzz_results { fuzz_id }` is
// populated for both successful and error variants. Store-write
// failures are non-fatal (slog.Warn + continue) — the wire data is on
// disk via RecordStep and remains the source of truth.
//
// USK-985: scope="job" hooks fire exactly once outside the variant
// loop against a separate job-scoped kvStore that is merged into each
// iteration's per-variant store. pre-job runs between loop-state setup
// and the for-variant loop; post-job runs after the loop body exits
// (including the stop_on_non_ok terminal path, but NOT on ctx cancel
// or pre-job abort). Mirrors the fuzz_http precedent in USK-961.
func (s *Server) runFuzzGRPCVariants(ctx context.Context, plan *fuzzGRPCPlan, timeout time.Duration, stopOnNonOK bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) ([]fuzzGRPCVariantRow, int, string, error) {
	loop := buildFuzzGRPCVariantLoop(s, plan, timeout, stopOnNonOK, tag, fuzzID, preMacro, postMacro)

	// USK-985 pre-job: fire once before the variant loop. Abort short-
	// circuits the whole job; skip returns success with stopped_reason;
	// continue records the error and proceeds with whatever jobKVStore
	// captured.
	if IsJobScope(preMacro) {
		jobAction, stopReason, retErr := loop.runPreJobMacro(ctx)
		if retErr != nil {
			return loop.rows, loop.completed, "", retErr
		}
		if jobAction == fuzzGRPCPreJobSkipAll {
			return loop.rows, loop.completed, stopReason, nil
		}
	}

	completedNormally, earlyStopReason, retErr := loop.runVariantLoop(ctx)
	if retErr != nil {
		return loop.rows, loop.completed, "", retErr
	}

	// USK-985 post-job: fire after the variant loop exits. Mirrors
	// USK-961 Q5 rule — post-job fires on natural exhaustion or
	// stop_on_non_ok exit, but NOT on ctx cancel.
	if completedNormally && IsJobScope(postMacro) {
		loop.runPostJobMacro(ctx)
	}

	return loop.rows, loop.completed, earlyStopReason, nil
}

// buildFuzzGRPCVariantLoop assembles the per-run state container shared
// by all variants. Split out of runFuzzGRPCVariants to keep that function
// below the gocyclo threshold; mirrors fuzz_http's
// buildFuzzHTTPVariantLoop (USK-961). The construction logic is
// mechanical and has no branch fan-out outside the hook-config assembly.
func buildFuzzGRPCVariantLoop(s *Server, plan *fuzzGRPCPlan, timeout time.Duration, stopOnNonOK bool, tag, fuzzID string, preMacro, postMacro *MacroConfig) *fuzzGRPCVariantLoop {
	loop := &fuzzGRPCVariantLoop{
		s:           s,
		plan:        plan,
		timeout:     timeout,
		stopOnNonOK: stopOnNonOK,
		tag:         tag,
		fuzzID:      fuzzID,
		preMacro:    preMacro,
		postMacro:   postMacro,
		encoders:    buildResendGRPCEncoderRegistry(),
	}
	loop.pipe = s.buildFuzzGRPCPipeline(loop.encoders)

	// Strip the port to align rate-limit bucket keys with the live data path
	// (connector/connect_handler.go, http1_forward_handler.go, socks5.go) and
	// with target_scope matching, both of which key on host only. Falling
	// back to the raw authority on SplitHostPort error mirrors the
	// connector's behaviour for entries without an explicit port.
	rateLimitHost, _, err := net.SplitHostPort(plan.basePlan.authority)
	if err != nil {
		rateLimitHost = plan.basePlan.authority
	}
	loop.rateLimitHost = rateLimitHost

	loop.hookExec = BuildIterationHookExecutor(s, preMacro, postMacro)
	loop.jobHookExec, loop.jobKVStore = BuildJobHookExecutor(s, preMacro, postMacro)

	loop.rows = make([]fuzzGRPCVariantRow, 0, plan.totalVariants)
	loop.indices = make([]int, len(plan.positions))

	return loop
}

// fuzzGRPCVariantLoop bundles the per-run state shared across iterations
// so the inner loop body (runOne) is a method on a small struct instead
// of a many-argument free function. Mirrors fuzz_http's
// fuzzHTTPVariantLoop (USK-961).
//
// USK-985 adds jobKVStore + jobHookExec for scope="job" hooks. The two
// kvStores (per-iteration + job) are deliberately separate: per-iteration
// reserved keys (§__iteration§ / §__nonce§ / __response_*) overwrite any
// conflicting keys from the job store at iteration start ("iteration
// wins" — matches the "caller wins" precedent in executePreMacro /
// executePostMacro's vars-merge dance).
type fuzzGRPCVariantLoop struct {
	s           *Server
	plan        *fuzzGRPCPlan
	timeout     time.Duration
	stopOnNonOK bool
	tag         string
	fuzzID      string
	preMacro    *MacroConfig
	postMacro   *MacroConfig
	encoders    *pipeline.WireEncoderRegistry
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

	rows      []fuzzGRPCVariantRow
	indices   []int
	completed int
}

// runVariantLoop drives the variant loop body and returns
// (completedNormally, earlyStopReason, retErr). completedNormally is
// true when the loop reached the post-job firing path (natural
// exhaustion or stop_on_non_ok); it is false on ctx cancel. retErr
// non-nil signals an unrecoverable abort and post-job MUST NOT fire.
// Mirrors fuzz_http's runVariantLoop (USK-979/USK-961).
func (l *fuzzGRPCVariantLoop) runVariantLoop(ctx context.Context) (bool, string, error) {
	for variantIdx := 0; variantIdx < l.plan.totalVariants; variantIdx++ {
		stop, retErr := l.runOne(ctx, variantIdx)
		if retErr != nil {
			if errors.Is(retErr, context.Canceled) || errors.Is(retErr, context.DeadlineExceeded) {
				// post-job does NOT fire on ctx cancel. Surface the cancel
				// reason via stopped_reason; do NOT propagate as retErr so
				// the caller still finalizes the fuzz_jobs row normally.
				return false, fmt.Sprintf("ctx cancelled: %v", retErr), nil
			}
			// pre-iteration abort or other unrecoverable error. post-job
			// does NOT fire on pre-iteration abort.
			return false, "", retErr
		}
		if stop == "" {
			continue
		}
		// stop_on_non_ok reaches here. post-job fires on stop_on_non_ok.
		return true, stop, nil
	}
	return true, "", nil
}

// runOne executes a single iteration of the variant loop. Returns
// (stopReason, retErr): stopReason "" means continue; non-empty means
// stop with that reason (e.g., stop_on_non_ok); retErr propagates an
// abort up the call stack. ctx cancel is surfaced via retErr wrapped
// with %w so the caller can distinguish via errors.Is.
func (l *fuzzGRPCVariantLoop) runOne(ctx context.Context, variantIdx int) (string, error) {
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("variant %d: %w", variantIdx, ctx.Err())
	default:
	}

	if err := l.s.waitRateLimit(ctx, l.rateLimitHost); err != nil {
		return fmt.Sprintf("rate limit: %v", err), nil
	}

	payloads, err := decodeFuzzGRPCPayloads(l.plan.positions, l.indices)
	if err != nil {
		return "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
	}

	// USK-985: build the per-iteration kvStore (jobKV copy + iter-scope
	// Vars + reserved-key seeding) shared between the variant request
	// templating and the pre/post macro hooks.
	kvStore := PrepareIteration(l.jobKVStore, l.preMacro, l.postMacro, variantIdx)

	// USK-985: pre-iteration only fires when pre is configured at
	// scope="iteration" (empty defaults to iteration). When pre is
	// scope="job", the executor was invoked once outside the loop.
	if IsIterationScope(l.preMacro) {
		preState, retErr := l.runPreMacro(ctx, variantIdx, payloads, kvStore)
		if retErr != nil {
			return "", retErr
		}
		if preState == fuzzGRPCPreSkipped {
			// USK-981: bump the iteration counter even on skip so
			// RunInterval engine gates (every_n) treat skipped iterations
			// as consuming their slot.
			BumpHookIterationCount(l.hookExec)
			nextFuzzGRPCIndices(l.indices, l.plan.positions)
			return "", nil
		}
	}

	variantStart := time.Now()
	row, statusCode, body, runErr := l.s.runFuzzGRPCSingleVariant(ctx, l.plan, l.pipe, l.timeout, variantIdx, payloads, l.tag)
	row.DurationMs = time.Since(variantStart).Milliseconds()

	if runErr != nil {
		row.Error = runErr.Error()
	}
	l.rows = append(l.rows, row)
	l.completed++
	l.s.saveFuzzGRPCResult(ctx, l.fuzzID, variantIdx, row, payloads)

	// USK-985: gate post-iteration on scope="iteration" (or empty —
	// defaults to iteration). scope="job" post runs once after the
	// variant loop completes.
	if IsIterationScope(l.postMacro) {
		l.runPostMacro(ctx, variantIdx, row, body, kvStore)
	}

	// USK-981: bump the iteration counter at the end of every normal-
	// path iteration so RunInterval engine gates (every_n) see one more
	// completed iteration before the next runOne call evaluates
	// shouldRunPreMacro.
	BumpHookIterationCount(l.hookExec)

	nextFuzzGRPCIndices(l.indices, l.plan.positions)

	if l.stopOnNonOK && (runErr != nil || statusCode != 0) {
		return fmt.Sprintf("stop_on_non_ok: variant %d returned status=%d err=%q", variantIdx, statusCode, errString(runErr)), nil
	}
	return "", nil
}

// fuzzGRPCPreMacroOutcome marks whether the variant loop should proceed
// with the upstream send after pre_macro resolution. Mirrors fuzz_http's
// fuzzHTTPPreMacroOutcome.
type fuzzGRPCPreMacroOutcome int

const (
	// fuzzGRPCPreOK = pre macro ran successfully, or was not configured;
	// continue to body send.
	fuzzGRPCPreOK fuzzGRPCPreMacroOutcome = iota
	// fuzzGRPCPreSkipped = pre macro failed under on_error=skip; the
	// caller has already recorded the skipped row, do NOT send the
	// variant, do NOT fire post_macro.
	fuzzGRPCPreSkipped
)

// runPreMacro dispatches the pre_macro hook for this iteration and
// translates the OnError policy into a pre-macro outcome. Returns
// (outcome, retErr): retErr non-nil aborts the whole fuzz run; outcome
// drives the caller's decision to send or short-circuit. Mirrors
// fuzz_http's runPreMacro (USK-960).
func (l *fuzzGRPCVariantLoop) runPreMacro(ctx context.Context, variantIdx int, payloads map[string]string, kvStore map[string]string) (fuzzGRPCPreMacroOutcome, error) {
	if l.preMacro == nil {
		return fuzzGRPCPreOK, nil
	}
	_, hookErr := l.hookExec.executePreMacro(ctx, kvStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "ok", 0, "")
		return fuzzGRPCPreOK, nil
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		return fuzzGRPCPreOK, fmt.Errorf("variant %d pre_macro hook abort: %w", variantIdx, hookErr)
	case "continue":
		slog.WarnContext(ctx, "fuzz_grpc: pre_macro hook error (on_error=continue)",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "error", 0, hookErr.Error())
		return fuzzGRPCPreOK, nil
	default: // skip
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "pre", "", "skipped", 0, hookErr.Error())
		row := fuzzGRPCVariantRow{
			Index:    variantIdx,
			Payloads: payloads,
			Error:    fmt.Sprintf("pre_macro hook failed (on_error=skip): %v", hookErr),
		}
		l.rows = append(l.rows, row)
		l.completed++
		l.s.saveFuzzGRPCResult(ctx, l.fuzzID, variantIdx, row, payloads)
		return fuzzGRPCPreSkipped, nil
	}
}

// runPostMacro fires the post_macro hook against the same kvStore that
// pre_macro shared. Post failures NEVER abort the run — record a
// fuzz_macro_results row and return. Mirrors fuzz_http's runPostMacro.
//
// USK-985: gRPC-specific __response_* keys (status / status_message /
// body / message_count / total_bytes) are injected into kvStore BEFORE
// executePostMacro fires so the gRPC status domain (0-16) is visible to
// the macro's template expansion. The statusCode passed to
// executePostMacro is the gRPC status code (0-16) so the on_status
// RunInterval gate matches against gRPC codes; PassResponse-driven
// HTTP-shaped injection inside executePostMacro becomes a no-op because
// we pass nil body / nil headers.
func (l *fuzzGRPCVariantLoop) runPostMacro(ctx context.Context, variantIdx int, row fuzzGRPCVariantRow, body []byte, kvStore map[string]string) {
	injectGRPCResponseVars(kvStore, row.Status, row.StatusMessage, body, row.ResponseMessageCount, row.ResponseTotalBytes)
	// Pass nil body / nil headers so the HTTP-shaped injectResponseVars
	// inside executePostMacro (gated by hookConfig.PassResponse=true)
	// becomes a no-op for the gRPC-specific keys we just wrote. The
	// statusCode parameter feeds the on_status RunInterval gate, so we
	// pass the gRPC status (int(row.Status)) — operators specifying
	// status_codes: [14] get UNAVAILABLE matching.
	hookErr := l.hookExec.executePostMacro(ctx, int(row.Status), nil, nil, kvStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_grpc: post_macro hook error",
			"fuzz_id", l.fuzzID, "variant", variantIdx, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "error", int(row.Status), hookErr.Error())
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, variantIdx, "post", "", "ok", int(row.Status), "")
}

// fuzzGRPCJobPreOutcome marks the pre-job hook's effect on the
// surrounding job loop. Mirrors fuzz_http's fuzzHTTPJobPreOutcome.
type fuzzGRPCJobPreOutcome int

const (
	// fuzzGRPCPreJobOK = pre-job ran successfully (or under
	// on_error=continue): proceed with the variant loop.
	fuzzGRPCPreJobOK fuzzGRPCJobPreOutcome = iota
	// fuzzGRPCPreJobSkipAll = pre-job failed under on_error=skip: skip
	// the entire job. fuzz_grpc returns a successful result with
	// CompletedVariants=0 and stopped_reason set (USK-961 U1 precedent).
	fuzzGRPCPreJobSkipAll
)

// runPreJobMacro fires the pre_macro hook ONCE outside the variant loop
// (scope="job"). Behavior on failure follows the OnError policy:
//
//   - abort: return a wrapped error that aborts the whole job before any
//     variant runs (caller propagates as retErr).
//   - continue: log warn, record a fuzz_macro_results row at
//     index_num=-1, status="error"; proceed with whatever jobKVStore
//     captured.
//   - skip: record a fuzz_macro_results row at index_num=-1,
//     status="skipped"; return fuzzGRPCPreJobSkipAll so the caller
//     short-circuits the whole job with a stopped_reason.
//
// fuzz_macro_results.index_num=-1 is the documented sentinel for
// job-scope hook rows (jobScopeIndexNumSentinel; defined in
// fuzz_http_helpers.go and shared across fuzz_* per USK-983).
func (l *fuzzGRPCVariantLoop) runPreJobMacro(ctx context.Context) (fuzzGRPCJobPreOutcome, string, error) {
	if l.jobHookExec == nil || l.preMacro == nil || !IsJobScope(l.preMacro) {
		return fuzzGRPCPreJobOK, "", nil
	}
	_, hookErr := l.jobHookExec.executePreMacro(ctx, l.jobKVStore)
	if hookErr == nil {
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "ok", 0, "")
		return fuzzGRPCPreJobOK, "", nil
	}
	policy := l.preMacro.OnError
	if policy == "" {
		policy = "skip"
	}
	switch policy {
	case "abort":
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzGRPCPreJobOK, "", fmt.Errorf("pre_macro hook abort (scope=job): %w", hookErr)
	case "continue":
		slog.WarnContext(ctx, "fuzz_grpc: pre_macro hook error (scope=job, on_error=continue)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "error", 0, hookErr.Error())
		return fuzzGRPCPreJobOK, "", nil
	default: // skip
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "pre", "", "skipped", 0, hookErr.Error())
		stopReason := fmt.Sprintf("pre_macro hook skipped (scope=job, on_error=skip): %v", hookErr)
		return fuzzGRPCPreJobSkipAll, stopReason, nil
	}
}

// runPostJobMacro fires the post_macro hook ONCE after the variant loop
// completes (scope="job"). Post-job fires on natural exhaustion or
// stop_on_non_ok, but NOT on ctx cancel (the caller gates on
// completedNormally). Post-job sees only the jobKVStore — per-iteration
// response keys (__response_*) are NOT available because each
// iteration's kvStore was discarded. Mirrors fuzz_http's runPostJobMacro
// (USK-961 Q5/Q21).
func (l *fuzzGRPCVariantLoop) runPostJobMacro(ctx context.Context) {
	if l.jobHookExec == nil || l.postMacro == nil || !IsJobScope(l.postMacro) {
		return
	}
	// Post-job has no per-iteration response to inject. Pass zero values
	// for status / body / headers; PassResponse=false on the jobHookExec
	// makes the HTTP-shaped injection a no-op.
	hookErr := l.jobHookExec.executePostMacro(ctx, 0, nil, nil, l.jobKVStore)
	if hookErr != nil {
		slog.WarnContext(ctx, "fuzz_grpc: post_macro hook error (scope=job)",
			"fuzz_id", l.fuzzID, "error", hookErr)
		l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "error", 0, hookErr.Error())
		return
	}
	l.s.saveFuzzMacroHookResult(ctx, l.fuzzID, jobScopeIndexNumSentinel, "post", "", "ok", 0, "")
}

// fuzzGRPCJobConfig is the JSON payload persisted to fuzz_jobs.config.
// Intentionally records only structural metadata: position paths,
// payload counts, encoding labels, and the stop_on_non_ok flag. Raw
// payload values are deliberately excluded — they can be re-derived
// from each Stream's recorded Flow, and including them here would
// inflate the row and surface potentially-sensitive payloads (auth
// tokens, PII used in fuzzing) in the aggregation table.
type fuzzGRPCJobConfig struct {
	Positions     []fuzzGRPCJobPosition `json:"positions"`
	StopOnNonOK   bool                  `json:"stop_on_non_ok"`
	TotalVariants int                   `json:"total_variants"`
}

// fuzzGRPCJobPosition is one position entry inside fuzz_jobs.config.
// Only structural metadata is recorded — see fuzzGRPCJobConfig for the
// payload-omission rationale.
type fuzzGRPCJobPosition struct {
	Path         string `json:"path"`
	PayloadCount int    `json:"payload_count"`
	Encoding     string `json:"encoding,omitempty"`
}

// saveFuzzGRPCJob persists the initial fuzz_jobs row at status="running".
// Called once before the variant loop starts. Store-write failures are
// logged at slog.Warn and ignored — the fuzz run itself is not blocked
// because aggregation persistence is best-effort.
//
// fuzz_jobs.stream_id is set from input.FlowID when the caller seeded
// the run from a recorded flow; otherwise it is left empty.
func (s *Server) saveFuzzGRPCJob(ctx context.Context, fuzzID string, input *fuzzGRPCInput, plan *fuzzGRPCPlan) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}

	cfg := fuzzGRPCJobConfig{
		Positions:     make([]fuzzGRPCJobPosition, 0, len(input.Positions)),
		StopOnNonOK:   input.StopOnNonOK,
		TotalVariants: plan.totalVariants,
	}
	for _, p := range input.Positions {
		cfg.Positions = append(cfg.Positions, fuzzGRPCJobPosition{
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
		slog.WarnContext(ctx, "fuzz_grpc: save fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"error", err,
		)
	}
}

// finalizeFuzzGRPCJob updates the fuzz_jobs row at end of run with the
// final status / completed_at / counts. Called with a fresh background
// context so caller-side ctx cancel does not prevent the closing
// UPDATE from landing.
//
// Status rule (mirrors USK-827): "completed" when the variant loop ran
// to natural exhaustion OR when stop_on_non_ok triggered (a documented
// exit, not a failure). "error" only when the run aborted before
// completion due to a non-stop_on_non_ok runErr.
//
// error_count counts per-variant errors observed in the rows
// (row.Error != ""); store-write failures intentionally do NOT bump
// this counter — they are observability gaps, not request failures.
func (s *Server) finalizeFuzzGRPCJob(ctx context.Context, fuzzID string, rows []fuzzGRPCVariantRow, completed int, stopReason string, runErr error) {
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
	// stop_on_non_ok aborts early (completed < total).
	existing, err := s.jobRunner.fuzzStore.GetFuzzJob(ctx, fuzzID)
	if err != nil {
		slog.WarnContext(ctx, "fuzz_grpc: load fuzz_jobs row for finalize failed",
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
		slog.WarnContext(ctx, "fuzz_grpc: update fuzz_jobs row failed",
			"fuzz_id", fuzzID,
			"status", status,
			"error", err,
		)
	}
	_ = stopReason // stop_reason is recorded in the response payload; no fuzz_jobs column today
}

// saveFuzzGRPCResult persists a single per-variant fuzz_results row.
// Called from the variant loop after each variant completes (success
// or error). Save failures are logged at slog.Warn and ignored — the
// per-variant Flow rows persisted via RecordStep are the source of
// truth for forensic drill-down.
//
// Per-protocol StatusCode mapping (USK-831): gRPC variant rows expose
// the gRPC status code via row.Status (uint32) and the summed response
// data byte length via row.ResponseTotalBytes. Mapped into
// FuzzResult.StatusCode (int) + ResponseLength so the aggregation query
// (`query fuzz_results`) has a uniform shape across protocols.
func (s *Server) saveFuzzGRPCResult(ctx context.Context, fuzzID string, index int, row fuzzGRPCVariantRow, payloads map[string]string) {
	if s.jobRunner == nil || s.jobRunner.fuzzStore == nil {
		return
	}
	result := &flow.FuzzResult{
		FuzzID:         fuzzID,
		IndexNum:       index,
		StreamID:       row.StreamID,
		Payloads:       flow.PayloadsToJSON(payloads),
		StatusCode:     int(row.Status),
		ResponseLength: row.ResponseTotalBytes,
		DurationMs:     int(row.DurationMs),
		Error:          row.Error,
	}
	if err := s.jobRunner.fuzzStore.SaveFuzzResult(ctx, result); err != nil {
		slog.WarnContext(ctx, "fuzz_grpc: save fuzz_results row failed",
			"fuzz_id", fuzzID,
			"index", index,
			"stream_id", row.StreamID,
			"error", err,
		)
	}
}

// buildFuzzGRPCPipeline constructs the per-variant pipeline for fuzz_grpc.
// Mirrors buildResendGRPCPipeline but stamps variant Streams with
// flow.OriginFuzz so `query flows { filter.origin: "fuzz" }` filters
// fuzz-originated traffic away from live capture views (parity with
// fuzz_http's OriginFuzz stamping).
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass). HostScope and Safety are handled at the handler level
// before the envelope reaches the pipeline.
func (s *Server) buildFuzzGRPCPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		// USK-818: BudgetStep at position #1 — only the GRPCStartMessage
		// Send counts (BudgetStep filters mid-stream Data/End).
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

// errString returns err.Error() or "" if err is nil. Tiny helper for
// stoppedReason formatting.
func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// runFuzzGRPCSingleVariant executes one variant: clones the base plan,
// applies all position payloads, runs the safety filter, then runs the
// resend_grpc-style RPC through the shared pipeline + a fresh dial.
//
// Per-variant SafetyFilter input gating runs after position application
// and before the upstream dial (mirroring fuzz_http per-variant
// semantics — USK-677 lesson F-1/S-1). On a violation the variant is
// recorded with row.Error set and returns runErr=nil, statusCode=0 — the
// run loop continues to the next variant. Safety-blocked variants do
// NOT trigger stop_on_non_ok (which fires only on runErr != nil or a
// non-zero gRPC status code), matching the fuzz_http precedent.
//
// USK-985: returns the per-variant concatenated DATA payload bytes
// (capped at maxFuzzGRPCResponseBodyCapture / 64 KiB at capture time)
// for post_macro __response_body injection. Truncation happens here
// rather than at injection time so multi-MiB streaming responses are
// not loaded into memory only to be discarded by the kvStore cap
// (CWE-770). The full per-flow wire payloads remain retrievable via
// the recorded Flow rows under row.StreamID — this return is the
// kvStore convenience projection, not the source of truth.
func (s *Server) runFuzzGRPCSingleVariant(ctx context.Context, plan *fuzzGRPCPlan, p *pipeline.Pipeline, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzGRPCVariantRow, uint32, []byte, error) {
	row := fuzzGRPCVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantPlan := cloneFuzzGRPCPlan(plan.basePlan)
	// Collected JSON-path mutations (USK-925) keyed by message index, then
	// proto field key. Committed after all positions are processed so
	// multiple JSON-path positions on the same message share one
	// Decode→mutate→Encode round-trip.
	jsonMuts := make(map[int]map[string]json.RawMessage)
	for _, pos := range plan.positions {
		payload, ok := payloads[pos.Path]
		if !ok {
			continue
		}
		if err := applyFuzzGRPCPosition(variantPlan, pos.Path, payload, jsonMuts); err != nil {
			return row, 0, nil, fmt.Errorf("apply position %q: %w", pos.Path, err)
		}
	}
	if err := commitFuzzGRPCJSONMutations(variantPlan, jsonMuts); err != nil {
		return row, 0, nil, fmt.Errorf("commit JSON-path mutations: %w", err)
	}
	// Re-derive the canonical URL after potential service/method mutation
	// so the safety filter and any downstream consumer see the substituted
	// values. Authority/scheme do not change per variant.
	scheme := "http"
	if variantPlan.useTLS {
		scheme = "https"
	}
	variantPlan.canonicalURL = resendGRPCCanonicalURL(scheme, variantPlan.authority, variantPlan.service, variantPlan.method)

	row.StreamID = variantPlan.streamID

	// SafetyFilter input gating: run AFTER position application so the
	// destructive-sql / destructive-os-command presets see the substituted
	// payloads (matches fuzz_http per-variant semantics — USK-677 F-1/S-1
	// lesson). On a violation we record row.Error and return statusCode=0;
	// the run loop continues to the next variant.
	if v := s.checkSafetyInput(concatResendGRPCPayloads(variantPlan), variantPlan.canonicalURL.String(), variantPlan.metadata); v != nil {
		row.Error = safetyViolationError(v)
		return row, 0, nil, nil
	}

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endEnv, recvData, _, err := s.runResendGRPC(rtCtx, variantPlan, p)
	if err != nil {
		return row, 0, nil, err
	}

	if endEnv != nil {
		if endMsg, ok := endEnv.Message.(*envelope.GRPCEndMessage); ok {
			row.Status = endMsg.Status
			row.StatusMessage = endMsg.Message
		}
	}
	row.ResponseMessageCount = len(recvData)
	// USK-985: capture the concatenated DATA payload bytes alongside the
	// per-variant byte sum. Cap at maxFuzzGRPCResponseBodyCapture so a
	// streaming response cannot bloat the post_macro kvStore (CWE-770).
	// Truncation is at capture time so we never allocate beyond the cap
	// even when the upstream emits gigabyte responses; row.ResponseTotalBytes
	// still records the true wire total because it counts per-payload-len.
	body := captureGRPCResponseBody(recvData)
	for _, e := range recvData {
		if dataMsg, ok := e.Message.(*envelope.GRPCDataMessage); ok {
			row.ResponseTotalBytes += len(dataMsg.Payload)
		}
	}

	// Tag persistence uses the parent ctx (not the per-variant rtCtx) so
	// the tag write is not bound to the variant's RPC timeout — matches
	// fuzz_http behaviour.
	if tag != "" && s.flowStore.store != nil {
		s.applyResendGRPCTag(ctx, variantPlan.streamID, tag)
	}
	return row, row.Status, body, nil
}

// injectGRPCResponseVars writes the gRPC-specific __response_* reserved
// keys into kvStore for consumption by fuzz_grpc post_macro template
// expansion. USK-985.
//
// Keys written:
//   - __response_status: gRPC status code as decimal string (0-16 domain
//     per google.golang.org/grpc/codes; 0 = OK). Operators specifying
//     run_interval=on_status with status_codes must supply gRPC codes,
//     NOT HTTP codes.
//   - __response_status_message: gRPC end-trailer status_message field
//     verbatim (empty on OK).
//   - __response_body: concatenated DATA-payload bytes from the receive
//     side, capped at maxFuzzGRPCResponseBodyCapture (64 KiB) at capture
//     time. CWE-770: cap is enforced at capture inside
//     runFuzzGRPCSingleVariant rather than here so multi-MiB streaming
//     responses are never loaded into memory beyond the cap.
//   - __response_message_count: number of receive-side DATA envelopes
//     (decimal int).
//   - __response_total_bytes: pre-truncation byte sum across every
//     receive-side DATA envelope (decimal int; matches
//     fuzz_results.response_length).
//
// Header-projected keys (__response_headers__<lower(name)>__) are NOT
// written: gRPC metadata is exposed only via the trailer-metadata path,
// which v1 of this seam defers to follow-up (USK-985 design lock). The
// recorded Flow under row.StreamID retains the full trailer metadata for
// drill-down via the query tool.
func injectGRPCResponseVars(kvStore map[string]string, status uint32, statusMessage string, body []byte, messageCount, totalBytes int) {
	kvStore[macroResponseStatusKey] = strconv.FormatUint(uint64(status), 10)
	kvStore[macroResponseStatusMessageKey] = statusMessage
	kvStore[macroResponseBodyKey] = string(body)
	kvStore[macroResponseMessageCountKey] = strconv.Itoa(messageCount)
	kvStore[macroResponseTotalBytesKey] = strconv.Itoa(totalBytes)
}

// captureGRPCResponseBody concatenates the DATA-message payloads from
// recvData, stopping once maxFuzzGRPCResponseBodyCapture is reached.
// USK-985: callers consume this as the source for the post_macro
// __response_body kvStore key. Truncation happens here (at receive-side
// walk time) rather than at template-expansion time so streaming
// responses with many GiB of payload do not allocate beyond the cap.
//
// Order: recvData is in receive order as appended by
// receiveResendGRPCResponses (resend_grpc_helpers.go), which is on-wire
// order — deterministic per stream.
func captureGRPCResponseBody(recvData []*envelope.Envelope) []byte {
	if len(recvData) == 0 {
		return nil
	}
	buf := make([]byte, 0, maxFuzzGRPCResponseBodyCapture)
	for _, e := range recvData {
		dataMsg, ok := e.Message.(*envelope.GRPCDataMessage)
		if !ok || len(dataMsg.Payload) == 0 {
			continue
		}
		remaining := maxFuzzGRPCResponseBodyCapture - len(buf)
		if remaining <= 0 {
			break
		}
		if len(dataMsg.Payload) <= remaining {
			buf = append(buf, dataMsg.Payload...)
			continue
		}
		buf = append(buf, dataMsg.Payload[:remaining]...)
		break
	}
	if len(buf) == 0 {
		return nil
	}
	return buf
}

// nextFuzzGRPCIndices increments the variant index counter (mixed-radix
// counter; position 0 = least-significant digit; carries propagate
// upward). Mirrors fuzz_http's nextIndices.
func nextFuzzGRPCIndices(indices []int, positions []fuzzGRPCPosition) {
	for i := 0; i < len(indices); i++ {
		indices[i]++
		if indices[i] < len(positions[i].Payloads) {
			return
		}
		indices[i] = 0
	}
}

// decodeFuzzGRPCPayloads materialises the per-position payload values
// for the current variant index combination into a path → decoded
// payload string map. Decoding follows the position's encoding ("text"
// or "base64").
//
// Each decoded payload is rejected if it exceeds maxFuzzGRPCPayloadSize.
// The cap applies post-decode so a 1.4 MiB base64 string that decodes
// to 1 MiB is allowed.
func decodeFuzzGRPCPayloads(positions []fuzzGRPCPosition, indices []int) (map[string]string, error) {
	out := make(map[string]string, len(positions))
	for i, pos := range positions {
		raw := pos.Payloads[indices[i]]
		decoded, err := decodeBodyEncoded(raw, pos.Encoding, fmt.Sprintf("positions[%d].payloads[%d]", i, indices[i]))
		if err != nil {
			return nil, err
		}
		if len(decoded) > maxFuzzGRPCPayloadSize {
			return nil, fmt.Errorf("positions[%d].payloads[%d]: decoded length %d exceeds %d byte cap", i, indices[i], len(decoded), maxFuzzGRPCPayloadSize)
		}
		out[pos.Path] = string(decoded)
	}
	return out, nil
}

// applyFuzzGRPCPosition writes payload at the given typed path on the
// variant plan. Unknown paths are rejected (validation runs upfront +
// against-plan, so this is a defensive catch — should never fire in
// practice).
//
// JSON-path positions (messages[N].payload.<key>, USK-925) are NOT
// applied here — they are batched per message and committed via
// commitFuzzGRPCJSONMutations after every position has been processed,
// so multiple JSON-path positions targeting the same message share a
// single Decode/Encode round-trip and one cohesive JSON tree mutation.
func applyFuzzGRPCPosition(plan *resendGRPCPlan, path, payload string, jsonMuts map[int]map[string]json.RawMessage) error {
	switch path {
	case "service":
		plan.service = payload
		return nil
	case "method":
		plan.method = payload
		return nil
	}
	if matches := fuzzGRPCMetadataPathRE.FindStringSubmatch(path); matches != nil {
		return applyFuzzGRPCMetadataPosition(plan, matches[1], matches[2], payload)
	}
	if matches := fuzzGRPCMessageJSONPathRE.FindStringSubmatch(path); matches != nil {
		return applyFuzzGRPCMessageJSONPathPosition(plan, matches[1], matches[2], payload, jsonMuts)
	}
	if matches := fuzzGRPCMessagePathRE.FindStringSubmatch(path); matches != nil {
		return applyFuzzGRPCMessagePosition(plan, matches[1], payload)
	}
	return fmt.Errorf("unsupported path %q", path)
}

// applyFuzzGRPCMetadataPosition writes payload to plan.metadata[idx].
// field is "name" or "value" per the regex shape.
func applyFuzzGRPCMetadataPosition(plan *resendGRPCPlan, rawIdx, field, payload string) error {
	idx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("invalid metadata index %q: %w", rawIdx, err)
	}
	if idx < 0 || idx >= len(plan.metadata) {
		return fmt.Errorf("metadata index %d out of range [0, %d)", idx, len(plan.metadata))
	}
	switch field {
	case "name":
		plan.metadata[idx].Name = payload
	case "value":
		plan.metadata[idx].Value = payload
	}
	return nil
}

// applyFuzzGRPCMessageJSONPathPosition stages a JSON-path mutation
// (USK-925) onto the per-variant jsonMuts map. The commit pass folds
// these into the message's proto-schemaless source and re-encodes once
// per message; see commitFuzzGRPCJSONMutations.
func applyFuzzGRPCMessageJSONPathPosition(plan *resendGRPCPlan, rawIdx, key, payload string, jsonMuts map[int]map[string]json.RawMessage) error {
	idx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("invalid messages index %q: %w", rawIdx, err)
	}
	if idx < 0 || idx >= len(plan.messages) {
		return fmt.Errorf("messages index %d out of range [0, %d)", idx, len(plan.messages))
	}
	val, err := encodeFuzzGRPCJSONFieldValue(key, payload)
	if err != nil {
		return fmt.Errorf("encode proto field value for %q: %w", key, err)
	}
	if jsonMuts[idx] == nil {
		jsonMuts[idx] = make(map[string]json.RawMessage)
	}
	jsonMuts[idx][key] = val
	return nil
}

// applyFuzzGRPCMessagePosition overwrites plan.messages[idx].payload
// with the raw bytes form. Mirror helper of the metadata variant.
func applyFuzzGRPCMessagePosition(plan *resendGRPCPlan, rawIdx, payload string) error {
	idx, err := strconv.Atoi(rawIdx)
	if err != nil {
		return fmt.Errorf("invalid messages index %q: %w", rawIdx, err)
	}
	if idx < 0 || idx >= len(plan.messages) {
		return fmt.Errorf("messages index %d out of range [0, %d)", idx, len(plan.messages))
	}
	plan.messages[idx].payload = []byte(payload)
	return nil
}

// encodeFuzzGRPCJSONFieldValue converts a fuzz-iterator payload string
// into the JSON literal a proto-schemaless-json object expects for the
// given key's wire type. Supported types match
// fuzzGRPCSupportedJSONFieldTypes; the caller has already
// type-validated, so this returns an error only on malformed numeric
// payloads (range, syntax) — never on type lookup miss.
//
// For String/bytes the payload is JSON-string-quoted verbatim; for
// integer wire types the payload must parse as a base-10 integer (signed
// for Varint/64-bit to round-trip negative values via two's-complement,
// like Decode emits). Range checks mirror the encoder
// (32-bit ⇒ fits uint32; bytes accepts the colon-hex form used by the
// rest of the proto-schemaless surface).
func encodeFuzzGRPCJSONFieldValue(key, payload string) (json.RawMessage, error) {
	parts := parseProtoKeyParts(key)
	if parts == nil {
		return nil, fmt.Errorf("invalid proto field key %q", key)
	}
	switch parts[2] {
	case "String":
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal string payload: %w", err)
		}
		return b, nil
	case "bytes":
		// The proto-schemaless encoder accepts colon-hex via
		// decodeHexColon. Validate the payload eagerly so a bad hex
		// surfaces here rather than during Encode where the error
		// shape would obscure which fuzz position failed.
		if _, err := hexColonDecode(payload); err != nil {
			return nil, fmt.Errorf("invalid bytes payload %q (expected colon-separated hex): %w", payload, err)
		}
		b, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal bytes payload: %w", err)
		}
		return b, nil
	case "Varint", "64-bit":
		// Accept either int64 (allows negative round-trip via two's
		// complement) or uint64 (allows values > int64 max). Mirrors
		// parseJSONNumber on the encoder side.
		if _, err := strconv.ParseInt(payload, 10, 64); err == nil {
			return json.RawMessage(payload), nil
		}
		if _, err := strconv.ParseUint(payload, 10, 64); err == nil {
			return json.RawMessage(payload), nil
		}
		return nil, fmt.Errorf("invalid integer payload %q for type %q", payload, parts[2])
	case "32-bit":
		// 32-bit must fit uint32 — the encoder rejects anything larger.
		if _, err := strconv.ParseUint(payload, 10, 32); err != nil {
			return nil, fmt.Errorf("invalid 32-bit payload %q: %w", payload, err)
		}
		return json.RawMessage(payload), nil
	default:
		return nil, fmt.Errorf("unsupported proto wire type %q", parts[2])
	}
}

// hexColonDecode validates the colon-separated hex form used by the
// proto-schemaless bytes wire type. Empty payload is treated as the
// empty byte slice (matches the encoder's decodeHexColon).
func hexColonDecode(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	clean := strings.ReplaceAll(s, ":", "")
	out := make([]byte, len(clean)/2)
	if len(clean)%2 != 0 {
		return nil, fmt.Errorf("odd hex length %d", len(clean))
	}
	for i := 0; i < len(clean); i += 2 {
		hi, err := hexNibble(clean[i])
		if err != nil {
			return nil, err
		}
		lo, err := hexNibble(clean[i+1])
		if err != nil {
			return nil, err
		}
		out[i/2] = (hi << 4) | lo
	}
	return out, nil
}

func hexNibble(c byte) (byte, error) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', nil
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, nil
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, nil
	}
	return 0, fmt.Errorf("invalid hex char %q", c)
}

// commitFuzzGRPCJSONMutations folds the per-variant JSON-path mutations
// into each affected message's proto-schemaless-json source, re-encodes
// to proto wire bytes via protobuf.Encode, and writes the bytes back to
// plan.messages[idx].payload. Idempotent on an empty mutation map.
//
// The size cap (maxResendGRPCPayload) is intentionally not re-checked
// here — populateResendGRPCMessages enforced it on the source payload
// during plan build, and the fuzz path payload cap
// (maxFuzzGRPCPayloadSize) bounds each substituted value; the
// re-encoded byte length is therefore bounded by their sum, well below
// the gRPC Layer's own framing limits.
func commitFuzzGRPCJSONMutations(plan *resendGRPCPlan, jsonMuts map[int]map[string]json.RawMessage) error {
	for idx, muts := range jsonMuts {
		if idx < 0 || idx >= len(plan.messages) {
			return fmt.Errorf("messages index %d out of range [0, %d)", idx, len(plan.messages))
		}
		src := plan.messages[idx].jsonPayload
		if src == "" {
			return fmt.Errorf("messages[%d]: JSON-path mutation requires body_encoding=\"proto-schemaless-json\" (no source JSON on the plan)", idx)
		}
		var tree map[string]json.RawMessage
		if err := json.Unmarshal([]byte(src), &tree); err != nil {
			return fmt.Errorf("messages[%d]: parse JSON payload: %w", idx, err)
		}
		for k, v := range muts {
			if _, ok := tree[k]; !ok {
				return fmt.Errorf("messages[%d]: proto field key %q not present in source JSON", idx, k)
			}
			tree[k] = v
		}
		merged, err := json.Marshal(tree)
		if err != nil {
			return fmt.Errorf("messages[%d]: marshal mutated JSON: %w", idx, err)
		}
		encoded, err := protobuf.Encode(string(merged))
		if err != nil {
			return fmt.Errorf("messages[%d]: re-encode proto bytes: %w", idx, err)
		}
		plan.messages[idx].payload = encoded
	}
	return nil
}

// cloneFuzzGRPCPlan returns a deep copy of plan suitable for per-variant
// mutation. streamID / connID are regenerated so each variant gets an
// independent gRPC stream as recorded by RecordStep. Slices that fuzz
// positions can mutate (metadata, messages) are deep-copied; immutable
// fields (encoding, acceptEncoding, trailerMetadata) are shared.
//
// canonicalURL is left dangling here and re-derived in the caller after
// position application (since service/method may mutate per variant).
func cloneFuzzGRPCPlan(base *resendGRPCPlan) *resendGRPCPlan {
	out := *base
	out.streamID = uuid.NewString()
	out.connID = uuid.NewString()
	out.canonicalURL = nil

	if len(base.metadata) > 0 {
		md := make([]envelope.KeyValue, len(base.metadata))
		copy(md, base.metadata)
		out.metadata = md
	}
	if len(base.messages) > 0 {
		ms := make([]resendGRPCDataPlan, len(base.messages))
		for i, m := range base.messages {
			payloadCopy := make([]byte, len(m.payload))
			copy(payloadCopy, m.payload)
			ms[i] = resendGRPCDataPlan{
				payload:      payloadCopy,
				compressed:   m.compressed,
				jsonPayload:  m.jsonPayload,
				bodyEncoding: m.bodyEncoding,
			}
		}
		out.messages = ms
	}
	// trailerMetadata is read-only across variants (we don't fuzz it);
	// share the slice.
	return &out
}
