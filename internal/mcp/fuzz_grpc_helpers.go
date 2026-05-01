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
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzGRPCVariants caps the cartesian product across all positions.
// 1000 variants is a balance between meaningful synchronous fuzz runs
// and bounded server-side resource use; callers that need more should
// chain calls or use the legacy `fuzz` tool with its async runner.
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
		return fmt.Errorf("positions[%d]: unsupported path %q (valid: service, method, metadata[N].name, metadata[N].value, messages[N].payload)", index, p.Path)
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
// indexed paths are regex-matched.
func isValidFuzzGRPCPath(path string) bool {
	if validFuzzGRPCRoots[path] {
		return true
	}
	if fuzzGRPCMetadataPathRE.MatchString(path) {
		return true
	}
	return fuzzGRPCMessagePathRE.MatchString(path)
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
// indexed paths (metadata[N], messages[N]) against the resolved base
// plan. Scalar paths (service, method) need no plan-side check.
func validateFuzzGRPCPositionAgainstPlan(idx int, pos fuzzGRPCPosition, plan *resendGRPCPlan) error {
	if matches := fuzzGRPCMetadataPathRE.FindStringSubmatch(pos.Path); matches != nil {
		mIdx, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("positions[%d]: invalid metadata index %q: %w", idx, matches[1], err)
		}
		if mIdx < 0 || mIdx >= len(plan.metadata) {
			return fmt.Errorf("positions[%d]: metadata index %d out of range [0, %d) — base plan has %d metadata entries", idx, mIdx, len(plan.metadata), len(plan.metadata))
		}
		return nil
	}
	if matches := fuzzGRPCMessagePathRE.FindStringSubmatch(pos.Path); matches != nil {
		mIdx, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("positions[%d]: invalid messages index %q: %w", idx, matches[1], err)
		}
		if mIdx < 0 || mIdx >= len(plan.messages) {
			return fmt.Errorf("positions[%d]: messages index %d out of range [0, %d) — base plan has %d messages", idx, mIdx, len(plan.messages), len(plan.messages))
		}
		return nil
	}
	return nil
}

// runFuzzGRPCVariants iterates the cartesian product of all positions,
// running each variant through a fresh resend_grpc-style upstream RPC.
// The pipeline is shared across variants (PluginStepPost + RecordStep
// fire on every variant's envelopes); each variant gets a fresh
// streamID + connID + dial.
//
// Returns the per-variant rows, the count of completed variants, and
// an optional stop reason ("" when all variants ran to completion).
func (s *Server) runFuzzGRPCVariants(ctx context.Context, plan *fuzzGRPCPlan, timeout time.Duration, stopOnNonOK bool, tag string) ([]fuzzGRPCVariantRow, int, string, error) {
	encoders := buildResendGRPCEncoderRegistry()
	pipe := s.buildResendGRPCPipeline(encoders)

	rows := make([]fuzzGRPCVariantRow, 0, plan.totalVariants)
	indices := make([]int, len(plan.positions))
	completed := 0

	for variantIdx := 0; variantIdx < plan.totalVariants; variantIdx++ {
		select {
		case <-ctx.Done():
			return rows, completed, fmt.Sprintf("ctx cancelled: %v", ctx.Err()), nil
		default:
		}

		payloads, err := decodeFuzzGRPCPayloads(plan.positions, indices)
		if err != nil {
			return nil, completed, "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
		}

		variantStart := time.Now()
		row, statusCode, runErr := s.runFuzzGRPCSingleVariant(ctx, plan, pipe, timeout, variantIdx, payloads, tag)
		row.DurationMs = time.Since(variantStart).Milliseconds()

		if runErr != nil {
			row.Error = runErr.Error()
		}
		rows = append(rows, row)
		completed++

		nextFuzzGRPCIndices(indices, plan.positions)

		if stopOnNonOK && (runErr != nil || statusCode != 0) {
			return rows, completed, fmt.Sprintf("stop_on_non_ok: variant %d returned status=%d err=%q", variantIdx, statusCode, errString(runErr)), nil
		}
	}
	return rows, completed, "", nil
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
func (s *Server) runFuzzGRPCSingleVariant(ctx context.Context, plan *fuzzGRPCPlan, p *pipeline.Pipeline, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzGRPCVariantRow, uint32, error) {
	row := fuzzGRPCVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantPlan := cloneFuzzGRPCPlan(plan.basePlan)
	for _, pos := range plan.positions {
		payload, ok := payloads[pos.Path]
		if !ok {
			continue
		}
		if err := applyFuzzGRPCPosition(variantPlan, pos.Path, payload); err != nil {
			return row, 0, fmt.Errorf("apply position %q: %w", pos.Path, err)
		}
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
	if v := s.checkSafetyInput(concatResendGRPCPayloads(variantPlan), variantPlan.canonicalURL.String(), keyValuesToExchangeKV(variantPlan.metadata)); v != nil {
		row.Error = safetyViolationError(v)
		return row, 0, nil
	}

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	endEnv, recvData, _, err := s.runResendGRPC(rtCtx, variantPlan, p)
	if err != nil {
		return row, 0, err
	}

	if endEnv != nil {
		if endMsg, ok := endEnv.Message.(*envelope.GRPCEndMessage); ok {
			row.Status = endMsg.Status
			row.StatusMessage = endMsg.Message
		}
	}
	row.ResponseMessageCount = len(recvData)
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
	return row, row.Status, nil
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
func applyFuzzGRPCPosition(plan *resendGRPCPlan, path, payload string) error {
	switch path {
	case "service":
		plan.service = payload
		return nil
	case "method":
		plan.method = payload
		return nil
	}
	if matches := fuzzGRPCMetadataPathRE.FindStringSubmatch(path); matches != nil {
		idx, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("invalid metadata index %q: %w", matches[1], err)
		}
		if idx < 0 || idx >= len(plan.metadata) {
			return fmt.Errorf("metadata index %d out of range [0, %d)", idx, len(plan.metadata))
		}
		switch matches[2] {
		case "name":
			plan.metadata[idx].Name = payload
		case "value":
			plan.metadata[idx].Value = payload
		}
		return nil
	}
	if matches := fuzzGRPCMessagePathRE.FindStringSubmatch(path); matches != nil {
		idx, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("invalid messages index %q: %w", matches[1], err)
		}
		if idx < 0 || idx >= len(plan.messages) {
			return fmt.Errorf("messages index %d out of range [0, %d)", idx, len(plan.messages))
		}
		plan.messages[idx].payload = []byte(payload)
		return nil
	}
	return fmt.Errorf("unsupported path %q", path)
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
				payload:    payloadCopy,
				compressed: m.compressed,
			}
		}
		out.messages = ms
	}
	// trailerMetadata is read-only across variants (we don't fuzz it);
	// share the slice.
	return &out
}
