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
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzWSVariants caps the cartesian product across all positions.
// 1000 variants is a balance between meaningful synchronous fuzz runs
// and bounded server-side resource use; callers that need more should
// chain calls or use the legacy `fuzz` tool with its async runner.
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
func (s *Server) runFuzzWSVariants(ctx context.Context, plan *fuzzWSPlan, timeout time.Duration, stopOnClose bool, tag string) ([]fuzzWSVariantRow, int, string, error) {
	pipe := s.buildResendWSPipeline(plan.encoders)

	rows := make([]fuzzWSVariantRow, 0, plan.totalVariants)
	indices := make([]int, len(plan.positions))
	completed := 0

	for variantIdx := 0; variantIdx < plan.totalVariants; variantIdx++ {
		select {
		case <-ctx.Done():
			return rows, completed, fmt.Sprintf("ctx cancelled: %v", ctx.Err()), nil
		default:
		}

		payloads, err := decodeFuzzWSPayloads(plan.positions, indices)
		if err != nil {
			return nil, completed, "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
		}

		variantStart := time.Now()
		row, gotClose, runErr := s.runFuzzWSSingleVariant(ctx, plan, pipe, timeout, variantIdx, payloads, tag)
		row.DurationMs = time.Since(variantStart).Milliseconds()
		if runErr != nil {
			row.Error = runErr.Error()
		}
		rows = append(rows, row)
		completed++

		nextIndicesWS(indices, plan.positions)

		if stopOnClose && gotClose {
			return rows, completed, fmt.Sprintf("stop_on_close: variant %d received Close frame", variantIdx), nil
		}
	}
	return rows, completed, "", nil
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
	if v := s.checkSafetyInput(variantPlan.payload, variantPlan.upgradeURL.String(), keyValuesToExchangeKV(variantPlan.upgradeHeaders)); v != nil {
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
		maskedPayload := s.filterOutputBody(respMsg.Payload)
		row.Payload, row.PayloadEncoding = encodeResendWSPayload(maskedPayload, respMsg.Opcode)
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
