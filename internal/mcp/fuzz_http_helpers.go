// Package mcp fuzz_http_helpers.go holds the building blocks used by
// fuzz_http.go: input validation, base-envelope construction (reusing
// resend_http helpers), variant enumeration (cartesian product with
// hard cap), per-variant payload application against the HTTPMessage
// envelope, the dial / pipeline factory (reused from resend_http), the
// per-variant run loop, and result formatting.
//
// # Payload passthrough — by design (MITM principle)
//
// Position payloads substituted into the HTTPMessage envelope via
// applyFuzzHTTPPosition / applyFuzzHTTPRoot are written verbatim,
// including CR/LF and other control characters. This is intentional:
// fuzz_http is the path most useful for request smuggling, header
// injection, URL/path injection, and CRLF-injection fuzzing. Adding a
// CRLF guard at substitution time would defeat the purpose of the tool.
//
// This is consistent with the project-wide MITM Implementation Principle
// "Do not normalize what the wire did not normalize" (CLAUDE.md). Note
// that this is asymmetric with the base-headers path: validateResendHTTPInput
// (called via fuzzHTTPInputToResendHTTP / validateHeaderKVList) does
// reject CR/LF in user-supplied *base* headers, but per-position
// payloads bypass that guard by design. Callers that need a strict
// (no-CRLF) mode should pre-filter their payload lists at the call
// site.
//
// SafetyFilter input gating still runs per-variant inside
// runFuzzHTTPSingleVariant (after position application, before the
// upstream dial), so the destructive-sql / destructive-os-command
// presets continue to apply to the substituted payload — fuzzing CRLF
// is allowed; sending `rm -rf /` is not, when the configured rules say
// so.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strconv"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxFuzzHTTPVariants caps the cartesian product across all positions.
// 1000 variants is a balance between meaningful synchronous fuzz runs
// and bounded server-side resource use; callers that need more should
// chain calls or use the legacy `fuzz` tool with its async runner.
const maxFuzzHTTPVariants = 1000

// maxFuzzHTTPPositions caps the number of positions per call. With 1000
// total variants and 8 positions you have at most ~2.4 payloads per
// position, which is mostly useless — practical fuzz jobs use 1-3
// positions. The cap is generous (32) so it almost never bites.
const maxFuzzHTTPPositions = 32

// maxFuzzHTTPPayloadSize caps the *decoded* size of a single position
// payload. Without a cap, a 16 MiB payload * maxFuzzHTTPVariants (1000)
// would queue up 16 GiB of allocated payload bytes (sequential, not
// concurrent — but still a footgun). 1 MiB is generous for header /
// URL / body fuzz cases (resend_http itself caps user-supplied bodies
// at the same order of magnitude).
const maxFuzzHTTPPayloadSize = 1 << 20

// validFuzzHTTPRoots lists the HTTPMessage root field paths that
// fuzz_http accepts. headers[N].name and headers[N].value are matched
// separately via regex; this set covers the scalar fields.
var validFuzzHTTPRoots = map[string]bool{
	"method":    true,
	"scheme":    true,
	"authority": true,
	"path":      true,
	"raw_query": true,
	"body":      true,
}

// fuzzHTTPHeadersPathRE matches "headers[N].name" or "headers[N].value"
// where N is a non-negative decimal integer. Captures the index and
// the field name.
var fuzzHTTPHeadersPathRE = regexp.MustCompile(`^headers\[(\d+)\]\.(name|value)$`)

// validateFuzzHTTPInput rejects malformed inputs at the schema
// boundary before any expensive lookups (flow store, dial) run.
//
// Inherits all of resend_http's validation discipline (CRLF guards on
// user-supplied URL components via the underlying resend_http
// helpers); fuzz-specific validation is layered on top:
// - positions list non-empty and within the per-call cap
// - each path resolves to a known HTTPMessage field
// - each payloads list non-empty
// - cartesian product within maxFuzzHTTPVariants
func validateFuzzHTTPInput(input *fuzzHTTPInput) error {
	rh := fuzzHTTPInputToResendHTTP(input)
	if err := validateResendHTTPInput(&rh); err != nil {
		return err
	}
	if len(input.Positions) == 0 {
		return errors.New("positions must contain at least one entry")
	}
	if len(input.Positions) > maxFuzzHTTPPositions {
		return fmt.Errorf("positions has %d entries; max %d per call", len(input.Positions), maxFuzzHTTPPositions)
	}
	totalVariants := 1
	for i, p := range input.Positions {
		if err := validateFuzzHTTPPosition(i, p); err != nil {
			return err
		}
		totalVariants *= len(p.Payloads)
		if totalVariants > maxFuzzHTTPVariants {
			return fmt.Errorf("positions cartesian product exceeds %d variants (computed at position %d); reduce payload counts or split into multiple calls", maxFuzzHTTPVariants, i)
		}
	}
	return nil
}

// validateFuzzHTTPPosition validates one position entry: the path must
// resolve to a known HTTPMessage field, the payloads list must be
// non-empty, and the encoding must be in the allowlist.
func validateFuzzHTTPPosition(index int, p fuzzHTTPPosition) error {
	if p.Path == "" {
		return fmt.Errorf("positions[%d]: path must not be empty", index)
	}
	if !isValidFuzzHTTPPath(p.Path) {
		return fmt.Errorf("positions[%d]: unsupported path %q (valid: method, scheme, authority, path, raw_query, body, headers[N].name, headers[N].value)", index, p.Path)
	}
	if len(p.Payloads) == 0 {
		return fmt.Errorf("positions[%d]: payloads must contain at least one element", index)
	}
	if p.Encoding != "" && p.Encoding != "text" && p.Encoding != "base64" {
		return fmt.Errorf("positions[%d]: unsupported encoding %q: must be text or base64", index, p.Encoding)
	}
	return nil
}

// isValidFuzzHTTPPath reports whether path resolves to a supported
// HTTPMessage field. Scalar paths are exact-match against
// validFuzzHTTPRoots; headers[N] paths are regex-matched.
func isValidFuzzHTTPPath(path string) bool {
	if validFuzzHTTPRoots[path] {
		return true
	}
	return fuzzHTTPHeadersPathRE.MatchString(path)
}

// fuzzHTTPInputToResendHTTP projects fuzz_http base fields onto a
// resendHTTPInput so we can reuse resend_http's validation and base-
// envelope helpers without copy-paste. Fuzz-specific fields
// (Positions, StopOn5xx) are not part of the projection.
func fuzzHTTPInputToResendHTTP(input *fuzzHTTPInput) resendHTTPInput {
	return resendHTTPInput{
		FlowID:         input.FlowID,
		Method:         input.Method,
		Scheme:         input.Scheme,
		Authority:      input.Authority,
		Path:           input.Path,
		RawQuery:       input.RawQuery,
		Headers:        input.Headers,
		Body:           input.Body,
		BodyEncoding:   input.BodyEncoding,
		BodySet:        input.BodySet,
		BodyPatches:    input.BodyPatches,
		OverrideHost:   input.OverrideHost,
		TLSFingerprint: input.TLSFingerprint,
		TimeoutMs:      input.TimeoutMs,
		Tag:            input.Tag,
	}
}

// fuzzHTTPPlan is the resolved base envelope + variant enumeration.
type fuzzHTTPPlan struct {
	baseEnv       *envelope.Envelope
	baseMsg       *envelope.HTTPMessage
	dialAddr      string
	useTLS        bool
	sni           string
	overrideHost  string
	positions     []fuzzHTTPPosition
	totalVariants int
}

// buildFuzzHTTPPlan resolves the base envelope (delegating to
// resend_http's buildResendHTTPEnvelope) and computes the dial target
// + total variant count.
func (s *Server) buildFuzzHTTPPlan(ctx context.Context, input *fuzzHTTPInput) (*fuzzHTTPPlan, error) {
	rh := fuzzHTTPInputToResendHTTP(input)
	baseEnv, err := s.buildResendHTTPEnvelope(ctx, &rh)
	if err != nil {
		return nil, err
	}
	baseMsg, ok := baseEnv.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("fuzz_http: base envelope has %T, expected *HTTPMessage", baseEnv.Message)
	}

	addr, useTLS, sni, err := resolveResendHTTPDial(baseMsg, input.OverrideHost)
	if err != nil {
		return nil, err
	}
	if err := s.checkResendHTTPScope(baseMsg, addr, input.OverrideHost); err != nil {
		return nil, err
	}

	totalVariants := 1
	for _, p := range input.Positions {
		totalVariants *= len(p.Payloads)
	}

	return &fuzzHTTPPlan{
		baseEnv:       baseEnv,
		baseMsg:       baseMsg,
		dialAddr:      addr,
		useTLS:        useTLS,
		sni:           sni,
		overrideHost:  input.OverrideHost,
		positions:     input.Positions,
		totalVariants: totalVariants,
	}, nil
}

// runFuzzHTTPVariants iterates the cartesian product of all positions,
// running each variant through the resend_http pipeline + dial path.
// Returns the per-variant rows, the count of completed variants, and
// an optional stop reason ("" when all variants ran to completion).
func (s *Server) runFuzzHTTPVariants(ctx context.Context, plan *fuzzHTTPPlan, timeout time.Duration, stopOn5xx bool, tag string) ([]fuzzHTTPVariantRow, int, string, error) {
	encoders := buildFuzzHTTPEncoderRegistry()
	pipe := s.buildFuzzHTTPPipeline(encoders)
	dial := buildResendHTTPDialFunc(s.connector.tlsTransport, plan.dialAddr, plan.useTLS, plan.sni)

	rows := make([]fuzzHTTPVariantRow, 0, plan.totalVariants)
	indices := make([]int, len(plan.positions))
	completed := 0

	for variantIdx := 0; variantIdx < plan.totalVariants; variantIdx++ {
		select {
		case <-ctx.Done():
			return rows, completed, fmt.Sprintf("ctx cancelled: %v", ctx.Err()), nil
		default:
		}

		payloads, err := decodeFuzzHTTPPayloads(plan.positions, indices)
		if err != nil {
			return nil, completed, "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
		}

		variantStart := time.Now()
		row, statusCode, runErr := s.runFuzzHTTPSingleVariant(ctx, plan, pipe, dial, timeout, variantIdx, payloads, tag)
		row.DurationMs = time.Since(variantStart).Milliseconds()

		if runErr != nil {
			row.Error = runErr.Error()
		}
		rows = append(rows, row)
		completed++

		nextIndices(indices, plan.positions)

		if stopOn5xx && statusCode >= 500 && statusCode < 600 {
			return rows, completed, fmt.Sprintf("stop_on_5xx: variant %d returned %d", variantIdx, statusCode), nil
		}
	}
	return rows, completed, "", nil
}

// buildFuzzHTTPEncoderRegistry constructs the wire encoder registry
// shared between PluginStepPost and RecordStep on every fuzz variant
// pipeline. Mirrors the resend_http registry — registers
// http1.EncodeWireBytes for envelope.ProtocolHTTP.
func buildFuzzHTTPEncoderRegistry() *pipeline.WireEncoderRegistry {
	encoders := pipeline.NewWireEncoderRegistry()
	encoders.Register(envelope.ProtocolHTTP, http1.EncodeWireBytes)
	return encoders
}

// buildFuzzHTTPPipeline constructs the per-variant pipeline shared
// across the fuzz run. PluginStepPost + RecordStep — same as
// resend_http per RFC §9.3 D1.
func (s *Server) buildFuzzHTTPPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(s.flowStore.store, slog.Default(), pipeline.WithWireEncoderRegistry(encoders)),
	}
	return pipeline.New(steps...)
}

// runFuzzHTTPSingleVariant executes one variant: clones the base
// envelope, applies all position payloads, runs through the pipeline,
// dials, sends, receives, runs response through the pipeline, returns
// the row.
//
// Per-variant SafetyFilter input gating runs after position application
// and before the upstream dial (mirroring legacy fuzz_tool.go per-payload
// semantics). On a violation the variant is recorded with row.Error set
// and returns statusCode=0 — the caller continues iterating; a single
// blocked variant does not abort the whole run.
func (s *Server) runFuzzHTTPSingleVariant(ctx context.Context, plan *fuzzHTTPPlan, p *pipeline.Pipeline, dial session.DialFunc, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzHTTPVariantRow, int, error) {
	row := fuzzHTTPVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantEnv := cloneFuzzHTTPEnvelope(plan.baseEnv)
	variantEnv.StreamID = uuid.NewString()
	variantMsg, ok := variantEnv.Message.(*envelope.HTTPMessage)
	if !ok {
		return row, 0, fmt.Errorf("variant envelope has %T, expected *HTTPMessage", variantEnv.Message)
	}
	for _, pos := range plan.positions {
		payload, ok := payloads[pos.Path]
		if !ok {
			continue
		}
		if err := applyFuzzHTTPPosition(variantMsg, pos.Path, payload); err != nil {
			return row, 0, fmt.Errorf("apply position %q: %w", pos.Path, err)
		}
	}

	// SafetyFilter input gating: run AFTER position application so the
	// destructive-sql / destructive-os-command presets see the substituted
	// payload (matches fuzz_tool.go per-payload semantics). On a violation
	// we record the variant with row.Error and return statusCode=0 — the
	// run loop continues to the next variant.
	row.StreamID = variantEnv.StreamID
	if v := s.checkSafetyInput(variantMsg.Body, resendHTTPRequestURL(variantMsg).String(), variantMsg.Headers); v != nil {
		row.Error = safetyViolationError(v)
		return row, 0, nil
	}

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	respEnv, err := runFuzzHTTPSingleExchange(rtCtx, variantEnv, dial, p)
	if err != nil {
		return row, 0, err
	}
	if respMsg, ok := respEnv.Message.(*envelope.HTTPMessage); ok {
		row.StatusCode = respMsg.Status
		row.BodySize = len(respMsg.Body)
	}
	// Tag persistence uses the parent ctx (not the per-variant rtCtx) so
	// the tag write is not bound to the variant's request timeout —
	// matches resend_http.go behaviour.
	if tag != "" && s.flowStore.store != nil {
		s.applyResendHTTPTag(ctx, variantEnv.StreamID, tag)
	}
	return row, row.StatusCode, nil
}

// runFuzzHTTPSingleExchange runs one variant's send/receive cycle and
// returns the response envelope. Mirrors runResendHTTP but takes the
// already-cloned send envelope and uses the per-variant pipeline.
func runFuzzHTTPSingleExchange(ctx context.Context, sendEnv *envelope.Envelope, dial session.DialFunc, p *pipeline.Pipeline) (*envelope.Envelope, error) {
	postSend, action, custom := p.Run(ctx, sendEnv)
	switch action {
	case pipeline.Drop:
		return nil, errors.New("send envelope dropped by pipeline")
	case pipeline.Respond:
		if custom == nil {
			return nil, errors.New("pipeline returned Respond with nil response envelope")
		}
		custom.StreamID = postSend.StreamID
		custom.Sequence = 1
		_, _, _ = p.Run(ctx, custom)
		return custom, nil
	}

	ch, err := dial(ctx, postSend)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	defer ch.Close()

	if err := ch.Send(ctx, postSend); err != nil {
		return nil, fmt.Errorf("upstream send: %w", err)
	}
	respEnv, err := ch.Next(ctx)
	if err != nil {
		return nil, fmt.Errorf("upstream receive: %w", err)
	}
	respEnv.StreamID = postSend.StreamID
	respEnv.Sequence = 1
	respEnv, _, _ = p.Run(ctx, respEnv)
	return respEnv, nil
}

// nextIndices increments the variant index counter. Treats
// indices[i] like a digit in a mixed-radix counter where the radix at
// position i is len(positions[i].Payloads). Position 0 is the
// least-significant digit; carries propagate upward.
func nextIndices(indices []int, positions []fuzzHTTPPosition) {
	for i := 0; i < len(indices); i++ {
		indices[i]++
		if indices[i] < len(positions[i].Payloads) {
			return
		}
		indices[i] = 0
	}
}

// decodeFuzzHTTPPayloads materialises the per-position payload values
// for the current variant index combination into a path → decoded
// payload string map. Decoding follows the position's encoding
// ("text" or "base64").
//
// Each decoded payload is rejected if it exceeds maxFuzzHTTPPayloadSize
// — see the constant doc for the rationale. The cap applies post-decode
// so a 1.4 MiB base64 string that decodes to 1 MiB is allowed.
func decodeFuzzHTTPPayloads(positions []fuzzHTTPPosition, indices []int) (map[string]string, error) {
	out := make(map[string]string, len(positions))
	for i, pos := range positions {
		raw := pos.Payloads[indices[i]]
		decoded, err := decodeBodyEncoded(raw, pos.Encoding, fmt.Sprintf("positions[%d].payloads[%d]", i, indices[i]))
		if err != nil {
			return nil, err
		}
		if len(decoded) > maxFuzzHTTPPayloadSize {
			return nil, fmt.Errorf("positions[%d].payloads[%d]: decoded length %d exceeds %d byte cap", i, indices[i], len(decoded), maxFuzzHTTPPayloadSize)
		}
		out[pos.Path] = string(decoded)
	}
	return out, nil
}

// applyFuzzHTTPPosition writes payload at the given typed path on
// msg. Unknown paths are rejected (validation runs upfront, so this
// is a defensive catch — should never fire in practice).
func applyFuzzHTTPPosition(msg *envelope.HTTPMessage, path, payload string) error {
	if validFuzzHTTPRoots[path] {
		applyFuzzHTTPRoot(msg, path, payload)
		return nil
	}
	if matches := fuzzHTTPHeadersPathRE.FindStringSubmatch(path); matches != nil {
		idx, err := strconv.Atoi(matches[1])
		if err != nil {
			return fmt.Errorf("invalid header index %q", matches[1])
		}
		if idx < 0 || idx >= len(msg.Headers) {
			return fmt.Errorf("headers index %d out of range [0, %d)", idx, len(msg.Headers))
		}
		switch matches[2] {
		case "name":
			msg.Headers[idx].Name = payload
		case "value":
			msg.Headers[idx].Value = payload
		}
		return nil
	}
	return fmt.Errorf("unsupported path %q", path)
}

// applyFuzzHTTPRoot writes payload at a scalar root path on msg.
// Caller has already validated the path via validFuzzHTTPRoots.
//
// All scalar substitutions (method/scheme/authority/path/raw_query/body)
// pass through verbatim — see the package-level "Payload passthrough"
// note for the rationale (CRLF / smuggling fuzz is the point).
//
// For the body case, msg.BodyBuffer is also cleared to enforce the
// HTTPMessage invariant "at most one of Body/BodyBuffer is non-nil".
// flow_id seeding currently only populates Body, so this is dormant
// today, but enforcing it here keeps the invariant honest if a future
// caller surfaces a BodyBuffer.
func applyFuzzHTTPRoot(msg *envelope.HTTPMessage, path, payload string) {
	switch path {
	case "method":
		msg.Method = payload
	case "scheme":
		msg.Scheme = payload
	case "authority":
		msg.Authority = payload
	case "path":
		msg.Path = payload
	case "raw_query":
		msg.RawQuery = payload
	case "body":
		msg.Body = []byte(payload)
		msg.BodyBuffer = nil
	}
}

// cloneFuzzHTTPEnvelope returns a deep copy of env suitable for per-
// variant mutation. Delegates the deep-copy semantics (Message subtree
// via CloneMessage, Raw cloned, Opaque intentionally dropped) to
// envelope.Envelope.Clone() so the invariants are enforced rather than
// relied upon. FlowID is regenerated so each variant gets a unique
// Send Flow row; StreamID is left empty for the caller to stamp; Raw
// is dropped because variant raw bytes are produced by the encoder
// inside the pipeline.
func cloneFuzzHTTPEnvelope(env *envelope.Envelope) *envelope.Envelope {
	out := env.Clone()
	out.FlowID = uuid.NewString()
	out.StreamID = ""
	out.Raw = nil
	return out
}
