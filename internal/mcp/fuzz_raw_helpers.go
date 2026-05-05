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
	"github.com/usk6666/yorishiro-proxy/internal/job"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// maxFuzzRawVariants caps the cartesian product across all positions.
// Mirrors maxFuzzHTTPVariants — 1000 variants is a balance between
// meaningful synchronous fuzz runs and bounded server-side resource
// use; callers that need more should chain calls or use the legacy
// `fuzz` tool with its async runner.
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
// running each variant through the resend_raw pipeline + dial path.
// Returns the per-variant rows, the count of completed variants, and
// an optional stop reason ("" when all variants ran to completion).
func (s *Server) runFuzzRawVariants(ctx context.Context, plan *fuzzRawPlan, timeout time.Duration, stopOnError bool, tag string) ([]fuzzRawVariantRow, int, string, error) {
	encoders := buildResendRawEncoderRegistry()
	pipe := s.buildResendRawPipeline(encoders)

	rows := make([]fuzzRawVariantRow, 0, plan.totalVariants)
	indices := make([]int, len(plan.positions))
	completed := 0

	for variantIdx := 0; variantIdx < plan.totalVariants; variantIdx++ {
		select {
		case <-ctx.Done():
			return rows, completed, fmt.Sprintf("ctx cancelled: %v", ctx.Err()), nil
		default:
		}

		payloads, err := decodeFuzzRawPayloads(plan.positions, indices)
		if err != nil {
			return nil, completed, "", fmt.Errorf("variant %d: decode payloads: %w", variantIdx, err)
		}

		variantStart := time.Now()
		row, runErr := s.runFuzzRawSingleVariant(ctx, plan, pipe, timeout, variantIdx, payloads, tag)
		row.DurationMs = time.Since(variantStart).Milliseconds()

		if runErr != nil {
			row.Error = runErr.Error()
		}
		rows = append(rows, row)
		completed++

		nextFuzzRawIndices(indices, plan.positions)

		if stopOnError && runErr != nil {
			return rows, completed, fmt.Sprintf("stop_on_error: variant %d failed: %v", variantIdx, runErr), nil
		}
	}
	return rows, completed, "", nil
}

// runFuzzRawSingleVariant executes one variant: assembles variant
// bytes from the base + per-variant patches + per-variant "payload"
// position, runs the safety filter, dials, sends, receives, and
// returns the row.
//
// Per-variant SafetyFilter input gating runs after variant assembly
// and before the upstream dial (mirroring fuzz_http per-variant
// semantics). On a violation the variant is recorded with row.Error
// set and returns nil error so the run loop continues; a single
// blocked variant does not abort the whole run.
func (s *Server) runFuzzRawSingleVariant(ctx context.Context, plan *fuzzRawPlan, p *pipeline.Pipeline, timeout time.Duration, variantIdx int, payloads map[string]string, tag string) (fuzzRawVariantRow, error) {
	row := fuzzRawVariantRow{
		Index:    variantIdx,
		Payloads: payloads,
	}

	variantBytes, err := assembleFuzzRawVariantBytes(plan, payloads)
	if err != nil {
		return row, fmt.Errorf("assemble variant bytes: %w", err)
	}
	if len(variantBytes) > maxResendRawPayload {
		return row, fmt.Errorf("variant payload too large: %d > %d", len(variantBytes), maxResendRawPayload)
	}

	row.StreamID = uuid.NewString()

	// SafetyFilter input gating: run AFTER variant assembly so the
	// destructive-sql / destructive-os-command presets see the substituted
	// payload (matches fuzz_http per-variant semantics). On a violation we
	// record the variant with row.Error and return nil err — the run loop
	// continues to the next variant.
	if v := s.checkSafetyInput(variantBytes, "", nil); v != nil {
		row.Error = safetyViolationError(v)
		return row, nil
	}

	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	respBytes, chunks, truncated, err := s.runFuzzRawSingleExchange(rtCtx, plan, row.StreamID, variantBytes, p)
	if err != nil {
		return row, err
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
	return row, nil
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
