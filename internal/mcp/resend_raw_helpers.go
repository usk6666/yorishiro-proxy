// Package mcp resend_raw_helpers.go holds the building blocks used by
// resend_raw.go: input validation, payload recovery + override / patch
// application, scope checking, the resend pipeline factory, the
// upstream dial + bytechunk Layer wrap, the send / receive loop, and
// result formatting.
//
// These are split out so resend_raw.go reads as a top-level
// orchestration while every step has a single responsibility documented
// in isolation.
package mcp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
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

// resendRawSupportedProtocols lists the flow.Stream.Protocol values
// that resend_raw accepts via flow_id. Non-raw protocols are rejected
// with an explicit pointer to the protocol-typed counterpart tool. The
// new pipeline writes Stream.Protocol = string(envelope.ProtocolRaw) =
// "raw"; the legacy projection tagged TCP raw streams as "TCP" /
// "Raw". We accept both spellings here.
var resendRawSupportedProtocols = map[string]bool{
	"raw":        true,
	"TCP":        true,
	"Raw":        true,
	"SOCKS5+TCP": true,
	"SOCKS5+raw": true,
}

// maxResendRawPayload caps the request payload size accepted at the
// schema boundary. Mirrors the per-message cap of resend_ws / resend_grpc
// so callers see a clean error rather than a mid-Send failure. The
// underlying bytechunk Layer has no size cap of its own; this cap is
// fail-fast for misuse, not a security boundary on its own.
const maxResendRawPayload = 16 << 20

// maxResendRawResponse caps the concatenated response payload returned
// in the result. The receive loop continues recording per-chunk Flows
// past this cap (so RecordStep retains full evidence on disk), but the
// MCP-side response is truncated to keep the tool output manageable.
const maxResendRawResponse = 16 << 20

// validateResendRawInput rejects malformed inputs at the schema
// boundary before any expensive lookups (flow store, dial) run.
//
// CRLF guards apply ONLY to user-supplied URL components (target_addr,
// sni). Wire bytes (override_bytes, patches[].data, recovered Flow
// RawBytes) are NEVER sanitized — preserving wire reality is the entire
// purpose of the resend_raw tool.
func validateResendRawInput(input *resendRawInput) error {
	if input.FlowID == "" {
		return errors.New("flow_id is required (resend_raw has no from-scratch path; use fuzz_raw for ad-hoc injection)")
	}
	if input.TargetAddr == "" {
		return errors.New("target_addr is required (host:port — explicit port mandatory)")
	}
	if err := validateResendRawNoCRLF("target_addr", input.TargetAddr); err != nil {
		return err
	}
	if err := validateResendRawNoCRLF("sni", input.SNI); err != nil {
		return err
	}
	if _, _, splitErr := net.SplitHostPort(input.TargetAddr); splitErr != nil {
		return fmt.Errorf("invalid target_addr %q: must be host:port (%v)", input.TargetAddr, splitErr)
	}
	if input.OverrideBytesEncoding != "" && input.OverrideBytesEncoding != "text" && input.OverrideBytesEncoding != "base64" {
		return fmt.Errorf("unsupported override_bytes_encoding %q: must be text or base64", input.OverrideBytesEncoding)
	}
	if hasOverride := input.OverrideBytes != "" || input.OverrideBytesSet; hasOverride && len(input.Patches) > 0 {
		return errors.New("override_bytes and patches are mutually exclusive")
	}
	for i, p := range input.Patches {
		if err := validateResendRawPatch(i, p); err != nil {
			return err
		}
	}
	return nil
}

// validateResendRawNoCRLF rejects CR/LF in user-supplied URL
// components. Wire bytes (payload / patches data) are NOT subject to
// this guard — see file-level comment.
func validateResendRawNoCRLF(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains CR/LF characters", field)
	}
	return nil
}

// validateResendRawPatch enforces non-negative offset, supported
// data_encoding, and rejects empty data (an empty patch is a no-op;
// reject loudly so callers don't think their patch applied).
//
// The offset is bounded to maxResendRawPayload at the schema boundary
// (CWE-789, security review S-1): job.ApplyPatches allocates dst :=
// make([]byte, requiredLen) where requiredLen >= offset, so an
// unbounded offset would let a caller force a multi-GiB allocation
// before the post-override size check fires in buildResendRawPlan.
// Capping at the same byte budget that maxResendRawPayload enforces
// for the post-application size keeps the allocation bounded.
func validateResendRawPatch(index int, p resendRawBP) error {
	if p.Offset < 0 {
		return fmt.Errorf("patches[%d]: offset must be >= 0, got %d", index, p.Offset)
	}
	if p.Offset > maxResendRawPayload {
		return fmt.Errorf("patches[%d]: offset %d exceeds payload cap %d", index, p.Offset, maxResendRawPayload)
	}
	if p.DataEncoding != "" && p.DataEncoding != "text" && p.DataEncoding != "base64" {
		return fmt.Errorf("patches[%d]: unsupported data_encoding %q: must be text or base64", index, p.DataEncoding)
	}
	if p.Data == "" {
		return fmt.Errorf("patches[%d]: data must not be empty (zero-length patch is a no-op)", index)
	}
	return nil
}

// resendRawPlan is the resolved payload + dial parameters produced by
// buildResendRawPlan. Consumed by every downstream helper; never escapes
// the resend_raw handler scope.
type resendRawPlan struct {
	streamID string
	connID   string

	// useTLS, dialAddr, sni resolve the upstream dial target. When
	// useTLS is false, sni is empty. dialAddr is the final host:port
	// passed to net.Dialer / connector.DialUpstreamRaw.
	useTLS   bool
	dialAddr string
	sni      string

	// payload is the post-override / post-patches byte sequence to send.
	// When neither override_bytes nor patches is supplied, this is a
	// fresh copy of the recovered Flow.RawBytes (or Flow.Body fallback).
	payload []byte

	// insecureSkipVerify mirrors the input flag for TLS dial.
	insecureSkipVerify bool
}

// buildResendRawPlan resolves the input into a fully-specified plan.
// flow_id is required; the recovered Send-direction Flow's RawBytes (or
// Body fallback) seeds the payload; user-supplied override_bytes /
// patches transform it (RawResendSource handles the precedence rule:
// override_bytes wins; patches apply to the recovered bytes when
// override_bytes is absent).
func (s *Server) buildResendRawPlan(ctx context.Context, input *resendRawInput) (*resendRawPlan, error) {
	if s.flowStore.store == nil {
		return nil, errors.New("resend_raw: flow store is not initialized")
	}
	stream, err := s.flowStore.store.GetStream(ctx, input.FlowID)
	if err != nil {
		return nil, fmt.Errorf("resend_raw: get stream %s: %w", input.FlowID, err)
	}
	if !resendRawSupportedProtocols[stream.Protocol] {
		return nil, fmt.Errorf("resend_raw: protocol %q not supported by this tool — use resend_http / resend_ws / resend_grpc for non-raw flows", stream.Protocol)
	}

	overrides, err := buildResendRawOverrides(input)
	if err != nil {
		return nil, err
	}

	source := job.NewRawResendSource(s.flowStore.store, input.FlowID, overrides)
	srcEnv, err := source.Next(ctx)
	if err != nil {
		return nil, fmt.Errorf("resend_raw: recover bytes: %w", err)
	}
	rawMsg, ok := srcEnv.Message.(*envelope.RawMessage)
	if !ok {
		return nil, fmt.Errorf("resend_raw: source returned %T, expected *RawMessage", srcEnv.Message)
	}
	if len(rawMsg.Bytes) > maxResendRawPayload {
		return nil, fmt.Errorf("resend_raw: payload too large after overrides: %d > %d", len(rawMsg.Bytes), maxResendRawPayload)
	}

	plan := &resendRawPlan{
		streamID:           uuid.NewString(),
		connID:             uuid.NewString(),
		useTLS:             input.UseTLS,
		dialAddr:           input.TargetAddr,
		payload:            rawMsg.Bytes,
		insecureSkipVerify: input.InsecureSkipVerify,
	}
	if input.UseTLS {
		host, _, _ := net.SplitHostPort(input.TargetAddr)
		plan.sni = input.SNI
		if plan.sni == "" {
			plan.sni = host
		}
	}
	return plan, nil
}

// buildResendRawOverrides translates the schema-shaped input into
// internal/job.RawResendOverrides. Mutual exclusion of override_bytes
// vs patches is enforced earlier by validateResendRawInput.
func buildResendRawOverrides(input *resendRawInput) (job.RawResendOverrides, error) {
	out := job.RawResendOverrides{}
	if input.OverrideBytes != "" || input.OverrideBytesSet {
		decoded, err := decodeBodyEncoded(input.OverrideBytes, input.OverrideBytesEncoding, "override_bytes")
		if err != nil {
			return out, err
		}
		out.OverrideBytes = decoded
		return out, nil
	}
	if len(input.Patches) > 0 {
		patches := make([]job.BytePatch, 0, len(input.Patches))
		for i, p := range input.Patches {
			data, err := decodeBodyEncoded(p.Data, p.DataEncoding, fmt.Sprintf("patches[%d].data", i))
			if err != nil {
				return out, err
			}
			patches = append(patches, job.BytePatch{Offset: p.Offset, Data: data})
		}
		out.Patches = patches
	}
	return out, nil
}

// checkResendRawScope enforces TargetScope rules on the dial target.
// scheme is "https" when use_tls=true and "" otherwise — the scope
// engine accepts a blank scheme per checkTargetScopeAddr.
func (s *Server) checkResendRawScope(plan *resendRawPlan) error {
	scheme := ""
	if plan.useTLS {
		scheme = "https"
	}
	return s.checkTargetScopeAddr(scheme, plan.dialAddr)
}

// buildResendRawEncoderRegistry constructs the WireEncoderRegistry
// shared between PluginStepPost and RecordStep for the resend pipeline.
// bytechunk.EncodeWireBytes returns env.Message.(*RawMessage).Bytes
// verbatim — there is no framing layer to re-serialize.
func buildResendRawEncoderRegistry() *pipeline.WireEncoderRegistry {
	encoders := pipeline.NewWireEncoderRegistry()
	encoders.Register(envelope.ProtocolRaw, bytechunk.EncodeWireBytes)
	return encoders
}

// buildResendRawPipeline constructs the resend Pipeline:
//
//	PluginStepPost → RecordStep
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass). HostScope and Safety are handled at the handler level
// before the envelope reaches the pipeline.
func (s *Server) buildResendRawPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(s.flowStore.store, slog.Default(), pipeline.WithWireEncoderRegistry(encoders)),
	}
	return pipeline.New(steps...)
}

// dialResendRawUpstream uses connector.DialUpstreamRaw to establish
// either a plain TCP or TLS-wrapped connection. Returns a connection
// owned by the caller (the bytechunk Layer takes ownership via Layer.New
// and closes it via Layer.Close).
func dialResendRawUpstream(ctx context.Context, plan *resendRawPlan) (net.Conn, error) {
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

// runResendRaw dials, wraps in the bytechunk Layer, runs the send
// envelope through the resend pipeline + Channel.Send, then reads
// chunks until io.EOF / ctx.Done() / response cap. Each receive
// envelope is pinned to the resend StreamID + a per-direction
// monotonic Sequence and run through the pipeline. Drop / Respond on
// the receive side is intentionally ignored (mirror resend_ws / grpc):
// the diagnostic caller sees what the upstream actually sent.
//
// Returns (concatenatedResponseBytes, chunkCount, truncated, error).
func (s *Server) runResendRaw(ctx context.Context, plan *resendRawPlan, p *pipeline.Pipeline) ([]byte, int, bool, error) {
	if p == nil {
		return nil, 0, false, errors.New("resend pipeline is nil")
	}

	sendEnv := buildResendRawSendEnvelope(plan)
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

	conn, err := dialResendRawUpstream(ctx, plan)
	if err != nil {
		return nil, 0, false, err
	}
	l := bytechunk.New(conn, plan.streamID, envelope.Receive)
	defer l.Close()
	ch := <-l.Channels()

	if err := ch.Send(ctx, postSend); err != nil {
		return nil, 0, false, fmt.Errorf("upstream send: %w", err)
	}

	return runResendRawReceiveLoop(ctx, plan, ch, p)
}

// runResendRawReceiveLoop reads bytechunk envelopes until io.EOF /
// ctx.Done() / response cap. Each envelope is pinned to plan.streamID
// + monotonic Sequence (parallel to Send-direction sequence — schema
// v8 UNIQUE(stream_id, sequence, direction) permits) and run through
// the pipeline.
//
// The cap is enforced AFTER a chunk is recorded so RecordStep retains
// full evidence on disk; the result is truncated for MCP transport but
// the per-Flow records are queryable via the `query` MCP tool.
func runResendRawReceiveLoop(ctx context.Context, plan *resendRawPlan, ch interface {
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
			slog.WarnContext(ctx, "resend_raw: receive loop terminated abnormally; returning partial results",
				"stream_id", plan.streamID,
				"chunks", chunks,
				"error", err,
			)
			return out, chunks, truncated, nil
		}
		respEnv.StreamID = plan.streamID
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

// buildResendRawSendEnvelope synthesises the Send-side RawMessage
// envelope. RawResendSource produces an envelope without StreamID /
// Sequence / EnvelopeContext — the handler stamps them here so
// RecordStep keys the new Stream row off plan.streamID and the
// pipeline sees consistent values across the RPC.
func buildResendRawSendEnvelope(plan *resendRawPlan) *envelope.Envelope {
	bytesCopy := make([]byte, len(plan.payload))
	copy(bytesCopy, plan.payload)
	return &envelope.Envelope{
		StreamID:  plan.streamID,
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

// applyResendRawTag persists the user-supplied tag on the new Stream
// row after the pipeline-driven RecordStep has created it.
func (s *Server) applyResendRawTag(ctx context.Context, streamID, tag string) {
	update := flow.StreamUpdate{Tags: map[string]string{"tag": tag}}
	if err := s.flowStore.store.UpdateStream(ctx, streamID, update); err != nil {
		slog.WarnContext(ctx, "resend_raw: tag update failed",
			"stream_id", streamID,
			"tag", tag,
			"error", err,
		)
	}
}

// formatResendRawResult builds the structured result. response_bytes
// is always base64 — raw payloads are binary by definition; never
// attempt UTF-8 sniffing.
func formatResendRawResult(streamID string, respBytes []byte, chunks int, truncated bool, tag string, duration time.Duration) *resendRawTypedResult {
	return &resendRawTypedResult{
		StreamID:       streamID,
		ResponseBytes:  base64.StdEncoding.EncodeToString(respBytes),
		ResponseSize:   len(respBytes),
		ResponseChunks: chunks,
		Truncated:      truncated,
		DurationMs:     duration.Milliseconds(),
		Tag:            tag,
	}
}
