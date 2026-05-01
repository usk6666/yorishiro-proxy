// Package mcp resend_grpc_helpers.go holds the building blocks used by
// resend_grpc.go: input validation, plan recovery (flow_id lookup +
// envelope / metadata reconstruction), envelope construction, scope
// checking, the resend pipeline factory, the upstream dial + HTTP/2
// Layer + gRPC Layer wrap, the send / receive loop, and result
// formatting.
//
// These are split out so resend_grpc.go reads as a top-level
// orchestration while every step has a single responsibility documented
// in isolation.
package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	httputilpkg "github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// resendGRPCSupportedProtocols lists the flow.Stream.Protocol values that
// resend_grpc accepts via flow_id. Non-gRPC protocols are rejected with
// an explicit pointer to the protocol-typed counterpart tool. The new
// pipeline writes Stream.Protocol = string(envelope.ProtocolGRPC) =
// "grpc"; the legacy projection tagged streams as "gRPC" / "gRPC-Web".
// We accept the new spelling here and reject the legacy gRPC-Web spelling
// (gRPC-Web is owned by a future tool).
var resendGRPCSupportedProtocols = map[string]bool{
	"grpc":        true,
	"gRPC":        true,
	"SOCKS5+grpc": true,
	"SOCKS5+gRPC": true,
}

// maxResendGRPCPayload caps each message's payload size accepted at the
// schema boundary. Mirrors resend_ws's frame cap so callers see a clean
// error rather than a mid-Send StreamError. The Layer enforces a higher
// cap via config.MaxGRPCMessageSize (254 MiB) — the schema-side cap is
// fail-fast for misuse, not a security boundary on its own.
const maxResendGRPCPayload = 16 << 20

// validateResendGRPCInput rejects malformed inputs at the schema boundary
// before any expensive lookups (flow store, dial) run.
//
// CRLF guards on user-supplied URL components (service, method, scheme,
// target_addr) defend against CWE-93 request smuggling on the upstream
// leg even though gRPC HEADERS are HPACK-encoded — we keep the same
// hygiene as resend_ws so the schema-level guarantees do not depend on
// downstream encoding details. Recovered metadata from the flow store is
// NOT sanitized (preserving wire reality on recorded inputs is a project
// MITM principle).
func validateResendGRPCInput(input *resendGRPCInput) error {
	if err := validateResendGRPCStringFields(input); err != nil {
		return err
	}
	if err := validateResendGRPCMetadataAndEncoding(input); err != nil {
		return err
	}
	if err := validateResendGRPCMessagesShape(input); err != nil {
		return err
	}
	if input.FlowID == "" {
		return validateResendGRPCFromScratch(input)
	}
	return nil
}

// validateResendGRPCStringFields runs CRLF guards on every user-supplied
// URL / RPC name component. Recovered headers are NOT sanitized (MITM
// principle); these guards apply only to user-input fields.
func validateResendGRPCStringFields(input *resendGRPCInput) error {
	if err := validateResendGRPCNoCRLF("service", input.Service); err != nil {
		return err
	}
	if err := validateResendGRPCNoCRLF("method", input.Method); err != nil {
		return err
	}
	if err := validateResendGRPCNoCRLF("scheme", input.Scheme); err != nil {
		return err
	}
	return validateResendGRPCNoCRLF("target_addr", input.TargetAddr)
}

// validateResendGRPCMetadataAndEncoding runs the per-list header guards
// and the encoding allowlist check.
func validateResendGRPCMetadataAndEncoding(input *resendGRPCInput) error {
	if err := validateHeaderKVList(input.Metadata, "metadata"); err != nil {
		return err
	}
	if err := validateHeaderKVList(input.TrailerMetadata, "trailer_metadata"); err != nil {
		return err
	}
	if input.Encoding != "" && input.Encoding != "identity" && input.Encoding != "gzip" {
		return fmt.Errorf("unsupported encoding %q: must be identity or gzip", input.Encoding)
	}
	return nil
}

// validateResendGRPCMessagesShape rejects an empty messages list and any
// message with an unsupported body_encoding.
func validateResendGRPCMessagesShape(input *resendGRPCInput) error {
	if len(input.Messages) == 0 {
		return errors.New("messages must contain at least one element (a gRPC RPC requires at least one DATA frame)")
	}
	for i, m := range input.Messages {
		if m.BodyEncoding != "" && m.BodyEncoding != "text" && m.BodyEncoding != "base64" {
			return fmt.Errorf("messages[%d]: unsupported body_encoding %q: must be text or base64", i, m.BodyEncoding)
		}
	}
	return nil
}

// validateResendGRPCNoCRLF rejects values containing CR/LF. Used on
// user-supplied URL / RPC name components.
func validateResendGRPCNoCRLF(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains CR/LF characters", field)
	}
	return nil
}

// validateResendGRPCFromScratch checks the required fields when flow_id
// is omitted. Service / Method / target_addr must be supplied; the scheme
// defaults to https; compressed=true on any message requires Encoding to
// be set up-front so the LPM compression byte makes sense to the Layer.
func validateResendGRPCFromScratch(input *resendGRPCInput) error {
	missing := []string{}
	if input.TargetAddr == "" {
		missing = append(missing, "target_addr")
	}
	if input.Service == "" {
		missing = append(missing, "service")
	}
	if input.Method == "" {
		missing = append(missing, "method")
	}
	if len(missing) > 0 {
		return fmt.Errorf("flow_id is empty; %s required", strings.Join(missing, ", "))
	}
	scheme := strings.ToLower(input.Scheme)
	if scheme != "" && scheme != "http" && scheme != "https" {
		return fmt.Errorf("unsupported scheme %q: only http and https are allowed", input.Scheme)
	}
	for i, m := range input.Messages {
		if m.Compressed && input.Encoding == "" {
			return fmt.Errorf("messages[%d]: compressed=true requires encoding to be set (identity or gzip)", i)
		}
	}
	return nil
}

// resendGRPCPlan is the resolved RPC + dial parameters produced by
// buildResendGRPCPlan. Consumed by every downstream helper; never escapes
// the resend_grpc handler scope.
type resendGRPCPlan struct {
	streamID string
	connID   string

	// canonicalURL is the URL used for safety/scope checks. Built directly
	// from validated fields (no String/Parse round-trip — CWE-918 lesson
	// from USK-672). Scheme is "https" (TLS+ALPN h2) or "http" (h2c);
	// Path is "/Service/Method".
	canonicalURL *url.URL

	// useTLS, dialAddr, sni, authority resolve the upstream dial target.
	// authority is the value used for the :authority pseudo-header and the
	// HEADERS frame; dialAddr is the actual host:port the dialer sees
	// (overridden by target_addr when supplied).
	useTLS    bool
	dialAddr  string
	sni       string
	authority string

	// service / method are the post-override values that populate
	// :path and the GRPCStartMessage.
	service string
	method  string

	// metadata is the ordered metadata list (post-override).
	metadata []envelope.KeyValue

	// encoding / acceptEncoding feed GRPCStartMessage.
	encoding       string
	acceptEncoding []string

	// messages are the per-LPM payloads ready for envelope construction.
	messages []resendGRPCDataPlan

	// trailerMetadata, when non-nil, terminates the stream via a
	// Send-direction trailer HEADERS frame.
	trailerMetadata []envelope.KeyValue
}

// resendGRPCDataPlan is one LPM ready for envelope construction.
type resendGRPCDataPlan struct {
	payload    []byte
	compressed bool
}

// buildResendGRPCPlan resolves the input into a fully-specified plan.
// When flow_id is set, the original RPC's send-direction GRPCStart Flow
// supplies Service / Method / Metadata / Encoding when not user-overridden;
// the receive-direction GRPCStart Flow supplies the negotiated upstream
// AcceptEncoding default. When flow_id is empty, every Start field comes
// from the user.
func (s *Server) buildResendGRPCPlan(ctx context.Context, input *resendGRPCInput) (*resendGRPCPlan, error) {
	plan := &resendGRPCPlan{
		streamID: uuid.NewString(),
		connID:   uuid.NewString(),
	}

	authority, scheme, recoveredMeta, recoveredEncoding, recoveredAccept, err := s.resolveResendGRPCStart(ctx, input, plan)
	if err != nil {
		return nil, err
	}

	plan.useTLS = scheme == "https"
	dialAuthority := authority
	if input.TargetAddr != "" {
		dialAuthority = input.TargetAddr
	}
	plan.dialAddr, plan.sni = resolveResendGRPCDialTarget(dialAuthority, plan.useTLS)
	plan.authority = authority
	plan.canonicalURL = resendGRPCCanonicalURL(scheme, authority, plan.service, plan.method)

	if len(plan.metadata) == 0 {
		plan.metadata = recoveredMeta
	}
	if plan.encoding == "" {
		plan.encoding = recoveredEncoding
	}
	if len(plan.acceptEncoding) == 0 {
		plan.acceptEncoding = recoveredAccept
	}

	if err := populateResendGRPCMessages(input, plan); err != nil {
		return nil, err
	}
	if len(input.TrailerMetadata) > 0 {
		plan.trailerMetadata = headerKVsToKeyValues(input.TrailerMetadata)
	}
	return plan, nil
}

// resolveResendGRPCStart pulls Service / Method / Metadata / Encoding /
// AcceptEncoding from the recovered Send-side GRPCStart Flow when
// flow_id is set, then layers user-supplied overrides on top. Returns
// the resolved (authority, scheme) plus the recovered metadata /
// encoding values for the caller to merge.
func (s *Server) resolveResendGRPCStart(ctx context.Context, input *resendGRPCInput, plan *resendGRPCPlan) (authority, scheme string, recoveredMeta []envelope.KeyValue, recoveredEncoding string, recoveredAccept []string, err error) {
	scheme = strings.ToLower(input.Scheme)
	applyResendGRPCUserStartFields(input, plan)

	if input.FlowID != "" {
		recAuthority, recScheme, recMeta, recEnc, recAccept, lerr := s.recoverResendGRPCStartFromFlow(ctx, input.FlowID, plan)
		if lerr != nil {
			return "", "", nil, "", nil, lerr
		}
		authority = recAuthority
		if scheme == "" {
			scheme = recScheme
		}
		recoveredMeta = recMeta
		recoveredEncoding = recEnc
		recoveredAccept = recAccept
	}

	authority, scheme, err = finalizeResendGRPCAuthorityScheme(input, plan, authority, scheme)
	if err != nil {
		return "", "", nil, "", nil, err
	}
	return authority, scheme, recoveredMeta, recoveredEncoding, recoveredAccept, nil
}

// applyResendGRPCUserStartFields copies user-supplied Service / Method /
// Metadata / Encoding / AcceptEncoding into the plan. Empty user fields
// stay zero so the recovery step can fill them.
func applyResendGRPCUserStartFields(input *resendGRPCInput, plan *resendGRPCPlan) {
	plan.service = input.Service
	plan.method = input.Method
	if input.Metadata != nil {
		plan.metadata = headerKVsToKeyValues(input.Metadata)
	}
	plan.encoding = input.Encoding
	if len(input.AcceptEncoding) > 0 {
		plan.acceptEncoding = append([]string(nil), input.AcceptEncoding...)
	}
}

// recoverResendGRPCStartFromFlow loads the original RPC's Send / Receive
// GRPCStart Flows and returns the recovered (authority, scheme,
// metadata, encoding, accept-encoding) values. Side-effect: fills empty
// plan.service / plan.method from the recovered URL.Path.
func (s *Server) recoverResendGRPCStartFromFlow(ctx context.Context, flowID string, plan *resendGRPCPlan) (authority, scheme string, meta []envelope.KeyValue, encoding string, accept []string, err error) {
	stream, sendStart, recvStart, lerr := s.loadResendGRPCFlows(ctx, flowID)
	if lerr != nil {
		return "", "", nil, "", nil, lerr
	}
	if !resendGRPCSupportedProtocols[stream.Protocol] {
		return "", "", nil, "", nil, fmt.Errorf("resend_grpc: protocol %q not supported by this tool — use resend_http / resend_ws / resend_raw for non-gRPC flows", stream.Protocol)
	}
	recAuthority, recService, recMethod, recScheme := extractResendGRPCStartFields(sendStart)
	if plan.service == "" {
		plan.service = recService
	}
	if plan.method == "" {
		plan.method = recMethod
	}
	authority = recAuthority
	scheme = recScheme
	meta = flowMapToKeyValues(sendStart.Headers)
	encoding = firstFlowHeaderValue(sendStart.Headers, "Grpc-Encoding")
	if recvStart != nil {
		if v := firstFlowHeaderValue(recvStart.Headers, "Grpc-Accept-Encoding"); v != "" {
			accept = splitAndTrimComma(v)
		}
	}
	return authority, scheme, meta, encoding, accept, nil
}

// finalizeResendGRPCAuthorityScheme defaults scheme to https, fills
// authority from target_addr when no recovered URL is available, and
// rejects malformed RPCs lacking service/method.
func finalizeResendGRPCAuthorityScheme(input *resendGRPCInput, plan *resendGRPCPlan, authority, scheme string) (string, string, error) {
	if scheme == "" {
		scheme = "https"
	}
	if authority == "" && input.TargetAddr != "" {
		authority = input.TargetAddr
	}
	if authority == "" {
		return "", "", errors.New("resend_grpc: authority is empty (no recovered URL and no target_addr)")
	}
	if plan.service == "" || plan.method == "" {
		return "", "", errors.New("resend_grpc: service and method are required (recovered RPC was malformed; pass overrides)")
	}
	return authority, scheme, nil
}

// extractResendGRPCStartFields pulls (authority, service, method, scheme)
// from the recorded Send-direction GRPCStart Flow. URL.Path is "/S/M";
// authority is URL.Host; scheme is URL.Scheme (mapped from h2 vs h2c).
// Empty-tolerant — any missing field surfaces as "" and the caller's
// validation requires the user to supply a non-empty override.
func extractResendGRPCStartFields(f *flow.Flow) (authority, service, method, scheme string) {
	if f == nil || f.URL == nil {
		return "", "", "", ""
	}
	authority = f.URL.Host
	scheme = f.URL.Scheme
	parts := strings.SplitN(strings.TrimPrefix(f.URL.Path, "/"), "/", 2)
	if len(parts) == 2 {
		service = parts[0]
		method = parts[1]
	}
	return authority, service, method, scheme
}

// loadResendGRPCFlows fetches the Stream and the first send / first
// receive Flows. The receive Flow is allowed to be missing (a request
// that never got a response is still resendable).
func (s *Server) loadResendGRPCFlows(ctx context.Context, flowID string) (*flow.Stream, *flow.Flow, *flow.Flow, error) {
	if s.flowStore.store == nil {
		return nil, nil, nil, errors.New("resend_grpc: flow store is not initialized")
	}
	stream, err := s.flowStore.store.GetStream(ctx, flowID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_grpc: get stream %s: %w", flowID, err)
	}
	sendFlows, err := s.flowStore.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_grpc: get send flows %s: %w", flowID, err)
	}
	if len(sendFlows) == 0 {
		return nil, nil, nil, fmt.Errorf("resend_grpc: stream %s has no send-direction flows", flowID)
	}
	recvFlows, err := s.flowStore.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_grpc: get receive flows %s: %w", flowID, err)
	}
	var recvFlow *flow.Flow
	if len(recvFlows) > 0 {
		recvFlow = recvFlows[0]
	}
	return stream, sendFlows[0], recvFlow, nil
}

// splitAndTrimComma splits on commas and trims whitespace from each
// element, dropping empty strings. Used to round-trip
// grpc-accept-encoding from the recorded HEADERS multimap.
func splitAndTrimComma(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		t := strings.TrimSpace(p)
		if t != "" {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil
	}
	res := make([]string, len(out))
	copy(res, out)
	return res
}

// resolveResendGRPCDialTarget produces the (host:port, sni) pair for the
// upstream connection. authority may be host:port or just host.
func resolveResendGRPCDialTarget(authority string, useTLS bool) (addr, sni string) {
	host := authority
	port := ""
	if h, p, err := net.SplitHostPort(authority); err == nil {
		host = h
		port = p
	}
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), host
}

// resendGRPCCanonicalURL builds the canonical *url.URL used for scope
// and safety checks. Path is "/Service/Method". Built directly from
// validated fields (no String → Parse round-trip — CWE-918 lesson from
// USK-672).
func resendGRPCCanonicalURL(scheme, authority, service, method string) *url.URL {
	return &url.URL{
		Scheme: scheme,
		Host:   authority,
		Path:   "/" + service + "/" + method,
	}
}

// populateResendGRPCMessages decodes each message's payload per
// body_encoding, enforces the per-message size cap, and rejects
// compressed=true on any message when the resolved Encoding is empty
// (the Layer's Send path treats Compressed=true with no encoding as
// passthrough — useful for fuzzing but a footgun for diagnostic resend).
func populateResendGRPCMessages(input *resendGRPCInput, plan *resendGRPCPlan) error {
	plan.messages = make([]resendGRPCDataPlan, 0, len(input.Messages))
	for i, m := range input.Messages {
		decoded, err := decodeBodyEncoded(m.Payload, m.BodyEncoding, fmt.Sprintf("messages[%d].payload", i))
		if err != nil {
			return err
		}
		if len(decoded) > maxResendGRPCPayload {
			return fmt.Errorf("messages[%d]: payload too large: %d > %d", i, len(decoded), maxResendGRPCPayload)
		}
		if m.Compressed && plan.encoding == "" {
			return fmt.Errorf("messages[%d]: compressed=true requires encoding to be set (identity or gzip)", i)
		}
		plan.messages = append(plan.messages, resendGRPCDataPlan{
			payload:    decoded,
			compressed: m.Compressed,
		})
	}
	return nil
}

// concatResendGRPCPayloads returns the concatenation of every plan
// message's payload bytes. Used as the safety filter input — cheap
// approximation (the wire form is per-LPM, but the safety patterns
// match plain text irrespective of LPM framing).
func concatResendGRPCPayloads(plan *resendGRPCPlan) []byte {
	total := 0
	for _, m := range plan.messages {
		total += len(m.payload)
	}
	if total == 0 {
		return nil
	}
	out := make([]byte, 0, total)
	for _, m := range plan.messages {
		out = append(out, m.payload...)
	}
	return out
}

// checkResendGRPCScope enforces TargetScope rules on both the canonical
// RPC URL and (when target_addr redirects the dial) the override
// target. Both must pass; an override that bypasses scope is rejected
// even when the canonical authority is in-scope.
func (s *Server) checkResendGRPCScope(plan *resendGRPCPlan) error {
	if err := s.checkTargetScopeURL(plan.canonicalURL); err != nil {
		return err
	}
	overrideScheme := ""
	if plan.useTLS {
		overrideScheme = "https"
	}
	if plan.dialAddr != plan.canonicalURL.Host {
		if err := s.checkTargetScopeAddr(overrideScheme, plan.dialAddr); err != nil {
			return err
		}
	}
	return nil
}

// buildResendGRPCEncoderRegistry constructs the WireEncoderRegistry
// shared between PluginStepPost and RecordStep for the resend pipeline.
// The gRPC EncodeWireBytes is the only encoder needed; it returns
// (nil, nil) fail-soft for Start and End (HPACK lives in the HTTP/2
// layer, not regenerable in isolation) and for Compressed=true Data
// (encoding lives on per-channel directionState). RecordStep preserves
// the original Raw on fail-soft per the USK-666 contract.
func buildResendGRPCEncoderRegistry() *pipeline.WireEncoderRegistry {
	encoders := pipeline.NewWireEncoderRegistry()
	encoders.Register(envelope.ProtocolGRPC, grpclayer.EncodeWireBytes)
	return encoders
}

// buildResendGRPCPipeline constructs the resend Pipeline:
//
//	PluginStepPost → RecordStep
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass). HostScope and Safety are handled at the handler level
// before the envelope reaches the pipeline.
func (s *Server) buildResendGRPCPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(s.flowStore.store, slog.Default(), pipeline.WithWireEncoderRegistry(encoders)),
	}
	return pipeline.New(steps...)
}

// runResendGRPC dials, opens an HTTP/2 stream, wraps in the gRPC Layer,
// runs each request envelope (Start → Data* → optional End) through the
// resend pipeline + Channel.Send, then reads response envelopes until
// GRPCEnd OR Channel close OR ctx timeout. Each response envelope is
// pinned to the resend StreamID + an incrementing receive Sequence and
// run through the pipeline.
//
// Returns (endEnvelope, dataEnvelopes, startMetadata, error). endEnvelope
// is nil when the stream terminated without a trailer HEADERS frame —
// callers surface this in the result as "end omitted" and may inspect
// the Channel's terminal Err() via the Layer.
func (s *Server) runResendGRPC(ctx context.Context, plan *resendGRPCPlan, p *pipeline.Pipeline) (*envelope.Envelope, []*envelope.Envelope, []envelope.KeyValue, error) {
	if p == nil {
		return nil, nil, nil, errors.New("resend pipeline is nil")
	}

	startEnv := buildResendGRPCStartEnvelope(plan)
	postStart, action, custom := p.Run(ctx, startEnv)
	switch action {
	case pipeline.Drop:
		return nil, nil, nil, errors.New("send envelope dropped by pipeline")
	case pipeline.Respond:
		if custom == nil {
			return nil, nil, nil, errors.New("pipeline returned Respond with nil response envelope")
		}
		custom.StreamID = postStart.StreamID
		custom.Sequence = 1
		_, _, _ = p.Run(ctx, custom)
		// Synthesise a result shape: the custom response is the End
		// envelope from the caller's perspective. No data envelopes; no
		// real receive metadata.
		return custom, nil, nil, nil
	}

	conn, err := dialResendGRPCUpstream(ctx, s.connector.tlsTransport, plan.dialAddr, plan.useTLS, plan.sni)
	if err != nil {
		return nil, nil, nil, err
	}

	// SETTINGS_MAX_HEADER_LIST_SIZE = 1 MiB. The default (0) is honored by
	// strict peers (notably google.golang.org/grpc) as "0 bytes allowed",
	// which RST_STREAMs every HEADERS frame the upstream sends back. The
	// 1 MiB ceiling matches the value the layer/grpc e2e harness uses to
	// negotiate with grpc-go and bounds memory exposure on response HEADERS
	// (CWE-770 envelope).
	initialSettings := http2.DefaultSettings()
	initialSettings.MaxHeaderListSize = 1 << 20
	l, err := http2.New(conn, "", http2.ClientRole,
		http2.WithEnvelopeContext(envelope.EnvelopeContext{
			ConnID: plan.connID,
		}),
		http2.WithInitialSettings(initialSettings),
	)
	if err != nil {
		_ = conn.Close()
		return nil, nil, nil, fmt.Errorf("http2 layer: %w", err)
	}
	defer l.Close()

	innerCh, err := l.OpenStream(ctx)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("open stream: %w", err)
	}

	// Synthetic firstHeaders=nil: triggers D5 discard so the wrapper's
	// first Next() reads a real envelope from the inner H2 channel
	// (i.e., the response HEADERS frame the upstream sends back).
	ch := grpclayer.Wrap(innerCh, nil, grpclayer.RoleClient)

	// Send Start envelope. Pin StreamID before the wire goes out so
	// receive-side rewriting stays consistent.
	postStart.StreamID = plan.streamID
	if err := ch.Send(ctx, postStart); err != nil {
		return nil, nil, nil, fmt.Errorf("upstream send Start: %w", err)
	}

	if err := sendResendGRPCDataAndEnd(ctx, plan, ch, p); err != nil {
		return nil, nil, nil, err
	}

	endEnv, recvData, recvStartMeta, err := receiveResendGRPCResponses(ctx, plan, ch, p)
	if err != nil {
		return nil, nil, nil, err
	}
	return endEnv, recvData, recvStartMeta, nil
}

// sendResendGRPCDataAndEnd sends each Data envelope (with EndStream on
// the last when no trailer is supplied) and the optional End envelope.
// Each envelope is run through the pipeline first (so PluginStepPost
// fires per envelope and RecordStep records each Send Flow).
func sendResendGRPCDataAndEnd(ctx context.Context, plan *resendGRPCPlan, ch layer.Channel, p *pipeline.Pipeline) error {
	wantTrailer := plan.trailerMetadata != nil
	for i, m := range plan.messages {
		envData := buildResendGRPCDataEnvelope(plan, i, m)
		if !wantTrailer && i == len(plan.messages)-1 {
			envData.Message.(*envelope.GRPCDataMessage).EndStream = true
		}
		postData, action, _ := p.Run(ctx, envData)
		// Drop / Respond on mid-stream Data: the surface table rejects
		// these on ("grpc","on_data") so PluginStepPost's dispatcher
		// already fail-softed them. The action returned to us is
		// effectively Continue. Handle defensively in case future
		// refactors loosen the surface.
		if action == pipeline.Drop {
			return fmt.Errorf("messages[%d] dropped by pipeline (mid-stream drop is not supported)", i)
		}
		postData.StreamID = plan.streamID
		if err := ch.Send(ctx, postData); err != nil {
			return fmt.Errorf("upstream send Data[%d]: %w", i, err)
		}
	}
	if !wantTrailer {
		return nil
	}
	envEnd := buildResendGRPCEndEnvelope(plan)
	postEnd, action, _ := p.Run(ctx, envEnd)
	if action == pipeline.Drop {
		return errors.New("trailer envelope dropped by pipeline")
	}
	postEnd.StreamID = plan.streamID
	if err := ch.Send(ctx, postEnd); err != nil {
		return fmt.Errorf("upstream send End: %w", err)
	}
	return nil
}

// receiveResendGRPCResponses reads response envelopes until a
// GRPCEndMessage is observed OR the channel terminates. Each envelope
// is pinned to the resend StreamID + a per-direction monotonic Sequence
// (independent of the layer-internal counter — schema v8
// UNIQUE(stream_id, sequence, direction) makes this safe) and run
// through the pipeline. Drop / Respond on receive side is intentionally
// ignored (mirror resend_ws): the diagnostic caller sees what the
// upstream actually sent.
func receiveResendGRPCResponses(ctx context.Context, plan *resendGRPCPlan, ch layer.Channel, p *pipeline.Pipeline) (*envelope.Envelope, []*envelope.Envelope, []envelope.KeyValue, error) {
	var (
		endEnv    *envelope.Envelope
		recvData  []*envelope.Envelope
		startMeta []envelope.KeyValue
		recvSeq   int
	)
	for {
		respEnv, err := ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return endEnv, recvData, startMeta, nil
			}
			// Non-EOF error: surface what we collected so far plus the
			// error so the diagnostic caller can correlate via tag.
			if endEnv == nil && len(recvData) == 0 {
				return nil, nil, nil, fmt.Errorf("upstream receive: %w", err)
			}
			slog.WarnContext(ctx, "resend_grpc: stream terminated abnormally; returning partial results",
				"stream_id", plan.streamID,
				"error", err,
			)
			return endEnv, recvData, startMeta, nil
		}
		respEnv.StreamID = plan.streamID
		respEnv.Sequence = recvSeq
		recvSeq++

		respEnv, _, _ = p.Run(ctx, respEnv)

		switch m := respEnv.Message.(type) {
		case *envelope.GRPCStartMessage:
			startMeta = append([]envelope.KeyValue(nil), m.Metadata...)
		case *envelope.GRPCDataMessage:
			recvData = append(recvData, respEnv)
		case *envelope.GRPCEndMessage:
			endEnv = respEnv
			return endEnv, recvData, startMeta, nil
		}
	}
}

// buildResendGRPCStartEnvelope synthesises the Send-side GRPCStart
// envelope. Service / Method / Metadata / Encoding / AcceptEncoding are
// resolved from the plan; ContentType defaults to application/grpc+proto
// (the gRPC Layer's sendStart consults this for the content-type pseudo-
// header and for downstream content-type detection on the upstream side
// via DispatchH2Stream).
func buildResendGRPCStartEnvelope(plan *resendGRPCPlan) *envelope.Envelope {
	msg := &envelope.GRPCStartMessage{
		Service:        plan.service,
		Method:         plan.method,
		Metadata:       plan.metadata,
		Encoding:       plan.encoding,
		AcceptEncoding: plan.acceptEncoding,
		ContentType:    "application/grpc+proto",
	}
	return &envelope.Envelope{
		StreamID:  plan.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			ConnID: plan.connID,
		},
	}
}

// buildResendGRPCDataEnvelope synthesises one Send-side GRPCData
// envelope. WireLength is derived from len(payload) — the Layer's
// sendData rebuilds the LPM prefix from the same value.
func buildResendGRPCDataEnvelope(plan *resendGRPCPlan, index int, m resendGRPCDataPlan) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  plan.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  index + 1,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Service:    plan.service,
			Method:     plan.method,
			Compressed: m.compressed,
			WireLength: uint32(len(m.payload)),
			Payload:    m.payload,
		},
		Context: envelope.EnvelopeContext{
			ConnID: plan.connID,
		},
	}
}

// buildResendGRPCEndEnvelope synthesises the Send-side GRPCEnd envelope
// when trailer_metadata is supplied. Status defaults to 0 (OK); callers
// that want non-zero status must encode it via grpc-status in the
// trailer_metadata directly (mirrors the Layer's parse-by-name path).
func buildResendGRPCEndEnvelope(plan *resendGRPCPlan) *envelope.Envelope {
	msg := &envelope.GRPCEndMessage{
		Trailers: plan.trailerMetadata,
	}
	return &envelope.Envelope{
		StreamID:  plan.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  len(plan.messages) + 1,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			ConnID: plan.connID,
		},
	}
}

// dialResendGRPCUpstream dials addr (TLS-upgraded for scheme=https with
// ALPN h2). Returns a connection owned by the caller.
func dialResendGRPCUpstream(ctx context.Context, transport httputilpkg.TLSTransport, addr string, useTLS bool, sni string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: defaultReplayTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if useTLS {
		if transport == nil {
			_ = conn.Close()
			return nil, errors.New("resend_grpc: TLS upstream requires a configured TLSTransport")
		}
		tlsConn, _, tlsErr := transport.TLSConnect(ctx, conn, sni)
		if tlsErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake %s: %w", sni, tlsErr)
		}
		conn = tlsConn
	}
	return conn, nil
}

// applyResendGRPCTag persists the user-supplied tag on the new Stream
// row after the pipeline-driven RecordStep has created it.
func (s *Server) applyResendGRPCTag(ctx context.Context, streamID, tag string) {
	update := flow.StreamUpdate{Tags: map[string]string{"tag": tag}}
	if err := s.flowStore.store.UpdateStream(ctx, streamID, update); err != nil {
		slog.WarnContext(ctx, "resend_grpc: tag update failed",
			"stream_id", streamID,
			"tag", tag,
			"error", err,
		)
	}
}

// formatResendGRPCResult turns the collected response envelopes into
// the wire-shape MCP result. SafetyFilter output masking is applied to
// each Data payload before it leaves the proxy boundary; the unmasked
// variant is on disk via RecordStep.
func (s *Server) formatResendGRPCResult(streamID string, startMeta []envelope.KeyValue, dataEnvs []*envelope.Envelope, endEnv *envelope.Envelope, tag string, duration time.Duration) *resendGRPCResult {
	result := &resendGRPCResult{
		StreamID:      streamID,
		StartMetadata: keyValuesToHeaderKVs(startMeta),
		DurationMs:    duration.Milliseconds(),
		Tag:           tag,
	}
	result.Messages = make([]resendGRPCDataResult, 0, len(dataEnvs))
	for _, env := range dataEnvs {
		msg, ok := env.Message.(*envelope.GRPCDataMessage)
		if !ok {
			continue
		}
		masked := s.filterOutputBody(msg.Payload)
		payload, encoding := encodeResendGRPCPayload(masked)
		result.Messages = append(result.Messages, resendGRPCDataResult{
			Payload:         payload,
			PayloadEncoding: encoding,
			Compressed:      msg.Compressed,
		})
	}
	if endEnv != nil {
		if endMsg, ok := endEnv.Message.(*envelope.GRPCEndMessage); ok {
			result.End = &resendGRPCEndResult{
				Status:   endMsg.Status,
				Message:  endMsg.Message,
				Trailers: keyValuesToHeaderKVs(endMsg.Trailers),
			}
		}
	}
	return result
}

// keyValuesToHeaderKVs projects an ordered envelope.KeyValue slice onto
// the MCP result schema's headerKV slice. Order and casing preserved.
func keyValuesToHeaderKVs(list []envelope.KeyValue) []headerKV {
	if len(list) == 0 {
		return nil
	}
	out := make([]headerKV, len(list))
	for i, kv := range list {
		out[i] = headerKV{Name: kv.Name, Value: kv.Value}
	}
	return out
}

// encodeResendGRPCPayload returns the payload string and its declared
// encoding. UTF-8-clean payloads report as text; otherwise base64. Empty
// payloads always report "text" so the schema stays consistent.
func encodeResendGRPCPayload(payload []byte) (string, string) {
	if len(payload) == 0 {
		return "", "text"
	}
	if utf8.Valid(payload) {
		return string(payload), "text"
	}
	return base64.StdEncoding.EncodeToString(payload), "base64"
}
