// Package mcp resend_ws_helpers.go holds the building blocks used by
// resend_ws.go: input validation, plan recovery (flow_id lookup +
// extension negotiation), envelope construction, scope checking, the
// resend pipeline factory, the upstream upgrade dance, the send/receive
// run loop, and result formatting.
//
// These are split out so resend_ws.go reads as a top-level orchestration
// while every step has a single responsibility documented in isolation.
package mcp

import (
	"context"
	"crypto/rand"
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

	httputilpkg "github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// resendWSSupportedProtocols lists the flow.Stream.Protocol values that
// resend_ws accepts via flow_id. Non-WS protocols are rejected with an
// explicit pointer to the protocol-typed counterpart tool.
var resendWSSupportedProtocols = map[string]bool{
	"WebSocket":        true,
	"SOCKS5+WebSocket": true,
	"ws":               true,
}

// validResendWSOpcodes maps schema opcode strings to WSOpcode constants.
// Continuation frames are excluded — a resend always starts a new message.
var validResendWSOpcodes = map[string]envelope.WSOpcode{
	"text":   envelope.WSText,
	"binary": envelope.WSBinary,
	"close":  envelope.WSClose,
	"ping":   envelope.WSPing,
	"pong":   envelope.WSPong,
}

// maxResendWSPayload caps the payload size accepted at the schema
// boundary. Mirrors the WS Layer's 16 MiB frame cap so callers see a
// clean error rather than a mid-Send StreamError.
const maxResendWSPayload = 16 << 20

// validateResendWSInput rejects malformed inputs at the schema boundary
// before any expensive lookups (flow store, dial) run.
//
// CRLF guards on user-supplied URL components (path, raw_query, scheme,
// target_addr) defend against CWE-93 request smuggling on the upstream
// upgrade leg: serializeRequestLine writes the supplied path verbatim
// into the request line without sanitization, so an embedded "\r\n"
// would inject a second request onto the upstream socket. Recovered
// headers from the flow store are NOT sanitized — preserving wire
// reality on recorded inputs is a project MITM principle.
func validateResendWSInput(input *resendWSInput) error {
	if input.Opcode == "" {
		return errors.New("opcode is required (text|binary|close|ping|pong)")
	}
	if _, ok := validResendWSOpcodes[strings.ToLower(input.Opcode)]; !ok {
		return fmt.Errorf("unsupported opcode %q: must be text|binary|close|ping|pong", input.Opcode)
	}
	if input.BodyEncoding != "" && input.BodyEncoding != "text" && input.BodyEncoding != "base64" {
		return fmt.Errorf("unsupported body_encoding %q: must be text or base64", input.BodyEncoding)
	}
	if err := validateResendWSNoCRLF("path", input.Path); err != nil {
		return err
	}
	if err := validateResendWSNoCRLF("raw_query", input.RawQuery); err != nil {
		return err
	}
	if err := validateResendWSNoCRLF("scheme", input.Scheme); err != nil {
		return err
	}
	if err := validateResendWSNoCRLF("target_addr", input.TargetAddr); err != nil {
		return err
	}
	if input.Mask != "" {
		// Mask is informational on Send (RoleClient regenerates), but
		// reject malformed encoding so callers don't pass nonsense by
		// accident.
		if _, err := decodeBodyEncoded(input.Mask, "base64", "mask"); err != nil {
			return fmt.Errorf("invalid mask: %w", err)
		}
	}
	if input.FlowID == "" {
		if err := validateResendWSFromScratch(input); err != nil {
			return err
		}
	}
	return nil
}

// validateResendWSNoCRLF rejects values containing CR/LF. Used on
// user-supplied URL components that are written verbatim into the
// HTTP/1.1 upgrade request line or Host header.
func validateResendWSNoCRLF(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains CR/LF characters", field)
	}
	return nil
}

// validateResendWSFromScratch checks the required fields when flow_id is
// omitted. Compressed=true is rejected here because there's no recorded
// extension header to drive deflate.
func validateResendWSFromScratch(input *resendWSInput) error {
	missing := []string{}
	if input.TargetAddr == "" {
		missing = append(missing, "target_addr")
	}
	if input.Path == "" {
		missing = append(missing, "path")
	}
	if len(missing) > 0 {
		return fmt.Errorf("flow_id is empty; %s required", strings.Join(missing, ", "))
	}
	scheme := strings.ToLower(input.Scheme)
	if scheme != "" && scheme != "ws" && scheme != "wss" {
		return fmt.Errorf("unsupported scheme %q: only ws and wss are allowed", input.Scheme)
	}
	if input.Compressed != nil && *input.Compressed {
		return errors.New("compressed=true requires flow_id to recover negotiated permessage-deflate parameters")
	}
	return nil
}

// resendWSPlan is the resolved frame + dial parameters produced by
// buildResendWSPlan. Consumed by every downstream helper; never escapes
// the resend_ws handler scope.
type resendWSPlan struct {
	streamID string
	connID   string

	// upgradeURL is the canonical URL used for safety/scope checks. ws →
	// http; wss → https. Built directly from validated fields (no
	// String/Parse round-trip — CWE-918 lesson from USK-672).
	upgradeURL *url.URL

	// useTLS, dialAddr, sni resolve the upstream dial target.
	useTLS   bool
	dialAddr string
	sni      string

	// upgradeHeaders are the request-side headers replayed on the upgrade
	// GET (Cookie, Authorization, Sec-WebSocket-Protocol, etc.). The
	// authoritative WebSocket handshake headers (Upgrade, Connection,
	// Sec-WebSocket-Key, Sec-WebSocket-Version, Host) are injected by
	// buildResendWSUpgradeHeaders.
	upgradeHeaders []envelope.KeyValue

	// extensionHeader is the server-negotiated Sec-WebSocket-Extensions
	// value recovered from the recorded 101 response. Empty when no
	// flow was supplied or no deflate was negotiated.
	extensionHeader string

	// frame fields
	opcode      envelope.WSOpcode
	fin         bool
	masked      bool
	mask        [4]byte
	payload     []byte
	closeCode   uint16
	closeReason string
	compressed  bool
}

// buildResendWSPlan resolves the input into a fully-specified plan. When
// flow_id is set, the upgrade Stream's send Flow supplies URL + headers
// and the receive Flow supplies the negotiated extension header. User-
// supplied fields override their inherited counterparts.
func (s *Server) buildResendWSPlan(ctx context.Context, input *resendWSInput) (*resendWSPlan, error) {
	plan := &resendWSPlan{
		streamID: uuid.NewString(),
		connID:   uuid.NewString(),
	}

	scheme, authority, upgradePath, rawQuery, err := s.resolveResendWSAddress(ctx, input, plan)
	if err != nil {
		return nil, err
	}

	dialAuthority := authority
	if input.TargetAddr != "" {
		dialAuthority = input.TargetAddr
	}
	plan.useTLS = scheme == "wss"
	plan.dialAddr, plan.sni = resolveResendWSDialTarget(dialAuthority, plan.useTLS)
	plan.upgradeURL = resendWSUpgradeURL(scheme, authority, upgradePath, rawQuery)

	if err := populateResendWSFrame(input, plan); err != nil {
		return nil, err
	}
	return plan, nil
}

// resolveResendWSAddress recovers (scheme, authority, path, rawQuery)
// from the optional flow_id and merges in user-supplied overrides.
// Populates plan.upgradeHeaders + plan.extensionHeader as a side effect
// when flow_id is set.
func (s *Server) resolveResendWSAddress(ctx context.Context, input *resendWSInput, plan *resendWSPlan) (scheme, authority, upgradePath, rawQuery string, err error) {
	scheme = strings.ToLower(input.Scheme)
	upgradePath = input.Path
	rawQuery = input.RawQuery

	if input.FlowID != "" {
		stream, sendFlow, recvFlow, lerr := s.loadResendWSFlows(ctx, input.FlowID)
		if lerr != nil {
			return "", "", "", "", lerr
		}
		if !resendWSSupportedProtocols[stream.Protocol] {
			return "", "", "", "", fmt.Errorf("resend_ws: protocol %q not supported by this tool — use resend_http / resend_grpc / resend_raw for non-WebSocket flows", stream.Protocol)
		}
		scheme, authority, upgradePath, rawQuery = mergeResendWSURL(sendFlow.URL, scheme, authority, upgradePath, rawQuery)
		plan.upgradeHeaders = flowMapToKeyValues(sendFlow.Headers)
		if recvFlow != nil {
			plan.extensionHeader = firstFlowHeaderValue(recvFlow.Headers, "Sec-WebSocket-Extensions")
		}
	}

	if scheme == "" {
		scheme = "ws"
	}
	if authority == "" && input.TargetAddr != "" {
		authority = input.TargetAddr
	}
	if authority == "" {
		return "", "", "", "", errors.New("resend_ws: authority is empty (no recovered URL and no target_addr)")
	}
	if upgradePath == "" {
		upgradePath = "/"
	}
	return scheme, authority, upgradePath, rawQuery, nil
}

// mergeResendWSURL fills empty (scheme, authority, path, rawQuery)
// slots from a recovered URL, leaving non-empty user-supplied fields
// untouched. Defensive against a nil URL.
func mergeResendWSURL(u *url.URL, scheme, authority, upgradePath, rawQuery string) (string, string, string, string) {
	if u == nil {
		return scheme, authority, upgradePath, rawQuery
	}
	if scheme == "" {
		scheme = mapHTTPSchemeToWS(u.Scheme)
	}
	if authority == "" {
		authority = u.Host
	}
	if upgradePath == "" {
		upgradePath = u.Path
		if upgradePath == "" {
			upgradePath = "/"
		}
	}
	if rawQuery == "" {
		rawQuery = u.RawQuery
	}
	return scheme, authority, upgradePath, rawQuery
}

// populateResendWSFrame copies the frame fields from input into plan,
// handling encoding, payload caps, and the compressed-needs-flow-id
// invariant.
func populateResendWSFrame(input *resendWSInput, plan *resendWSPlan) error {
	plan.opcode = validResendWSOpcodes[strings.ToLower(input.Opcode)]
	plan.fin = true
	if input.Fin != nil {
		plan.fin = *input.Fin
	}
	if input.Masked != nil {
		plan.masked = *input.Masked
	}
	if input.Mask != "" {
		raw, _ := decodeBodyEncoded(input.Mask, "base64", "mask")
		copy(plan.mask[:], raw)
	}
	if input.CloseCode != nil {
		if *input.CloseCode < 0 || *input.CloseCode > 0xFFFF {
			return fmt.Errorf("close_code %d out of uint16 range", *input.CloseCode)
		}
		plan.closeCode = uint16(*input.CloseCode)
	}
	plan.closeReason = input.CloseReason

	if input.Payload != "" || input.PayloadSet {
		decoded, err := decodeBodyEncoded(input.Payload, input.BodyEncoding, "payload")
		if err != nil {
			return err
		}
		plan.payload = decoded
	}
	if len(plan.payload) > maxResendWSPayload {
		return fmt.Errorf("payload too large: %d > %d", len(plan.payload), maxResendWSPayload)
	}
	if input.Compressed != nil && *input.Compressed {
		if plan.extensionHeader == "" {
			return errors.New("compressed=true but no permessage-deflate extension recovered from flow_id")
		}
		plan.compressed = true
	}
	return nil
}

// mapHTTPSchemeToWS maps an HTTP-flavoured scheme back into the WS
// scheme used in URI form. https → wss, http → ws. Empty in, empty out.
func mapHTTPSchemeToWS(s string) string {
	switch strings.ToLower(s) {
	case "https", "wss":
		return "wss"
	case "http", "ws":
		return "ws"
	default:
		return ""
	}
}

// loadResendWSFlows fetches the Stream, the first send-direction Flow
// (the upgrade GET), and the first receive-direction Flow (the 101
// response — needed for Sec-WebSocket-Extensions). The receive Flow is
// allowed to be missing; only the send Flow is required.
func (s *Server) loadResendWSFlows(ctx context.Context, flowID string) (*flow.Stream, *flow.Flow, *flow.Flow, error) {
	if s.flowStore.store == nil {
		return nil, nil, nil, errors.New("resend_ws: flow store is not initialized")
	}
	stream, err := s.flowStore.store.GetStream(ctx, flowID)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_ws: get stream %s: %w", flowID, err)
	}
	sendFlows, err := s.flowStore.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_ws: get send flows %s: %w", flowID, err)
	}
	if len(sendFlows) == 0 {
		return nil, nil, nil, fmt.Errorf("resend_ws: stream %s has no send-direction flows", flowID)
	}
	recvFlows, err := s.flowStore.store.GetFlows(ctx, flowID, flow.FlowListOptions{Direction: "receive"})
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_ws: get receive flows %s: %w", flowID, err)
	}
	var recvFlow *flow.Flow
	if len(recvFlows) > 0 {
		recvFlow = recvFlows[0]
	}
	return stream, sendFlows[0], recvFlow, nil
}

// firstFlowHeaderValue returns the first value for name (case-insensitive)
// from a flow.Flow.Headers multimap. Empty when not present.
func firstFlowHeaderValue(headers map[string][]string, name string) string {
	for k, vs := range headers {
		if strings.EqualFold(k, name) && len(vs) > 0 {
			return vs[0]
		}
	}
	return ""
}

// resolveResendWSDialTarget produces the (host:port, sni) pair for the
// upstream connection. authority may be host:port or just host.
func resolveResendWSDialTarget(authority string, useTLS bool) (addr, sni string) {
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

// resendWSUpgradeURL builds the canonical *url.URL used for scope and
// safety checks. ws → http, wss → https mapping aligns with RFC 6455 §3
// where the WebSocket URI scheme is overlaid on top of the HTTP origin.
//
// Built directly from validated fields (no String → Parse round-trip)
// to avoid the CWE-918 footgun documented in resend_http review S-1.
func resendWSUpgradeURL(scheme, authority, path, rawQuery string) *url.URL {
	mapped := scheme
	switch strings.ToLower(scheme) {
	case "ws":
		mapped = "http"
	case "wss":
		mapped = "https"
	}
	return &url.URL{
		Scheme:   mapped,
		Host:     authority,
		Path:     path,
		RawQuery: rawQuery,
	}
}

// checkResendWSScope enforces TargetScope rules on both the canonical
// upgrade URL and (when target_addr redirects the dial) the override
// target. Both must pass; an override that bypasses scope is rejected
// even when the canonical authority is in-scope.
//
// Note: the dialAddr/upgradeURL.Host comparison can fire on the no-port
// recovered-flow path (e.g. canonical Host "example.com" vs dialAddr
// "example.com:80"). Both legs target the same logical host in that
// case, so the extra check is redundant but safe. The simpler rule is
// preferred over a port-normalizing comparison so the override path
// stays explicit when target_addr really does redirect the dial.
func (s *Server) checkResendWSScope(plan *resendWSPlan) error {
	if err := s.checkTargetScopeURL(plan.upgradeURL); err != nil {
		return err
	}
	overrideScheme := ""
	if plan.useTLS {
		overrideScheme = "https"
	}
	if plan.dialAddr != plan.upgradeURL.Host {
		if err := s.checkTargetScopeAddr(overrideScheme, plan.dialAddr); err != nil {
			return err
		}
	}
	return nil
}

// buildResendWSEnvelope constructs the Send envelope and the wire bytes
// the resend-side WS encoder will record. The wire bytes are pre-
// computed here (rather than left for the Layer's Send to render at
// write time) so RecordStep records meaningful Flow.RawBytes for both
// compressed and uncompressed sends. The encoder uses a throwaway
// deflateState so it does not corrupt the live Layer's LZ77 dictionary;
// for the synthetic resend (one frame, no prior dict) the produced wire
// bytes match what Layer.Send produces modulo the random per-frame mask
// (RoleClient regenerates the mask on Send per RFC 6455 §5.3).
//
// The returned WireEncoderRegistry is shared between PluginStepPost and
// RecordStep on the resend pipeline so MessageOnly mutations regenerate
// Raw consistently with what RecordStep records as the modified-variant
// bytes.
func (s *Server) buildResendWSEnvelope(plan *resendWSPlan) (*pipeline.WireEncoderRegistry, *envelope.Envelope, []byte, error) {
	msg := &envelope.WSMessage{
		Opcode:      plan.opcode,
		Fin:         plan.fin,
		Masked:      plan.masked,
		Mask:        plan.mask,
		Payload:     plan.payload,
		CloseCode:   plan.closeCode,
		CloseReason: plan.closeReason,
		Compressed:  plan.compressed,
	}

	encoder := ws.NewResendWireEncoder(plan.extensionHeader)
	tmpEnv := &envelope.Envelope{
		StreamID:  plan.streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			ConnID:       plan.connID,
			UpgradePath:  plan.upgradeURL.Path,
			UpgradeQuery: plan.upgradeURL.RawQuery,
		},
	}
	rawBytes, err := encoder(tmpEnv)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("resend_ws: pre-encode: %w", err)
	}

	encoders := pipeline.NewWireEncoderRegistry()
	encoders.Register(envelope.ProtocolWebSocket, encoder)

	return encoders, tmpEnv, rawBytes, nil
}

// buildResendWSPipeline constructs the resend Pipeline:
//
//	PluginStepPost → RecordStep
//
// PluginStepPre and InterceptStep are intentionally absent (RFC §9.3 D1
// resend bypass). HostScope and Safety are handled at the handler level
// before the envelope reaches the pipeline.
func (s *Server) buildResendWSPipeline(encoders *pipeline.WireEncoderRegistry) *pipeline.Pipeline {
	steps := []pipeline.Step{
		pipeline.NewPluginStepPost(pluginEngineForResend(s), encoders, slog.Default()),
		pipeline.NewRecordStep(s.flowStore.store, slog.Default(), pipeline.WithWireEncoderRegistry(encoders)),
	}
	return pipeline.New(steps...)
}

// dialResendWSUpstream dials addr (TLS-upgraded for wss). Returns a
// connection owned by the caller.
func dialResendWSUpstream(ctx context.Context, transport httputilpkg.TLSTransport, addr string, useTLS bool, sni string) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: defaultReplayTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", addr, err)
	}
	if useTLS {
		if transport == nil {
			_ = conn.Close()
			return nil, errors.New("resend_ws: TLS upstream requires a configured TLSTransport")
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

// performResendWSUpgrade drives the HTTP/1.1 Upgrade dance via the
// http1 Layer (no net/http per RFC-001 principle 6). Returns the
// post-101 reader/writer/closer triple plus the server-negotiated
// Sec-WebSocket-Extensions header value.
//
// Caller owns conn lifecycle: this helper does NOT close conn on error;
// the handler's defer chain handles cleanup.
func performResendWSUpgrade(ctx context.Context, conn net.Conn, plan *resendWSPlan) (io.Reader, io.Writer, io.Closer, string, error) {
	wsKey := generateResendWSKey()
	headers := buildResendWSUpgradeHeaders(plan.upgradeHeaders, plan.upgradeURL.Host, wsKey, plan.compressed, plan.extensionHeader)
	upgradeEnv := http1.BuildSendEnvelope("GET", plan.upgradeURL.Scheme, plan.upgradeURL.Host, plan.upgradeURL.Path, plan.upgradeURL.RawQuery, headers, nil)

	// Receive direction = upstream-client side: writes requests on Send,
	// parses responses on Next. Same pattern as resend_http L410.
	l := http1.New(conn, "", envelope.Receive)
	ch := <-l.Channels()

	if err := ch.Send(ctx, upgradeEnv); err != nil {
		return nil, nil, nil, "", fmt.Errorf("upgrade send: %w", err)
	}
	respEnv, err := ch.Next(ctx)
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("upgrade response: %w", err)
	}
	respMsg, ok := respEnv.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, nil, nil, "", fmt.Errorf("upgrade response: unexpected message type %T", respEnv.Message)
	}
	if respMsg.Status != 101 {
		return nil, nil, nil, "", fmt.Errorf("upstream upgrade returned status %d, want 101", respMsg.Status)
	}

	extension := lookupKVHeader(respMsg.Headers, "Sec-WebSocket-Extensions")

	reader, writer, closer, err := l.DetachStream()
	if err != nil {
		return nil, nil, nil, "", fmt.Errorf("detach stream: %w", err)
	}
	return reader, writer, closer, extension, nil
}

// generateResendWSKey produces a fresh 16-byte Sec-WebSocket-Key value
// per RFC 6455 §4.1 and base64-encodes it for the request header.
func generateResendWSKey() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is fatal; no safe fallback.
		panic("crypto/rand: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b[:])
}

// buildResendWSUpgradeHeaders merges recovered request headers with the
// minimum required WebSocket handshake set. RFC 6455-mandated values
// (Upgrade, Connection, Sec-WebSocket-Version, Sec-WebSocket-Key, Host)
// always override inherited values to ensure a valid handshake.
//
// When compressed=true and the recovered extension header is non-empty,
// it is forwarded as Sec-WebSocket-Extensions so the upstream re-
// negotiates the same parameters. When compressed=false, any inherited
// Sec-WebSocket-Extensions is dropped to prevent unintended deflate.
func buildResendWSUpgradeHeaders(recovered []envelope.KeyValue, host, wsKey string, compressed bool, extensionHeader string) []envelope.KeyValue {
	dropped := map[string]bool{
		"upgrade":                  true,
		"connection":               true,
		"sec-websocket-key":        true,
		"sec-websocket-version":    true,
		"sec-websocket-accept":     true,
		"sec-websocket-extensions": true,
		"host":                     true,
	}
	out := make([]envelope.KeyValue, 0, len(recovered)+6)
	out = append(out, envelope.KeyValue{Name: "Host", Value: host})
	out = append(out, envelope.KeyValue{Name: "Upgrade", Value: "websocket"})
	out = append(out, envelope.KeyValue{Name: "Connection", Value: "Upgrade"})
	out = append(out, envelope.KeyValue{Name: "Sec-WebSocket-Version", Value: "13"})
	out = append(out, envelope.KeyValue{Name: "Sec-WebSocket-Key", Value: wsKey})
	if compressed && extensionHeader != "" {
		out = append(out, envelope.KeyValue{Name: "Sec-WebSocket-Extensions", Value: extensionHeader})
	}
	for _, kv := range recovered {
		if dropped[strings.ToLower(kv.Name)] {
			continue
		}
		out = append(out, kv)
	}
	return out
}

// lookupKVHeader returns the first value matching name (case-insensitive)
// from an ordered KeyValue slice.
func lookupKVHeader(headers []envelope.KeyValue, name string) string {
	for _, kv := range headers {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value
		}
	}
	return ""
}

// runResendWS dials, performs the upgrade dance, switches to the WS
// layer, runs the Send envelope through the resend pipeline, writes the
// frame, and reads frames until the first non-control frame OR a Close
// OR ctx times out. Auto-Pong replies are emitted for incoming Ping
// frames per RFC 6455 §5.5.3 (control bypass — not pipelined). Pong
// frames are recorded but do not terminate the loop.
//
// Returns the terminating envelope (the result frame). nil is returned
// when the pipeline drops the send envelope before it reaches the wire.
func (s *Server) runResendWS(ctx context.Context, plan *resendWSPlan, sendEnv *envelope.Envelope, p *pipeline.Pipeline) (*envelope.Envelope, error) {
	if p == nil {
		return nil, errors.New("resend pipeline is nil")
	}

	postSendEnv, short, err := runResendWSPreSend(ctx, sendEnv, p)
	if err != nil {
		return nil, err
	}
	if short != nil {
		return short, nil
	}

	conn, err := dialResendWSUpstream(ctx, s.connector.tlsTransport, plan.dialAddr, plan.useTLS, plan.sni)
	if err != nil {
		return nil, err
	}

	reader, writer, _, negotiatedExt, err := performResendWSUpgrade(ctx, conn, plan)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	useExt := plan.extensionHeader
	if negotiatedExt != "" {
		useExt = negotiatedExt
	}
	l := ws.New(reader, writer, conn, plan.streamID, ws.RoleClient, buildResendWSLayerOpts(plan, useExt)...)
	defer l.Close()
	ch := <-l.Channels()

	if err := ch.Send(ctx, postSendEnv); err != nil {
		return nil, fmt.Errorf("upstream send: %w", err)
	}

	return runResendWSReceiveLoop(ctx, plan, ch, postSendEnv.StreamID, p)
}

// runResendWSPreSend runs the synthetic Send envelope through the
// resend Pipeline. Returns (postEnv, nil, nil) on the normal path that
// proceeds to dial; (nil, customRespEnv, nil) when the pipeline
// short-circuits via Respond; (nil, nil, err) on Drop.
func runResendWSPreSend(ctx context.Context, sendEnv *envelope.Envelope, p *pipeline.Pipeline) (*envelope.Envelope, *envelope.Envelope, error) {
	postSendEnv, action, custom := p.Run(ctx, sendEnv)
	switch action {
	case pipeline.Drop:
		return nil, nil, errors.New("send envelope dropped by pipeline")
	case pipeline.Respond:
		if custom == nil {
			return nil, nil, errors.New("pipeline returned Respond with nil response envelope")
		}
		custom.StreamID = postSendEnv.StreamID
		custom.Sequence = 1
		_, _, _ = p.Run(ctx, custom)
		return nil, custom, nil
	}
	return postSendEnv, nil, nil
}

// buildResendWSLayerOpts constructs the WS Layer Options for the
// upstream-facing Channel. Always sets the EnvelopeContext template;
// adds deflate when a non-empty extension header is supplied.
func buildResendWSLayerOpts(plan *resendWSPlan, extensionHeader string) []ws.Option {
	opts := []ws.Option{
		ws.WithEnvelopeContext(envelope.EnvelopeContext{
			ConnID:       plan.connID,
			UpgradePath:  plan.upgradeURL.Path,
			UpgradeQuery: plan.upgradeURL.RawQuery,
		}),
	}
	if extensionHeader != "" {
		opts = append(opts, ws.WithDeflateFromExtensionHeader(extensionHeader))
	}
	return opts
}

// runResendWSReceiveLoop reads frames from ch, runs each through the
// resend Pipeline, auto-Pongs any incoming Pings (control-frame bypass),
// continues on incoming Pongs, and returns the first non-control frame
// (or Close) as the terminating envelope.
func runResendWSReceiveLoop(ctx context.Context, plan *resendWSPlan, ch interface {
	Next(context.Context) (*envelope.Envelope, error)
	Send(context.Context, *envelope.Envelope) error
}, streamID string, p *pipeline.Pipeline) (*envelope.Envelope, error) {
	seq := 1
	for {
		respEnv, err := ch.Next(ctx)
		if err != nil {
			return nil, fmt.Errorf("upstream receive: %w", err)
		}
		respEnv.StreamID = streamID
		respEnv.Sequence = seq
		seq++

		// Drop / Respond on the receive-side pipeline are intentionally
		// ignored on resend: the tool surfaces what the upstream
		// actually sent so a diagnostic caller sees end-to-end
		// behaviour even when a plugin would normally suppress or
		// rewrite the frame on the live data path.
		respEnv, _, _ = p.Run(ctx, respEnv)

		respMsg, ok := respEnv.Message.(*envelope.WSMessage)
		if !ok {
			return respEnv, nil
		}
		switch respMsg.Opcode {
		case envelope.WSPing:
			// RFC 6455 §5.5.3: Pong with identical payload. Bypass the
			// pipeline (reflexive control, not user-driven send).
			pongEnv := buildResendWSPongEnvelope(plan, streamID, seq, respMsg.Payload)
			seq++
			if err := ch.Send(ctx, pongEnv); err != nil {
				return nil, fmt.Errorf("auto-pong send: %w", err)
			}
			continue
		case envelope.WSPong:
			continue
		default:
			return respEnv, nil
		}
	}
}

// buildResendWSPongEnvelope constructs the synthetic Pong envelope sent
// in reply to an incoming Ping. Direction=Send, RoleClient masks at
// write time; the Layer regenerates per-frame mask per RFC 6455 §5.3.
func buildResendWSPongEnvelope(plan *resendWSPlan, streamID string, sequence int, payload []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.NewString(),
		Sequence:  sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message: &envelope.WSMessage{
			Opcode:  envelope.WSPong,
			Fin:     true,
			Payload: payload,
		},
		Context: envelope.EnvelopeContext{
			ConnID:       plan.connID,
			UpgradePath:  plan.upgradeURL.Path,
			UpgradeQuery: plan.upgradeURL.RawQuery,
		},
	}
}

// applyResendWSTag persists the user-supplied tag on the new Stream row
// after the pipeline-driven RecordStep has created it.
func (s *Server) applyResendWSTag(ctx context.Context, streamID, tag string) {
	update := flow.StreamUpdate{Tags: map[string]string{"tag": tag}}
	if err := s.flowStore.store.UpdateStream(ctx, streamID, update); err != nil {
		slog.WarnContext(ctx, "resend_ws: tag update failed",
			"stream_id", streamID,
			"tag", tag,
			"error", err,
		)
	}
}

// formatResendWSResult turns the response envelope into the wire-shape
// MCP result. SafetyFilter output masking is applied to the payload
// before it leaves the proxy boundary; the unmasked variant is on disk
// via RecordStep.
func (s *Server) formatResendWSResult(streamID string, respEnv *envelope.Envelope, tag string, duration time.Duration) *resendWSResult {
	result := &resendWSResult{
		StreamID:   streamID,
		DurationMs: duration.Milliseconds(),
		Tag:        tag,
	}
	if respEnv == nil {
		result.Opcode = "text"
		result.PayloadEncoding = "text"
		return result
	}
	msg, ok := respEnv.Message.(*envelope.WSMessage)
	if !ok {
		result.Opcode = "text"
		result.PayloadEncoding = "text"
		return result
	}
	result.Opcode = wsOpcodeName(msg.Opcode)
	result.Fin = msg.Fin
	result.Compressed = msg.Compressed
	result.CloseCode = msg.CloseCode
	result.CloseReason = msg.CloseReason
	maskedPayload := s.filterOutputBody(msg.Payload)
	result.Payload, result.PayloadEncoding = encodeResendWSPayload(maskedPayload, msg.Opcode)
	return result
}

// encodeResendWSPayload returns the payload string and its declared
// encoding. For Text and Close opcodes the payload is reported as text
// when it round-trips through utf8.Valid; otherwise base64. Empty
// payloads always report "text" so the schema stays consistent.
func encodeResendWSPayload(payload []byte, opcode envelope.WSOpcode) (string, string) {
	if len(payload) == 0 {
		return "", "text"
	}
	if (opcode == envelope.WSText || opcode == envelope.WSClose) && utf8.Valid(payload) {
		return string(payload), "text"
	}
	return base64.StdEncoding.EncodeToString(payload), "base64"
}

// wsOpcodeName turns a WSOpcode into its schema string. Unknown opcodes
// (which the parser would surface as Anomalies) report a hex form so AI
// agents see something meaningful.
func wsOpcodeName(o envelope.WSOpcode) string {
	switch o {
	case envelope.WSText:
		return "text"
	case envelope.WSBinary:
		return "binary"
	case envelope.WSClose:
		return "close"
	case envelope.WSPing:
		return "ping"
	case envelope.WSPong:
		return "pong"
	case envelope.WSContinuation:
		return "continuation"
	default:
		return fmt.Sprintf("0x%X", uint8(o))
	}
}
