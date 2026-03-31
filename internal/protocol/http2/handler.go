// Package http2 implements an HTTP/2 protocol handler for the yorishiro-proxy.
// It supports both h2 (TLS via ALPN) and h2c (cleartext) HTTP/2 connections.
// Each HTTP/2 stream is recorded as an individual unary flow.
package http2

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/http/httptrace"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// http2Preface is the HTTP/2 connection preface sent by clients.
// Only the first 16 bytes are needed for detection since the listener peeks 16 bytes.
var http2Preface = []byte("PRI * HTTP/2.0\r\n")

// Handler processes HTTP/2 connections (h2c cleartext).
// For h2 (TLS), the HTTP handler's CONNECT flow calls HandleH2 after ALPN negotiation.
//
// NOTE (S-2): For h2 connections via CONNECT, the HTTP/1.x handler's
// handleCONNECT already performs target scope enforcement before the tunnel
// is established. For h2c (cleartext HTTP/2) connections, target scope
// enforcement is applied per-stream in handleStream. This ensures all
// HTTP/2 traffic paths are covered by scope checks.
type Handler struct {
	proxy.HandlerBase

	// tlsMu protects the handler's upstream transport and connection-pool
	// configuration from concurrent access. It guards reads and writes of
	// connPool (including connPool.Get and connPool.TLSTransport), h2Transport,
	// and the legacy Transport while requests are in flight.
	tlsMu sync.RWMutex

	// connPool manages upstream connections for the unary HTTP/2 path using
	// ConnPool + ALPN routing instead of gohttp.Transport.
	connPool *httputil.ConnPool

	// h2Transport is the custom HTTP/2 frame-engine transport used for raw mode
	// forwarding and ConnPool-based unary upstream routing.
	h2Transport *Transport

	// grpcHandler processes gRPC flow recording when Content-Type: application/grpc
	// is detected. If nil, gRPC streams are recorded as plain HTTP/2.
	grpcHandler *protogrpc.Handler

	// pluginEngine dispatches Starlark plugin hooks during HTTP/2 stream processing.
	// If nil, no plugin hooks are invoked.
	pluginEngine *plugin.Engine

	// detector performs technology stack detection on HTTP responses.
	// If nil, fingerprinting is skipped.
	detector *fingerprint.Detector

	// transformPipeline applies auto-transform rules to request and response
	// bodies. If nil, no auto-transform rules are applied.
	transformPipeline *rules.Pipeline
}

// NewHandler creates a new HTTP/2 handler with flow recording.
func NewHandler(store flow.FlowWriter, logger *slog.Logger) *Handler {
	return &Handler{
		HandlerBase: proxy.HandlerBase{
			Store:  store,
			Logger: logger,
			Transport: &gohttp.Transport{
				ForceAttemptHTTP2: true,
			},
		},
		connPool: &httputil.ConnPool{
			// Leave TLSTransport nil so that ConnPool's effectiveTLSTransport()
			// provides the default (InsecureSkipVerify=true for proxy use-case).
			// Production code calls SetTLSTransport or SetInsecureSkipVerify
			// during initialization to configure the desired behavior.
			AllowH2:        true,
			DialViaProxy:   proxy.DialViaUpstreamProxy,
			RedactProxyURL: proxy.RedactProxyURL,
		},
		h2Transport: &Transport{Logger: logger},
	}
}

// SetTLSTransport configures the TLS transport used for upstream TLS connections.
// When set, the handler uses this transport (e.g. uTLS with browser fingerprinting)
// instead of the standard crypto/tls library.
//
// The ConnPool's TLSTransport is updated directly — it supports full ALPN
// negotiation (including h2) and routes to h2Transport or H1Transport based
// on the negotiated protocol.
//
// If t is nil, the default crypto/tls behavior is restored.
//
// This method is safe to call concurrently with in-flight requests.
func (h *Handler) SetTLSTransport(t httputil.TLSTransport) {
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()

	h.connPool.TLSTransport = t
}

// SetInsecureSkipVerify overrides HandlerBase.SetInsecureSkipVerify to also
// update the ConnPool's default TLSTransport for the unary HTTP/2 path.
// When skip is true, the ConnPool's StandardTransport is configured with
// InsecureSkipVerify=true so that upstream certificate verification is disabled.
func (h *Handler) SetInsecureSkipVerify(skip bool) {
	h.HandlerBase.SetInsecureSkipVerify(skip)
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()
	if st, ok := h.connPool.TLSTransport.(*httputil.StandardTransport); ok {
		st.InsecureSkipVerify = skip
	} else if h.connPool.TLSTransport == nil {
		// When no TLSTransport is explicitly configured, create a
		// StandardTransport with the requested setting so that the
		// caller's intent is preserved instead of relying on the
		// ConnPool default (which is InsecureSkipVerify=true).
		h.connPool.TLSTransport = &httputil.StandardTransport{InsecureSkipVerify: skip}
	}
}

// SetUpstreamProxy overrides HandlerBase.SetUpstreamProxy to also update the
// ConnPool's upstream proxy for the unary HTTP/2 path.
func (h *Handler) SetUpstreamProxy(proxyURL *url.URL) {
	h.HandlerBase.SetUpstreamProxy(proxyURL)
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()
	h.connPool.UpstreamProxy = proxyURL
	// Ensure ConnPool has the proxy dial/redact functions when a proxy is set.
	// These are also set in NewHandler, but re-affirm here for safety in case
	// the ConnPool was replaced after construction.
	if proxyURL != nil {
		h.connPool.DialViaProxy = proxy.DialViaUpstreamProxy
		h.connPool.RedactProxyURL = proxy.RedactProxyURL
	}
}

// SetH2Transport sets the custom HTTP/2 frame-engine transport used for raw
// mode intercept forwarding. When set, raw mode release/modify_and_forward
// actions can send edited frame bytes directly to the upstream server.
func (h *Handler) SetH2Transport(t *Transport) {
	h.h2Transport = t
}

// H2Transport returns the handler's custom HTTP/2 transport, or nil.
func (h *Handler) H2Transport() *Transport {
	return h.h2Transport
}

// SetGRPCHandler sets the gRPC handler used for gRPC-specific flow recording.
// When set, streams with Content-Type: application/grpc are recorded as gRPC
// sessions with parsed service/method metadata instead of plain HTTP/2.
func (h *Handler) SetGRPCHandler(gh *protogrpc.Handler) {
	h.grpcHandler = gh
}

// SetPluginEngine sets the plugin engine used to dispatch hook events
// during HTTP/2 stream processing.
func (h *Handler) SetPluginEngine(engine *plugin.Engine) {
	h.pluginEngine = engine
}

// PluginEngine returns the handler's current plugin engine, or nil.
func (h *Handler) PluginEngine() *plugin.Engine {
	return h.pluginEngine
}

// SetDetector sets the fingerprint detector for technology stack detection on
// HTTP/2 responses. When set, response headers and body are analyzed during
// flow recording and the results are stored as flow tags.
func (h *Handler) SetDetector(d *fingerprint.Detector) {
	h.detector = d
}

// Detector returns the handler's current fingerprint detector, or nil.
func (h *Handler) Detector() *fingerprint.Detector {
	return h.detector
}

// SetTransformPipeline sets the auto-transform rule pipeline used to
// modify request and response bodies passing through the HTTP/2 handler.
func (h *Handler) SetTransformPipeline(pipeline *rules.Pipeline) {
	h.transformPipeline = pipeline
}

// TransformPipeline returns the handler's current transform pipeline, or nil.
func (h *Handler) TransformPipeline() *rules.Pipeline {
	return h.transformPipeline
}

// Name returns the protocol name for h2c (cleartext HTTP/2).
func (h *Handler) Name() string {
	return "HTTP/2 (h2c)"
}

// Detect checks if the peeked bytes match the HTTP/2 connection preface.
// This detects h2c (cleartext HTTP/2) connections.
func (h *Handler) Detect(peek []byte) bool {
	return len(peek) >= len(http2Preface) && bytes.Equal(peek[:len(http2Preface)], http2Preface)
}

// Handle processes an h2c (cleartext HTTP/2) connection.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	logger := h.connLogger(ctx)
	logger.Info("HTTP/2 h2c connection")

	return h.serveHTTP2(ctx, conn, "", tlsMetadata{})
}

// tlsMetadata holds TLS connection information extracted from the handshake.
type tlsMetadata struct {
	Version     string
	CipherSuite string
	ALPN        string
}

// HandleH2 processes an h2 (TLS) HTTP/2 connection after ALPN negotiation.
// This is called from the HTTP handler's CONNECT flow when the client
// negotiates "h2" during the TLS handshake. It satisfies the
// protohttp.H2Handler interface.
func (h *Handler) HandleH2(ctx context.Context, tlsConn *tls.Conn, connectAuthority string, tlsVersion, tlsCipher, tlsALPN string) error {
	logger := h.connLogger(ctx)
	logger.Info("HTTP/2 h2 connection", "authority", connectAuthority)

	tlsMeta := tlsMetadata{
		Version:     tlsVersion,
		CipherSuite: tlsCipher,
		ALPN:        tlsALPN,
	}
	return h.serveHTTP2(ctx, tlsConn, connectAuthority, tlsMeta)
}

// serveHTTP2 runs the HTTP/2 server on the given connection, proxying each
// stream to the upstream server and recording sessions.
//
// It uses the custom frame engine (clientConn) to handle HTTP/2 frames
// directly.
func (h *Handler) serveHTTP2(ctx context.Context, conn net.Conn, connectAuthority string, tlsMeta tlsMetadata) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	streamHandler := func(ctx context.Context, w h2ResponseWriter, req *h2Request) {
		h.handleStream(ctx, w, req, connID, clientAddr, connectAuthority, tlsMeta, logger)
	}

	// Use a context-cancellation watcher to close the connection on shutdown.
	// A done channel ensures the goroutine exits when serveHTTP2 returns
	// normally, preventing a goroutine leak. (F-3)
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.SetReadDeadline(time.Now())
		case <-done:
		}
	}()

	cc := newClientConn(ctx, conn, logger, streamHandler)
	err := cc.serve()

	logger.Debug("HTTP/2 connection closed")
	return err
}

// streamContext holds the state for a single HTTP/2 stream being proxied.
type streamContext struct {
	ctx              context.Context
	w                h2ResponseWriter
	h2req            *h2Request
	req              *gohttp.Request // derived from h2req for subsystem compatibility
	connID           string
	clientAddr       string
	connectAuthority string
	tlsMeta          tlsMetadata
	logger           *slog.Logger
	start            time.Time

	reqBody      []byte
	reqTruncated bool
	reqURL       *url.URL
	flowScheme   string // "https" for h2 (TLS), "http" for h2c (plaintext)
	connInfo     *flow.ConnectionInfo
	srp          sendRecordParams

	// reqRawFrames holds the raw HTTP/2 frame bytes received from the client
	// for this stream. Extracted from the context set by clientConn.dispatchStream.
	reqRawFrames [][]byte
	// respRawFrames holds the raw HTTP/2 frame bytes from the upstream response.
	respRawFrames [][]byte

	// interceptRawAction holds the intercept action when raw mode is active.
	// Non-nil indicates raw forwarding should be used instead of standard
	// http.Transport.RoundTrip. Set by handleRequestIntercept.
	interceptRawAction *intercept.InterceptAction

	// Plugin state shared across hooks for this stream.
	pluginConnInfo *plugin.ConnInfo
	txCtx          map[string]any
}

// handleStream proxies a single HTTP/2 stream to the upstream server
// and records the flow.
func (h *Handler) handleStream(
	ctx context.Context,
	w h2ResponseWriter,
	h2req *h2Request,
	connID, clientAddr, connectAuthority string,
	tlsMeta tlsMetadata,
	logger *slog.Logger,
) {
	sc := h.initStreamContext(ctx, w, h2req, connID, clientAddr, connectAuthority, tlsMeta, logger)
	if sc == nil {
		return
	}

	if h.tryHandleGRPCStream(sc) {
		return
	}

	h.readAndTruncateBody(sc)
	h.resolveSchemeAndHost(sc)
	h.buildStreamRecordParams(sc)

	if h.checkTargetScope(sc) {
		return
	}

	if h.checkRateLimit(sc) {
		return
	}

	// Safety filter enforcement (after target scope + rate limit, before plugin hooks).
	// NOTE (L-1): The safety filter is intentionally placed after the rate limiter.
	// The filter requires the request body (read in readAndTruncateBody above).
	// Placing it before the rate limiter would allow rate-limited clients to
	// force body reads and safety checks on every request, increasing resource
	// consumption under abuse.
	if h.checkSafetyFilter(sc) {
		return
	}

	if h.runClientPluginHook(sc) {
		return
	}

	h.refreshRecordParams(sc)

	outReq, ok := h.buildOutboundRequest(sc)
	if !ok {
		return
	}

	snap := snapshotRequest(outReq.Header, sc.srp.reqBody)

	outReq, ok = h.handleRequestIntercept(sc, outReq, &snap)
	if !ok {
		return
	}

	// Raw mode forwarding: bypass L7 transforms, plugins, and standard
	// transport. Send edited raw frames directly to the upstream.
	if sc.interceptRawAction != nil {
		h.handleRawForward(sc, &snap)
		return
	}

	h.applyRequestTransform(sc, outReq)

	outReq = h.runServerPluginHook(sc, outReq)

	h.forwardAndRecord(sc, outReq, &snap)
}

// initStreamContext creates a streamContext from an h2Request, converting to
// gohttp.Request for subsystem compatibility. Returns nil if conversion fails.
func (h *Handler) initStreamContext(
	ctx context.Context,
	w h2ResponseWriter,
	h2req *h2Request,
	connID, clientAddr, connectAuthority string,
	tlsMeta tlsMetadata,
	logger *slog.Logger,
) *streamContext {
	goReq, err := h2RequestToGoHTTP(ctx, h2req)
	if err != nil {
		logger.Error("HTTP/2 failed to convert h2Request to gohttp.Request", "error", err)
		w.WriteHeaders(gohttp.StatusBadRequest, nil)
		return nil
	}

	return &streamContext{
		ctx:              ctx,
		w:                w,
		h2req:            h2req,
		req:              goReq,
		connID:           connID,
		clientAddr:       clientAddr,
		connectAuthority: connectAuthority,
		tlsMeta:          tlsMeta,
		logger:           logger,
		start:            time.Now(),
		reqRawFrames:     rawFramesFromContext(ctx),
	}
}

// forwardAndRecord performs upstream forwarding, response processing, output
// filtering, and flow recording. Extracted from handleStream to reduce
// cyclomatic complexity.
func (h *Handler) forwardAndRecord(sc *streamContext, outReq *gohttp.Request, snap *requestSnapshot) {
	isGRPC := h.grpcHandler != nil && isGRPCContentType(sc.req.Header.Get("Content-Type"))

	var sendResult *sendRecordResult
	if !isGRPC {
		sendResult = h.recordSendWithVariant(sc.ctx, sc.srp, snap, sc.logger)
	}

	fwd, ok := h.forwardUpstream(sc, outReq, sendResult)
	if !ok {
		return
	}

	fwd.resp.Header, fwd.respBody = h.applyResponseTransform(fwd.resp, fwd.respBody)

	respSnap := snapshotResponse(fwd.resp.StatusCode, fwd.resp.Header, fwd.respBody)

	resp, fullRespBody, ok := h.handleResponseIntercept(sc, fwd.resp, fwd.respBody)
	if !ok {
		return
	}

	resp, fullRespBody = h.runResponsePluginHooks(sc, resp, fullRespBody)

	// Save unmasked body and trailers for recording before output filter
	// masks them. Deep copy to guard against future FilterOutput
	// implementations that may modify the underlying data in place (S-2).
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)
	rawTrailers := cloneHeaders(resp.Trailer)

	// Output filter: mask sensitive data in response body, headers, and
	// trailers before sending to client. Raw (unmasked) data is preserved
	// in Flow Store. Trailers (e.g. grpc-message) may contain PII.
	fullRespBody, resp.Header = h.ApplyOutputFilter(fullRespBody, resp.Header, sc.logger)
	if len(resp.Trailer) > 0 {
		resp.Trailer = h.ApplyOutputFilterHeaders(resp.Trailer, sc.logger)
	}

	writeResponseToClient(sc, resp, fullRespBody)

	duration := time.Since(sc.start)
	tlsCertSubject := extractTLSCertSubject(resp)

	h.recordStreamResponse(sc, isGRPC, sendResult, resp, rawRespBody, rawTrailers, fwd.serverAddr, duration, tlsCertSubject, &respSnap, fwd.sendMs, fwd.waitMs, fwd.receiveMs, fwd.respRawFrames)

	logProtocol := "http/2"
	if isGRPC {
		logProtocol = "grpc"
	}
	sc.logger.Info(logProtocol+" request",
		"method", sc.req.Method,
		"url", sc.reqURL.String(),
		"status", resp.StatusCode,
		"duration_ms", duration.Milliseconds())
}

// readAndTruncateBody reads the full request body and truncates for recording.
func (h *Handler) readAndTruncateBody(sc *streamContext) {
	if sc.req.Body != nil {
		fullBody, err := io.ReadAll(sc.req.Body)
		if err != nil {
			sc.logger.Warn("HTTP/2 failed to read request body", "error", err)
		}
		sc.req.Body.Close()
		sc.reqBody = fullBody
		sc.req.Body = io.NopCloser(bytes.NewReader(fullBody))
	}
	sc.reqTruncated = len(sc.reqBody) > int(config.MaxBodySize)
}

// resolveSchemeAndHost determines the scheme and host for the upstream request.
// When a TCP forwarding target is present in the context, it overrides the host
// so that the request is sent to the correct upstream server rather than
// the localhost address that the client connected to via TCP forwarding.
func (h *Handler) resolveSchemeAndHost(sc *streamContext) {
	scheme := "http"
	if sc.connectAuthority != "" {
		scheme = "https"
	}
	sc.flowScheme = scheme
	host := sc.req.Host
	if host == "" && sc.connectAuthority != "" {
		host = sc.connectAuthority
	}
	if sc.req.URL.Host == "" {
		sc.req.URL.Host = host
	}
	if sc.req.URL.Scheme == "" || sc.connectAuthority != "" {
		sc.req.URL.Scheme = scheme
	}
	// TCP forwarding: override host with the actual upstream target.
	// When a forwarding target is set, the client connected to a local port
	// (e.g. localhost:50051) and the real upstream is in the context.
	if target, ok := proxy.ForwardTargetFromContext(sc.ctx); ok {
		sc.req.URL.Host = target
		sc.req.Host = target
		if sc.req.URL.Scheme == "" {
			sc.req.URL.Scheme = scheme
		}
	}
	sc.reqURL = cloneURL(sc.req.URL)
}

// buildStreamRecordParams builds the initial send record params and connection info.
func (h *Handler) buildStreamRecordParams(sc *streamContext) {
	sc.connInfo = &flow.ConnectionInfo{
		ClientAddr: sc.clientAddr,
		TLSVersion: sc.tlsMeta.Version,
		TLSCipher:  sc.tlsMeta.CipherSuite,
		TLSALPN:    sc.tlsMeta.ALPN,
	}

	recordBody := sc.reqBody
	if sc.reqTruncated {
		recordBody = sc.reqBody[:int(config.MaxBodySize)]
	}

	sc.srp = sendRecordParams{
		connID:       sc.connID,
		clientAddr:   sc.clientAddr,
		scheme:       sc.flowScheme,
		start:        sc.start,
		connInfo:     sc.connInfo,
		req:          sc.req,
		reqURL:       sc.reqURL,
		reqBody:      recordBody,
		reqTruncated: sc.reqTruncated,
		rawFrames:    sc.reqRawFrames,
	}
}

// checkTargetScope enforces target scope rules. Returns true if the request was blocked.
func (h *Handler) checkTargetScope(sc *streamContext) bool {
	if h.TargetScope == nil || !h.TargetScope.HasRules() {
		return false
	}
	allowed, reason := h.TargetScope.CheckURL(sc.req.URL)
	if allowed {
		return false
	}
	writeScopeBlockResponse(sc.w, sc.req.URL.Hostname(), reason)
	sc.logger.Info("HTTP/2 request blocked by target scope",
		"host", sc.req.URL.Host, "reason", reason)
	h.recordBlocked(sc.ctx, sc.srp, "target_scope", nil, nil, sc.logger)
	return true
}

// checkSafetyFilter enforces safety filter rules. Returns true if the request was blocked.
func (h *Handler) checkSafetyFilter(sc *streamContext) bool {
	violation := h.CheckSafetyFilter(sc.reqBody, sc.req.URL.String(), sc.req.Header)
	if violation == nil {
		return false
	}

	action := h.SafetyFilterAction(violation)
	if action != safety.ActionBlock {
		// log_only: log the violation but continue processing.
		sc.logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", proxy.TruncateForLog(violation.MatchedOn, 256))
		return false
	}

	writeSafetyFilterResponse(sc.w, violation)
	sc.logger.Info("HTTP/2 request blocked by safety filter",
		"rule_id", violation.RuleID, "rule_name", violation.RuleName,
		"target", violation.Target.String(), "matched_on", proxy.TruncateForLog(violation.MatchedOn, 256))
	h.recordBlocked(sc.ctx, sc.srp, "safety_filter", violation, nil, sc.logger)
	return true
}

// writeSafetyFilterResponse writes a 403 Forbidden response for safety filter violations.
func writeSafetyFilterResponse(w h2ResponseWriter, violation *safety.InputViolation) {
	body := proxy.BuildSafetyFilterResponseBody(violation)
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-blocked-by", Value: "yorishiro-proxy"},
		{Name: "x-block-reason", Value: "safety_filter"},
		{Name: "content-length", Value: fmt.Sprintf("%d", len(body))},
	}
	if err := w.WriteHeaders(gohttp.StatusForbidden, headers); err != nil {
		slog.Debug("failed to write safety filter response headers", "error", err)
		return
	}
	if err := w.WriteData(body); err != nil {
		slog.Debug("failed to write safety filter response body", "error", err)
	}
}

// checkRateLimit enforces rate limits. Returns true if the request was blocked.
func (h *Handler) checkRateLimit(sc *streamContext) bool {
	if h.RateLimiter == nil || !h.RateLimiter.HasLimits() {
		return false
	}
	denial := h.RateLimiter.Check(sc.req.URL.Hostname())
	if denial == nil {
		return false
	}
	writeRateLimitResponse(sc.w)
	sc.logger.Info("HTTP/2 request blocked by rate limit",
		"host", sc.req.URL.Host)
	h.recordBlocked(sc.ctx, sc.srp, "rate_limit", nil, denial.Tags(), sc.logger)
	return true
}

// writeRateLimitResponse writes a 429 Too Many Requests response for rate limiting.
func writeRateLimitResponse(w h2ResponseWriter) {
	body := `{"error":"rate limit exceeded","blocked_by":"rate_limit"}`
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "x-blocked-by", Value: "yorishiro-proxy"},
		{Name: "x-block-reason", Value: "rate_limit"},
		{Name: "retry-after", Value: "1"},
		{Name: "content-length", Value: fmt.Sprintf("%d", len(body))},
	}
	if err := w.WriteHeaders(gohttp.StatusTooManyRequests, headers); err != nil {
		slog.Debug("failed to write rate limit response headers", "error", err)
		return
	}
	if err := w.WriteData([]byte(body)); err != nil {
		slog.Debug("failed to write rate limit response body", "error", err)
	}
}

// writeScopeBlockResponse writes a 403 Forbidden response for scope violations.
func writeScopeBlockResponse(w h2ResponseWriter, target, reason string) {
	body := fmt.Sprintf(`{"error":"blocked by target scope","target":%q,"reason":%q}`,
		target, reason)
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "application/json"},
		{Name: "content-length", Value: fmt.Sprintf("%d", len(body))},
	}
	if err := w.WriteHeaders(gohttp.StatusForbidden, headers); err != nil {
		slog.Debug("failed to write scope block response headers", "error", err)
		return
	}
	if err := w.WriteData([]byte(body)); err != nil {
		slog.Debug("failed to write scope block response body", "error", err)
	}
}

// runClientPluginHook dispatches the on_receive_from_client plugin hook.
// Returns true if the request was terminated.
func (h *Handler) runClientPluginHook(sc *streamContext) bool {
	pluginConnInfo := &plugin.ConnInfo{
		ClientAddr: sc.clientAddr,
		TLSVersion: sc.tlsMeta.Version,
		TLSCipher:  sc.tlsMeta.CipherSuite,
		TLSALPN:    sc.tlsMeta.ALPN,
	}
	txCtx := plugin.NewTxCtx()
	var terminated bool
	sc.req, sc.reqBody, terminated = h.dispatchOnReceiveFromClient(sc.ctx, sc.w, sc.req, sc.reqBody, pluginConnInfo, txCtx, sc.reqRawFrames, sc.logger)
	// Store txCtx and pluginConnInfo on the context for later hooks — we
	// piggyback on the streamContext's context value.  For simplicity we
	// store them as unexported fields (added below).
	sc.pluginConnInfo = pluginConnInfo
	sc.txCtx = txCtx
	return terminated
}

// refreshRecordParams updates record params after plugin modification.
func (h *Handler) refreshRecordParams(sc *streamContext) {
	if len(sc.reqBody) > int(config.MaxBodySize) {
		sc.srp.reqBody = sc.reqBody[:int(config.MaxBodySize)]
		sc.reqTruncated = true
		sc.srp.reqTruncated = true
	} else {
		sc.srp.reqBody = sc.reqBody
	}
	sc.reqURL = cloneURL(sc.req.URL)
	sc.srp.req = sc.req
	sc.srp.reqURL = sc.reqURL
}

// buildOutboundRequest creates the outbound HTTP request for the upstream server.
// Returns false if the request could not be built.
func (h *Handler) buildOutboundRequest(sc *streamContext) (*gohttp.Request, bool) {
	outURL := cloneURL(sc.req.URL)
	outReq, err := gohttp.NewRequestWithContext(sc.ctx, sc.req.Method, outURL.String(), io.NopCloser(bytes.NewReader(sc.reqBody)))
	if err != nil {
		sc.logger.Error("HTTP/2 failed to build upstream request", "error", err)
		h.recordOutReqError(sc.ctx, sc.srp, err, sc.logger)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		return nil, false
	}
	// Explicitly set ContentLength since io.NopCloser hides the size from
	// gohttp.NewRequestWithContext's automatic detection.
	outReq.ContentLength = int64(len(sc.reqBody))
	for key, vals := range sc.req.Header {
		outReq.Header[key] = vals
	}
	removeHTTP2HopByHop(outReq.Header)
	return outReq, true
}

// handleRequestIntercept processes request interception. Returns the (possibly
// modified) outbound request and false if the request was dropped/blocked.
func (h *Handler) handleRequestIntercept(sc *streamContext, outReq *gohttp.Request, snap *requestSnapshot) (*gohttp.Request, bool) {
	action, intercepted := h.interceptRequest(sc.ctx, sc.req, sc.srp.reqBody, sc.reqRawFrames, sc.logger)
	if !intercepted {
		return outReq, true
	}

	// Raw mode: the action contains raw bytes to forward directly.
	if action.IsRawMode() {
		sc.interceptRawAction = &action
		switch action.Type {
		case intercept.ActionRelease:
			// Raw release: forward original raw frames as-is to upstream.
			// The raw bytes are the original captured frames.
			sc.interceptRawAction.RawOverride = joinRawFrames(sc.reqRawFrames)
			return outReq, true
		case intercept.ActionModifyAndForward:
			// Raw modify_and_forward: forward the edited raw bytes.
			return outReq, true
		case intercept.ActionDrop:
			h.recordInterceptDrop(sc.ctx, sc.srp, sc.logger)
			writeErrorResponse(sc.w, gohttp.StatusBadGateway)
			sc.logger.Info("intercepted HTTP/2 request dropped (raw mode)",
				"method", sc.req.Method, "url", sc.reqURL.String())
			return nil, false
		default:
			sc.logger.Error("HTTP/2 raw intercept: unknown action type",
				"action_type", action.Type)
			writeErrorResponse(sc.w, gohttp.StatusBadGateway)
			return nil, false
		}
	}

	switch action.Type {
	case intercept.ActionDrop:
		h.recordInterceptDrop(sc.ctx, sc.srp, sc.logger)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		sc.logger.Info("intercepted HTTP/2 request dropped",
			"method", sc.req.Method, "url", sc.reqURL.String())
		return nil, false
	case intercept.ActionModifyAndForward:
		return h.applyRequestInterceptMods(sc, outReq, action)
	default:
		return outReq, true
	}
}

// applyRequestInterceptMods applies intercept modifications to the outbound
// request, including re-checking target scope after URL override.
func (h *Handler) applyRequestInterceptMods(sc *streamContext, outReq *gohttp.Request, action intercept.InterceptAction) (*gohttp.Request, bool) {
	var modErr error
	outReq, modErr = applyInterceptModifications(outReq, action, sc.reqBody)
	if modErr != nil {
		sc.logger.Error("HTTP/2 intercept modification failed", "error", modErr)
		writeErrorResponse(sc.w, gohttp.StatusBadRequest)
		return nil, false
	}
	if action.OverrideURL != "" && h.TargetScope != nil && h.TargetScope.HasRules() {
		if allowed, reason := h.TargetScope.CheckURL(outReq.URL); !allowed {
			writeScopeBlockResponse(sc.w, outReq.URL.Hostname(), reason)
			sc.logger.Warn("HTTP/2 intercept override_url blocked by target scope",
				"url", outReq.URL.String(), "reason", reason)
			return nil, false
		}
	}
	if action.OverrideBody != nil {
		sc.srp.reqBody = []byte(*action.OverrideBody)
	}
	sc.srp.req = outReq
	return outReq, true
}

// applyRequestTransform applies auto-transform rules to the outbound request
// headers and body. If no transform pipeline is configured, this is a no-op.
// The method mirrors the HTTP/1.x applyTransform pattern: it modifies the
// outbound request's headers, body, and content length in place, and updates
// the streamContext's reqBody and srp for recording.
func (h *Handler) applyRequestTransform(sc *streamContext, outReq *gohttp.Request) {
	if h.transformPipeline == nil {
		return
	}
	// Use sc.srp.reqBody as input (reflects intercept overrides).
	rh := httpHeaderToRawHeaders(outReq.Header)
	rh, sc.reqBody = h.transformPipeline.TransformRequest(outReq.Method, outReq.URL, rh, sc.srp.reqBody)
	outReq.Header = rawHeadersToHTTPHeader(rh)
	outReq.Body = io.NopCloser(bytes.NewReader(sc.reqBody))
	outReq.ContentLength = int64(len(sc.reqBody))
	sc.srp.reqBody = sc.reqBody
	sc.srp.req = outReq // Ensure recording reflects transform changes.
}

// applyResponseTransform applies auto-transform rules to the upstream response
// headers and body. If no transform pipeline is configured, the original
// headers and body are returned unchanged. This mirrors the HTTP/1.x
// readResponseBody pattern where response transforms are applied immediately
// after reading the response body.
func (h *Handler) applyResponseTransform(resp *gohttp.Response, body []byte) (gohttp.Header, []byte) {
	if h.transformPipeline == nil {
		return resp.Header, body
	}
	rh, newBody := h.transformPipeline.TransformResponse(resp.StatusCode, httpHeaderToRawHeaders(resp.Header), body)
	return rawHeadersToHTTPHeader(rh), newBody
}

// runServerPluginHook dispatches the on_before_send_to_server hook.
func (h *Handler) runServerPluginHook(sc *streamContext, outReq *gohttp.Request) *gohttp.Request {
	outReq, body := h.dispatchOnBeforeSendToServer(sc.ctx, outReq, sc.reqBody, sc.pluginConnInfo, sc.txCtx, sc.reqRawFrames, sc.logger)
	if body != nil {
		outReq.Body = io.NopCloser(bytes.NewReader(body))
		outReq.ContentLength = int64(len(body))
		sc.reqBody = body
	}
	return outReq
}

// forwardUpstream sends the request to the upstream server and reads the response.
// Returns false if the upstream request failed.
// forwardUpstreamResult holds the result of forwarding a request upstream.
type forwardUpstreamResult struct {
	resp       *gohttp.Response
	serverAddr string
	respBody   []byte
	sendMs     *int64
	waitMs     *int64
	receiveMs  *int64
	// respRawFrames holds the raw HTTP/2 frame bytes from the upstream response.
	// Populated when the custom frame-engine Transport is used. Nil when the
	// standard net/http Transport is used.
	respRawFrames [][]byte
}

func (h *Handler) forwardUpstream(sc *streamContext, outReq *gohttp.Request, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	// gRPC requests are handled by tryHandleGRPCStream → handleGRPCStream
	// using ConnPool + h2Transport.RoundTripStream (USK-520). They never
	// reach this path.
	return h.forwardUpstreamConnPool(sc, outReq, sendResult)
}

// forwardUpstreamConnPool forwards the request via ConnPool + ALPN routing.
// This is the new unary path that replaces roundTripWithTrace for non-gRPC
// HTTP/2 requests.
func (h *Handler) forwardUpstreamConnPool(sc *streamContext, outReq *gohttp.Request, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	sendStart := time.Now()

	// Use url.URL.Hostname()/Port() for correct IPv6 bracket handling.
	// strings.Contains(host, ":") would always match IPv6 literals like [::1].
	hostname := outReq.URL.Hostname()
	port := outReq.URL.Port()
	useTLS := outReq.URL.Scheme == "https"
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(hostname, port)

	// Non-TLS upstreams cannot negotiate ALPN, so ConnPool.Get would always
	// fall back to the legacy path after a redundant dial. Short-circuit here.
	if !useTLS {
		return h.forwardUpstreamLegacy(sc, outReq, sendResult)
	}

	h.tlsMu.RLock()
	cr, err := h.connPool.Get(sc.ctx, addr, useTLS, hostname)
	h.tlsMu.RUnlock()
	if err != nil {
		sc.logger.Error("HTTP/2 upstream connection failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		return nil, false
	}

	var result *forwardUpstreamResult

	switch cr.ALPN {
	case "h2":
		// forwardH2 → RoundTripOnConn takes ownership of cr.Conn and closes
		// it before returning; the caller must NOT close cr.Conn after this call.
		result, err = h.forwardH2(sc.ctx, cr.Conn, outReq)
	default:
		// For non-h2 connections, close the ConnPool connection and fall back
		// to the legacy gohttp.Transport path which handles HTTP/1.1 properly
		// (chunked encoding, connection reuse, etc.).
		//
		// Known trade-off: this causes a double TLS handshake — once in
		// ConnPool (to discover ALPN) and again in gohttp.Transport. This is
		// acceptable because ConnPool intentionally has no pooling (YAGNI) and
		// the non-h2 fallback is not the primary path. If this becomes a
		// bottleneck, adding ALPN-aware connection reuse to ConnPool would be
		// the correct fix (not caching here).
		cr.Conn.Close()
		return h.forwardUpstreamLegacy(sc, outReq, sendResult)
	}
	if err != nil {
		sc.logger.Error("HTTP/2 upstream request failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err, "alpn", cr.ALPN)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		return nil, false
	}

	receiveEnd := time.Now()
	// For the ConnPool path we don't have httptrace hooks. Compute a
	// simplified timing: send includes connect + request, receive is the
	// remainder. Wait is unavailable (nil).
	totalMs := receiveEnd.Sub(sendStart).Milliseconds()
	connectMs := cr.ConnectDuration.Milliseconds()
	sendVal := connectMs
	if sendVal > totalMs {
		sendVal = totalMs
	}
	receiveVal := totalMs - sendVal
	if receiveVal < 0 {
		receiveVal = 0
	}
	result.sendMs = &sendVal
	result.receiveMs = &receiveVal

	return result, true
}

// forwardH2 forwards a request via the HTTP/2 frame engine on a pre-established
// h2 connection. It converts the outbound gohttp.Request to hpack headers and
// uses RoundTripOnConn.
func (h *Handler) forwardH2(ctx context.Context, conn net.Conn, outReq *gohttp.Request) (*forwardUpstreamResult, error) {
	// Build hpack headers from the gohttp.Request.
	headers := buildH2HeadersFromGoHTTP(outReq)

	h.tlsMu.RLock()
	transport := h.h2Transport
	h.tlsMu.RUnlock()
	if transport == nil {
		transport = &Transport{Logger: h.Logger}
	}

	h2Result, err := transport.RoundTripOnConn(ctx, conn, headers, outReq.Body)
	if err != nil {
		return nil, fmt.Errorf("h2 round trip: %w", err)
	}

	// Convert h2 result to gohttp.Response for downstream compatibility.
	resp := h2ResultToGoHTTPResponse(h2Result)

	fullRespBody, readErr := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if readErr != nil {
		return nil, fmt.Errorf("read h2 response body: %w", readErr)
	}
	resp.Body.Close()

	return &forwardUpstreamResult{
		resp:          resp,
		serverAddr:    conn.RemoteAddr().String(),
		respBody:      fullRespBody,
		respRawFrames: h2Result.RawFrames,
	}, nil
}

// forwardUpstreamLegacy uses the gohttp.Transport for forwarding (gRPC path).
// This is the original implementation, kept for backward compatibility until
// USK-520 migrates gRPC to ConnPool.
func (h *Handler) forwardUpstreamLegacy(sc *streamContext, outReq *gohttp.Request, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	sendStart := time.Now()
	h.tlsMu.RLock()
	resp, serverAddr, timing, err := h.roundTripWithTrace(outReq)
	h.tlsMu.RUnlock()
	if err != nil {
		sc.logger.Error("HTTP/2 upstream request failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		return nil, false
	}
	defer resp.Body.Close()

	fullRespBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if err != nil {
		sc.logger.Warn("HTTP/2 failed to read response body", "error", err)
	}
	receiveEnd := time.Now()

	sMs, wMs, rMs := httputil.ComputeTiming(sendStart, timing, receiveEnd)

	return &forwardUpstreamResult{
		resp:       resp,
		serverAddr: serverAddr,
		respBody:   fullRespBody,
		sendMs:     sMs,
		waitMs:     wMs,
		receiveMs:  rMs,
	}, true
}

// handleResponseIntercept processes response interception.
// Returns false if the response was dropped.
func (h *Handler) handleResponseIntercept(sc *streamContext, resp *gohttp.Response, fullRespBody []byte) (*gohttp.Response, []byte, bool) {
	action, intercepted := h.interceptResponse(sc.ctx, sc.req, resp, fullRespBody, sc.logger)
	if !intercepted {
		return resp, fullRespBody, true
	}
	switch action.Type {
	case intercept.ActionDrop:
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		sc.logger.Info("intercepted HTTP/2 response dropped",
			"method", sc.req.Method, "url", sc.reqURL.String(), "status", resp.StatusCode)
		return nil, nil, false
	case intercept.ActionModifyAndForward:
		var modErr error
		resp, fullRespBody, modErr = applyResponseModifications(resp, action, fullRespBody)
		if modErr != nil {
			sc.logger.Error("HTTP/2 response intercept modification failed", "error", modErr)
			writeErrorResponse(sc.w, gohttp.StatusBadGateway)
			return nil, nil, false
		}
		return resp, fullRespBody, true
	default:
		return resp, fullRespBody, true
	}
}

// runResponsePluginHooks dispatches the on_receive_from_server and
// on_before_send_to_client hooks.
func (h *Handler) runResponsePluginHooks(sc *streamContext, resp *gohttp.Response, fullRespBody []byte) (*gohttp.Response, []byte) {
	resp, fullRespBody = h.dispatchOnReceiveFromServer(sc.ctx, resp, fullRespBody, sc.req, sc.pluginConnInfo, sc.txCtx, sc.respRawFrames, sc.logger)
	resp, fullRespBody = h.dispatchOnBeforeSendToClient(sc.ctx, resp, fullRespBody, sc.req, sc.pluginConnInfo, sc.txCtx, sc.respRawFrames, sc.logger)
	return resp, fullRespBody
}

// writeResponseToClient writes the HTTP response headers, body, and trailers
// to the client using h2ResponseWriter for direct HPACK encoding.
func writeResponseToClient(sc *streamContext, resp *gohttp.Response, body []byte) {
	// Remove HTTP/1.1 hop-by-hop headers from the upstream response before
	// writing to the HTTP/2 client. These headers are invalid in HTTP/2
	// (RFC 9113 §8.2.2) and cause PROTOCOL_ERROR when the upstream is
	// HTTP/1.1 (e.g., when ALPN negotiation falls back to http/1.1).
	removeHTTP2HopByHop(resp.Header)

	// RFC 9110 §6.4.1: 1xx, 204, 205, and 304 responses must not contain a body.
	// Strip Content-Length and suppress DATA frames for these statuses.
	noBody := isNoBodyStatus(resp.StatusCode)
	if noBody {
		resp.Header.Del("Content-Length")
		body = nil
	} else if len(body) > 0 {
		// Recalculate Content-Length to match the actual body bytes being sent.
		// The body may have been modified by transform/intercept/output-filter
		// after the upstream response was received, making the original
		// Content-Length incorrect.
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	} else {
		resp.Header.Del("Content-Length")
	}

	// Convert response headers to hpack fields.
	respHeaders := goHTTPHeaderToHpack(resp.Header)

	if err := sc.w.WriteHeaders(resp.StatusCode, respHeaders); err != nil {
		sc.logger.Debug("HTTP/2 failed to write response headers", "error", err)
		return
	}

	if len(body) > 0 {
		if err := sc.w.WriteData(body); err != nil {
			sc.logger.Debug("HTTP/2 failed to write response body", "error", err)
		}
	}

	// Write trailers if present.
	if len(resp.Trailer) > 0 {
		trailerFields := goHTTPHeaderToHpack(resp.Trailer)
		if err := sc.w.WriteTrailers(trailerFields); err != nil {
			sc.logger.Debug("HTTP/2 failed to write response trailers", "error", err)
		}
	}
}

// extractTLSCertSubject returns the upstream server's TLS certificate subject,
// or an empty string if not available.
func extractTLSCertSubject(resp *gohttp.Response) string {
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		return resp.TLS.PeerCertificates[0].Subject.String()
	}
	return ""
}

// recordStreamResponse records the receive phase for HTTP/2 or gRPC flows.
func (h *Handler) recordStreamResponse(sc *streamContext, isGRPC bool, sendResult *sendRecordResult, resp *gohttp.Response, fullRespBody []byte, rawTrailers gohttp.Header, serverAddr string, duration time.Duration, tlsCertSubject string, respSnap *responseSnapshot, sendMs, waitMs, receiveMs *int64, respRawFrames [][]byte) {
	if isGRPC {
		h.recordGRPCFlow(sc, resp, fullRespBody, rawTrailers, serverAddr, duration, tlsCertSubject)
	} else {
		h.recordReceiveWithVariant(sc.ctx, sendResult, receiveRecordParams{
			start:                sc.start,
			duration:             duration,
			serverAddr:           serverAddr,
			tlsServerCertSubject: tlsCertSubject,
			resp:                 resp,
			respBody:             fullRespBody,
			sendMs:               sendMs,
			waitMs:               waitMs,
			receiveMs:            receiveMs,
			rawFrames:            respRawFrames,
		}, respSnap, sc.logger)
	}
}

// recordGRPCFlow records a gRPC session via the gRPC handler.
func (h *Handler) recordGRPCFlow(sc *streamContext, resp *gohttp.Response, fullRespBody []byte, rawTrailers gohttp.Header, serverAddr string, duration time.Duration, tlsCertSubject string) {
	if !h.shouldCapture(sc.req.Method, sc.reqURL) {
		return
	}
	var trailers map[string][]string
	if rawTrailers != nil {
		trailers = make(map[string][]string, len(rawTrailers))
		for k, vals := range rawTrailers {
			trailers[k] = vals
		}
	}
	info := &protogrpc.StreamInfo{
		ConnID:               sc.connID,
		ClientAddr:           sc.clientAddr,
		ServerAddr:           serverAddr,
		Method:               sc.req.Method,
		URL:                  sc.reqURL,
		RequestHeaders:       sc.req.Header,
		ResponseHeaders:      resp.Header,
		Trailers:             trailers,
		RequestBody:          sc.reqBody,
		ResponseBody:         fullRespBody,
		StatusCode:           resp.StatusCode,
		Start:                sc.start,
		Duration:             duration,
		TLSVersion:           sc.tlsMeta.Version,
		TLSCipher:            sc.tlsMeta.CipherSuite,
		TLSALPN:              sc.tlsMeta.ALPN,
		TLSServerCertSubject: tlsCertSubject,
		Scheme:               sc.flowScheme,
	}
	if err := h.grpcHandler.RecordSession(sc.ctx, info); err != nil {
		sc.logger.Error("gRPC flow recording failed", "error", err)
	}
}

// cloneHeaders creates a deep copy of an http.Header map. Returns nil if the
// input is nil. Each value slice is independently copied so that mutations to
// the returned header do not affect the original.
func cloneHeaders(h gohttp.Header) gohttp.Header {
	if h == nil {
		return nil
	}
	clone := make(gohttp.Header, len(h))
	for k, vals := range h {
		cp := make([]string, len(vals))
		copy(cp, vals)
		clone[k] = cp
	}
	return clone
}

// cloneURL creates a shallow copy of a URL suitable for recording/forwarding.
func cloneURL(u *url.URL) *url.URL {
	return &url.URL{
		Scheme:   u.Scheme,
		Host:     u.Host,
		Path:     u.Path,
		RawQuery: u.RawQuery,
		Fragment: u.Fragment,
	}
}

// roundTripWithTrace wraps transport.RoundTrip with an httptrace hook to
// capture the remote address of the TCP connection used for the request
// and per-phase timing data (send, wait, receive).
func (h *Handler) roundTripWithTrace(req *gohttp.Request) (*gohttp.Response, string, *httputil.RoundTripTiming, error) {
	var serverAddr string
	timing := &httputil.RoundTripTiming{}
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				serverAddr = info.Conn.RemoteAddr().String()
			}
		},
		WroteRequest: func(info httptrace.WroteRequestInfo) {
			timing.SetWroteRequest(time.Now())
		},
		GotFirstResponseByte: func() {
			timing.SetGotFirstByte(time.Now())
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Hold a read lock while accessing transport.Proxy via RoundTrip to
	// prevent a data race with concurrent SetUpstreamProxy writes.
	h.UpstreamMu.RLock()
	resp, err := h.Transport.RoundTrip(req)
	h.UpstreamMu.RUnlock()

	return resp, serverAddr, timing, err
}

// shouldCapture checks the capture scope to determine whether a request
// should be recorded. Returns true if no scope is configured.
func (h *Handler) shouldCapture(method string, u *url.URL) bool {
	return h.ShouldCapture(method, u)
}

// connLogger returns the connection-scoped logger from context,
// falling back to the handler's logger.
func (h *Handler) connLogger(ctx context.Context) *slog.Logger {
	return h.ConnLogger(ctx)
}

// interceptRequest checks if the request matches any intercept rules and,
// if so, enqueues it for AI agent review. It blocks until the agent responds
// or the timeout expires. Returns the action and true if intercepted, or a
// zero-value action and false if not intercepted.
//
// rawFrames are the raw HTTP/2 frame bytes for this request. They are
// atomically attached to the enqueued item via EnqueueOpts so that AI agents
// can inspect and edit them in raw mode.
func (h *Handler) interceptRequest(ctx context.Context, req *gohttp.Request, body []byte, rawFrames [][]byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchRequestRules(req.Method, req.URL, httpHeaderToRawHeaders(req.Header))
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("HTTP/2 request intercepted", "method", req.Method, "url", req.URL.String(), "matched_rules", matchedRules)

	var opts []intercept.EnqueueOpts
	if joined := joinRawFrames(rawFrames); len(joined) > 0 {
		opts = append(opts, intercept.EnqueueOpts{RawBytes: joined})
	}

	id, actionCh := h.InterceptQueue.Enqueue(req.Method, req.URL, httpHeaderToRawHeaders(req.Header), body, matchedRules, opts...)
	defer h.InterceptQueue.Remove(id) // ensure cleanup on timeout/cancel

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action, true
	case <-timeoutCtx.Done():
		// Timeout or context cancellation.
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			// Proxy shutting down — drop.
			logger.Info("intercepted HTTP/2 request cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted HTTP/2 request timed out", "id", id, "behavior", string(behavior))
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		default:
			// auto_release or unrecognized → release.
			return intercept.InterceptAction{Type: intercept.ActionRelease}, true
		}
	}
}

// applyInterceptModifications applies the modifications from a modify_and_forward
// action to the HTTP/2 request. It delegates to the shared httputil package for
// CRLF validation, URL scheme enforcement, and header/body modifications.
func applyInterceptModifications(req *gohttp.Request, action intercept.InterceptAction, originalBody []byte) (*gohttp.Request, error) {
	return httputil.ApplyRequestModifications(req, action)
}

// interceptResponse checks if the response matches any intercept rules and,
// if so, enqueues it for AI agent review. It blocks until the agent responds
// or the timeout expires. Returns the action and true if intercepted, or a
// zero-value action and false if not intercepted.
func (h *Handler) interceptResponse(ctx context.Context, req *gohttp.Request, resp *gohttp.Response, body []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, httpHeaderToRawHeaders(resp.Header))
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("HTTP/2 response intercepted",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, req.URL, resp.StatusCode, httpHeaderToRawHeaders(resp.Header), body, matchedRules,
	)
	defer h.InterceptQueue.Remove(id)

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action, true
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			logger.Info("intercepted HTTP/2 response cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted HTTP/2 response timed out", "id", id, "behavior", string(behavior))
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		default:
			return intercept.InterceptAction{Type: intercept.ActionRelease}, true
		}
	}
}

// applyResponseModifications applies the modifications from a modify_and_forward
// action to the HTTP/2 response. It delegates to the shared httputil package for
// status code validation, CRLF injection checks, and header/body modifications.
func applyResponseModifications(resp *gohttp.Response, action intercept.InterceptAction, body []byte) (*gohttp.Response, []byte, error) {
	return httputil.ApplyResponseModifications(resp, action, body)
}

// isGRPCContentType reports whether the Content-Type indicates a gRPC request.
func isGRPCContentType(ct string) bool {
	ct = strings.TrimSpace(ct)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// removeHTTP2HopByHop removes HTTP/2 hop-by-hop and connection-specific
// headers that should not be forwarded to the upstream server.
func removeHTTP2HopByHop(header gohttp.Header) {
	header.Del("Connection")
	header.Del("Keep-Alive")
	header.Del("Proxy-Connection")
	header.Del("Transfer-Encoding")
	header.Del("Upgrade")
	// RFC 7540 §8.1.2.2: TE is a hop-by-hop header. The only allowed value
	// in HTTP/2 is "trailers"; remove TE unless it is exactly "trailers".
	if te := header.Get("Te"); te != "" && !strings.EqualFold(te, "trailers") {
		header.Del("Te")
	}
}

// isNoBodyStatus returns true for HTTP status codes that must not include a
// message body per RFC 9110 §6.4.1: 1xx (informational), 204 (No Content),
// 205 (Reset Content), and 304 (Not Modified).
func isNoBodyStatus(code int) bool {
	return (code >= 100 && code < 200) || code == 204 || code == 205 || code == 304
}
