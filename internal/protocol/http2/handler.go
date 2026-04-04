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
	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
	// ConnPool + ALPN routing. Routes to h2Transport for h2 ALPN and
	// H1Transport for non-h2 ALPN (including non-TLS).
	connPool *httputil.ConnPool

	// h2Transport is the custom HTTP/2 frame-engine transport used for raw mode
	// forwarding and ConnPool-based unary upstream routing.
	h2Transport *Transport

	// grpcHandler processes gRPC flow recording when Content-Type: application/grpc
	// is detected. If nil, gRPC streams are recorded as plain HTTP/2.
	grpcHandler *protogrpc.Handler

	// grpcWebHandler processes gRPC-Web flow recording when Content-Type:
	// application/grpc-web or application/grpc-web-text is detected.
	// If nil, gRPC-Web streams are recorded as plain HTTP/2.
	grpcWebHandler *grpcweb.Handler

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
// The ConnPool's TLSTransport is updated directly and is used to establish
// upstream TLS connections, including ALPN negotiation (e.g. h2 vs. http/1.1).
// HTTP/2 upstream connections negotiated via ALPN are handled by h2Transport;
// HTTP/1.1 upstream connections are handled by H1Transport on the
// ConnPool-established connection.
//
// If t is nil, the default crypto/tls behavior is restored.
//
// This method is safe to call concurrently with in-flight requests.
func (h *Handler) SetTLSTransport(t httputil.TLSTransport) {
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()

	h.connPool.TLSTransport = t
}

// SetInsecureSkipVerify configures whether the handler skips TLS certificate
// verification when connecting to upstream servers via the ConnPool.
// The HTTP/2 handler does not use HandlerBase.Transport (gohttp.Transport);
// it only configures the ConnPool's TLSTransport.
func (h *Handler) SetInsecureSkipVerify(skip bool) {
	if skip {
		h.Logger.Warn("upstream TLS certificate verification is disabled — connections to upstream servers will not verify certificates")
	}
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

// SetUpstreamProxy configures the upstream proxy for the HTTP/2 handler.
// The HTTP/2 handler does not use HandlerBase.Transport (gohttp.Transport);
// it only configures the ConnPool's UpstreamProxy.
func (h *Handler) SetUpstreamProxy(proxyURL *url.URL) {
	h.UpstreamMu.Lock()
	h.UpstreamProxy = proxyURL
	h.UpstreamMu.Unlock()

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

// SetGRPCWebHandler sets the gRPC-Web handler used for gRPC-Web-specific flow recording.
// When set, streams with Content-Type: application/grpc-web or application/grpc-web-text
// are recorded as gRPC-Web sessions instead of plain HTTP/2.
func (h *Handler) SetGRPCWebHandler(gwh *grpcweb.Handler) {
	h.grpcWebHandler = gwh
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
	// State holds the raw tls.ConnectionState for handlers (e.g. gRPC-Web)
	// that require the full TLS state rather than decomposed string fields.
	State *tls.ConnectionState
}

// HandleH2 processes an h2 (TLS) HTTP/2 connection after ALPN negotiation.
// This is called from the HTTP handler's CONNECT flow when the client
// negotiates "h2" during the TLS handshake. It satisfies the
// protohttp.H2Handler interface.
func (h *Handler) HandleH2(ctx context.Context, tlsConn *tls.Conn, connectAuthority string, tlsVersion, tlsCipher, tlsALPN string) error {
	logger := h.connLogger(ctx)
	logger.Info("HTTP/2 h2 connection", "authority", connectAuthority)

	cs := tlsConn.ConnectionState()
	tlsMeta := tlsMetadata{
		Version:     tlsVersion,
		CipherSuite: tlsCipher,
		ALPN:        tlsALPN,
		State:       &cs,
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
	req              *gohttp.Request // lazily built for gRPC intercept path only
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

	// respAutoContentLength controls CL/TE normalization in the response write
	// path. true (default) = recalculate CL and strip TE; false = passthrough.
	// Set by handleResponseIntercept when the intercept action has
	// AutoContentLength=false.
	respAutoContentLength bool

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

	outHeaders := h.buildOutboundHeaders(sc)

	snap := snapshotRequest(sc.h2req.RegularHeaders(), sc.srp.reqBody)

	outHeaders, ok := h.handleRequestIntercept(sc, outHeaders, &snap)
	if !ok {
		return
	}

	// Raw mode forwarding: bypass L7 transforms, plugins, and standard
	// transport. Send edited raw frames directly to the upstream.
	if sc.interceptRawAction != nil {
		h.handleRawForward(sc, &snap)
		return
	}

	h.applyRequestTransform(sc, &outHeaders)

	outHeaders = h.runServerPluginHook(sc, outHeaders)

	h.forwardAndRecord(sc, outHeaders, &snap)
}

// initStreamContext creates a streamContext from an h2Request using hpack
// native types. Returns nil if the request is invalid.
func (h *Handler) initStreamContext(
	ctx context.Context,
	w h2ResponseWriter,
	h2req *h2Request,
	connID, clientAddr, connectAuthority string,
	tlsMeta tlsMetadata,
	logger *slog.Logger,
) *streamContext {
	if h2req.Method == "" {
		logger.Error("HTTP/2 h2Request missing method")
		w.WriteHeaders(httputil.StatusBadRequest, nil)
		return nil
	}

	return &streamContext{
		ctx:                   ctx,
		w:                     w,
		h2req:                 h2req,
		connID:                connID,
		clientAddr:            clientAddr,
		connectAuthority:      connectAuthority,
		tlsMeta:               tlsMeta,
		logger:                logger,
		start:                 time.Now(),
		reqRawFrames:          rawFramesFromContext(ctx),
		respAutoContentLength: true,
	}
}

// forwardAndRecord performs upstream forwarding, response processing, output
// filtering, and flow recording. Extracted from handleStream to reduce
// cyclomatic complexity.
func (h *Handler) forwardAndRecord(sc *streamContext, outHeaders []hpack.HeaderField, snap *requestSnapshot) {
	ct := hpackGetHeader(sc.h2req.AllHeaders, "content-type")
	isGRPC := h.grpcHandler != nil && isGRPCContentType(ct)
	isGRPCWeb := h.grpcWebHandler != nil && grpcweb.IsGRPCWebContentType(ct)

	var sendResult *sendRecordResult
	if !isGRPC && !isGRPCWeb {
		sendResult = h.recordSendWithVariant(sc.ctx, sc.srp, snap, sc.logger)
	}

	fwd, ok := h.forwardUpstream(sc, outHeaders, sendResult)
	if !ok {
		return
	}

	fwd.h2resp.Headers, fwd.h2resp.Body = h.applyResponseTransform(fwd.h2resp)

	respSnap := snapshotH2Response(fwd.h2resp)

	resp, ok := h.handleResponseIntercept(sc, fwd.h2resp)
	if !ok {
		return
	}

	resp = h.runResponsePluginHooks(sc, resp)

	// Save unmasked body and trailers for recording before output filter
	// masks them. Deep copy to guard against future FilterOutput
	// implementations that may modify the underlying data in place (S-2).
	rawRespBody := make([]byte, len(resp.Body))
	copy(rawRespBody, resp.Body)
	rawTrailers := cloneHpackHeaders(resp.Trailers)

	// Output filter: mask sensitive data in response body, headers, and
	// trailers before sending to client. Raw (unmasked) data is preserved
	// in Flow Store. Trailers (e.g. grpc-message) may contain PII.
	maskedRespHeaders := hpackToRawHeaders(resp.Headers)
	resp.Body, maskedRespHeaders = h.ApplyOutputFilter(resp.Body, maskedRespHeaders, sc.logger)
	resp.Headers = rawHeadersToHpack(maskedRespHeaders)
	if len(resp.Trailers) > 0 {
		maskedTrailers := h.ApplyOutputFilterHeaders(hpackToRawHeaders(resp.Trailers), sc.logger)
		resp.Trailers = rawHeadersToHpack(maskedTrailers)
	}

	writeH2ResponseToClient(sc, resp)

	duration := time.Since(sc.start)
	tlsCertSubject := fwd.tlsCertSubject

	h.recordStreamResponse(sc, isGRPC, isGRPCWeb, sendResult, resp, rawRespBody, rawTrailers, fwd.serverAddr, duration, tlsCertSubject, &respSnap, fwd.sendMs, fwd.waitMs, fwd.receiveMs, fwd.respRawFrames)

	logProtocol := "http/2"
	if isGRPC {
		logProtocol = "grpc"
	} else if isGRPCWeb {
		logProtocol = "grpc-web"
	}
	sc.logger.Info(logProtocol+" request",
		"method", sc.h2req.Method,
		"url", sc.reqURL.String(),
		"status", resp.StatusCode,
		"duration_ms", duration.Milliseconds())
}

// readAndTruncateBody reads the full request body and truncates for recording.
func (h *Handler) readAndTruncateBody(sc *streamContext) {
	if sc.h2req.Body != nil {
		fullBody, err := io.ReadAll(sc.h2req.Body)
		if err != nil {
			sc.logger.Warn("HTTP/2 failed to read request body", "error", err)
		}
		sc.h2req.Body.Close()
		sc.reqBody = fullBody
		sc.h2req.Body = io.NopCloser(bytes.NewReader(fullBody))
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

	host := sc.h2req.Authority
	if host == "" {
		host = hpackGetHeader(sc.h2req.AllHeaders, "host")
	}
	if host == "" && sc.connectAuthority != "" {
		host = sc.connectAuthority
	}

	// Build the URL from h2req pseudo-headers.
	reqURL := h2RequestURL(sc.h2req)
	if reqURL.Host == "" {
		reqURL.Host = host
	}
	if reqURL.Scheme == "" || sc.connectAuthority != "" {
		reqURL.Scheme = scheme
	}

	// TCP forwarding: override host with the actual upstream target.
	if target, ok := proxy.ForwardTargetFromContext(sc.ctx); ok {
		reqURL.Host = target
		sc.h2req.Authority = target
		if reqURL.Scheme == "" {
			reqURL.Scheme = scheme
		}
	}

	// Update h2req scheme to match resolved scheme.
	sc.h2req.Scheme = reqURL.Scheme

	sc.reqURL = cloneURL(reqURL)
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
		method:       sc.h2req.Method,
		reqURL:       sc.reqURL,
		host:         sc.h2req.Authority,
		headers:      sc.h2req.AllHeaders,
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
	allowed, reason := h.TargetScope.CheckURL(sc.reqURL)
	if allowed {
		return false
	}
	writeScopeBlockResponse(sc.w, sc.reqURL.Hostname(), reason)
	sc.logger.Info("HTTP/2 request blocked by target scope",
		"host", sc.reqURL.Host, "reason", reason)
	h.recordBlocked(sc.ctx, sc.srp, "target_scope", nil, nil, sc.logger)
	return true
}

// checkSafetyFilter enforces safety filter rules. Returns true if the request was blocked.
func (h *Handler) checkSafetyFilter(sc *streamContext) bool {
	violation := h.CheckSafetyFilter(sc.reqBody, sc.reqURL.String(), hpackToRawHeaders(sc.h2req.AllHeaders))
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
	if err := w.WriteHeaders(httputil.StatusForbidden, headers); err != nil {
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
	denial := h.RateLimiter.Check(sc.reqURL.Hostname())
	if denial == nil {
		return false
	}
	writeRateLimitResponse(sc.w)
	sc.logger.Info("HTTP/2 request blocked by rate limit",
		"host", sc.reqURL.Host)
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
	if err := w.WriteHeaders(httputil.StatusTooManyRequests, headers); err != nil {
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
	if err := w.WriteHeaders(httputil.StatusForbidden, headers); err != nil {
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
	sc.h2req, sc.reqBody, terminated = h.dispatchOnReceiveFromClient(sc.ctx, sc.w, sc.h2req, sc.reqBody, pluginConnInfo, txCtx, sc.reqRawFrames, sc.logger)
	if !terminated && h.pluginEngine != nil {
		// After plugin modification, update reqURL from h2req fields.
		newURL := h2RequestURL(sc.h2req)
		// Preserve scheme and host from resolved values.
		if newURL.Scheme == "" {
			newURL.Scheme = sc.reqURL.Scheme
		}
		if newURL.Host == "" {
			newURL.Host = sc.reqURL.Host
		}
		sc.reqURL = newURL
	}
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
	sc.srp.method = sc.h2req.Method
	sc.srp.host = sc.h2req.Authority
	sc.srp.headers = sc.h2req.AllHeaders
	sc.srp.reqURL = sc.reqURL
}

// buildOutboundHeaders creates the outbound HTTP/2 HPACK headers for the
// upstream server, including pseudo-headers and filtered hop-by-hop headers.
func (h *Handler) buildOutboundHeaders(sc *streamContext) []hpack.HeaderField {
	return buildH2HeadersFromH2Req(sc.h2req)
}

// handleRequestIntercept processes request interception. Returns the (possibly
// modified) outbound headers and false if the request was dropped/blocked.
func (h *Handler) handleRequestIntercept(sc *streamContext, outHeaders []hpack.HeaderField, snap *requestSnapshot) ([]hpack.HeaderField, bool) {
	action, intercepted := h.interceptRequest(sc.ctx, sc.h2req, sc.srp.reqBody, sc.reqRawFrames, sc.logger)
	if !intercepted {
		return outHeaders, true
	}

	// Raw mode: the action contains raw bytes to forward directly.
	if action.IsRawMode() {
		sc.interceptRawAction = &action
		switch action.Type {
		case intercept.ActionRelease:
			sc.interceptRawAction.RawOverride = joinRawFrames(sc.reqRawFrames)
			return outHeaders, true
		case intercept.ActionModifyAndForward:
			return outHeaders, true
		case intercept.ActionDrop:
			h.recordInterceptDrop(sc.ctx, sc.srp, sc.logger)
			writeErrorResponse(sc.w, httputil.StatusBadGateway)
			sc.logger.Info("intercepted HTTP/2 request dropped (raw mode)",
				"method", sc.h2req.Method, "url", sc.reqURL.String())
			return nil, false
		default:
			sc.logger.Error("HTTP/2 raw intercept: unknown action type",
				"action_type", action.Type)
			writeErrorResponse(sc.w, httputil.StatusBadGateway)
			return nil, false
		}
	}

	switch action.Type {
	case intercept.ActionDrop:
		h.recordInterceptDrop(sc.ctx, sc.srp, sc.logger)
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		sc.logger.Info("intercepted HTTP/2 request dropped",
			"method", sc.h2req.Method, "url", sc.reqURL.String())
		return nil, false
	case intercept.ActionModifyAndForward:
		return h.applyRequestInterceptMods(sc, outHeaders, action)
	default:
		return outHeaders, true
	}
}

// applyRequestInterceptMods applies intercept modifications to the outbound
// headers, including re-checking target scope after URL override.
func (h *Handler) applyRequestInterceptMods(sc *streamContext, outHeaders []hpack.HeaderField, action intercept.InterceptAction) ([]hpack.HeaderField, bool) {
	modHeaders, modBody, modURL, modErr := applyInterceptModifications(sc.h2req, action, sc.reqBody)
	if modErr != nil {
		sc.logger.Error("HTTP/2 intercept modification failed", "error", modErr)
		writeErrorResponse(sc.w, httputil.StatusBadRequest)
		return nil, false
	}
	if modURL != nil {
		if h.TargetScope != nil && h.TargetScope.HasRules() {
			if allowed, reason := h.TargetScope.CheckURL(modURL); !allowed {
				writeScopeBlockResponse(sc.w, modURL.Hostname(), reason)
				sc.logger.Warn("HTTP/2 intercept override_url blocked by target scope",
					"url", modURL.String(), "reason", reason)
				return nil, false
			}
		}
		sc.reqURL = modURL
		sc.srp.reqURL = modURL
		// Update h2req authority from modified URL.
		sc.h2req.Authority = modURL.Host
	}
	if action.OverrideBody != nil {
		sc.reqBody = modBody
		sc.srp.reqBody = modBody
	}
	// Update h2req with modified method/headers.
	sc.h2req.AllHeaders = modHeaders
	sc.h2req.Method = hpackGetPseudo(modHeaders, ":method")
	sc.srp.method = sc.h2req.Method
	sc.srp.headers = modHeaders
	// Rebuild outbound headers from modified h2req.
	return buildH2HeadersFromH2Req(sc.h2req), true
}

// applyRequestTransform applies auto-transform rules to the outbound request
// headers and body. If no transform pipeline is configured, this is a no-op.
// The outHeaders are modified in place (rebuilt from transformed RawHeaders).
func (h *Handler) applyRequestTransform(sc *streamContext, outHeaders *[]hpack.HeaderField) {
	if h.transformPipeline == nil {
		return
	}
	kv := hpackToKeyValues(*outHeaders)
	kv, sc.reqBody = h.transformPipeline.TransformRequest(sc.h2req.Method, sc.reqURL, kv, sc.srp.reqBody)
	// Rebuild outbound hpack headers from transformed KeyValues, preserving
	// pseudo-headers from the original outHeaders.
	var pseudos []hpack.HeaderField
	for _, hf := range *outHeaders {
		if strings.HasPrefix(hf.Name, ":") {
			pseudos = append(pseudos, hf)
		}
	}
	rebuilt := make([]hpack.HeaderField, 0, len(pseudos)+len(kv))
	rebuilt = append(rebuilt, pseudos...)
	rebuilt = append(rebuilt, keyValuesToHpack(kv)...)
	*outHeaders = rebuilt
	sc.srp.reqBody = sc.reqBody
	sc.srp.headers = sc.h2req.AllHeaders
}

// applyResponseTransform applies auto-transform rules to the upstream response
// headers and body. If no transform pipeline is configured, the original
// headers and body are returned unchanged.
func (h *Handler) applyResponseTransform(resp *h2Response) ([]hpack.HeaderField, []byte) {
	if h.transformPipeline == nil {
		return resp.Headers, resp.Body
	}
	kv, newBody := h.transformPipeline.TransformResponse(resp.StatusCode, hpackToKeyValues(resp.Headers), resp.Body)
	return keyValuesToHpack(kv), newBody
}

// runServerPluginHook dispatches the on_before_send_to_server hook.
// Returns the (possibly updated) outbound headers.
func (h *Handler) runServerPluginHook(sc *streamContext, outHeaders []hpack.HeaderField) []hpack.HeaderField {
	var body []byte
	sc.h2req, body = h.dispatchOnBeforeSendToServer(sc.ctx, sc.h2req, sc.reqBody, sc.pluginConnInfo, sc.txCtx, sc.reqRawFrames, sc.logger)
	if body != nil {
		sc.reqBody = body
	}
	// When plugin engine is active, rebuild outbound headers from h2req.
	if h.pluginEngine != nil {
		return buildH2HeadersFromH2Req(sc.h2req)
	}
	return outHeaders
}

// forwardUpstream sends the request to the upstream server and reads the response.
// Returns false if the upstream request failed.
// forwardUpstreamResult holds the result of forwarding a request upstream.
type forwardUpstreamResult struct {
	h2resp         *h2Response
	serverAddr     string
	tlsCertSubject string
	sendMs         *int64
	waitMs         *int64
	receiveMs      *int64
	// respRawFrames holds the raw HTTP/2 frame bytes from the upstream response.
	// Populated when the custom frame-engine Transport is used (h2 ALPN path).
	// Nil when H1Transport is used (non-h2 fallback).
	respRawFrames [][]byte
}

func (h *Handler) forwardUpstream(sc *streamContext, outHeaders []hpack.HeaderField, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	// gRPC requests are handled by tryHandleGRPCStream → handleGRPCStream
	// using ConnPool + h2Transport.RoundTripStream (USK-520). They never
	// reach this path.
	return h.forwardUpstreamConnPool(sc, outHeaders, sendResult)
}

// forwardUpstreamConnPool forwards the request via ConnPool + ALPN routing.
// Handles both h2 (via h2Transport) and non-h2 (via H1Transport) upstream
// connections, as well as non-TLS (plaintext) upstreams.
func (h *Handler) forwardUpstreamConnPool(sc *streamContext, outHeaders []hpack.HeaderField, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	sendStart := time.Now()

	hostname := sc.reqURL.Hostname()
	port := sc.reqURL.Port()
	useTLS := sc.reqURL.Scheme == "https"
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(hostname, port)

	h.tlsMu.RLock()
	cr, err := h.connPool.Get(sc.ctx, addr, useTLS, hostname)
	h.tlsMu.RUnlock()
	if err != nil {
		sc.logger.Error("HTTP/2 upstream connection failed",
			"method", sc.h2req.Method, "url", sc.reqURL.String(), "error", err)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		return nil, false
	}

	var result *forwardUpstreamResult

	switch cr.ALPN {
	case "h2":
		result, err = h.forwardH2(sc.ctx, cr.Conn, outHeaders, sc.reqBody)
	default:
		// Non-h2 ALPN (including non-TLS plain connections with empty ALPN):
		// forward as HTTP/1.1 via H1Transport on the pre-established connection.
		result, err = h.forwardH1WithConn(cr.Conn, sc, outHeaders)
	}
	if err != nil {
		sc.logger.Error("HTTP/2 upstream request failed",
			"method", sc.h2req.Method, "url", sc.reqURL.String(), "error", err, "alpn", cr.ALPN)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		return nil, false
	}

	receiveEnd := time.Now()
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
// h2 connection using hpack native types directly.
func (h *Handler) forwardH2(ctx context.Context, conn net.Conn, outHeaders []hpack.HeaderField, body []byte) (*forwardUpstreamResult, error) {
	h.tlsMu.RLock()
	transport := h.h2Transport
	h.tlsMu.RUnlock()
	if transport == nil {
		transport = &Transport{Logger: h.Logger}
	}

	h2Result, err := transport.RoundTripOnConn(ctx, conn, outHeaders, io.NopCloser(bytes.NewReader(body)))
	if err != nil {
		return nil, fmt.Errorf("h2 round trip: %w", err)
	}

	var fullRespBody []byte
	if h2Result.Body != nil {
		fullRespBody, err = io.ReadAll(io.LimitReader(h2Result.Body, config.MaxBodySize))
		if err != nil {
			return nil, fmt.Errorf("read h2 response body: %w", err)
		}
	}

	h2resp := h2ResultToH2Response(h2Result, fullRespBody)

	return &forwardUpstreamResult{
		h2resp:        h2resp,
		serverAddr:    conn.RemoteAddr().String(),
		respRawFrames: h2Result.RawFrames,
	}, nil
}

// forwardH1WithConn forwards a request via H1Transport on a pre-established
// connection. Converts hpack headers to parser.RawRequest, sends via
// H1Transport.RoundTripOnConn, and converts the parser.RawResponse back to
// h2Response. Used for non-h2 ALPN (HTTP/1.1 fallback) and non-TLS upstreams.
func (h *Handler) forwardH1WithConn(conn net.Conn, sc *streamContext, outHeaders []hpack.HeaderField) (*forwardUpstreamResult, error) {
	defer conn.Close()

	// Build parser.RawRequest from hpack headers.
	method := hpackGetPseudo(outHeaders, ":method")
	reqHeaders := hpackToRawHeadersWithHost(outHeaders, sc.reqURL.Host)
	// Ensure Content-Length matches the actual body (transforms may have
	// changed the body without updating the header).
	if len(sc.reqBody) > 0 {
		reqHeaders = setRawHeader(reqHeaders, "content-length", strconv.Itoa(len(sc.reqBody)))
	}
	rawReq := &parser.RawRequest{
		Method:     method,
		RequestURI: sc.reqURL.RequestURI(),
		Proto:      "HTTP/1.1",
		Headers:    reqHeaders,
		Body:       io.NopCloser(bytes.NewReader(sc.reqBody)),
	}

	sendStart := time.Now()
	transport := &httputil.H1Transport{}
	rtResult, err := transport.RoundTripOnConn(sc.ctx, conn, rawReq)
	if err != nil {
		return nil, fmt.Errorf("h1 round trip: %w", err)
	}

	// Read the full response body.
	var fullRespBody []byte
	if rtResult.Response.Body != nil {
		fullRespBody, err = io.ReadAll(io.LimitReader(rtResult.Response.Body, config.MaxBodySize))
		if err != nil {
			return nil, fmt.Errorf("read h1 response body: %w", err)
		}
	}
	receiveEnd := time.Now()

	// Convert response headers from RawHeaders to hpack, lowercasing names
	// per RFC 9113 (HTTP/2 headers must be lowercase).
	respHeaders := rawHeadersToHpackLower(rtResult.Response.Headers)

	sMs, wMs, rMs := httputil.ComputeTiming(sendStart, rtResult.Timing, receiveEnd)

	return &forwardUpstreamResult{
		h2resp: &h2Response{
			StatusCode: rtResult.Response.StatusCode,
			Headers:    respHeaders,
			Body:       fullRespBody,
		},
		serverAddr: rtResult.ServerAddr,
		sendMs:     sMs,
		waitMs:     wMs,
		receiveMs:  rMs,
	}, nil
}

// handleResponseIntercept processes response interception.
// Returns false if the response was dropped.
func (h *Handler) handleResponseIntercept(sc *streamContext, resp *h2Response) (*h2Response, bool) {
	action, intercepted := h.interceptResponse(sc.ctx, sc.h2req, resp, sc.logger)
	if !intercepted {
		return resp, true
	}

	// Propagate AutoContentLength flag to the write path.
	sc.respAutoContentLength = httputil.AutoContentLength(action.AutoContentLength)

	switch action.Type {
	case intercept.ActionDrop:
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		sc.logger.Info("intercepted HTTP/2 response dropped",
			"method", sc.h2req.Method, "url", sc.reqURL.String(), "status", resp.StatusCode)
		return nil, false
	case intercept.ActionModifyAndForward:
		modResp, modErr := applyResponseModifications(resp, action)
		if modErr != nil {
			sc.logger.Error("HTTP/2 response intercept modification failed", "error", modErr)
			writeErrorResponse(sc.w, httputil.StatusBadGateway)
			return nil, false
		}
		return modResp, true
	default:
		return resp, true
	}
}

// runResponsePluginHooks dispatches the on_receive_from_server and
// on_before_send_to_client hooks using hpack native types.
func (h *Handler) runResponsePluginHooks(sc *streamContext, resp *h2Response) *h2Response {
	resp = h.dispatchOnReceiveFromServerH2(sc.ctx, resp, sc.h2req, sc.pluginConnInfo, sc.txCtx, sc.respRawFrames, sc.logger)
	resp = h.dispatchOnBeforeSendToClientH2(sc.ctx, resp, sc.h2req, sc.pluginConnInfo, sc.txCtx, sc.respRawFrames, sc.logger)
	return resp
}

// writeH2ResponseToClient writes the HTTP/2 response headers, body, and
// trailers to the client using h2ResponseWriter with hpack native types.
//
// When sc.respAutoContentLength is true (default), Content-Length is
// recalculated to match the actual body. When false (intercept with flag
// disabled), Content-Length is preserved as-is to allow intentional CL
// mismatches for pentest scenarios.
func writeH2ResponseToClient(sc *streamContext, resp *h2Response) {
	// Remove HTTP/1.1 hop-by-hop headers from the upstream response before
	// writing to the HTTP/2 client.
	respHeaders := removeHpackHopByHop(resp.Headers)

	// RFC 9110 §6.4.1: 1xx, 204, 205, and 304 responses must not contain a body.
	noBody := isNoBodyStatus(resp.StatusCode)
	body := resp.Body
	if noBody {
		respHeaders = hpackDelHeader(respHeaders, "content-length")
		body = nil
	} else if sc.respAutoContentLength {
		respHeaders = hpackDelHeader(respHeaders, "content-length")
		if len(body) > 0 {
			respHeaders = append(respHeaders, hpack.HeaderField{Name: "content-length", Value: strconv.Itoa(len(body))})
		}
	}

	if err := sc.w.WriteHeaders(resp.StatusCode, respHeaders); err != nil {
		sc.logger.Debug("HTTP/2 failed to write response headers", "error", err)
		return
	}

	if len(body) > 0 {
		if err := sc.w.WriteData(body); err != nil {
			sc.logger.Debug("HTTP/2 failed to write response body", "error", err)
		}
	}

	if len(resp.Trailers) > 0 {
		if err := sc.w.WriteTrailers(resp.Trailers); err != nil {
			sc.logger.Debug("HTTP/2 failed to write response trailers", "error", err)
		}
	}
}

// recordStreamResponse records the receive phase for HTTP/2, gRPC, or gRPC-Web flows.
func (h *Handler) recordStreamResponse(sc *streamContext, isGRPC, isGRPCWeb bool, sendResult *sendRecordResult, resp *h2Response, fullRespBody []byte, rawTrailers []hpack.HeaderField, serverAddr string, duration time.Duration, tlsCertSubject string, respSnap *responseSnapshot, sendMs, waitMs, receiveMs *int64, respRawFrames [][]byte) {
	if isGRPC {
		h.recordGRPCFlow(sc, resp, fullRespBody, rawTrailers, serverAddr, duration, tlsCertSubject)
	} else if isGRPCWeb {
		h.recordGRPCWebFlow(sc, resp, fullRespBody, serverAddr, duration, tlsCertSubject)
	} else {
		h.recordReceiveWithVariant(sc.ctx, sendResult, receiveRecordParams{
			start:                sc.start,
			duration:             duration,
			serverAddr:           serverAddr,
			tlsServerCertSubject: tlsCertSubject,
			statusCode:           resp.StatusCode,
			respHeaders:          resp.Headers,
			respBody:             fullRespBody,
			sendMs:               sendMs,
			waitMs:               waitMs,
			receiveMs:            receiveMs,
			rawFrames:            respRawFrames,
		}, respSnap, sc.logger)
	}
}

// recordGRPCFlow records a gRPC session via the gRPC handler.
func (h *Handler) recordGRPCFlow(sc *streamContext, resp *h2Response, fullRespBody []byte, rawTrailers []hpack.HeaderField, serverAddr string, duration time.Duration, tlsCertSubject string) {
	if !h.shouldCapture(sc.h2req.Method, sc.reqURL) {
		return
	}
	var trailers map[string][]string
	if rawTrailers != nil {
		trailers = hpackToHeaderMap(rawTrailers)
	}
	info := &protogrpc.StreamInfo{
		ConnID:               sc.connID,
		ClientAddr:           sc.clientAddr,
		ServerAddr:           serverAddr,
		Method:               sc.h2req.Method,
		URL:                  sc.reqURL,
		RequestHeaders:       hpackToHeaderMap(sc.h2req.AllHeaders),
		ResponseHeaders:      hpackToHeaderMap(resp.Headers),
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

// recordGRPCWebFlow records a gRPC-Web session via the gRPC-Web handler.
func (h *Handler) recordGRPCWebFlow(sc *streamContext, resp *h2Response, fullRespBody []byte, serverAddr string, duration time.Duration, tlsCertSubject string) {
	if !h.shouldCapture(sc.h2req.Method, sc.reqURL) {
		return
	}

	info := &grpcweb.StreamInfo{
		ConnID:          sc.connID,
		ClientAddr:      sc.clientAddr,
		ServerAddr:      serverAddr,
		RequestHeaders:  hpackToRawHeaders(sc.h2req.AllHeaders),
		ResponseHeaders: hpackToRawHeaders(resp.Headers),
		RequestBody:     sc.reqBody,
		ResponseBody:    fullRespBody,
		TLS:             sc.tlsMeta.State,
		Start:           sc.start,
		Duration:        duration,
		StatusCode:      resp.StatusCode,
		Method:          sc.h2req.Method,
		URL:             sc.reqURL,
		Scheme:          sc.flowScheme,
	}
	if err := h.grpcWebHandler.RecordSession(sc.ctx, info); err != nil {
		sc.logger.Error("gRPC-Web flow recording failed", "error", err)
	}
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
func (h *Handler) interceptRequest(ctx context.Context, req *h2Request, body []byte, rawFrames [][]byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	reqURL := h2RequestURL(req)
	kv := hpackToKV(req.AllHeaders)

	matchedRules := h.InterceptEngine.MatchRequestRules(req.Method, reqURL, kv)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("HTTP/2 request intercepted", "method", req.Method, "url", reqURL.String(), "matched_rules", matchedRules)

	var opts []intercept.EnqueueOpts
	if joined := joinRawFrames(rawFrames); len(joined) > 0 {
		opts = append(opts, intercept.EnqueueOpts{RawBytes: joined})
	}

	id, actionCh := h.InterceptQueue.Enqueue(req.Method, reqURL, kv, body, matchedRules, opts...)
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
			logger.Info("intercepted HTTP/2 request cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted HTTP/2 request timed out", "id", id, "behavior", string(behavior))
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		default:
			return intercept.InterceptAction{Type: intercept.ActionRelease}, true
		}
	}
}

// applyInterceptModifications applies the modifications from a modify_and_forward
// action to the HTTP/2 request using hpack native types. It converts to
// RawRequest for the httputil modification layer, then converts back to hpack.
// Returns the modified AllHeaders (with pseudo-headers), modified body, and
// the parsed URL override (nil if no URL override).
func applyInterceptModifications(req *h2Request, action intercept.InterceptAction, originalBody []byte) ([]hpack.HeaderField, []byte, *url.URL, error) {
	rawReq := h2RequestToRaw(req, originalBody)
	modRaw, modBody, modURL, err := httputil.ApplyRequestModifications(rawReq, originalBody, action)
	if err != nil {
		return req.AllHeaders, originalBody, nil, err
	}
	// Determine the authority and scheme for the modified request.
	scheme := req.Scheme
	authority := req.Authority
	path := req.Path
	method := modRaw.Method
	if modURL != nil {
		authority = modURL.Host
		scheme = modURL.Scheme
		path = modURL.RequestURI()
	}
	// Build hpack headers from modified RawHeaders.
	modHeaders := rawHeadersToHpackWithPseudo(method, scheme, authority, path, modRaw.Headers)
	return modHeaders, modBody, modURL, nil
}

// interceptResponse checks if the response matches any intercept rules and,
// if so, enqueues it for AI agent review. It blocks until the agent responds
// or the timeout expires. Returns the action and true if intercepted, or a
// zero-value action and false if not intercepted.
func (h *Handler) interceptResponse(ctx context.Context, req *h2Request, resp *h2Response, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	kv := hpackToKV(resp.Headers)
	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, kv)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	reqURL := h2RequestURL(req)
	logger.Info("HTTP/2 response intercepted",
		"method", req.Method,
		"url", reqURL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, reqURL, resp.StatusCode, kv, resp.Body, matchedRules,
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
// action to the HTTP/2 response using hpack native types. It converts to
// RawResponse for the httputil modification layer, then converts back to hpack.
func applyResponseModifications(resp *h2Response, action intercept.InterceptAction) (*h2Response, error) {
	rawResp := h2ResponseToRaw(resp.StatusCode, resp.Headers, resp.Body)
	modRaw, modBody, err := httputil.ApplyResponseModifications(rawResp, action, resp.Body)
	if err != nil {
		return resp, err
	}
	return &h2Response{
		StatusCode: modRaw.StatusCode,
		Headers:    rawHeadersToHpack(modRaw.Headers),
		Trailers:   resp.Trailers,
		Body:       modBody,
	}, nil
}

// isGRPCContentType reports whether the Content-Type indicates a gRPC request.
func isGRPCContentType(ct string) bool {
	ct = strings.TrimSpace(ct)
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// isNoBodyStatus returns true for HTTP status codes that must not include a
// message body per RFC 9110 §6.4.1: 1xx (informational), 204 (No Content),
// 205 (Reset Content), and 304 (Not Modified).
func isNoBodyStatus(code int) bool {
	return (code >= 100 && code < 200) || code == 204 || code == 205 || code == 304
}
