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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
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

	// tlsMu protects Transport.DialTLSContext from concurrent access
	// when SetTLSTransport is called while requests are in flight.
	tlsMu sync.RWMutex

	// grpcHandler processes gRPC flow recording when Content-Type: application/grpc
	// is detected. If nil, gRPC streams are recorded as plain HTTP/2.
	grpcHandler *protogrpc.Handler

	// pluginEngine dispatches Starlark plugin hooks during HTTP/2 stream processing.
	// If nil, no plugin hooks are invoked.
	pluginEngine *plugin.Engine

	// detector performs technology stack detection on HTTP responses.
	// If nil, fingerprinting is skipped.
	detector *fingerprint.Detector
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
	}
}

// SetTLSTransport configures the TLS transport used for upstream TLS connections.
// When set, the handler uses this transport (e.g. uTLS with browser fingerprinting)
// instead of the standard crypto/tls library. The transport's DialTLSContext on
// the underlying gohttp.Transport is reconfigured to route TLS handshakes through
// the provided TLSTransport. If t is nil, the default crypto/tls behavior is restored.
//
// This method is safe to call concurrently with in-flight requests.
func (h *Handler) SetTLSTransport(t httputil.TLSTransport) {
	h.tlsMu.Lock()
	defer h.tlsMu.Unlock()

	if t == nil {
		h.Transport.DialTLSContext = nil
		return
	}
	h.Transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := (&net.Dialer{Timeout: 30 * time.Second}).DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("dial upstream %s: %w", addr, err)
		}

		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("parse upstream address %s: %w", addr, err)
		}

		tlsConn, negotiatedProto, err := t.TLSConnect(ctx, rawConn, host)
		if err != nil {
			rawConn.Close()
			return nil, fmt.Errorf("TLS connect to %s: %w", addr, err)
		}

		// Log ALPN negotiation result for debugging protocol mismatches.
		h.Logger.Debug("upstream TLS handshake complete",
			"addr", addr,
			"negotiated_protocol", negotiatedProto,
		)

		return tlsConn, nil
	}
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
func (h *Handler) serveHTTP2(ctx context.Context, conn net.Conn, connectAuthority string, tlsMeta tlsMetadata) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Track all in-flight request goroutines so we can wait for them
	// before returning (and closing the connection).
	//
	// We use an atomic counter + mutex/cond instead of sync.WaitGroup
	// because http2.Server.ServeConn dispatches handler goroutines
	// internally, and wg.Add(1) inside the handler has a race window
	// with wg.Wait() after ServeConn returns. (F-2)
	var active atomic.Int64
	var mu sync.Mutex
	cond := sync.NewCond(&mu)

	h2Server := &http2.Server{}
	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, req *gohttp.Request) {
		active.Add(1)
		defer func() {
			if active.Add(-1) == 0 {
				cond.Signal()
			}
		}()
		h.handleStream(ctx, w, req, connID, clientAddr, connectAuthority, tlsMeta, logger)
	})

	// http2.Server.ServeConn blocks until the connection is closed or an error occurs.
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

	opts := &http2.ServeConnOpts{
		Handler: handler,
		Context: ctx,
	}
	h2Server.ServeConn(conn, opts)

	// Wait for all in-flight handlers to complete before returning,
	// so that flow recording finishes before the connection is closed.
	// We must check after ServeConn returns because new handlers cannot
	// be dispatched after that point, making the counter monotonically
	// decreasing from here. (F-2)
	mu.Lock()
	for active.Load() > 0 {
		cond.Wait()
	}
	mu.Unlock()

	logger.Debug("HTTP/2 connection closed")
	return nil
}

// streamContext holds the state for a single HTTP/2 stream being proxied.
type streamContext struct {
	ctx              context.Context
	w                gohttp.ResponseWriter
	req              *gohttp.Request
	connID           string
	clientAddr       string
	connectAuthority string
	tlsMeta          tlsMetadata
	logger           *slog.Logger
	start            time.Time

	reqBody      []byte
	reqTruncated bool
	reqURL       *url.URL
	connInfo     *flow.ConnectionInfo
	srp          sendRecordParams

	// Plugin state shared across hooks for this stream.
	pluginConnInfo *plugin.ConnInfo
	txCtx          map[string]any
}

// handleStream proxies a single HTTP/2 stream to the upstream server
// and records the flow.
func (h *Handler) handleStream(
	ctx context.Context,
	w gohttp.ResponseWriter,
	req *gohttp.Request,
	connID, clientAddr, connectAuthority string,
	tlsMeta tlsMetadata,
	logger *slog.Logger,
) {
	sc := &streamContext{
		ctx:              ctx,
		w:                w,
		req:              req,
		connID:           connID,
		clientAddr:       clientAddr,
		connectAuthority: connectAuthority,
		tlsMeta:          tlsMeta,
		logger:           logger,
		start:            time.Now(),
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

	outReq = h.runServerPluginHook(sc, outReq)

	isGRPC := h.grpcHandler != nil && isGRPCContentType(sc.req.Header.Get("Content-Type"))

	var sendResult *sendRecordResult
	if !isGRPC {
		sendResult = h.recordSendWithVariant(sc.ctx, sc.srp, &snap, sc.logger)
	}

	fwd, ok := h.forwardUpstream(sc, outReq, sendResult)
	if !ok {
		return
	}

	respSnap := snapshotResponse(fwd.resp.StatusCode, fwd.resp.Header, fwd.respBody)

	resp, fullRespBody, ok := h.handleResponseIntercept(sc, fwd.resp, fwd.respBody)
	if !ok {
		return
	}

	resp, fullRespBody = h.runResponsePluginHooks(sc, resp, fullRespBody)

	// Save unmasked body for recording before output filter masks it.
	// Deep copy to guard against future FilterOutput implementations that
	// may modify the underlying array in place (S-2).
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

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

	h.recordStreamResponse(sc, isGRPC, sendResult, resp, rawRespBody, fwd.serverAddr, duration, tlsCertSubject, &respSnap, fwd.sendMs, fwd.waitMs, fwd.receiveMs)

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
func (h *Handler) resolveSchemeAndHost(sc *streamContext) {
	scheme := "http"
	if sc.connectAuthority != "" {
		scheme = "https"
	}
	host := sc.req.Host
	if host == "" && sc.connectAuthority != "" {
		host = sc.connectAuthority
	}
	if sc.req.URL.Host == "" {
		sc.req.URL.Host = host
	}
	if sc.req.URL.Scheme == "" {
		sc.req.URL.Scheme = scheme
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
		start:        sc.start,
		connInfo:     sc.connInfo,
		req:          sc.req,
		reqURL:       sc.reqURL,
		reqBody:      recordBody,
		reqTruncated: sc.reqTruncated,
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
	return true
}

// checkSafetyFilter enforces safety filter rules. Returns true if the request was blocked.
// NOTE: HTTP/2 blocked flow recording is not implemented yet (consistent with checkTargetScope/checkRateLimit).
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
	return true
}

// writeSafetyFilterResponse writes a 403 Forbidden response for safety filter violations.
func writeSafetyFilterResponse(w gohttp.ResponseWriter, violation *safety.InputViolation) {
	body := proxy.BuildSafetyFilterResponseBody(violation)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Blocked-By", "yorishiro-proxy")
	w.Header().Set("X-Block-Reason", "safety_filter")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(gohttp.StatusForbidden)
	w.Write(body)
}

// checkRateLimit enforces rate limits. Returns true if the request was blocked.
func (h *Handler) checkRateLimit(sc *streamContext) bool {
	if h.RateLimiter == nil || !h.RateLimiter.HasLimits() {
		return false
	}
	if h.RateLimiter.Allow(sc.req.URL.Hostname()) {
		return false
	}
	writeRateLimitResponse(sc.w)
	sc.logger.Info("HTTP/2 request blocked by rate limit",
		"host", sc.req.URL.Host)
	return true
}

// writeRateLimitResponse writes a 429 Too Many Requests response for rate limiting.
func writeRateLimitResponse(w gohttp.ResponseWriter) {
	body := `{"error":"rate limit exceeded","blocked_by":"rate_limit"}`
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Blocked-By", "yorishiro-proxy")
	w.Header().Set("X-Block-Reason", "rate_limit")
	w.Header().Set("Retry-After", "1")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(gohttp.StatusTooManyRequests)
	w.Write([]byte(body))
}

// writeScopeBlockResponse writes a 403 Forbidden response for scope violations.
func writeScopeBlockResponse(w gohttp.ResponseWriter, target, reason string) {
	body := fmt.Sprintf(`{"error":"blocked by target scope","target":%q,"reason":%q}`,
		target, reason)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
	w.WriteHeader(gohttp.StatusForbidden)
	w.Write([]byte(body))
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
	sc.req, sc.reqBody, terminated = h.dispatchOnReceiveFromClient(sc.ctx, sc.w, sc.req, sc.reqBody, pluginConnInfo, txCtx, sc.logger)
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
		sc.w.WriteHeader(gohttp.StatusBadGateway)
		return nil, false
	}
	for key, vals := range sc.req.Header {
		outReq.Header[key] = vals
	}
	removeHTTP2HopByHop(outReq.Header)
	return outReq, true
}

// handleRequestIntercept processes request interception. Returns the (possibly
// modified) outbound request and false if the request was dropped/blocked.
func (h *Handler) handleRequestIntercept(sc *streamContext, outReq *gohttp.Request, snap *requestSnapshot) (*gohttp.Request, bool) {
	action, intercepted := h.interceptRequest(sc.ctx, sc.req, sc.srp.reqBody, sc.logger)
	if !intercepted {
		return outReq, true
	}
	switch action.Type {
	case intercept.ActionDrop:
		h.recordInterceptDrop(sc.ctx, sc.srp, sc.logger)
		sc.w.WriteHeader(gohttp.StatusBadGateway)
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
		sc.w.WriteHeader(gohttp.StatusBadRequest)
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

// runServerPluginHook dispatches the on_before_send_to_server hook.
func (h *Handler) runServerPluginHook(sc *streamContext, outReq *gohttp.Request) *gohttp.Request {
	outReq, body := h.dispatchOnBeforeSendToServer(sc.ctx, outReq, sc.reqBody, sc.pluginConnInfo, sc.txCtx, sc.logger)
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
}

func (h *Handler) forwardUpstream(sc *streamContext, outReq *gohttp.Request, sendResult *sendRecordResult) (*forwardUpstreamResult, bool) {
	sendStart := time.Now()
	resp, serverAddr, timing, err := h.roundTripWithTrace(outReq)
	if err != nil {
		sc.logger.Error("HTTP/2 upstream request failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		sc.w.WriteHeader(gohttp.StatusBadGateway)
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
		sc.w.WriteHeader(gohttp.StatusBadGateway)
		sc.logger.Info("intercepted HTTP/2 response dropped",
			"method", sc.req.Method, "url", sc.reqURL.String(), "status", resp.StatusCode)
		return nil, nil, false
	case intercept.ActionModifyAndForward:
		var modErr error
		resp, fullRespBody, modErr = applyResponseModifications(resp, action, fullRespBody)
		if modErr != nil {
			sc.logger.Error("HTTP/2 response intercept modification failed", "error", modErr)
			sc.w.WriteHeader(gohttp.StatusBadGateway)
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
	resp, fullRespBody = h.dispatchOnReceiveFromServer(sc.ctx, resp, fullRespBody, sc.req, sc.pluginConnInfo, sc.txCtx, sc.logger)
	resp, fullRespBody = h.dispatchOnBeforeSendToClient(sc.ctx, resp, fullRespBody, sc.req, sc.pluginConnInfo, sc.txCtx, sc.logger)
	return resp, fullRespBody
}

// writeResponseToClient writes the HTTP response headers, body, and trailers
// to the client. For HTTP/2, trailers are sent as a HEADERS frame with
// END_STREAM after the body. Go's net/http server handles this automatically
// when trailer keys are declared via the "Trailer" header before WriteHeader,
// and trailer values are set on the ResponseWriter's Header after the body
// is written.
func writeResponseToClient(sc *streamContext, resp *gohttp.Response, body []byte) {
	// Declare trailer keys before WriteHeader so Go's HTTP/2 server knows to
	// send them as a trailing HEADERS frame.
	var trailerKeys []string
	for key := range resp.Trailer {
		trailerKeys = append(trailerKeys, key)
	}
	if len(trailerKeys) > 0 {
		sc.w.Header().Set("Trailer", strings.Join(trailerKeys, ", "))
	}

	for key, vals := range resp.Header {
		for _, val := range vals {
			sc.w.Header().Add(key, val)
		}
	}
	sc.w.WriteHeader(resp.StatusCode)
	if len(body) > 0 {
		if _, err := sc.w.Write(body); err != nil {
			sc.logger.Debug("HTTP/2 failed to write response body", "error", err)
		}
	}

	// Set trailer values after body write. Go's HTTP/2 server sends these as
	// a HEADERS(END_STREAM) frame when the handler returns.
	for key, vals := range resp.Trailer {
		for _, val := range vals {
			sc.w.Header().Set(gohttp.TrailerPrefix+key, val)
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
func (h *Handler) recordStreamResponse(sc *streamContext, isGRPC bool, sendResult *sendRecordResult, resp *gohttp.Response, fullRespBody []byte, serverAddr string, duration time.Duration, tlsCertSubject string, respSnap *responseSnapshot, sendMs, waitMs, receiveMs *int64) {
	if isGRPC {
		h.recordGRPCFlow(sc, resp, fullRespBody, serverAddr, duration, tlsCertSubject)
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
		}, respSnap, sc.logger)
	}
}

// recordGRPCFlow records a gRPC session via the gRPC handler.
func (h *Handler) recordGRPCFlow(sc *streamContext, resp *gohttp.Response, fullRespBody []byte, serverAddr string, duration time.Duration, tlsCertSubject string) {
	if !h.shouldCapture(sc.req.Method, sc.reqURL) {
		return
	}
	var trailers map[string][]string
	if resp.Trailer != nil {
		trailers = make(map[string][]string, len(resp.Trailer))
		for k, vals := range resp.Trailer {
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
	}
	if err := h.grpcHandler.RecordSession(sc.ctx, info); err != nil {
		sc.logger.Error("gRPC flow recording failed", "error", err)
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
func (h *Handler) interceptRequest(ctx context.Context, req *gohttp.Request, body []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchRequestRules(req.Method, req.URL, req.Header)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("HTTP/2 request intercepted", "method", req.Method, "url", req.URL.String(), "matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.Enqueue(req.Method, req.URL, req.Header, body, matchedRules)
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

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, resp.Header)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("HTTP/2 response intercepted",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, req.URL, resp.StatusCode, resp.Header, body, matchedRules,
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
}
