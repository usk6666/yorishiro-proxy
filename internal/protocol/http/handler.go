package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// maxRawCaptureSize limits the size of raw request/response bytes captured.
// This prevents excessive memory use for very large requests.
const maxRawCaptureSize = 2 << 20 // 2MB

const defaultRequestTimeout = 60 * time.Second

// httpMethods contains the common HTTP method prefixes used for protocol detection.
var httpMethods = [][]byte{
	[]byte("GET "),
	[]byte("POST "),
	[]byte("PUT "),
	[]byte("DELETE "),
	[]byte("HEAD "),
	[]byte("OPTIONS "),
	[]byte("PATCH "),
	[]byte("CONNECT "),
}

// hop-by-hop headers that should not be forwarded.
var hopByHopHeaders = []string{
	"Connection",
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Proxy-Connection",
	"Te",
	"Trailer",
	"Transfer-Encoding",
	"Upgrade",
}

// H2Handler defines the interface for delegating HTTP/2 connections
// after TLS ALPN negotiation selects "h2". This avoids a circular import
// between the HTTP/1.x and HTTP/2 packages.
type H2Handler interface {
	HandleH2(ctx context.Context, tlsConn *tls.Conn, connectAuthority string, tlsVersion, tlsCipher, tlsALPN string) error
}

// Handler processes HTTP/1.x connections.
type Handler struct {
	proxy.HandlerBase

	issuer            *cert.Issuer
	requestTimeoutNs  atomic.Int64 // nanoseconds; read/written atomically
	passthrough       *proxy.PassthroughList
	transformPipeline *rules.Pipeline
	h2Handler         H2Handler
	grpcWebHandler    *grpcweb.Handler
	tlsTransport      httputil.TLSTransport
	detector          *fingerprint.Detector
	connPool          *ConnPool
	upstreamRouter    *UpstreamRouter
}

// NewHandler creates a new HTTP handler with flow recording.
// If issuer is non-nil, CONNECT requests are handled for HTTPS MITM;
// otherwise CONNECT requests receive a 501 Not Implemented response.
func NewHandler(store flow.Writer, issuer *cert.Issuer, logger *slog.Logger) *Handler {
	return &Handler{
		HandlerBase: proxy.HandlerBase{
			Store:     store,
			Transport: proxy.NewDefaultTransport(),
			Logger:    logger,
		},
		issuer: issuer,
	}
}

// SetRequestTimeout sets the timeout for reading HTTP request headers.
// The value is stored atomically so it can be changed concurrently
// while connections are being processed.
func (h *Handler) SetRequestTimeout(d time.Duration) {
	h.requestTimeoutNs.Store(int64(d))
}

// RequestTimeout returns the effective request timeout.
// If no timeout has been explicitly set, it returns the default (60s).
func (h *Handler) RequestTimeout() time.Duration {
	return h.effectiveRequestTimeout()
}

// SetPassthroughList sets the TLS passthrough list used to determine which
// CONNECT destinations should bypass MITM interception. When a CONNECT target
// matches a pattern in the list, the proxy relays encrypted bytes directly
// without performing a TLS handshake.
func (h *Handler) SetPassthroughList(pl *proxy.PassthroughList) {
	h.passthrough = pl
}

// PassthroughList returns the handler's current TLS passthrough list, or nil.
func (h *Handler) PassthroughList() *proxy.PassthroughList {
	return h.passthrough
}

// SetTransformPipeline sets the auto-transform rule pipeline used to
// automatically modify requests and responses passing through the proxy.
// When set, matching rules are applied to request headers/body before upstream
// forwarding and to response headers/body before client delivery.
func (h *Handler) SetTransformPipeline(pipeline *rules.Pipeline) {
	h.transformPipeline = pipeline
}

// TransformPipeline returns the handler's current transform pipeline, or nil.
func (h *Handler) TransformPipeline() *rules.Pipeline {
	return h.transformPipeline
}

// SetH2Handler sets the HTTP/2 handler used for connections where ALPN
// negotiates "h2" during the TLS handshake in a CONNECT tunnel.
func (h *Handler) SetH2Handler(handler H2Handler) {
	h.h2Handler = handler
}

// SetGRPCWebHandler sets the gRPC-Web handler used for gRPC-Web-specific
// flow recording. When set, requests with Content-Type: application/grpc-web*
// are forwarded as-is and recorded as gRPC-Web sessions with parsed
// service/method metadata instead of plain HTTP/1.x flows.
func (h *Handler) SetGRPCWebHandler(handler *grpcweb.Handler) {
	h.grpcWebHandler = handler
}

// SetTLSTransport sets the TLS transport used for upstream HTTPS connections.
// When set, the transport's TLSConnect method is used instead of Go's default
// crypto/tls, enabling uTLS fingerprint spoofing.
func (h *Handler) SetTLSTransport(t httputil.TLSTransport) {
	h.tlsTransport = t
}

// TLSTransport returns the handler's current TLS transport, or nil.
func (h *Handler) TLSTransport() httputil.TLSTransport {
	return h.tlsTransport
}

// SetDetector sets the fingerprint detector for technology stack detection on
// HTTP responses. When set, response headers and body are analyzed during flow
// recording and the results are stored as flow tags.
func (h *Handler) SetDetector(d *fingerprint.Detector) {
	h.detector = d
}

// Detector returns the handler's current fingerprint detector, or nil.
func (h *Handler) Detector() *fingerprint.Detector {
	return h.detector
}

// SetConnPool sets the connection pool used for upstream HTTP/1.x connections.
// When set, the ConnPool is used by the independent HTTP/1.x engine to dial
// upstream servers.
func (h *Handler) SetConnPool(pool *ConnPool) {
	h.connPool = pool
}

// ConnPool returns the handler's current connection pool, or nil.
func (h *Handler) ConnPool() *ConnPool {
	return h.connPool
}

// SetUpstreamRouter sets the upstream router used for request forwarding.
// When set, requests are forwarded via the UpstreamRouter which handles
// ALPN-based routing to H1/H2 transports.
func (h *Handler) SetUpstreamRouter(r *UpstreamRouter) {
	h.upstreamRouter = r
}

// UpstreamRouter returns the handler's current upstream router, or nil.
func (h *Handler) GetUpstreamRouter() *UpstreamRouter {
	return h.upstreamRouter
}

// effectiveTLSTransport returns the configured TLS transport, falling back to
// a StandardTransport. The InsecureSkipVerify setting is inherited from the
// handler's base transport TLS config (set via SetInsecureSkipVerify).
// Defaults to secure (InsecureSkipVerify: false) when not explicitly configured.
func (h *Handler) effectiveTLSTransport() httputil.TLSTransport {
	if h.tlsTransport != nil {
		return h.tlsTransport
	}
	insecure := false
	if h.Transport != nil && h.Transport.TLSClientConfig != nil {
		insecure = h.Transport.TLSClientConfig.InsecureSkipVerify
	}
	return &httputil.StandardTransport{InsecureSkipVerify: insecure}
}

// effectiveUpstreamRouter returns the configured UpstreamRouter or builds one
// from the ConnPool and TLS transport.
func (h *Handler) effectiveUpstreamRouter() *UpstreamRouter {
	if h.upstreamRouter != nil {
		return h.upstreamRouter
	}
	pool := h.connPool
	if pool == nil {
		pool = &ConnPool{
			TLSTransport:   h.effectiveTLSTransport(),
			UpstreamProxy:  h.GetUpstreamProxy(),
			DialViaProxy:   proxy.DialViaUpstreamProxy,
			RedactProxyURL: proxy.RedactProxyURL,
		}
	}
	return &UpstreamRouter{
		H1:   &H1Transport{},
		Pool: pool,
	}
}

// Issuer returns the handler's TLS certificate issuer, or nil if not configured.
func (h *Handler) Issuer() *cert.Issuer {
	return h.issuer
}

// IsPassthrough checks if the given hostname is in the TLS passthrough list.
// Returns false if no passthrough list is configured.
func (h *Handler) IsPassthrough(hostname string) bool {
	return h.passthrough != nil && h.passthrough.Contains(hostname)
}

// UpstreamProxy returns the current upstream proxy URL, or nil if not set.
// This is a convenience alias for GetUpstreamProxy from HandlerBase.
func (h *Handler) UpstreamProxy() *url.URL {
	return h.GetUpstreamProxy()
}

func (h *Handler) effectiveRequestTimeout() time.Duration {
	if d := time.Duration(h.requestTimeoutNs.Load()); d > 0 {
		return d
	}
	return defaultRequestTimeout
}

// Name returns the protocol name.
func (h *Handler) Name() string {
	return "HTTP/1.x"
}

// Detect checks if the peeked bytes look like an HTTP request.
func (h *Handler) Detect(peek []byte) bool {
	for _, method := range httpMethods {
		if bytes.HasPrefix(peek, method) {
			return true
		}
	}
	return false
}

// connLogger returns the connection-scoped logger from context,
// falling back to the handler's logger.
func (h *Handler) connLogger(ctx context.Context) *slog.Logger {
	return h.ConnLogger(ctx)
}

// Handle processes HTTP connections in a loop (keep-alive support).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)

	// Watch for context cancellation and interrupt blocking reads.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		conn.SetReadDeadline(time.Now())
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read deadline for request header reading (Slowloris protection).
		if timeout := h.effectiveRequestTimeout(); timeout > 0 {
			conn.SetReadDeadline(time.Now().Add(timeout))
		}

		req, err := parser.ParseRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read request: %w", err)
		}

		// Log any detected anomalies (replaces smuggling detection).
		logAnomalyWarnings(h.Logger, req.Anomalies, req.Method, req.RequestURI)

		// Reset deadline after successful read.
		conn.SetReadDeadline(time.Time{})

		// CONNECT method starts HTTPS MITM tunnel.
		if req.Method == "CONNECT" {
			return h.handleCONNECT(ctx, conn, req)
		}

		if err := h.handleRequest(ctx, conn, req); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

func (h *Handler) handleRequest(ctx context.Context, conn net.Conn, req *parser.RawRequest) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Parse and normalize request URL.
	reqURL := parseRequestURL(ctx, req, "http")

	// Target scope enforcement (before WebSocket — S-1: CWE-863).
	if blocked, reason := h.checkTargetScope(reqURL); blocked {
		h.writeBlockedResponse(conn, reqURL.Hostname(), reason, logger)
		h.recordBlockedSession(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, "target_scope", nil, logger)
		return nil
	}

	// Rate limit enforcement (after target scope, before WebSocket).
	if denial := h.checkRateLimit(reqURL.Hostname()); denial != nil {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedSessionWithTags(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, "rate_limit", nil, denial.Tags(), logger)
		return nil
	}

	// WebSocket upgrade: check using raw headers.
	if isWebSocketUpgradeRaw(req.Headers) {
		return h.handleWebSocket(ctx, conn, req, reqURL)
	}

	bodyResult := readAndCaptureBody(req, logger)

	// Safety filter enforcement.
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, reqURL.String(), req.Headers); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedSession(ctx, req, reqURL, bodyResult.recordBody, req.RawBytes, bodyResult.truncated, req.Anomalies, start, connID, clientAddr, "safety_filter", violation, logger)
			return nil
		}
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", proxy.TruncateForLog(violation.MatchedOn, 256))
	}

	removeHopByHopHeadersRaw(&req.Headers)

	// gRPC-Web detection: after safety filter and hop-by-hop removal.
	// gRPC-Web requests are forwarded as-is and recorded via the gRPC-Web handler.
	if h.isGRPCWebRequest(req.Headers) {
		return h.handleGRPCWeb(ctx, conn, req, reqURL, bodyResult.recordBody, false, nil, logger)
	}

	// Build send record params for progressive recording.
	sp := sendRecordParams{
		connID:       connID,
		clientAddr:   clientAddr,
		protocol:     socks5Protocol(ctx, "HTTP/1.x"),
		scheme:       "http",
		start:        start,
		tags:         mergeSOCKS5Tags(ctx, anomalyTags(req.Anomalies)),
		connInfo:     &flow.ConnectionInfo{ClientAddr: clientAddr},
		req:          req,
		reqURL:       reqURL,
		reqBody:      bodyResult.recordBody,
		rawRequest:   req.RawBytes,
		reqTruncated: bodyResult.truncated,
	}

	// Snapshot headers/body before intercept/transform for variant recording.
	snap := snapshotRawRequest(req.Headers, bodyResult.recordBody)

	iResult := h.applyIntercept(ctx, conn, req, reqURL, bodyResult.recordBody, req.RawBytes, logger)
	if iResult.Dropped {
		sp.reqBody = iResult.RecordBody
		h.recordInterceptDrop(ctx, sp, logger)
		return nil
	}
	req = iResult.Req
	bodyResult.recordBody = iResult.RecordBody

	// Re-derive reqURL after intercept — the intercept action may have
	// overridden the URL (CP-8). Use the explicitly returned ModURL when
	// available; otherwise re-parse from the (potentially modified) request.
	if iResult.ModURL != nil {
		reqURL = iResult.ModURL
	} else {
		reqURL = parseRequestURL(ctx, req, "http")
	}
	sp.reqURL = reqURL

	// Raw mode: bypass UpstreamRouter and forward raw bytes directly.
	if iResult.IsRaw {
		return h.handleRawForward(ctx, conn, req, reqURL, iResult, sp, &snap, start, logger)
	}

	bodyResult.recordBody = h.applyTransform(req, reqURL, bodyResult.recordBody)

	sp.reqBody = bodyResult.recordBody

	// Progressive recording: record send before forwarding.
	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	sendStart := time.Now()
	fwd, err := h.forwardUpstream(ctx, conn, req, reqURL, reqURL.Scheme == "https", logger)
	if err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}

	// SSE detection.
	if isSSEResponseRaw(fwd.resp) {
		sendResult.tags = addSSETags(sendResult.tags)
		return h.handleSSEStream(ctx, conn, req, reqURL, fwd, start, sendResult, logger)
	}

	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	// Snapshot response before intercept for variant recording.
	respSnap := snapshotRawResponse(fwd.resp.StatusCode, fwd.resp.Headers, fullRespBody)

	// Response intercept.
	rir := h.applyInterceptResponse(ctx, conn, req, reqURL, fwd.resp, fullRespBody, logger)
	if rir.dropped {
		return nil
	}
	fwd.resp, fullRespBody = rir.resp, rir.body

	// Serialize raw response for recording.
	rawResponse := serializeRawResponseBytes(fwd.resp, fullRespBody)
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

	// Output filter: mask sensitive data.
	fullRespBody, fwd.resp.Headers = h.ApplyOutputFilter(fullRespBody, fwd.resp.Headers, logger)

	if err := writeRawResponse(conn, fwd.resp, fullRespBody, rir.autoContentLength); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	// Progressive recording: record receive.
	duration := time.Since(start)
	sendMs, waitMs, receiveMs := httputil.ComputeTiming(sendStart, fwd.timing, receiveEnd)

	h.recordReceiveWithVariant(ctx, sendResult, receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  fwd.serverAddr,
		resp:        fwd.resp,
		rawResponse: rawResponse,
		respBody:    rawRespBody,
		sendMs:      sendMs,
		waitMs:      waitMs,
		receiveMs:   receiveMs,
	}, &respSnap, logger)

	logHTTPRequest(logger, req.Method, reqURL.String(), fwd.resp.StatusCode, duration)
	return nil
}

// parseRequestURL constructs a full URL from the raw request, normalizing
// it for forward proxy use. When a forwarding target is present in the
// context, it overrides the Host.
func parseRequestURL(ctx context.Context, req *parser.RawRequest, defaultScheme string) *url.URL {
	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		u = &url.URL{Path: req.RequestURI}
	}

	host := req.Headers.Get("Host")
	if u.Host == "" {
		u.Host = host
	}
	if u.Scheme == "" {
		u.Scheme = defaultScheme
	}

	// TCP forwarding: override the host with the actual upstream target.
	if target, ok := proxy.ForwardTargetFromContext(ctx); ok {
		u.Host = target
		req.Headers.Set("Host", target)
	}

	return u
}

// requestBodyResult holds the result of reading and capturing a request body.
type requestBodyResult struct {
	recordBody []byte
	truncated  bool
}

// readAndCaptureBody reads the full request body and returns it for recording
// (truncated to MaxBodySize if necessary). After this call the request's Body
// reader is replaced with a re-readable copy.
//
// The parser already decodes chunked Transfer-Encoding, so the body is always
// plain decoded data. When the request had chunked TE (which will be stripped
// by hop-by-hop header removal), a Content-Length header is added to reflect
// the actual body size.
func readAndCaptureBody(req *parser.RawRequest, logger *slog.Logger) requestBodyResult {
	if req.Body == nil {
		return requestBodyResult{}
	}

	fullBody, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Warn("failed to read request body", "error", err)
	}

	// If the request used chunked TE, add Content-Length since TE will be
	// removed by hop-by-hop header stripping. The body is already decoded
	// by the parser's dechunkedReader.
	if parser.IsChunked(req.Headers) && len(fullBody) > 0 {
		req.Headers.Del("Content-Length")
		req.Headers.Set("Content-Length", fmt.Sprintf("%d", len(fullBody)))
	}

	req.Body = bytes.NewReader(fullBody)

	recordBody := fullBody
	var truncated bool
	if len(fullBody) > int(config.MaxBodySize) {
		recordBody = fullBody[:int(config.MaxBodySize)]
		truncated = true
	}
	return requestBodyResult{recordBody: recordBody, truncated: truncated}
}

// shouldCapture checks the capture scope to determine whether a request
// should be recorded. Returns true if no scope is configured.
func (h *Handler) shouldCapture(method string, u *url.URL) bool {
	return h.ShouldCapture(method, u)
}

func removeHopByHopHeadersRaw(headers *parser.RawHeaders) {
	for _, name := range hopByHopHeaders {
		headers.Del(name)
	}
}

// forwardResult holds the result of forwarding a request upstream.
type forwardResult struct {
	resp       *parser.RawResponse
	serverAddr string
	timing     *httputil.RoundTripTiming
}

// forwardUpstream sends the request to the upstream server via the
// UpstreamRouter and returns the response. On failure, it writes a
// 502 Bad Gateway to the client connection.
func (h *Handler) forwardUpstream(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, useTLS bool, logger *slog.Logger) (*forwardResult, error) {
	router := h.effectiveUpstreamRouter()

	// Determine upstream address and hostname.
	host := reqURL.Host
	if host == "" {
		host = req.Headers.Get("Host")
	}
	addr := host
	hostname := host

	// Add default port if not specified.
	if _, _, err := net.SplitHostPort(addr); err != nil {
		if useTLS {
			addr = addr + ":443"
		} else {
			addr = addr + ":80"
		}
	} else {
		hostname, _, _ = net.SplitHostPort(addr)
	}

	// Build the request for upstream. Use relative URI for HTTPS, absolute for HTTP.
	outReq := cloneRequestForUpstream(req, reqURL, useTLS)

	result, err := router.RoundTrip(ctx, outReq, addr, useTLS, hostname)
	if err != nil {
		logger.Error("upstream request failed", "method", req.Method, "url", reqURL.String(), "error", err)
		writeHTTPError(conn, statusBadGateway, logger)
		return nil, fmt.Errorf("upstream request: %w", err)
	}

	return &forwardResult{
		resp:       result.Response,
		serverAddr: result.ServerAddr,
		timing:     result.Timing,
	}, nil
}

// cloneRequestForUpstream creates a copy of the request suitable for upstream
// forwarding. The RequestURI is always normalized to origin-form (path+query)
// because upstream connections use CONNECT tunneling for both HTTP and HTTPS.
func cloneRequestForUpstream(req *parser.RawRequest, reqURL *url.URL, useTLS bool) *parser.RawRequest {
	out := &parser.RawRequest{
		Method:     req.Method,
		RequestURI: reqURL.RequestURI(),
		Proto:      req.Proto,
		Headers:    req.Headers.Clone(),
		Body:       req.Body,
	}

	return out
}

// readResponseBody reads the full response body (up to MaxBodySize) and applies
// response transforms if configured.
//
// The parser already decodes chunked Transfer-Encoding, so the body is always
// plain decoded data.
func (h *Handler) readResponseBody(resp *parser.RawResponse, logger *slog.Logger) []byte {
	if resp.Body == nil {
		return nil
	}
	fullBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if err != nil {
		logger.Warn("failed to read response body", "error", err)
	}
	// Close the body to release the underlying connection. When the body
	// is truncated by LimitReader, the reader may not have reached EOF,
	// so explicit Close is required to avoid connection leaks (CP-9).
	if closer, ok := resp.Body.(io.Closer); ok {
		closer.Close()
	}

	if h.transformPipeline != nil {
		kv := rawHeadersToKeyValues(resp.Headers)
		kv, fullBody = h.transformPipeline.TransformResponse(resp.StatusCode, kv, fullBody)
		resp.Headers = keyValuesToRawHeaders(kv)
	}

	return fullBody
}

// checkTargetScope checks if the request URL is allowed by the target scope.
func (h *Handler) checkTargetScope(u *url.URL) (blocked bool, reason string) {
	if h.TargetScope == nil || !h.TargetScope.HasRules() {
		return false, ""
	}
	allowed, reason := h.TargetScope.CheckURL(u)
	if !allowed {
		return true, reason
	}
	return false, ""
}

// checkTargetScopeHost checks if a hostname:port is allowed by the target scope.
func (h *Handler) checkTargetScopeHost(hostname string, port int) (blocked bool, reason string) {
	if h.TargetScope == nil || !h.TargetScope.HasRules() {
		return false, ""
	}
	allowed, reason := h.TargetScope.CheckTarget("", hostname, port, "")
	if !allowed {
		return true, reason
	}
	return false, ""
}

// checkRateLimit checks whether the request is rate limited.
func (h *Handler) checkRateLimit(hostname string) *proxy.RateLimitDenial {
	if h.RateLimiter == nil || !h.RateLimiter.HasLimits() {
		return nil
	}
	return h.RateLimiter.Check(hostname)
}

// writeRateLimitResponse writes a 429 Too Many Requests response.
func (h *Handler) writeRateLimitResponse(conn net.Conn, logger *slog.Logger) {
	body := `{"error":"rate limit exceeded","blocked_by":"rate_limit"}`
	resp := fmt.Sprintf("HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nX-Blocked-By: yorishiro-proxy\r\nX-Block-Reason: rate_limit\r\nRetry-After: 1\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write rate limit response", "error", err)
	}
	logger.Info("request blocked by rate limit")
}

// writeSafetyFilterResponse writes a 403 Forbidden response indicating the
// request was blocked by the safety filter.
func (h *Handler) writeSafetyFilterResponse(conn net.Conn, violation *safety.InputViolation, logger *slog.Logger) {
	body := proxy.BuildSafetyFilterResponseBody(violation)
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nX-Blocked-By: yorishiro-proxy\r\nX-Block-Reason: safety_filter\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write safety filter blocked response", "error", err)
	}
	logger.Info("request blocked by safety filter",
		"rule_id", violation.RuleID, "rule_name", violation.RuleName,
		"target", violation.Target.String(), "matched_on", proxy.TruncateForLog(violation.MatchedOn, 256))
}

// writeBlockedResponse writes a 403 Forbidden response.
func (h *Handler) writeBlockedResponse(conn net.Conn, target, reason string, logger *slog.Logger) {
	body := fmt.Sprintf(`{"error":"blocked by target scope","target":%q,"reason":%q}`, target, reason)
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write target scope blocked response", "error", err)
	}
	logger.Info("request blocked by target scope", "target", target, "reason", reason)
}

// logHTTPRequest logs the completed HTTP request with method, URL, status, and duration.
func logHTTPRequest(logger *slog.Logger, method, urlStr string, statusCode int, duration time.Duration) {
	logger.Info("http request", "method", method, "url", urlStr, "status", statusCode, "duration_ms", duration.Milliseconds())
}

// recordBlockedSession records a blocked request as a flow.
func (h *Handler) recordBlockedSession(ctx context.Context, req *parser.RawRequest, reqURL *url.URL, reqBody, rawRequest []byte, reqTruncated bool, anomalies []parser.Anomaly, start time.Time, connID, clientAddr, blockedBy string, violation *safety.InputViolation, logger *slog.Logger) {
	h.recordBlockedSessionWithTags(ctx, req, reqURL, reqBody, rawRequest, reqTruncated, anomalies, start, connID, clientAddr, blockedBy, violation, nil, logger)
}

// recordBlockedSessionWithTags records a blocked request as a flow with extra tags.
func (h *Handler) recordBlockedSessionWithTags(ctx context.Context, req *parser.RawRequest, reqURL *url.URL, reqBody, rawRequest []byte, reqTruncated bool, anomalies []parser.Anomaly, start time.Time, connID, clientAddr, blockedBy string, violation *safety.InputViolation, extraTags map[string]string, logger *slog.Logger) {
	if h.Store == nil {
		return
	}
	if !h.shouldCapture(req.Method, reqURL) {
		return
	}

	duration := time.Since(start)
	tags := anomalyTags(anomalies)
	if violation != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["safety_rule"] = violation.RuleID
		tags["safety_target"] = violation.Target.String()
	}
	for k, v := range extraTags {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags[k] = v
	}
	fl := &flow.Stream{
		ConnID:    connID,
		Protocol:  "HTTP/1.x",
		Scheme:    "http",
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      tags,
		BlockedBy: blockedBy,
		ConnInfo:  &flow.ConnectionInfo{ClientAddr: clientAddr},
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("blocked flow save failed", "method", req.Method, "url", reqURL.String(), "error", err)
		return
	}
	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     start,
		Method:        req.Method,
		URL:           reqURL,
		Headers:       rawHeadersToMap(req.Headers),
		Body:          reqBody,
		RawBytes:      rawRequest,
		BodyTruncated: reqTruncated,
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
		logger.Error("blocked send message save failed", "error", err)
	}
}

// socks5Protocol returns the protocol string with a "SOCKS5+" prefix if the
// request arrived through a SOCKS5 tunnel.
func socks5Protocol(ctx context.Context, base string) string {
	return proxy.SOCKS5Protocol(ctx, base)
}

// mergeSOCKS5Tags adds SOCKS5 metadata tags to the given tags map.
func mergeSOCKS5Tags(ctx context.Context, tags map[string]string) map[string]string {
	return proxy.MergeSOCKS5Tags(ctx, tags)
}
