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
	gohttp "net/http"
	"net/http/httptrace"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxRawCaptureSize limits the size of raw request/response bytes captured.
// This prevents excessive memory use for very large requests.
const maxRawCaptureSize = 2 << 20 // 2MB

const defaultRequestTimeout = 60 * time.Second

// captureReader wraps an io.Reader and records all bytes read into a buffer.
// It is used to capture raw HTTP request/response bytes as they flow through
// the reader, preserving the exact wire format for smuggling analysis and replay.
type captureReader struct {
	r   io.Reader
	buf bytes.Buffer
}

// Read implements io.Reader, recording bytes into the capture buffer.
func (cr *captureReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 && cr.buf.Len() < maxRawCaptureSize {
		// Limit capture to maxRawCaptureSize to prevent OOM.
		remaining := maxRawCaptureSize - cr.buf.Len()
		if n <= remaining {
			cr.buf.Write(p[:n])
		} else {
			cr.buf.Write(p[:remaining])
		}
	}
	return n, err
}

// Bytes returns a copy of the captured bytes.
func (cr *captureReader) Bytes() []byte {
	if cr.buf.Len() == 0 {
		return nil
	}
	out := make([]byte, cr.buf.Len())
	copy(out, cr.buf.Bytes())
	return out
}

// Reset clears the capture buffer for reuse.
func (cr *captureReader) Reset() {
	cr.buf.Reset()
}

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
	store             session.Store
	issuer            *cert.Issuer
	transport         *gohttp.Transport
	logger            *slog.Logger
	requestTimeoutNs  atomic.Int64 // nanoseconds; read/written atomically
	passthrough       *proxy.PassthroughList
	scope             *proxy.CaptureScope
	targetScope       *proxy.TargetScope
	interceptEngine   *intercept.Engine
	interceptQueue    *intercept.Queue
	transformPipeline *rules.Pipeline
	h2Handler         H2Handler

	// upstreamMu protects upstreamProxy for concurrent access.
	upstreamMu    sync.RWMutex
	upstreamProxy *url.URL
}

// NewHandler creates a new HTTP handler with session recording.
// If issuer is non-nil, CONNECT requests are handled for HTTPS MITM;
// otherwise CONNECT requests receive a 501 Not Implemented response.
func NewHandler(store session.Store, issuer *cert.Issuer, logger *slog.Logger) *Handler {
	return &Handler{
		store:     store,
		issuer:    issuer,
		transport: &gohttp.Transport{},
		logger:    logger,
	}
}

// SetTransport replaces the handler's HTTP transport. This is primarily
// useful for testing, where the upstream server uses a self-signed certificate.
func (h *Handler) SetTransport(t *gohttp.Transport) {
	h.transport = t
}

// SetInsecureSkipVerify configures whether the handler skips TLS certificate
// verification when connecting to upstream servers. When enabled, a warning
// is logged because this disables important security checks.
// This is intended for vulnerability assessments against targets using
// self-signed or expired certificates.
func (h *Handler) SetInsecureSkipVerify(skip bool) {
	if skip {
		h.logger.Warn("upstream TLS certificate verification is disabled — connections to upstream servers will not verify certificates")
		if h.transport.TLSClientConfig == nil {
			h.transport.TLSClientConfig = &tls.Config{
				MinVersion: tls.VersionTLS12,
			}
		}
		h.transport.TLSClientConfig.InsecureSkipVerify = true
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

// SetCaptureScope sets the capture scope used to filter which requests
// are recorded to the session store. If scope is nil, all requests are recorded.
func (h *Handler) SetCaptureScope(scope *proxy.CaptureScope) {
	h.scope = scope
}

// CaptureScope returns the handler's capture scope, or nil if not set.
func (h *Handler) CaptureScope() *proxy.CaptureScope {
	return h.scope
}

// SetTargetScope sets the target scope used to enforce which network targets
// are allowed or blocked. When set, requests to targets outside the scope
// receive a 403 Forbidden response.
func (h *Handler) SetTargetScope(scope *proxy.TargetScope) {
	h.targetScope = scope
}

// TargetScope returns the handler's target scope, or nil if not set.
func (h *Handler) TargetScope() *proxy.TargetScope {
	return h.targetScope
}

// SetInterceptEngine sets the intercept rule engine used to determine which
// requests should be intercepted. When set together with an intercept queue,
// matching requests are held for AI agent review.
func (h *Handler) SetInterceptEngine(engine *intercept.Engine) {
	h.interceptEngine = engine
}

// SetInterceptQueue sets the intercept queue used to hold requests that match
// intercept rules. The queue must be set together with an intercept engine.
func (h *Handler) SetInterceptQueue(queue *intercept.Queue) {
	h.interceptQueue = queue
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

// SetUpstreamProxy configures the upstream proxy for outgoing connections.
// Pass nil to disable the upstream proxy (direct connections).
// This method is safe to call concurrently and updates both the transport's
// Proxy function (for HTTP/HTTPS requests) and the stored URL (for CONNECT tunnels).
func (h *Handler) SetUpstreamProxy(proxyURL *url.URL) {
	h.upstreamMu.Lock()
	defer h.upstreamMu.Unlock()
	h.upstreamProxy = proxyURL
	h.transport.Proxy = proxy.TransportProxyFunc(proxyURL)
}

// UpstreamProxy returns the current upstream proxy URL, or nil if not set.
func (h *Handler) UpstreamProxy() *url.URL {
	h.upstreamMu.RLock()
	defer h.upstreamMu.RUnlock()
	return h.upstreamProxy
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
	return proxy.LoggerFromContext(ctx, h.logger)
}

// Handle processes HTTP connections in a loop (keep-alive support).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	capture := &captureReader{r: conn}
	reader := bufio.NewReader(capture)

	// Watch for context cancellation and interrupt blocking reads.
	// When the proxy is shutting down, ReadRequest may be blocked waiting
	// for the next request on a keep-alive connection. Setting an immediate
	// read deadline causes it to return with a timeout error.
	//
	// Use a child context so the goroutine is reclaimed when the connection
	// handler returns, not only when the parent context is cancelled.
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

		// Mark the capture position before reading the request.
		// After ReadRequest + body read, everything between this mark
		// and the current position (minus remaining buffer) is the raw request.
		captureStart := capture.buf.Len()

		// Check for HTTP request smuggling patterns in raw headers before
		// ReadRequest normalizes them. This is important because Go's
		// ReadRequest strips Content-Length when Transfer-Encoding is
		// present, making post-parse detection impossible.
		smuggling := checkRequestSmuggling(reader, h.logger)

		req, err := gohttp.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			// If the context was cancelled, return the context error
			// instead of the read deadline error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read request: %w", err)
		}

		// Log any detected smuggling patterns.
		logSmugglingWarnings(h.logger, smuggling, req)

		// Reset deadline after successful read.
		conn.SetReadDeadline(time.Time{})

		// CONNECT method starts HTTPS MITM tunnel.
		if req.Method == gohttp.MethodConnect {
			return h.handleCONNECT(ctx, conn, req)
		}

		if err := h.handleRequest(ctx, conn, req, smuggling, capture, captureStart, reader); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

func (h *Handler) handleRequest(ctx context.Context, conn net.Conn, req *gohttp.Request, smuggling *smugglingFlags, capture *captureReader, captureStart int, reader *bufio.Reader) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Ensure absolute URL for forward proxy. This must happen before the
	// target scope check so that the URL has a valid Host for matching.
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// Target scope enforcement: check if the target is allowed before
	// forwarding the request upstream. This MUST happen before the WebSocket
	// upgrade check to prevent WebSocket requests from bypassing scope
	// enforcement (S-1: CWE-863).
	if blocked, reason := h.checkTargetScope(req.URL); blocked {
		h.writeBlockedResponse(conn, req.URL.Hostname(), reason, logger)
		h.recordBlockedSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, logger)
		return nil
	}

	// Check for WebSocket upgrade before processing as normal HTTP.
	// This must happen before hop-by-hop headers are removed.
	if isWebSocketUpgrade(req) {
		return h.handleWebSocket(ctx, conn, req)
	}

	// Read the full request body so the upstream receives uncorrupted data.
	var recordReqBody []byte
	var reqTruncated bool
	if req.Body != nil {
		fullBody, err := io.ReadAll(req.Body)
		if err != nil {
			logger.Warn("failed to read request body", "error", err)
		}
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(fullBody))

		recordReqBody = fullBody
		if len(fullBody) > int(config.MaxBodySize) {
			recordReqBody = fullBody[:int(config.MaxBodySize)]
			reqTruncated = true
		}
	}

	// Extract raw request bytes captured by the captureReader.
	// The raw bytes span from captureStart to the current capture position,
	// minus any bytes buffered by the bufio.Reader (which belong to the next request).
	var rawRequest []byte
	if capture != nil {
		captureEnd := capture.buf.Len()
		buffered := reader.Buffered()
		rawEnd := captureEnd - buffered
		if rawEnd > captureStart && captureStart < capture.buf.Len() {
			rawRequest = make([]byte, rawEnd-captureStart)
			copy(rawRequest, capture.buf.Bytes()[captureStart:rawEnd])
		}
	}

	// Remove hop-by-hop headers.
	removeHopByHopHeaders(req.Header)

	// Intercept check: if an intercept engine and queue are configured,
	// check if the request matches any intercept rules. If so, enqueue
	// the request and block until the AI agent responds with an action.
	if action, intercepted := h.interceptRequest(ctx, conn, req, recordReqBody, logger); intercepted {
		switch action.Type {
		case intercept.ActionDrop:
			// Drop: return 502 to client.
			errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
			if _, writeErr := conn.Write([]byte(errResp)); writeErr != nil {
				logger.Debug("failed to write drop response", "error", writeErr)
			}
			logger.Info("intercepted request dropped", "method", req.Method, "url", req.URL.String())
			return nil
		case intercept.ActionModifyAndForward:
			// Apply modifications to the request.
			var modErr error
			req, modErr = applyInterceptModifications(req, action, recordReqBody)
			if modErr != nil {
				logger.Error("intercept modification failed", "error", modErr)
				errResp := "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
				if _, writeErr := conn.Write([]byte(errResp)); writeErr != nil {
					logger.Debug("failed to write error response", "error", writeErr)
				}
				return nil
			}
			// Update recordReqBody for session recording if body changed.
			if action.OverrideBody != nil {
				recordReqBody = []byte(*action.OverrideBody)
			}
		case intercept.ActionRelease:
			// Continue with the original request.
		}
	}

	// Apply auto-transform rules to the request before forwarding upstream.
	if h.transformPipeline != nil {
		req.Header, recordReqBody = h.transformPipeline.TransformRequest(req.Method, req.URL, req.Header, recordReqBody)
		req.Body = io.NopCloser(bytes.NewReader(recordReqBody))
		req.ContentLength = int64(len(recordReqBody))
	}

	// Forward request upstream.
	outReq := req.WithContext(ctx)
	outReq.RequestURI = ""

	resp, serverAddr, err := roundTripWithTrace(h.transport, outReq)
	if err != nil {
		logger.Error("upstream request failed", "method", req.Method, "url", req.URL.String(), "error", err)
		// Send 502 Bad Gateway to client.
		errResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write([]byte(errResp)); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body with a size limit to prevent OOM (CWE-770).
	fullRespBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if err != nil {
		logger.Warn("failed to read response body", "error", err)
	}

	// Apply auto-transform rules to the response before sending to client.
	if h.transformPipeline != nil {
		resp.Header, fullRespBody = h.transformPipeline.TransformResponse(resp.StatusCode, resp.Header, fullRespBody)
	}

	// Capture raw response bytes by serializing the response as received.
	rawResponse := serializeRawResponse(resp, fullRespBody)

	// Write response back to client (full body).
	if err := writeResponse(conn, resp, fullRespBody); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	// Decompress response body for recording. The raw (potentially compressed)
	// bytes are preserved in rawResponse for wire-level analysis.
	recordRespBody := fullRespBody
	var respTruncated bool
	decompressed := false
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		decoded, err := httputil.DecompressBody(fullRespBody, ce, config.MaxBodySize)
		if err != nil {
			logger.Debug("response body decompression failed, storing as-is", "encoding", ce, "error", err)
		} else {
			recordRespBody = decoded
			decompressed = true
		}
	}
	if len(recordRespBody) > int(config.MaxBodySize) {
		recordRespBody = recordRespBody[:int(config.MaxBodySize)]
		respTruncated = true
	}

	duration := time.Since(start)

	// Record session + messages.
	if h.store != nil && h.shouldCapture(req.Method, req.URL) {
		sess := &session.Session{
			ConnID:      connID,
			Protocol:    "HTTP/1.x",
			SessionType: "unary",
			State:       "complete",
			Timestamp:   start,
			Duration:    duration,
			Tags:        smugglingTags(smuggling),
			ConnInfo: &session.ConnectionInfo{
				ClientAddr: clientAddr,
				ServerAddr: serverAddr,
			},
		}
		if err := h.store.SaveSession(ctx, sess); err != nil {
			logger.Error("session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		} else {
			sendMsg := &session.Message{
				SessionID:     sess.ID,
				Sequence:      0,
				Direction:     "send",
				Timestamp:     start,
				Method:        req.Method,
				URL:           req.URL,
				Headers:       req.Header,
				Body:          recordReqBody,
				RawBytes:      rawRequest,
				BodyTruncated: reqTruncated,
			}
			if err := h.store.AppendMessage(ctx, sendMsg); err != nil {
				logger.Error("send message save failed", "error", err)
			}
			recvMsg := &session.Message{
				SessionID:     sess.ID,
				Sequence:      1,
				Direction:     "receive",
				Timestamp:     start.Add(duration),
				StatusCode:    resp.StatusCode,
				Headers:       httputil.RecordingHeaders(resp.Header, decompressed, len(recordRespBody)),
				Body:          recordRespBody,
				RawBytes:      rawResponse,
				BodyTruncated: respTruncated,
			}
			if err := h.store.AppendMessage(ctx, recvMsg); err != nil {
				logger.Error("receive message save failed", "error", err)
			}
		}
	}

	logger.Info("http request", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration_ms", duration.Milliseconds())

	return nil
}

// serializeRawResponse reconstructs raw HTTP response bytes from the parsed response
// and body. This preserves the status line, headers, and body in wire format.
func serializeRawResponse(resp *gohttp.Response, body []byte) []byte {
	if resp == nil {
		return nil
	}
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, gohttp.StatusText(resp.StatusCode))
	for key, vals := range resp.Header {
		for _, val := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, val)
		}
	}
	buf.WriteString("\r\n")
	if len(body) > 0 {
		remaining := maxRawCaptureSize - buf.Len()
		if len(body) <= remaining {
			buf.Write(body)
		} else if remaining > 0 {
			buf.Write(body[:remaining])
		}
	}
	return buf.Bytes()
}

// shouldCapture checks the capture scope to determine whether a request
// should be recorded. Returns true if no scope is configured.
func (h *Handler) shouldCapture(method string, u *url.URL) bool {
	if h.scope == nil {
		return true
	}
	return h.scope.ShouldCapture(method, u)
}

func removeHopByHopHeaders(header gohttp.Header) {
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// roundTripWithTrace wraps transport.RoundTrip with an httptrace hook to
// capture the remote address of the TCP connection used for the request.
func roundTripWithTrace(transport *gohttp.Transport, req *gohttp.Request) (*gohttp.Response, string, error) {
	var serverAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				serverAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))
	resp, err := transport.RoundTrip(req)
	return resp, serverAddr, err
}

func writeResponse(conn net.Conn, resp *gohttp.Response, body []byte) error {
	w := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(w, "HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, gohttp.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Header.Del("Transfer-Encoding")
	for key, vals := range resp.Header {
		for _, val := range vals {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", key, val); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Flush()
}

// interceptRequest checks if the request matches any intercept rules and,
// if so, enqueues it for AI agent review. It blocks until the agent responds
// or the timeout expires. Returns the action and true if intercepted, or a
// zero-value action and false if not intercepted.
func (h *Handler) interceptRequest(ctx context.Context, conn net.Conn, req *gohttp.Request, body []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.interceptEngine == nil || h.interceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.interceptEngine.MatchRequestRules(req.Method, req.URL, req.Header)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("request intercepted", "method", req.Method, "url", req.URL.String(), "matched_rules", matchedRules)

	id, actionCh := h.interceptQueue.Enqueue(req.Method, req.URL, req.Header, body, matchedRules)
	defer h.interceptQueue.Remove(id) // ensure cleanup on timeout/cancel

	timeout := h.interceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action, true
	case <-timeoutCtx.Done():
		// Timeout or context cancellation.
		behavior := h.interceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			// Proxy shutting down — drop.
			logger.Info("intercepted request cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted request timed out", "id", id, "behavior", string(behavior))
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
// action to the HTTP request. It returns the modified request and an error if
// validation fails (e.g., invalid URL scheme, CRLF injection).
func applyInterceptModifications(req *gohttp.Request, action intercept.InterceptAction, originalBody []byte) (*gohttp.Request, error) {
	// Override method.
	if action.OverrideMethod != "" {
		req.Method = action.OverrideMethod
	}

	// Override URL with scheme validation to prevent SSRF (CWE-918).
	if action.OverrideURL != "" {
		parsed, err := url.Parse(action.OverrideURL)
		if err != nil {
			return req, fmt.Errorf("invalid override URL: %w", err)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return req, fmt.Errorf("unsupported override URL scheme %q: only http and https are allowed", parsed.Scheme)
		}
		req.URL = parsed
		req.Host = parsed.Host
	}

	// Validate header values for CRLF injection (CWE-113).
	for key, val := range action.OverrideHeaders {
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
			return req, fmt.Errorf("header %q contains CR/LF characters (header injection attempt)", key)
		}
	}
	for key, val := range action.AddHeaders {
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
			return req, fmt.Errorf("header %q contains CR/LF characters (header injection attempt)", key)
		}
	}

	// Validate RemoveHeaders keys for CRLF injection (CWE-113).
	for _, key := range action.RemoveHeaders {
		if strings.ContainsAny(key, "\r\n") {
			return req, fmt.Errorf("remove header key %q contains CR/LF characters (header injection attempt)", key)
		}
	}

	// Remove headers first.
	for _, key := range action.RemoveHeaders {
		req.Header.Del(key)
	}

	// Override headers.
	for key, val := range action.OverrideHeaders {
		req.Header.Set(key, val)
	}

	// Add headers.
	for key, val := range action.AddHeaders {
		req.Header.Add(key, val)
	}

	// Override body.
	if action.OverrideBody != nil {
		bodyBytes := []byte(*action.OverrideBody)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}

	return req, nil
}

// checkTargetScope checks if the request URL is allowed by the target scope.
// Returns (true, reason) if the target is blocked, (false, "") if allowed.
// If no target scope is configured or it has no rules, the target is always allowed.
func (h *Handler) checkTargetScope(u *url.URL) (blocked bool, reason string) {
	if h.targetScope == nil || !h.targetScope.HasRules() {
		return false, ""
	}
	allowed, reason := h.targetScope.CheckURL(u)
	if !allowed {
		return true, reason
	}
	return false, ""
}

// checkTargetScopeHost checks if a hostname:port is allowed by the target scope.
// This is used for CONNECT requests where only host and port are available.
// Returns (true, reason) if the target is blocked, (false, "") if allowed.
func (h *Handler) checkTargetScopeHost(hostname string, port int) (blocked bool, reason string) {
	if h.targetScope == nil || !h.targetScope.HasRules() {
		return false, ""
	}
	// CONNECT targets don't have scheme or path information.
	allowed, reason := h.targetScope.CheckTarget("", hostname, port, "")
	if !allowed {
		return true, reason
	}
	return false, ""
}

// writeBlockedResponse writes a 403 Forbidden response with a JSON body
// indicating that the target was blocked by the target scope.
func (h *Handler) writeBlockedResponse(conn net.Conn, target, reason string, logger *slog.Logger) {
	body := fmt.Sprintf(`{"error":"blocked by target scope","target":%q,"reason":%q}`, target, reason)
	resp := fmt.Sprintf("HTTP/1.1 403 Forbidden\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write target scope blocked response", "error", err)
	}
	logger.Info("request blocked by target scope", "target", target, "reason", reason)
}

// recordBlockedSession records a blocked request as a session with BlockedBy="target_scope".
func (h *Handler) recordBlockedSession(ctx context.Context, req *gohttp.Request, reqBody, rawRequest []byte, reqTruncated bool, smuggling *smugglingFlags, start time.Time, connID, clientAddr string, logger *slog.Logger) {
	if h.store == nil {
		return
	}
	if !h.shouldCapture(req.Method, req.URL) {
		return
	}

	duration := time.Since(start)
	sess := &session.Session{
		ConnID:      connID,
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        smugglingTags(smuggling),
		BlockedBy:   "target_scope",
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: clientAddr,
		},
	}
	if err := h.store.SaveSession(ctx, sess); err != nil {
		logger.Error("blocked session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		return
	}
	sendMsg := &session.Message{
		SessionID:     sess.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     start,
		Method:        req.Method,
		URL:           req.URL,
		Headers:       req.Header,
		Body:          reqBody,
		RawBytes:      rawRequest,
		BodyTruncated: reqTruncated,
	}
	if err := h.store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("blocked send message save failed", "error", err)
	}
}
