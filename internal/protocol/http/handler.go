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
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
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
	proxy.HandlerBase

	issuer            *cert.Issuer
	requestTimeoutNs  atomic.Int64 // nanoseconds; read/written atomically
	passthrough       *proxy.PassthroughList
	transformPipeline *rules.Pipeline
	h2Handler         H2Handler
	pluginEngine      *plugin.Engine
	tlsTransport      httputil.TLSTransport
	detector          *fingerprint.Detector
}

// NewHandler creates a new HTTP handler with flow recording.
// If issuer is non-nil, CONNECT requests are handled for HTTPS MITM;
// otherwise CONNECT requests receive a 501 Not Implemented response.
func NewHandler(store flow.FlowWriter, issuer *cert.Issuer, logger *slog.Logger) *Handler {
	return &Handler{
		HandlerBase: proxy.HandlerBase{
			Store:     store,
			Transport: &gohttp.Transport{},
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

// SetPluginEngine sets the plugin engine used to dispatch hook events
// during HTTP request/response processing.
func (h *Handler) SetPluginEngine(engine *plugin.Engine) {
	h.pluginEngine = engine
}

// PluginEngine returns the handler's current plugin engine, or nil.
func (h *Handler) PluginEngine() *plugin.Engine {
	return h.pluginEngine
}

// SetTLSTransport sets the TLS transport used for upstream HTTPS connections.
// When set, the transport's TLSConnect method is used instead of Go's default
// crypto/tls, enabling uTLS fingerprint spoofing.
func (h *Handler) SetTLSTransport(t httputil.TLSTransport) {
	h.tlsTransport = t
	h.configureTLSDialer()
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

// effectiveTLSTransport returns the configured TLS transport, falling back to
// a StandardTransport with InsecureSkipVerify matching the handler's transport
// configuration.
func (h *Handler) effectiveTLSTransport() httputil.TLSTransport {
	if h.tlsTransport != nil {
		return h.tlsTransport
	}
	insecure := h.Transport != nil && h.Transport.TLSClientConfig != nil &&
		h.Transport.TLSClientConfig.InsecureSkipVerify
	return &httputil.StandardTransport{InsecureSkipVerify: insecure}
}

// configureTLSDialer installs a DialTLSContext function on the handler's
// http.Transport so that outgoing HTTPS requests use the configured
// TLSTransport (e.g. uTLS) instead of Go's default TLS stack.
func (h *Handler) configureTLSDialer() {
	if h.Transport == nil || h.tlsTransport == nil {
		return
	}
	// Restrict ALPN to HTTP/1.1 only. Go's http.Transport cannot handle
	// HTTP/2 frames when DialTLSContext is set (it disables automatic HTTP/2
	// upgrade). If the upstream negotiates h2 via ALPN, the transport
	// receives HTTP/2 binary frames but parses them as HTTP/1.x text,
	// causing "malformed HTTP response" errors and 502 Bad Gateway.
	transport := httputil.HTTP1OnlyTransport(h.tlsTransport)
	h.Transport.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		dialer := &net.Dialer{Timeout: 30 * time.Second}
		rawConn, err := dialer.DialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		tlsConn, _, err := transport.TLSConnect(ctx, rawConn, host)
		if err != nil {
			rawConn.Close()
			return nil, err
		}
		// Wrap the connection so http.Transport can detect TLS and
		// populate resp.TLS via ConnectionState() tls.ConnectionState.
		return httputil.WrapTLSConn(tlsConn), nil
	}
	// Disable the default TLS config since DialTLSContext handles TLS.
	h.Transport.TLSClientConfig = nil
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
		smuggling := checkRequestSmuggling(reader, h.Logger)

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
		logSmugglingWarnings(h.Logger, smuggling, req)

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
	normalizeRequestURL(ctx, req)

	// Target scope enforcement (before WebSocket — S-1: CWE-863).
	if blocked, reason := h.checkTargetScope(req.URL); blocked {
		h.writeBlockedResponse(conn, req.URL.Hostname(), reason, logger)
		h.recordBlockedSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, "target_scope", nil, logger)
		return nil
	}

	// Rate limit enforcement (after target scope, before WebSocket).
	if denial := h.checkRateLimit(req.URL.Hostname()); denial != nil {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedSessionWithTags(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, "rate_limit", nil, denial.Tags(), logger)
		return nil
	}
	// NOTE (S-LOW-1): WebSocket upgrade requests bypass the safety filter
	// intentionally. WS upgrade requests do not carry a meaningful body,
	// so input filtering would not add value. The safety filter runs on
	// the body-bearing code path below instead.
	if isWebSocketUpgrade(req) {
		return h.handleWebSocket(ctx, conn, req)
	}

	bodyResult := readAndCaptureRequestBody(req, logger)
	rawRequest := extractRawRequest(capture, captureStart, reader)

	// Safety filter enforcement (after target scope + rate limit, before plugin hooks).
	// NOTE (L-1): The safety filter is intentionally placed after the rate limiter
	// rather than before it. The filter requires the request body, which is read
	// above by readAndCaptureRequestBody. Moving it before the rate limiter would
	// require reading the body earlier, which would allow a rate-limited client
	// to force body reads on every request, increasing resource consumption.
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, req.URL.String(), req.Header); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedSession(ctx, req, bodyResult.recordBody, rawRequest, bodyResult.truncated, smuggling, start, connID, clientAddr, "safety_filter", violation, logger)
			return nil
		}
		// log_only: log the violation but continue processing.
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", proxy.TruncateForLog(violation.MatchedOn, 256))
	}

	removeHopByHopHeaders(req.Header)

	// Build plugin ConnInfo for hook data.
	pluginConnInfo := &plugin.ConnInfo{ClientAddr: clientAddr}

	// Create transaction context shared across all plugin hooks for this
	// request-response pair. Plugins can store and retrieve values via
	// data["ctx"] to pass data between hooks.
	txCtx := plugin.NewTxCtx()

	// Plugin hook: on_receive_from_client — after TargetScope, before Intercept.
	// Supports DROP (close connection) and RESPOND (custom response) actions.
	var pluginDropped bool
	req, bodyResult.recordBody, pluginDropped = h.dispatchOnReceiveFromClient(ctx, conn, req, bodyResult.recordBody, pluginConnInfo, txCtx, logger)
	if pluginDropped {
		return nil
	}

	// Build send record params for progressive recording.
	sp := sendRecordParams{
		connID:       connID,
		clientAddr:   clientAddr,
		protocol:     socks5Protocol(ctx, "HTTP/1.x"),
		scheme:       "http",
		start:        start,
		tags:         mergeSOCKS5Tags(ctx, smugglingTags(smuggling)),
		connInfo:     &flow.ConnectionInfo{ClientAddr: clientAddr},
		req:          req,
		reqBody:      bodyResult.recordBody,
		rawRequest:   rawRequest,
		reqTruncated: bodyResult.truncated,
	}

	// Snapshot headers/body before intercept/transform for variant recording.
	// If intercept or transform modifies the request, both the original and
	// modified versions are recorded as separate send messages.
	snap := snapshotRequest(req.Header, bodyResult.recordBody)

	iResult := h.applyIntercept(ctx, conn, req, bodyResult.recordBody, rawRequest, logger)
	if iResult.Dropped {
		sp.reqBody = iResult.RecordBody
		h.recordInterceptDrop(ctx, sp, logger)
		return nil
	}
	req = iResult.Req
	bodyResult.recordBody = iResult.RecordBody

	// Raw mode: bypass net/http.Transport and forward raw bytes directly.
	if iResult.IsRaw {
		return h.handleRawForward(ctx, conn, req, iResult, sp, &snap, start, logger)
	}

	bodyResult.recordBody = h.applyTransform(req, bodyResult.recordBody)

	// Plugin hook: on_before_send_to_server — after Transform, before Recording.
	req, bodyResult.recordBody = h.dispatchOnBeforeSendToServer(ctx, req, bodyResult.recordBody, pluginConnInfo, txCtx, logger)

	sp.reqBody = bodyResult.recordBody

	// Progressive recording: record send (session + request) before forwarding.
	// Uses variant-aware recording to capture both original and modified
	// versions when intercept/transform changed the request.
	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	sendStart := time.Now()
	fwd, err := h.forwardUpstream(ctx, conn, req, logger)
	if err != nil {
		// Upstream failed — record session as error. Send is already recorded.
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}
	defer fwd.resp.Body.Close()

	// SSE detection: if the response is text/event-stream, switch to
	// streaming mode. SSE responses are long-lived streams that would
	// block forever in readResponseBody's io.ReadAll. SSE streams use
	// per-event processing: output filter is applied per event, intercept
	// is applied at header level. Full-body buffering and auto-transform
	// rules are skipped.
	// The send phase is already recorded via sendResult above; pass it
	// directly to avoid duplicate flow recording.
	if isSSEResponse(fwd.resp) {
		sendResult.tags = addSSETags(sendResult.tags)
		hookCtx := &sseHookContext{connInfo: pluginConnInfo, txCtx: txCtx}
		return h.handleSSEStream(ctx, conn, req, fwd, start, sendResult, hookCtx, logger)
	}

	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	// Plugin hook: on_receive_from_server — after response received, before Transform.
	fwd.resp, fullRespBody = h.dispatchOnReceiveFromServer(ctx, fwd.resp, fullRespBody, req, pluginConnInfo, txCtx, logger)

	// Snapshot response before intercept for variant recording.
	// If intercept modifies the response, both the original and modified
	// versions are recorded as separate receive messages.
	respSnap := snapshotResponse(fwd.resp.StatusCode, fwd.resp.Header, fullRespBody)

	// Response intercept: check if the response matches any intercept rules
	// and allow the AI agent to modify or drop it before sending to the client.
	var respDropped bool
	fwd.resp, fullRespBody, respDropped = h.applyInterceptResponse(ctx, conn, req, fwd.resp, fullRespBody, logger)
	if respDropped {
		return nil
	}

	// Plugin hook: on_before_send_to_client — after intercept, before Recording/write.
	fwd.resp, fullRespBody = h.dispatchOnBeforeSendToClient(ctx, fwd.resp, fullRespBody, req, pluginConnInfo, txCtx, logger)

	// Serialize raw response for recording. This is done after plugin/intercept
	// so that any modifications are reflected in the recorded bytes.
	// The raw response captures the unmasked data for Flow Store.
	rawResponse := serializeRawResponse(fwd.resp, fullRespBody)
	// Save unmasked body for recording before output filter masks it.
	// Deep copy to guard against future FilterOutput implementations that
	// may modify the underlying array in place (S-2).
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

	// Output filter: mask sensitive data in response body and headers before
	// sending to client. Raw (unmasked) data is preserved in Flow Store via
	// rawResponse/rawRespBody above.
	fullRespBody, fwd.resp.Header = h.ApplyOutputFilter(fullRespBody, fwd.resp.Header, logger)

	if err := writeResponseToClient(conn, fwd.resp, fullRespBody); err != nil {
		return err
	}

	// Progressive recording: record receive (response + session completion).
	// Uses variant-aware recording to capture both original and modified
	// versions when intercept changed the response.
	// NOTE: respBody uses rawRespBody (unmasked) so Flow Store has raw data.
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

	logHTTPRequest(logger, req, fwd.resp.StatusCode, duration)
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
	return h.ShouldCapture(method, u)
}

func removeHopByHopHeaders(header gohttp.Header) {
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
}

// roundTripWithTrace wraps transport.RoundTrip with an httptrace hook to
// capture the remote address of the TCP connection used for the request
// and per-phase timing data (send, wait, receive).
func roundTripWithTrace(transport *gohttp.Transport, req *gohttp.Request) (*gohttp.Response, string, *httputil.RoundTripTiming, error) {
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
	resp, err := transport.RoundTrip(req)
	return resp, serverAddr, timing, err
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
//
// The rawBytes parameter is the captured raw request bytes from captureReader.
// When non-nil, they are atomically attached to the queued item via
// EnqueueOpts so that the AI agent can view/edit the raw bytes and select
// raw forwarding mode.
func (h *Handler) interceptRequest(ctx context.Context, conn net.Conn, req *gohttp.Request, body []byte, rawBytes []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchRequestRules(req.Method, req.URL, httpHeaderToRawHeaders(req.Header))
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("request intercepted", "method", req.Method, "url", req.URL.String(), "matched_rules", matchedRules)

	var opts []intercept.EnqueueOpts
	if len(rawBytes) > 0 {
		opts = append(opts, intercept.EnqueueOpts{RawBytes: rawBytes})
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
// action to the HTTP request. It delegates to the shared httputil package for
// CRLF validation, URL scheme enforcement, and header/body modifications.
func applyInterceptModifications(req *gohttp.Request, action intercept.InterceptAction, originalBody []byte) (*gohttp.Request, error) {
	return httputil.ApplyRequestModifications(req, action)
}

// checkTargetScope checks if the request URL is allowed by the target scope.
// Returns (true, reason) if the target is blocked, (false, "") if allowed.
// If no target scope is configured or it has no rules, the target is always allowed.
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
// This is used for CONNECT requests where only host and port are available.
// Returns (true, reason) if the target is blocked, (false, "") if allowed.
func (h *Handler) checkTargetScopeHost(hostname string, port int) (blocked bool, reason string) {
	if h.TargetScope == nil || !h.TargetScope.HasRules() {
		return false, ""
	}
	// CONNECT targets don't have scheme or path information.
	allowed, reason := h.TargetScope.CheckTarget("", hostname, port, "")
	if !allowed {
		return true, reason
	}
	return false, ""
}

// checkRateLimit checks whether the request is rate limited.
// Returns nil if the request is allowed, or a *proxy.RateLimitDenial if blocked.
func (h *Handler) checkRateLimit(hostname string) *proxy.RateLimitDenial {
	if h.RateLimiter == nil || !h.RateLimiter.HasLimits() {
		return nil
	}
	return h.RateLimiter.Check(hostname)
}

// writeRateLimitResponse writes a 429 Too Many Requests response with
// the standard rate limit headers.
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

// recordBlockedSession records a blocked request as a flow with the given blockedBy reason.
// If violation is non-nil and blockedBy is "safety_filter", safety rule tags are added.
func (h *Handler) recordBlockedSession(ctx context.Context, req *gohttp.Request, reqBody, rawRequest []byte, reqTruncated bool, smuggling *smugglingFlags, start time.Time, connID, clientAddr, blockedBy string, violation *safety.InputViolation, logger *slog.Logger) {
	h.recordBlockedSessionWithTags(ctx, req, reqBody, rawRequest, reqTruncated, smuggling, start, connID, clientAddr, blockedBy, violation, nil, logger)
}

// recordBlockedSessionWithTags records a blocked request as a flow with the given blockedBy reason.
// If violation is non-nil and blockedBy is "safety_filter", safety rule tags are added.
// extraTags are merged into the flow tags (e.g., rate limit detail tags).
func (h *Handler) recordBlockedSessionWithTags(ctx context.Context, req *gohttp.Request, reqBody, rawRequest []byte, reqTruncated bool, smuggling *smugglingFlags, start time.Time, connID, clientAddr, blockedBy string, violation *safety.InputViolation, extraTags map[string]string, logger *slog.Logger) {
	if h.Store == nil {
		return
	}
	if !h.shouldCapture(req.Method, req.URL) {
		return
	}

	duration := time.Since(start)
	tags := smugglingTags(smuggling)
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
	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "HTTP/1.x",
		Scheme:    "http",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      tags,
		BlockedBy: blockedBy,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
		},
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("blocked flow save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		return
	}
	sendMsg := &flow.Message{
		FlowID:        fl.ID,
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
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("blocked send message save failed", "error", err)
	}
}
