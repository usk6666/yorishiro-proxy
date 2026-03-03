// Package http2 implements an HTTP/2 protocol handler for the yorishiro-proxy.
// It supports both h2 (TLS via ALPN) and h2c (cleartext) HTTP/2 connections.
// Each HTTP/2 stream is recorded as an individual unary session.
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
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/session"
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

	// grpcHandler processes gRPC session recording when Content-Type: application/grpc
	// is detected. If nil, gRPC streams are recorded as plain HTTP/2.
	grpcHandler *protogrpc.Handler
}

// NewHandler creates a new HTTP/2 handler with session recording.
func NewHandler(store session.SessionWriter, logger *slog.Logger) *Handler {
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

// SetGRPCHandler sets the gRPC handler used for gRPC-specific session recording.
// When set, streams with Content-Type: application/grpc are recorded as gRPC
// sessions with parsed service/method metadata instead of plain HTTP/2.
func (h *Handler) SetGRPCHandler(gh *protogrpc.Handler) {
	h.grpcHandler = gh
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
	// so that session recording finishes before the connection is closed.
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

// handleStream proxies a single HTTP/2 stream to the upstream server
// and records the session.
func (h *Handler) handleStream(
	ctx context.Context,
	w gohttp.ResponseWriter,
	req *gohttp.Request,
	connID, clientAddr, connectAuthority string,
	tlsMeta tlsMetadata,
	logger *slog.Logger,
) {
	start := time.Now()

	// Read the full request body.
	var reqBody []byte
	var reqTruncated bool
	if req.Body != nil {
		fullBody, err := io.ReadAll(req.Body)
		if err != nil {
			logger.Warn("HTTP/2 failed to read request body", "error", err)
		}
		req.Body.Close()
		reqBody = fullBody
		req.Body = io.NopCloser(bytes.NewReader(fullBody))
	}

	recordReqBody := reqBody
	if len(reqBody) > int(config.MaxBodySize) {
		recordReqBody = reqBody[:int(config.MaxBodySize)]
		reqTruncated = true
	}

	// Determine scheme and host for the upstream request.
	scheme := "http"
	if connectAuthority != "" {
		scheme = "https"
	}
	host := req.Host
	if host == "" && connectAuthority != "" {
		host = connectAuthority
	}
	if req.URL.Host == "" {
		req.URL.Host = host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = scheme
	}

	// Target scope enforcement: check if the target is allowed before
	// forwarding the request upstream. For h2c connections this is the
	// only scope check; for h2 via CONNECT the tunnel-level check in
	// the HTTP/1.x handler provides the first line of defense (S-2).
	if h.TargetScope != nil && h.TargetScope.HasRules() {
		if allowed, reason := h.TargetScope.CheckURL(req.URL); !allowed {
			body := fmt.Sprintf(`{"error":"blocked by target scope","target":%q,"reason":%q}`,
				req.URL.Hostname(), reason)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Length", fmt.Sprintf("%d", len(body)))
			w.WriteHeader(gohttp.StatusForbidden)
			w.Write([]byte(body))
			logger.Info("HTTP/2 request blocked by target scope",
				"host", req.URL.Host, "reason", reason)
			return
		}
	}

	// Build the outbound request for the upstream server.
	outURL := &url.URL{
		Scheme:   scheme,
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}

	outReq, err := gohttp.NewRequestWithContext(ctx, req.Method, outURL.String(), io.NopCloser(bytes.NewReader(reqBody)))
	if err != nil {
		logger.Error("HTTP/2 failed to build upstream request", "error", err)
		w.WriteHeader(gohttp.StatusBadGateway)
		return
	}

	// Copy headers from the original request, skipping HTTP/2 pseudo-headers
	// and hop-by-hop headers that should not be forwarded.
	for key, vals := range req.Header {
		outReq.Header[key] = vals
	}
	removeHTTP2HopByHop(outReq.Header)

	// Intercept check: if an intercept engine and queue are configured,
	// check if the request matches any intercept rules. If so, enqueue
	// the request and block until the AI agent responds with an action.
	if action, intercepted := h.interceptRequest(ctx, req, recordReqBody, logger); intercepted {
		switch action.Type {
		case intercept.ActionDrop:
			// Drop: return 502 to client.
			w.WriteHeader(gohttp.StatusBadGateway)
			logger.Info("intercepted HTTP/2 request dropped", "method", req.Method, "url", outURL.String())
			return
		case intercept.ActionModifyAndForward:
			// Apply modifications to the outbound request.
			var modErr error
			outReq, modErr = applyInterceptModifications(outReq, action, reqBody)
			if modErr != nil {
				logger.Error("HTTP/2 intercept modification failed", "error", modErr)
				w.WriteHeader(gohttp.StatusBadRequest)
				return
			}
			// Update recordReqBody for session recording if body changed.
			if action.OverrideBody != nil {
				recordReqBody = []byte(*action.OverrideBody)
			}
		case intercept.ActionRelease:
			// Continue with the original request.
		}
	}

	// Forward to upstream.
	resp, serverAddr, err := h.roundTripWithTrace(outReq)
	if err != nil {
		logger.Error("HTTP/2 upstream request failed",
			"method", req.Method, "url", outURL.String(), "error", err)
		w.WriteHeader(gohttp.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Read the response body with a size limit to prevent OOM (CWE-770).
	fullRespBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if err != nil {
		logger.Warn("HTTP/2 failed to read response body", "error", err)
	}

	// Write response headers back to the client.
	for key, vals := range resp.Header {
		for _, val := range vals {
			w.Header().Add(key, val)
		}
	}
	w.WriteHeader(resp.StatusCode)

	// Write response body back to the client.
	if len(fullRespBody) > 0 {
		if _, err := w.Write(fullRespBody); err != nil {
			logger.Debug("HTTP/2 failed to write response body", "error", err)
		}
	}

	// Decompress response body for recording. The raw (potentially compressed)
	// bytes are written to the client as-is above.
	recordRespBody := fullRespBody
	var respTruncated bool
	decompressed := false
	if ce := resp.Header.Get("Content-Encoding"); ce != "" {
		decoded, err := httputil.DecompressBody(fullRespBody, ce, config.MaxBodySize)
		if err != nil {
			logger.Debug("HTTP/2 response body decompression failed, storing as-is", "encoding", ce, "error", err)
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

	// Extract the upstream server's TLS certificate subject if available.
	var tlsCertSubject string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = resp.TLS.PeerCertificates[0].Subject.String()
	}

	// Record session.
	reqURL := &url.URL{
		Scheme:   scheme,
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}

	if h.shouldCapture(req.Method, reqURL) {
		// Check if this is a gRPC request and delegate to the gRPC handler.
		isGRPC := h.grpcHandler != nil && isGRPCContentType(req.Header.Get("Content-Type"))

		if isGRPC {
			// Collect trailers from the response.
			var trailers map[string][]string
			if resp.Trailer != nil {
				trailers = make(map[string][]string, len(resp.Trailer))
				for k, vals := range resp.Trailer {
					trailers[k] = vals
				}
			}

			info := &protogrpc.StreamInfo{
				ConnID:               connID,
				ClientAddr:           clientAddr,
				ServerAddr:           serverAddr,
				Method:               req.Method,
				URL:                  reqURL,
				RequestHeaders:       req.Header,
				ResponseHeaders:      resp.Header,
				Trailers:             trailers,
				RequestBody:          reqBody,
				ResponseBody:         fullRespBody,
				StatusCode:           resp.StatusCode,
				Start:                start,
				Duration:             duration,
				TLSVersion:           tlsMeta.Version,
				TLSCipher:            tlsMeta.CipherSuite,
				TLSALPN:              tlsMeta.ALPN,
				TLSServerCertSubject: tlsCertSubject,
			}
			if err := h.grpcHandler.RecordSession(ctx, info); err != nil {
				logger.Error("gRPC session recording failed", "error", err)
			}
		} else if h.Store != nil {
			// Standard HTTP/2 session recording.
			protocol := "HTTP/2"
			sess := &session.Session{
				ConnID:      connID,
				Protocol:    protocol,
				SessionType: "unary",
				State:       "complete",
				Timestamp:   start,
				Duration:    duration,
				ConnInfo: &session.ConnectionInfo{
					ClientAddr:           clientAddr,
					ServerAddr:           serverAddr,
					TLSVersion:           tlsMeta.Version,
					TLSCipher:            tlsMeta.CipherSuite,
					TLSALPN:              tlsMeta.ALPN,
					TLSServerCertSubject: tlsCertSubject,
				},
			}
			if err := h.Store.SaveSession(ctx, sess); err != nil {
				logger.Error("HTTP/2 session save failed", "error", err)
			} else {
				sendMsg := &session.Message{
					SessionID:     sess.ID,
					Sequence:      0,
					Direction:     "send",
					Timestamp:     start,
					Method:        req.Method,
					URL:           reqURL,
					Headers:       req.Header,
					Body:          recordReqBody,
					BodyTruncated: reqTruncated,
				}
				if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
					logger.Error("HTTP/2 send message save failed", "error", err)
				}

				recvMsg := &session.Message{
					SessionID:     sess.ID,
					Sequence:      1,
					Direction:     "receive",
					Timestamp:     start.Add(duration),
					StatusCode:    resp.StatusCode,
					Headers:       httputil.RecordingHeaders(resp.Header, decompressed, len(recordRespBody)),
					Body:          recordRespBody,
					BodyTruncated: respTruncated,
				}
				if err := h.Store.AppendMessage(ctx, recvMsg); err != nil {
					logger.Error("HTTP/2 receive message save failed", "error", err)
				}
			}
		}
	}

	logProtocol := "http/2"
	if h.grpcHandler != nil && isGRPCContentType(req.Header.Get("Content-Type")) {
		logProtocol = "grpc"
	}
	logger.Info(logProtocol+" request",
		"method", req.Method,
		"url", outURL.String(),
		"status", resp.StatusCode,
		"duration_ms", duration.Milliseconds())
}

// roundTripWithTrace wraps transport.RoundTrip with an httptrace hook to
// capture the remote address of the TCP connection used for the request.
func (h *Handler) roundTripWithTrace(req *gohttp.Request) (*gohttp.Response, string, error) {
	var serverAddr string
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			if info.Conn != nil {
				serverAddr = info.Conn.RemoteAddr().String()
			}
		},
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	// Hold a read lock while accessing transport.Proxy via RoundTrip to
	// prevent a data race with concurrent SetUpstreamProxy writes.
	h.UpstreamMu.RLock()
	resp, err := h.Transport.RoundTrip(req)
	h.UpstreamMu.RUnlock()

	return resp, serverAddr, err
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
// action to the HTTP/2 request. It returns the modified request and an error if
// validation fails (e.g., invalid URL scheme).
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
