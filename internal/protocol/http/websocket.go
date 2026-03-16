package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// isWebSocketUpgrade checks if the HTTP request is a WebSocket upgrade request.
// It must be called before hop-by-hop headers are removed.
func isWebSocketUpgrade(req *gohttp.Request) bool {
	// RFC 6455 Section 4.1: The request must contain:
	// - Connection: Upgrade
	// - Upgrade: websocket (case-insensitive)
	connection := req.Header.Get("Connection")
	upgrade := req.Header.Get("Upgrade")

	return headerContains(connection, "upgrade") &&
		strings.EqualFold(strings.TrimSpace(upgrade), "websocket")
}

// headerContains checks if a comma-separated header value contains the given
// token (case-insensitive).
func headerContains(headerValue, token string) bool {
	for _, v := range strings.Split(headerValue, ",") {
		if strings.EqualFold(strings.TrimSpace(v), token) {
			return true
		}
	}
	return false
}

// wsErrorRecordParams holds the parameters needed to record a WebSocket
// upgrade failure as an error flow.
type wsErrorRecordParams struct {
	connID     string
	clientAddr string
	start      time.Time
	connInfo   *flow.ConnectionInfo
	req        *gohttp.Request
}

// handleWebSocket processes a WebSocket upgrade request in HTTP forward proxy mode.
// It dials the upstream server, forwards the upgrade request, validates the 101
// response, sends it back to the client, then delegates to the ws.Handler for
// bidirectional frame relay.
//
// Error paths (dial failure, write failure, response read failure) record a
// Session(State="error") with the upgrade request so that failed WebSocket
// attempts are visible in session history.
func (h *Handler) handleWebSocket(ctx context.Context, conn net.Conn, req *gohttp.Request) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	// Ensure absolute URL for forward proxy.
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// Determine upstream address.
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	logger.Info("websocket upgrade detected", "url", req.URL.String(), "host", host)

	// Build error recording params for use if any error path is reached.
	ep := wsErrorRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: clientAddr},
		req:        req,
	}

	// Dial the upstream server, optionally via upstream proxy.
	upstreamConn, err := h.dialUpstream(ctx, host, 30*time.Second)
	if err != nil {
		logger.Error("websocket upstream dial failed", "host", host, "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("dial websocket upstream %s: %w", host, err), logger)
		return fmt.Errorf("dial websocket upstream %s: %w", host, err)
	}
	defer upstreamConn.Close()

	serverAddr := upstreamConn.RemoteAddr().String()

	// Forward the original upgrade request to the upstream server.
	if err := req.Write(upstreamConn); err != nil {
		logger.Error("websocket upstream write failed", "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("write websocket upgrade request: %w", err), logger)
		return fmt.Errorf("write websocket upgrade request: %w", err)
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := gohttp.ReadResponse(upstreamReader, req)
	if err != nil {
		logger.Error("websocket upstream response read failed", "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("read websocket upgrade response: %w", err), logger)
		return fmt.Errorf("read websocket upgrade response: %w", err)
	}

	// Validate 101 Switching Protocols response.
	if resp.StatusCode != gohttp.StatusSwitchingProtocols {
		defer resp.Body.Close()
		logger.Warn("websocket upgrade rejected by upstream", "status", resp.StatusCode)
		// Forward the non-101 response to the client.
		if writeErr := resp.Write(conn); writeErr != nil {
			logger.Debug("failed to forward rejection response", "error", writeErr)
		}
		return nil
	}

	// Forward the 101 response to the client.
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write websocket 101 response to client: %w", err)
	}

	connInfo := &flow.ConnectionInfo{
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
	}

	// Delegate to the WebSocket handler for frame relay.
	// Pass upstreamReader to preserve any bytes buffered during HTTP response parsing.
	wsHandler := h.newWSHandler(logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamConn, upstreamReader, req, resp, connID, clientAddr, connInfo)
}

// handleWebSocketTLS processes a WebSocket upgrade request in HTTPS MITM mode (WSS).
// It dials the upstream server over TLS, forwards the upgrade request, validates
// the 101 response, sends it back to the client, then delegates to the ws.Handler
// for bidirectional frame relay.
//
// Error paths (dial failure, TLS handshake failure, write failure, response read
// failure) record a Session(State="error") with the upgrade request so that
// failed WSS attempts are visible in session history.
func (h *Handler) handleWebSocketTLS(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, tlsMeta tlsMetadata) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	// Reconstruct the full URL.
	if req.URL.Host == "" {
		req.URL.Host = connectHost
	}
	req.URL.Scheme = "wss"

	// Determine upstream address.
	host := connectHost
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	logger.Info("wss websocket upgrade detected", "url", req.URL.String(), "host", host)

	// Build error recording params for use if any error path is reached.
	ep := wsErrorRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		start:      start,
		connInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			TLSVersion: tlsMeta.Version,
			TLSCipher:  tlsMeta.CipherSuite,
			TLSALPN:    tlsMeta.ALPN,
		},
		req: req,
	}

	// Dial the upstream server, optionally via upstream proxy.
	rawConn, err := h.dialUpstream(ctx, host, 30*time.Second)
	if err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("dial wss upstream %s: %w", host, err))
	}
	defer rawConn.Close()

	// Perform TLS handshake with the upstream server using a transport that
	// offers only HTTP/1.1 via ALPN (WebSocket requires HTTP/1.1 Upgrade).
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}
	tlsTransport := h.wsHTTP1Transport()
	upstreamTLS, negotiatedProto, err := tlsTransport.TLSConnect(ctx, rawConn, hostname)
	if err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("wss upstream TLS handshake: %w", err))
	}
	defer upstreamTLS.Close()

	// Safety net: if the server negotiated HTTP/2 despite our preference for
	// HTTP/1.1, WebSocket upgrade cannot proceed (RFC 8441 not yet supported).
	if negotiatedProto == "h2" {
		return h.wssUpstreamError(ctx, conn, ep, logger, host,
			fmt.Errorf("wss upstream %s negotiated HTTP/2 via ALPN; WebSocket requires HTTP/1.1 (RFC 8441 not supported)", host))
	}

	serverAddr := rawConn.RemoteAddr().String()

	// Extract the upstream server's TLS certificate subject if available.
	var tlsCertSubject string
	if tc, ok := httputil.TLSConnectionState(upstreamTLS); ok && len(tc.PeerCertificates) > 0 {
		tlsCertSubject = tc.PeerCertificates[0].Subject.String()
	}

	// Forward the upgrade request to the upstream TLS connection.
	// Use the original request URI (relative form for HTTPS).
	outReq := req.Clone(ctx)
	outReq.RequestURI = req.URL.RequestURI()
	if err := outReq.Write(upstreamTLS); err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("write wss upgrade request: %w", err))
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := gohttp.ReadResponse(upstreamReader, req)
	if err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("read wss upgrade response: %w", err))
	}

	// Validate 101 Switching Protocols response.
	if resp.StatusCode != gohttp.StatusSwitchingProtocols {
		logger.Warn("wss websocket upgrade rejected by upstream", "status", resp.StatusCode)
		// Read and forward the response body (limited to 1MB to prevent OOM from malicious upstream).
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		writeResponse(conn, resp, body)
		return nil
	}

	// Forward the 101 response to the client.
	if err := resp.Write(conn); err != nil {
		return fmt.Errorf("write wss 101 response to client: %w", err)
	}

	connInfo := &flow.ConnectionInfo{
		ClientAddr:           clientAddr,
		ServerAddr:           serverAddr,
		TLSVersion:           tlsMeta.Version,
		TLSCipher:            tlsMeta.CipherSuite,
		TLSALPN:              tlsMeta.ALPN,
		TLSServerCertSubject: tlsCertSubject,
	}

	// Delegate to the WebSocket handler for frame relay.
	// Pass upstreamReader to preserve any bytes buffered during HTTP response parsing.
	wsHandler := h.newWSHandler(logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamTLS, upstreamReader, req, resp, connID, clientAddr, connInfo)
}

// newWSHandler creates a ws.Handler configured with the handler's safety engine,
// intercept engine, and intercept queue.
func (h *Handler) newWSHandler(logger *slog.Logger) *ws.Handler {
	wsHandler := ws.NewHandler(h.Store, logger)
	if h.SafetyEngine != nil {
		wsHandler.SetSafetyEngine(h.SafetyEngine)
	}
	if h.InterceptEngine != nil {
		wsHandler.SetInterceptEngine(h.InterceptEngine)
	}
	if h.InterceptQueue != nil {
		wsHandler.SetInterceptQueue(h.InterceptQueue)
	}
	return wsHandler
}

// wssUpstreamError is a helper that handles common WSS upstream error paths:
// it logs the error, sends 502 to the client, records the error flow, and
// returns the formatted error. This reduces cyclomatic complexity in
// handleWebSocketTLS.
func (h *Handler) wssUpstreamError(ctx context.Context, conn net.Conn, ep wsErrorRecordParams, logger *slog.Logger, host string, wrapErr error) error {
	logger.Error("wss upstream error", slog.String("host", host), "error", wrapErr)
	httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
	h.recordWebSocketError(ctx, ep, wrapErr, logger)
	return wrapErr
}

// wsHTTP1Transport returns a TLS transport configured to offer only HTTP/1.1
// via ALPN. WebSocket requires HTTP/1.1 Upgrade semantics, so offering h2
// would cause failures when the upstream server selects HTTP/2.
//
// For StandardTransport, a copy with NextProtos set to ["http/1.1"] is returned.
// For other transport types (e.g. UTLSTransport), the original transport is
// returned as-is — the h2 ALPN check after TLSConnect acts as a safety net.
func (h *Handler) wsHTTP1Transport() httputil.TLSTransport {
	t := h.effectiveTLSTransport()
	if st, ok := t.(*httputil.StandardTransport); ok {
		cp := *st // shallow copy — picks up all current and future fields
		cp.NextProtos = []string{"http/1.1"}
		return &cp
	}
	return t
}

// recordWebSocketError records a WebSocket upgrade failure as an error flow.
// It creates a Session(State="error") with the upgrade request as the send
// message (no receive message). The error is stored in the flow tags.
//
// This is called from handleWebSocket and handleWebSocketTLS error paths where
// the WebSocket upgrade could not complete (dial failure, TLS handshake failure,
// upstream write/read failure).
//
// If the store is nil or capture scope filtering excludes the request,
// this is a no-op.
func (h *Handler) recordWebSocketError(ctx context.Context, p wsErrorRecordParams, upstreamErr error, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	if !h.shouldCapture(p.req.Method, p.req.URL) {
		return
	}

	duration := time.Since(p.start)
	tags := map[string]string{
		"error": upstreamErr.Error(),
	}

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "error",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("websocket error flow save failed",
			"method", p.req.Method, "url", p.req.URL.String(), "error", err)
		return
	}

	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: p.start,
		Method:    p.req.Method,
		URL:       p.req.URL,
		Headers:   p.req.Header,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("websocket error send message save failed", "error", err)
	}
}
