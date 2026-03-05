package http

import (
	"bufio"
	"context"
	"crypto/tls"
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
	wsHandler := ws.NewHandler(h.Store, logger)
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
		logger.Error("wss upstream dial failed", "host", host, "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("dial wss upstream %s: %w", host, err), logger)
		return fmt.Errorf("dial wss upstream %s: %w", host, err)
	}
	defer rawConn.Close()

	// Perform TLS handshake with the upstream server.
	hostname, _, splitErr := net.SplitHostPort(host)
	if splitErr != nil {
		hostname = host
	}
	tlsConfig := &tls.Config{
		ServerName: hostname,
		MinVersion: tls.VersionTLS12,
	}
	if h.Transport != nil && h.Transport.TLSClientConfig != nil {
		tlsConfig.InsecureSkipVerify = h.Transport.TLSClientConfig.InsecureSkipVerify
	}
	upstreamTLS := tls.Client(rawConn, tlsConfig)
	if err := upstreamTLS.HandshakeContext(ctx); err != nil {
		logger.Error("wss upstream TLS handshake failed", "host", host, "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("wss upstream TLS handshake: %w", err), logger)
		return fmt.Errorf("wss upstream TLS handshake: %w", err)
	}
	defer upstreamTLS.Close()

	serverAddr := rawConn.RemoteAddr().String()

	// Extract the upstream server's TLS certificate subject if available.
	var tlsCertSubject string
	upstreamState := upstreamTLS.ConnectionState()
	if len(upstreamState.PeerCertificates) > 0 {
		tlsCertSubject = upstreamState.PeerCertificates[0].Subject.String()
	}

	// Forward the upgrade request to the upstream TLS connection.
	// Use the original request URI (relative form for HTTPS).
	outReq := req.Clone(ctx)
	outReq.RequestURI = req.URL.RequestURI()
	if err := outReq.Write(upstreamTLS); err != nil {
		logger.Error("wss upstream write failed", "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("write wss upgrade request: %w", err), logger)
		return fmt.Errorf("write wss upgrade request: %w", err)
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := gohttp.ReadResponse(upstreamReader, req)
	if err != nil {
		logger.Error("wss upstream response read failed", "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("read wss upgrade response: %w", err), logger)
		return fmt.Errorf("read wss upgrade response: %w", err)
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
	wsHandler := ws.NewHandler(h.Store, logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamTLS, upstreamReader, req, resp, connID, clientAddr, connInfo)
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
