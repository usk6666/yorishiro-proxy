package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/protocol/ws"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
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

// handleWebSocket processes a WebSocket upgrade request in HTTP forward proxy mode.
// It dials the upstream server, forwards the upgrade request, validates the 101
// response, sends it back to the client, then delegates to the ws.Handler for
// bidirectional frame relay.
func (h *Handler) handleWebSocket(ctx context.Context, conn net.Conn, req *gohttp.Request) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

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

	// Dial the upstream server.
	upstreamConn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		logger.Error("websocket upstream dial failed", "host", host, "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
		return fmt.Errorf("dial websocket upstream %s: %w", host, err)
	}
	defer upstreamConn.Close()

	serverAddr := upstreamConn.RemoteAddr().String()

	// Forward the original upgrade request to the upstream server.
	if err := req.Write(upstreamConn); err != nil {
		logger.Error("websocket upstream write failed", "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
		return fmt.Errorf("write websocket upgrade request: %w", err)
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := gohttp.ReadResponse(upstreamReader, req)
	if err != nil {
		logger.Error("websocket upstream response read failed", "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
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

	connInfo := &session.ConnectionInfo{
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
	}

	// Delegate to the WebSocket handler for frame relay.
	// Pass upstreamReader to preserve any bytes buffered during HTTP response parsing.
	wsHandler := ws.NewHandler(h.store, logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamConn, upstreamReader, req, resp, connID, clientAddr, connInfo)
}

// handleWebSocketTLS processes a WebSocket upgrade request in HTTPS MITM mode (WSS).
// It dials the upstream server over TLS, forwards the upgrade request, validates
// the 101 response, sends it back to the client, then delegates to the ws.Handler
// for bidirectional frame relay.
func (h *Handler) handleWebSocketTLS(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, tlsMeta tlsMetadata) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

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

	// Dial the upstream server.
	rawConn, err := net.DialTimeout("tcp", host, 30*time.Second)
	if err != nil {
		logger.Error("wss upstream dial failed", "host", host, "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
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
	}
	if h.transport != nil && h.transport.TLSClientConfig != nil {
		tlsConfig.InsecureSkipVerify = h.transport.TLSClientConfig.InsecureSkipVerify
	}
	upstreamTLS := tls.Client(rawConn, tlsConfig)
	if err := upstreamTLS.HandshakeContext(ctx); err != nil {
		logger.Error("wss upstream TLS handshake failed", "host", host, "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
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
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
		return fmt.Errorf("write wss upgrade request: %w", err)
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := gohttp.ReadResponse(upstreamReader, req)
	if err != nil {
		logger.Error("wss upstream response read failed", "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		conn.Write([]byte(errResp))
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

	connInfo := &session.ConnectionInfo{
		ClientAddr:           clientAddr,
		ServerAddr:           serverAddr,
		TLSVersion:           tlsMeta.Version,
		TLSCipher:            tlsMeta.CipherSuite,
		TLSALPN:              tlsMeta.ALPN,
		TLSServerCertSubject: tlsCertSubject,
	}

	// Delegate to the WebSocket handler for frame relay.
	// Pass upstreamReader to preserve any bytes buffered during HTTP response parsing.
	wsHandler := ws.NewHandler(h.store, logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamTLS, upstreamReader, req, resp, connID, clientAddr, connInfo)
}
