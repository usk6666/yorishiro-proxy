package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/ws"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// wsErrorRecordParams holds parameters for recording WebSocket upgrade failures.
type wsErrorRecordParams struct {
	connID     string
	clientAddr string
	scheme     string
	start      time.Time
	connInfo   *flow.ConnectionInfo
	req        *parser.RawRequest
	reqURL     *url.URL
}

// handleWebSocket processes a WebSocket upgrade request in HTTP forward proxy mode.
func (h *Handler) handleWebSocket(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	// TCP forwarding: override the host with the actual upstream target.
	if target, ok := proxy.ForwardTargetFromContext(ctx); ok {
		reqURL.Host = target
		req.Headers.Set("Host", target)
	}

	host := reqURL.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	logger.Info("websocket upgrade detected", "url", reqURL.String(), "host", host)

	ep := wsErrorRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		scheme:     "ws",
		start:      start,
		connInfo:   &flow.ConnectionInfo{ClientAddr: clientAddr},
		req:        req,
		reqURL:     reqURL,
	}

	upstreamConn, err := h.dialUpstream(ctx, host, 30*time.Second)
	if err != nil {
		logger.Error("websocket upstream dial failed", "host", host, "error", err)
		writeHTTPError(conn, statusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("dial websocket upstream %s: %w", host, err), logger)
		return fmt.Errorf("dial websocket upstream %s: %w", host, err)
	}
	defer upstreamConn.Close()

	serverAddr := upstreamConn.RemoteAddr().String()

	// Write the upgrade request to upstream using the serialized form.
	payload := serializeRequest(req)
	if err := writeRequest(upstreamConn, payload, req.Body); err != nil {
		logger.Error("websocket upstream write failed", "error", err)
		writeHTTPError(conn, statusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("write websocket upgrade request: %w", err), logger)
		return fmt.Errorf("write websocket upgrade request: %w", err)
	}

	// Read the upstream's response.
	upstreamReader := bufio.NewReader(upstreamConn)
	resp, err := parser.ParseResponse(upstreamReader)
	if err != nil {
		logger.Error("websocket upstream response read failed", "error", err)
		writeHTTPError(conn, statusBadGateway, logger)
		h.recordWebSocketError(ctx, ep, fmt.Errorf("read websocket upgrade response: %w", err), logger)
		return fmt.Errorf("read websocket upgrade response: %w", err)
	}

	// Validate 101 Switching Protocols response.
	if resp.StatusCode != statusSwitchingProtocols {
		logger.Warn("websocket upgrade rejected by upstream", "status", resp.StatusCode)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		writeRawResponse(conn, resp, body)
		return nil
	}

	// Forward the 101 response to the client.
	if err := writeRawResponseHeaders(conn, resp); err != nil {
		return fmt.Errorf("write websocket 101 response to client: %w", err)
	}

	connInfo := &flow.ConnectionInfo{
		ClientAddr: clientAddr,
		ServerAddr: serverAddr,
	}

	// Delegate to the WebSocket handler for frame relay.
	goReq := httputil.RawRequestToHTTP(req, nil)
	goResp := httputil.RawResponseToHTTP(resp, nil)
	wsHandler := h.newWSHandler(logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamConn, upstreamReader, goReq, goResp, connID, clientAddr, connInfo)
}

// handleWebSocketTLS processes a WebSocket upgrade request in HTTPS MITM mode (WSS).
func (h *Handler) handleWebSocketTLS(ctx context.Context, conn net.Conn, connectHost string, req *parser.RawRequest, reqURL *url.URL, tlsMeta tlsMetadata) error {
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	effectiveHost := proxy.ResolveUpstreamTarget(ctx, connectHost)
	if reqURL.Host == "" {
		reqURL.Host = effectiveHost
	}
	if _, ok := proxy.ForwardTargetFromContext(ctx); ok {
		reqURL.Host = effectiveHost
		req.Headers.Set("Host", effectiveHost)
	}
	reqURL.Scheme = "wss"

	host := effectiveHost
	if !strings.Contains(host, ":") {
		host = host + ":443"
	}

	logger.Info("wss websocket upgrade detected", "url", reqURL.String(), "host", host)

	ep := wsErrorRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		scheme:     "wss",
		start:      start,
		connInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			TLSVersion: tlsMeta.Version,
			TLSCipher:  tlsMeta.CipherSuite,
			TLSALPN:    tlsMeta.ALPN,
		},
		req:    req,
		reqURL: reqURL,
	}

	rawConn, err := h.dialUpstream(ctx, host, 30*time.Second)
	if err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("dial wss upstream %s: %w", host, err))
	}
	defer rawConn.Close()

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

	if negotiatedProto == "h2" {
		return h.wssUpstreamError(ctx, conn, ep, logger, host,
			fmt.Errorf("wss upstream %s negotiated HTTP/2 via ALPN; WebSocket requires HTTP/1.1 (RFC 8441 not supported)", host))
	}

	serverAddr := rawConn.RemoteAddr().String()

	var tlsCertSubject string
	if tc, ok := httputil.TLSConnectionState(upstreamTLS); ok && len(tc.PeerCertificates) > 0 {
		tlsCertSubject = tc.PeerCertificates[0].Subject.String()
	}
	_ = tlsCertSubject // stored in connInfo

	// Write the upgrade request using origin-form URI.
	outReq := cloneRequestForUpstream(req, reqURL, true)
	payload := serializeRequest(outReq)
	if err := writeRequest(upstreamTLS, payload, outReq.Body); err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("write wss upgrade request: %w", err))
	}

	upstreamReader := bufio.NewReader(upstreamTLS)
	resp, err := parser.ParseResponse(upstreamReader)
	if err != nil {
		return h.wssUpstreamError(ctx, conn, ep, logger, host, fmt.Errorf("read wss upgrade response: %w", err))
	}

	if resp.StatusCode != statusSwitchingProtocols {
		logger.Warn("wss websocket upgrade rejected by upstream", "status", resp.StatusCode)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		writeRawResponse(conn, resp, body)
		return nil
	}

	// Forward the 101 response to the client.
	if err := writeRawResponseHeaders(conn, resp); err != nil {
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

	goReq := httputil.RawRequestToHTTP(req, nil)
	goResp := httputil.RawResponseToHTTP(resp, nil)
	wsHandler := h.newWSHandler(logger)
	return wsHandler.HandleUpgrade(ctx, conn, upstreamTLS, upstreamReader, goReq, goResp, connID, clientAddr, connInfo)
}

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

func (h *Handler) wssUpstreamError(ctx context.Context, conn net.Conn, ep wsErrorRecordParams, logger *slog.Logger, host string, wrapErr error) error {
	logger.Error("wss upstream error", "host", host, "error", wrapErr)
	writeHTTPError(conn, statusBadGateway, logger)
	h.recordWebSocketError(ctx, ep, wrapErr, logger)
	return wrapErr
}

// wsHTTP1Transport returns a TLS transport configured for HTTP/1.1 only.
func (h *Handler) wsHTTP1Transport() httputil.TLSTransport {
	t := h.effectiveTLSTransport()
	if st, ok := t.(*httputil.StandardTransport); ok {
		cp := *st
		cp.NextProtos = []string{"http/1.1"}
		return &cp
	}
	return t
}

func (h *Handler) recordWebSocketError(ctx context.Context, p wsErrorRecordParams, upstreamErr error, logger *slog.Logger) {
	if h.Store == nil {
		return
	}
	if !h.shouldCapture(p.req.Method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	tags := map[string]string{"error": upstreamErr.Error()}

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "WebSocket",
		Scheme:    p.scheme,
		FlowType:  "bidirectional",
		State:     "error",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("websocket error flow save failed",
			"method", p.req.Method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: p.start,
		Method:    p.req.Method,
		URL:       p.reqURL,
		Headers:   httputil.RawHeadersToHTTPHeader(p.req.Headers),
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("websocket error send message save failed", "error", err)
	}
}
