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
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// tlsMetadata holds TLS connection information extracted from the handshake.
type tlsMetadata struct {
	Version     string
	CipherSuite string
	ALPN        string
}

// handleCONNECT processes an HTTP CONNECT request. If the target host matches
// a TLS passthrough pattern, it relays encrypted bytes directly without
// interception. Otherwise, it performs HTTPS MITM: sends a 200 Connection
// Established response, performs a TLS handshake with the client using a
// dynamically issued certificate, then proxies decrypted HTTP requests to the
// upstream server over TLS.
func (h *Handler) handleCONNECT(ctx context.Context, conn net.Conn, req *gohttp.Request) error {
	logger := h.connLogger(ctx)

	// Parse the hostname from the CONNECT request for passthrough check and
	// certificate generation.
	hostname, err := parseConnectHost(req.Host)
	if err != nil {
		logger.Warn("invalid CONNECT host", "host", req.Host, "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadRequest, logger)
		return nil
	}

	// Preserve the full host:port for upstream forwarding.
	// req.Host contains the original "host:port" from the CONNECT request.
	connectAuthority := req.Host

	// Target scope enforcement: check if the CONNECT target is allowed
	// before establishing the tunnel. Parse the port from the authority
	// for the scope check.
	port := parseConnectPort(req.Host)
	if port == 0 {
		// Invalid (non-numeric) port in CONNECT request — reject immediately
		// to prevent scope check bypass (S-3: CWE-20).
		logger.Warn("CONNECT with invalid port", "host", req.Host)
		httputil.WriteHTTPError(conn, gohttp.StatusBadRequest, logger)
		return nil
	}
	if blocked, reason := h.checkTargetScopeHost(hostname, port); blocked {
		h.writeBlockedResponse(conn, hostname, reason, logger)
		h.recordBlockedCONNECTSession(ctx, req, hostname, connectAuthority, logger)
		return nil
	}

	// Check if the target host is in the TLS passthrough list.
	// If so, relay encrypted bytes directly without MITM interception.
	if h.passthrough != nil && h.passthrough.Contains(hostname) {
		return h.handlePassthrough(ctx, conn, connectAuthority, hostname)
	}

	// Validate that the issuer is configured for TLS interception.
	if h.issuer == nil {
		logger.Warn("CONNECT received but TLS issuer not configured", "host", req.Host)
		httputil.WriteHTTPError(conn, gohttp.StatusNotImplemented, logger)
		return nil
	}

	// Send 200 Connection Established to the client.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("write CONNECT 200: %w", err)
	}

	// Perform TLS handshake with the client.
	tlsConn, err := h.tlsHandshake(ctx, conn, hostname)
	if err != nil {
		logger.Error("TLS handshake failed", "host", hostname, "error", err)
		return nil // Connection is already broken; don't propagate.
	}
	defer tlsConn.Close()

	// Extract TLS metadata from the client-side handshake.
	tlsMeta := extractTLSMetadata(tlsConn)

	logger.Info("CONNECT tunnel established", "host", connectAuthority,
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite,
		"alpn", tlsMeta.ALPN)

	// If the client negotiated HTTP/2 via ALPN and we have an h2 handler,
	// delegate to it instead of the HTTP/1.x loop.
	if tlsMeta.ALPN == "h2" && h.h2Handler != nil {
		return h.h2Handler.HandleH2(ctx, tlsConn, connectAuthority,
			tlsMeta.Version, tlsMeta.CipherSuite, tlsMeta.ALPN)
	}

	// Process HTTPS requests over the decrypted TLS connection.
	// Pass the full authority (host:port) for URL reconstruction.
	return h.httpsLoop(ctx, tlsConn, connectAuthority, tlsMeta)
}

// handlePassthrough relays encrypted bytes between the client and the upstream
// server without TLS interception. This is used for domains in the passthrough
// list (e.g., cert-pinned services, out-of-scope domains).
func (h *Handler) handlePassthrough(ctx context.Context, clientConn net.Conn, authority, hostname string) error {
	logger := h.connLogger(ctx)
	logger.Info("TLS passthrough", "host", authority)

	// Connect to the upstream server, optionally via upstream proxy.
	upstream, err := h.dialUpstream(ctx, authority, 30*time.Second)
	if err != nil {
		logger.Error("passthrough upstream dial failed", "host", authority, "error", err)
		httputil.WriteHTTPError(clientConn, gohttp.StatusBadGateway, logger)
		return nil
	}
	defer upstream.Close()

	// Send 200 Connection Established to the client.
	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("write passthrough CONNECT 200: %w", err)
	}

	// Bidirectional relay: copy bytes in both directions until one side closes
	// or the context is cancelled.
	return relay(ctx, clientConn, upstream)
}

// relay copies data bidirectionally between two connections until one side
// closes, an error occurs, or the context is cancelled.
func relay(ctx context.Context, a, b net.Conn) error {
	// Watch for context cancellation and interrupt blocking reads.
	// Use a child context so the goroutine is reclaimed when the relay
	// returns, not only when the parent context is cancelled.
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()
	go func() {
		<-relayCtx.Done()
		a.SetReadDeadline(time.Now())
		b.SetReadDeadline(time.Now())
	}()

	errCh := make(chan error, 2)

	go func() {
		_, err := io.Copy(b, a)
		errCh <- err
		// Signal the other goroutine to stop by closing the write side.
		b.SetReadDeadline(time.Now())
	}()

	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
		a.SetReadDeadline(time.Now())
	}()

	// Wait for the first goroutine to finish.
	err := <-errCh

	// If context was cancelled, return the context error.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return err
}

// parseConnectHost extracts the hostname from a CONNECT request's Host field.
// The host may be in the form "host:port" or just "host". It returns the
// hostname portion (without port) for certificate generation.
func parseConnectHost(hostPort string) (string, error) {
	if hostPort == "" {
		return "", fmt.Errorf("empty host")
	}

	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		// If SplitHostPort fails, the host may not have a port.
		// Validate it's not empty after trimming.
		host = hostPort
	}

	if host == "" {
		return "", fmt.Errorf("empty hostname in %q", hostPort)
	}

	return host, nil
}

// tlsHandshake performs a TLS server handshake on the client connection,
// presenting a dynamically generated certificate for the given hostname.
// When an h2Handler is configured, ALPN advertises both "h2" and "http/1.1"
// so that clients can negotiate HTTP/2 over TLS.
func (h *Handler) tlsHandshake(ctx context.Context, conn net.Conn, hostname string) (*tls.Conn, error) {
	tlsConfig := &tls.Config{
		GetCertificate: h.issuer.GetCertificateForClientHello,
		MinVersion:     tls.VersionTLS12,
	}

	// Advertise HTTP/2 and HTTP/1.1 via ALPN when an h2 handler is available.
	if h.h2Handler != nil {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}

	tlsConn := tls.Server(conn, tlsConfig)

	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake for %s: %w", hostname, err)
	}

	return tlsConn, nil
}

// extractTLSMetadata extracts TLS connection information from a completed handshake.
func extractTLSMetadata(tlsConn *tls.Conn) tlsMetadata {
	state := tlsConn.ConnectionState()
	return tlsMetadata{
		Version:     tlsVersionString(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
}

// tlsVersionString converts a TLS version constant to a human-readable string.
func tlsVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("unknown (0x%04x)", version)
	}
}

// httpsLoop reads HTTP requests from the decrypted TLS connection in a loop
// (supporting keep-alive) and forwards each to the upstream server over HTTPS.
func (h *Handler) httpsLoop(ctx context.Context, tlsConn *tls.Conn, connectHost string, tlsMeta tlsMetadata) error {
	capture := &captureReader{r: tlsConn}
	reader := bufio.NewReader(capture)

	// Watch for context cancellation and interrupt blocking reads.
	// Same as Handle(): ReadRequest may block on keep-alive connections
	// and needs an immediate deadline to unblock during shutdown.
	//
	// Use a child context so the goroutine is reclaimed when the loop
	// returns, not only when the parent context is cancelled.
	connCtx, connCancel := context.WithCancel(ctx)
	defer connCancel()
	go func() {
		<-connCtx.Done()
		tlsConn.SetReadDeadline(time.Now())
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Set read deadline for request header reading (Slowloris protection).
		if timeout := h.effectiveRequestTimeout(); timeout > 0 {
			tlsConn.SetReadDeadline(time.Now().Add(timeout))
		}

		// Mark the capture position before reading the request.
		captureStart := capture.buf.Len()

		// Check for HTTP request smuggling patterns in raw headers before
		// ReadRequest normalizes them. Same check as Handle() for HTTP.
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
			return fmt.Errorf("read HTTPS request: %w", err)
		}

		// Log any detected smuggling patterns.
		logSmugglingWarnings(h.Logger, smuggling, req)

		// Reset deadline after successful read.
		tlsConn.SetReadDeadline(time.Time{})

		if err := h.handleHTTPSRequest(ctx, tlsConn, connectHost, req, smuggling, tlsMeta, capture, captureStart, reader); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

// handleHTTPSRequest forwards a single decrypted HTTPS request to the upstream
// server, records the flow, and writes the response back to the client.
func (h *Handler) handleHTTPSRequest(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, smuggling *smugglingFlags, tlsMeta tlsMetadata, capture *captureReader, captureStart int, reader *bufio.Reader) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Step 1: Target scope enforcement for HTTPS requests inside the MITM tunnel.
	// The CONNECT target was already checked, but the Host header inside
	// the tunnel may differ (e.g., HTTP/1.1 Host header rewrite).
	if blocked := h.checkHTTPSScopeRewrite(ctx, conn, connectHost, req, smuggling, start, connID, clientAddr, tlsMeta, logger); blocked {
		return nil
	}

	// Step 2: WebSocket upgrade (before hop-by-hop header removal).
	if isWebSocketUpgrade(req) {
		return h.handleWebSocketTLS(ctx, conn, connectHost, req, tlsMeta)
	}

	// Step 3: Read request body + capture raw bytes.
	bodyResult := readAndCaptureRequestBody(req, logger)
	rawRequest := extractRawRequest(capture, captureStart, reader)

	// Reconstruct the full URL for the upstream request.
	if req.URL.Host == "" {
		req.URL.Host = connectHost
	}
	req.URL.Scheme = "https"

	// Remove hop-by-hop headers.
	removeHopByHopHeaders(req.Header)

	// Build the reconstructed HTTPS URL for recording.
	reqURL := &url.URL{
		Scheme:   "https",
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}

	// Build send record params for progressive recording.
	sp := sendRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		protocol:   "HTTPS",
		start:      start,
		tags:       smugglingTags(smuggling),
		connInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			TLSVersion: tlsMeta.Version,
			TLSCipher:  tlsMeta.CipherSuite,
			TLSALPN:    tlsMeta.ALPN,
		},
		req:          req,
		reqURL:       reqURL,
		reqBody:      bodyResult.recordBody,
		rawRequest:   rawRequest,
		reqTruncated: bodyResult.truncated,
	}

	// Step 4: Snapshot + Intercept check + modifications.
	// Snapshot headers/body before intercept/transform for variant recording.
	snap := snapshotRequest(req.Header, bodyResult.recordBody)

	var dropped bool
	req, bodyResult.recordBody, dropped = h.applyIntercept(ctx, conn, req, bodyResult.recordBody, logger)
	if dropped {
		sp.reqBody = bodyResult.recordBody
		h.recordInterceptDrop(ctx, sp, logger)
		return nil
	}

	// Step 5: Apply auto-transform rules.
	bodyResult.recordBody = h.applyTransform(req, bodyResult.recordBody)
	sp.reqBody = bodyResult.recordBody

	// Progressive recording: record send (session + request) before forwarding.
	// Uses variant-aware recording to capture both original and modified
	// versions when intercept/transform changed the request.
	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	// Step 6: Forward upstream.
	fwd, err := h.forwardUpstream(ctx, conn, req, logger)
	if err != nil {
		// Upstream failed — record session as error. Send is already recorded.
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}
	defer fwd.resp.Body.Close()

	// Step 7: Read response, write to client, and record flow.
	fullRespBody, rawResponse := h.readResponseBody(fwd.resp, logger)

	if err := writeResponseToClient(conn, fwd.resp, fullRespBody); err != nil {
		return err
	}

	// Progressive recording: record receive (response + session completion).
	// Update ConnInfo with server-side TLS certificate info now that we have it.
	duration := time.Since(start)
	var tlsCertSubject string
	if fwd.resp.TLS != nil && len(fwd.resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = fwd.resp.TLS.PeerCertificates[0].Subject.String()
	}
	h.recordReceive(ctx, sendResult, receiveRecordParams{
		start:                start,
		duration:             duration,
		serverAddr:           fwd.serverAddr,
		tlsServerCertSubject: tlsCertSubject,
		resp:                 fwd.resp,
		rawResponse:          rawResponse,
		respBody:             fullRespBody,
	}, logger)

	logHTTPRequest(logger, req, fwd.resp.StatusCode, duration)

	return nil
}

// checkHTTPSScopeRewrite re-checks the target scope when the Host header inside
// an HTTPS MITM tunnel differs from the CONNECT authority. Returns true if the
// request was blocked.
func (h *Handler) checkHTTPSScopeRewrite(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, smuggling *smugglingFlags, start time.Time, connID, clientAddr string, tlsMeta tlsMetadata, logger *slog.Logger) bool {
	requestHost := req.Host
	if requestHost == "" && req.URL.Host != "" {
		requestHost = req.URL.Host
	}
	if requestHost == "" || strings.EqualFold(requestHost, connectHost) {
		return false
	}

	checkURL := &url.URL{
		Scheme: "https",
		Host:   requestHost,
		Path:   req.URL.Path,
	}
	blocked, reason := h.checkTargetScope(checkURL)
	if !blocked {
		return false
	}

	// Set req.URL fields before recording so the flow has the full URL.
	if req.URL.Host == "" {
		req.URL.Host = requestHost
	}
	req.URL.Scheme = "https"
	h.writeBlockedResponse(conn, checkURL.Hostname(), reason, logger)
	h.recordBlockedHTTPSSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, tlsMeta, logger)
	return true
}

// dialUpstream dials the target address, optionally routing through the
// configured upstream proxy. If no upstream proxy is set, it dials directly.
func (h *Handler) dialUpstream(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	proxyURL := h.UpstreamProxy()
	if proxyURL != nil {
		return proxy.DialViaUpstreamProxy(ctx, proxyURL, addr, timeout)
	}
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

// parseConnectPort extracts the port number from a CONNECT host:port string.
// Returns the port number, or 443 as the default if no port is present.
// Returns 0 if the port cannot be parsed.
func parseConnectPort(hostPort string) int {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		// No port specified; default to 443 for CONNECT.
		return 443
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// recordBlockedCONNECTSession records a blocked CONNECT request as a flow
// with BlockedBy="target_scope".
func (h *Handler) recordBlockedCONNECTSession(ctx context.Context, req *gohttp.Request, hostname, authority string, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	// Build a synthetic URL for CONNECT recording.
	connectURL := &url.URL{
		Scheme: "https",
		Host:   authority,
	}

	if !h.shouldCapture(req.Method, connectURL) {
		return
	}

	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		BlockedBy: "target_scope",
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
		},
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("blocked CONNECT flow save failed", "host", authority, "error", err)
		return
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    "CONNECT",
		URL:       connectURL,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("blocked CONNECT send message save failed", "error", err)
	}
}

// recordBlockedHTTPSSession records a blocked HTTPS request (inside MITM tunnel)
// as a flow with BlockedBy="target_scope".
func (h *Handler) recordBlockedHTTPSSession(ctx context.Context, req *gohttp.Request, reqBody, rawRequest []byte, reqTruncated bool, smuggling *smugglingFlags, start time.Time, connID, clientAddr string, tlsMeta tlsMetadata, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	reqURL := &url.URL{
		Scheme:   "https",
		Host:     req.URL.Host,
		Path:     req.URL.Path,
		RawQuery: req.URL.RawQuery,
		Fragment: req.URL.Fragment,
	}
	if !h.shouldCapture(req.Method, reqURL) {
		return
	}

	duration := time.Since(start)
	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "HTTPS",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      smugglingTags(smuggling),
		BlockedBy: "target_scope",
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			TLSVersion: tlsMeta.Version,
			TLSCipher:  tlsMeta.CipherSuite,
			TLSALPN:    tlsMeta.ALPN,
		},
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("blocked HTTPS flow save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		return
	}
	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     start,
		Method:        req.Method,
		URL:           reqURL,
		Headers:       req.Header,
		Body:          reqBody,
		RawBytes:      rawRequest,
		BodyTruncated: reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("blocked HTTPS send message save failed", "error", err)
	}
}
