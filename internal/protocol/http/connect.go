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
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
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

	logger.Debug("CONNECT request received", "host", req.Host)

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
		h.recordBlockedCONNECTSession(ctx, req, hostname, connectAuthority, "target_scope", logger)
		return nil
	}

	// Rate limit check for CONNECT tunnels.
	if blocked := h.checkRateLimit(hostname); blocked {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedCONNECTSession(ctx, req, hostname, connectAuthority, "rate_limit", logger)
		return nil
	}

	// Check if the target host is in the TLS passthrough list.
	// If so, relay encrypted bytes directly without MITM interception.
	if h.passthrough != nil && h.passthrough.Contains(hostname) {
		logger.Debug("TLS passthrough matched", "host", hostname)
		return h.handlePassthrough(ctx, conn, connectAuthority, hostname)
	}
	logger.Debug("TLS passthrough not matched, proceeding with MITM", "host", hostname)

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

	// Peek the first bytes from the client to detect whether this is a TLS
	// ClientHello or plaintext HTTP. SOCKS5 has equivalent logic in its
	// post-handshake dispatch (isTLSClientHello in socks5/dispatch.go).
	peekConn := proxy.NewPeekConn(conn)
	peek, peekErr := peekConn.Peek(2)
	if peekErr != nil {
		// Client closed or errored before sending data; nothing to do.
		logger.Debug("CONNECT tunnel peek failed", "host", connectAuthority, "error", peekErr)
		return nil
	}

	// TLS ClientHello starts with ContentType 0x16 (handshake) followed by
	// protocol version 0x03 (SSL/TLS).
	if peek[0] == 0x16 && peek[1] == 0x03 {
		// TLS path: delegate to the shared TLS MITM handler.
		return h.HandleTunnelMITM(ctx, peekConn, connectAuthority)
	}

	// Non-TLS (plaintext) path: handle as plain HTTP inside the CONNECT
	// tunnel. This supports ws:// WebSocket upgrades and plain HTTP requests
	// sent through CONNECT tunnels to non-TLS ports (e.g. CONNECT host:80).
	logger.Info("CONNECT tunnel plaintext HTTP detected", "host", connectAuthority)
	return h.handlePlaintextCONNECT(ctx, peekConn, connectAuthority)
}

// handlePlaintextCONNECT processes plaintext HTTP requests inside a CONNECT
// tunnel. This handles the case where a client sends CONNECT host:port followed
// by plaintext HTTP (not TLS), e.g. ws:// WebSocket upgrades via CONNECT to
// port 80. The method reads HTTP requests in a loop (supporting keep-alive)
// and dispatches each to the appropriate handler (WebSocket upgrade or normal
// HTTP forwarding).
func (h *Handler) handlePlaintextCONNECT(ctx context.Context, conn net.Conn, connectAuthority string) error {
	capture := &captureReader{r: conn}
	reader := bufio.NewReader(capture)

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

		captureStart := capture.buf.Len()

		smuggling := checkRequestSmuggling(reader, h.Logger)

		req, err := gohttp.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read plaintext CONNECT request: %w", err)
		}

		logSmugglingWarnings(h.Logger, smuggling, req)

		// Reset deadline after successful read.
		conn.SetReadDeadline(time.Time{})

		// Ensure absolute URL with http scheme for forward proxying.
		if req.URL.Host == "" {
			req.URL.Host = connectAuthority
		}
		if req.URL.Scheme == "" {
			req.URL.Scheme = "http"
		}

		// WebSocket upgrade: delegate to the plaintext WebSocket handler.
		if isWebSocketUpgrade(req) {
			return h.handleWebSocket(ctx, conn, req)
		}

		// Normal HTTP request inside the CONNECT tunnel.
		if err := h.handlePlaintextCONNECTRequest(ctx, conn, connectAuthority, req, smuggling, capture, captureStart, reader); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

// handlePlaintextCONNECTRequest forwards a single plaintext HTTP request from
// inside a CONNECT tunnel to the upstream server, records the flow, and writes
// the response back to the client.
func (h *Handler) handlePlaintextCONNECTRequest(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, smuggling *smugglingFlags, capture *captureReader, captureStart int, reader *bufio.Reader) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Host header mismatch check: if the Host header differs from the
	// CONNECT authority, re-check target scope against the Host header to
	// prevent scope bypass via Host header manipulation (similar to
	// checkHTTPSScopeRewrite for HTTPS).
	if blocked := h.checkPlaintextScopeRewrite(ctx, conn, connectHost, req, smuggling, start, connID, clientAddr, logger); blocked {
		return nil
	}

	// Target scope enforcement.
	if blocked, reason := h.checkTargetScope(req.URL); blocked {
		h.writeBlockedResponse(conn, req.URL.Hostname(), reason, logger)
		h.recordBlockedSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, "target_scope", nil, logger)
		return nil
	}

	// Rate limit enforcement.
	if blocked := h.checkRateLimit(req.URL.Hostname()); blocked {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, "rate_limit", nil, logger)
		return nil
	}

	// Read request body + capture raw bytes.
	bodyResult := readAndCaptureRequestBody(req, logger)
	rawRequest := extractRawRequest(capture, captureStart, reader)

	// Safety filter enforcement.
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, req.URL.String(), req.Header); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedSession(ctx, req, bodyResult.recordBody, rawRequest, bodyResult.truncated, smuggling, start, connID, clientAddr, "safety_filter", violation, logger)
			return nil
		}
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", violation.MatchedOn)
	}

	removeHopByHopHeaders(req.Header)

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
		reqURL:       req.URL,
		reqBody:      bodyResult.recordBody,
		rawRequest:   rawRequest,
		reqTruncated: bodyResult.truncated,
	}

	// Snapshot + Intercept check + modifications.
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
	// Update sp fields after intercept/transform: req and reqURL may have
	// changed (e.g. override_url), so the recorded flow must reflect the
	// post-intercept state.
	sp.req = req
	sp.reqURL = req.URL
	sp.reqBody = bodyResult.recordBody

	// Progressive recording: record send before forwarding.
	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	// Forward upstream.
	sendStart := time.Now()
	fwd, err := h.forwardUpstream(ctx, conn, req, logger)
	if err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}
	defer fwd.resp.Body.Close()

	// SSE detection.
	if isSSEResponse(fwd.resp) {
		sendResult.tags = addSSETags(sendResult.tags)
		return h.handleSSEStream(ctx, conn, req, fwd, start, sendResult, nil, logger)
	}

	// Read response, write to client, and record flow.
	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	rawResponse := serializeRawResponse(fwd.resp, fullRespBody)
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

	fullRespBody, fwd.resp.Header = h.ApplyOutputFilter(fullRespBody, fwd.resp.Header, logger)

	if err := writeResponseToClient(conn, fwd.resp, fullRespBody); err != nil {
		return err
	}

	duration := time.Since(start)
	sendMs, waitMs, receiveMs := httputil.ComputeTiming(sendStart, fwd.timing, receiveEnd)
	h.recordReceive(ctx, sendResult, receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  fwd.serverAddr,
		resp:        fwd.resp,
		rawResponse: rawResponse,
		respBody:    rawRespBody,
		sendMs:      sendMs,
		waitMs:      waitMs,
		receiveMs:   receiveMs,
	}, logger)

	logHTTPRequest(logger, req, fwd.resp.StatusCode, duration)

	return nil
}

// HandleTunnelMITM performs TLS MITM on a tunneled connection. It performs a
// TLS handshake with the client using a dynamically issued certificate for the
// target hostname, then dispatches to the appropriate protocol handler based on
// ALPN negotiation (HTTP/2 via h2, or HTTP/1.x via httpsLoop).
//
// This method is the shared MITM path used by both HTTP CONNECT tunnels and
// SOCKS5 post-handshake dispatch. The caller must have already established the
// tunnel (e.g., sent "200 Connection Established" for CONNECT, or completed
// the SOCKS5 handshake) before calling this method.
//
// The authority parameter is the target "host:port" used for certificate
// generation and upstream forwarding.
func (h *Handler) HandleTunnelMITM(ctx context.Context, conn net.Conn, authority string) error {
	logger := h.connLogger(ctx)

	hostname, err := parseConnectHost(authority)
	if err != nil {
		logger.Warn("invalid tunnel authority", "authority", authority, "error", err)
		return fmt.Errorf("invalid tunnel authority %q: %w", authority, err)
	}

	if h.issuer == nil {
		logger.Warn("TLS MITM requested but issuer not configured", "host", authority)
		return fmt.Errorf("TLS issuer not configured")
	}

	// Perform TLS handshake with the client.
	logger.Debug("client TLS handshake starting", "host", hostname)
	tlsConn, err := h.tlsHandshake(ctx, conn, hostname)
	if err != nil {
		logger.Error("TLS handshake failed", "host", hostname, "error", err)
		return nil // Connection is already broken; don't propagate.
	}
	defer tlsConn.Close()

	// Extract TLS metadata from the client-side handshake.
	tlsMeta := extractTLSMetadata(tlsConn)
	logger.Debug("client TLS handshake complete", "host", hostname,
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite,
		"alpn", tlsMeta.ALPN)

	// Dispatch on_tls_handshake lifecycle hook (fail-open).
	h.dispatchOnTLSHandshake(ctx, hostname, tlsMeta)

	logger.Info("TLS tunnel established", "host", authority,
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite,
		"alpn", tlsMeta.ALPN)

	// If the client negotiated HTTP/2 via ALPN and we have an h2 handler,
	// delegate to it instead of the HTTP/1.x loop.
	if tlsMeta.ALPN == "h2" && h.h2Handler != nil {
		return h.h2Handler.HandleH2(ctx, tlsConn, authority,
			tlsMeta.Version, tlsMeta.CipherSuite, tlsMeta.ALPN)
	}

	// Process HTTPS requests over the decrypted TLS connection.
	return h.httpsLoop(ctx, tlsConn, authority, tlsMeta)
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
	logger := h.connLogger(ctx)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			// When the client connects to an IP address, SNI is not sent
			// (RFC 6066), so ServerName is empty. Fall back to the hostname
			// extracted from the CONNECT/tunnel authority.
			if name == "" {
				logger.Debug("TLS ClientHello without SNI, using tunnel hostname", "hostname", hostname)
				name = hostname
			} else {
				logger.Debug("TLS ClientHello SNI received", "sni", name)
			}
			return h.issuer.GetCertificate(name)
		},
		MinVersion: tls.VersionTLS12,
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

	// Step 3.5: Safety filter enforcement (after body read, before hop-by-hop removal).
	httpsURL := (&url.URL{Scheme: "https", Host: req.URL.Host, Path: req.URL.Path, RawQuery: req.URL.RawQuery}).String()
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, httpsURL, req.Header); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedHTTPSSession(ctx, req, bodyResult.recordBody, rawRequest, bodyResult.truncated, smuggling, start, connID, clientAddr, tlsMeta, "safety_filter", violation, logger)
			return nil
		}
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", violation.MatchedOn)
	}

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
		protocol:   socks5Protocol(ctx, "HTTPS"),
		scheme:     "https",
		start:      start,
		tags:       mergeSOCKS5Tags(ctx, smugglingTags(smuggling)),
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

	// Step 5: Apply auto-transform rules.
	bodyResult.recordBody = h.applyTransform(req, bodyResult.recordBody)
	sp.reqBody = bodyResult.recordBody

	// Progressive recording: record send (session + request) before forwarding.
	// Uses variant-aware recording to capture both original and modified
	// versions when intercept/transform changed the request.
	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	// Step 6: Forward upstream.
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
		return h.handleSSEStreamTLS(ctx, conn, req, fwd, start, sendResult, logger)
	}

	// Step 7: Read response, write to client, and record flow.
	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	// Serialize raw response for recording before output filter masks it.
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
	// Update ConnInfo with server-side TLS certificate info now that we have it.
	// NOTE: respBody uses rawRespBody (unmasked) so Flow Store has raw data.
	duration := time.Since(start)
	sendMs, waitMs, receiveMs := httputil.ComputeTiming(sendStart, fwd.timing, receiveEnd)
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
		respBody:             rawRespBody,
		sendMs:               sendMs,
		waitMs:               waitMs,
		receiveMs:            receiveMs,
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
	h.recordBlockedHTTPSSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, tlsMeta, "target_scope", nil, logger)
	return true
}

// checkPlaintextScopeRewrite re-checks the target scope when the Host header
// inside a plaintext CONNECT tunnel differs from the CONNECT authority. This
// prevents scope bypass via Host header manipulation (CWE-20). Returns true
// if the request was blocked.
func (h *Handler) checkPlaintextScopeRewrite(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, smuggling *smugglingFlags, start time.Time, connID, clientAddr string, logger *slog.Logger) bool {
	requestHost := req.Host
	if requestHost == "" && req.URL.Host != "" {
		requestHost = req.URL.Host
	}
	if requestHost == "" || strings.EqualFold(requestHost, connectHost) {
		return false
	}

	checkURL := &url.URL{
		Scheme: "http",
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
	req.URL.Scheme = "http"
	h.writeBlockedResponse(conn, checkURL.Hostname(), reason, logger)
	h.recordBlockedSession(ctx, req, nil, nil, false, smuggling, start, connID, clientAddr, "target_scope", nil, logger)
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
// with the specified blockedBy reason (e.g. "target_scope", "rate_limit").
func (h *Handler) recordBlockedCONNECTSession(ctx context.Context, req *gohttp.Request, hostname, authority, blockedBy string, logger *slog.Logger) {
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
		Scheme:    "https",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		BlockedBy: blockedBy,
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

// hookTimeout is the maximum time allowed for lifecycle hook dispatches.
const hookTimeout = 5 * time.Second

// dispatchOnTLSHandshake dispatches the on_tls_handshake lifecycle hook after
// a successful TLS handshake. Errors are logged but do not block processing (fail-open).
func (h *Handler) dispatchOnTLSHandshake(ctx context.Context, serverName string, tlsMeta tlsMetadata) {
	if h.pluginEngine == nil {
		return
	}

	ctx, cancel := context.WithTimeout(ctx, hookTimeout)
	defer cancel()

	logger := h.connLogger(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	connInfo := &plugin.ConnInfo{
		ClientAddr: clientAddr,
		TLSVersion: tlsMeta.Version,
		TLSCipher:  tlsMeta.CipherSuite,
		TLSALPN:    tlsMeta.ALPN,
	}
	data := map[string]any{
		"event":       "tls_handshake",
		"conn_info":   connInfo.ToMap(),
		"server_name": serverName,
	}

	_, err := h.pluginEngine.Dispatch(ctx, plugin.HookOnTLSHandshake, data)
	if err != nil {
		logger.Warn("plugin on_tls_handshake hook error", "error", err)
	}
}

// recordBlockedHTTPSSession records a blocked HTTPS request (inside MITM tunnel)
// as a flow with the specified blockedBy reason. If violation is non-nil,
// safety rule tags are added to the flow.
func (h *Handler) recordBlockedHTTPSSession(ctx context.Context, req *gohttp.Request, reqBody, rawRequest []byte, reqTruncated bool, smuggling *smugglingFlags, start time.Time, connID, clientAddr string, tlsMeta tlsMetadata, blockedBy string, violation *safety.InputViolation, logger *slog.Logger) {
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
	tags := smugglingTags(smuggling)
	if violation != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["safety_rule"] = violation.RuleID
		tags["safety_target"] = violation.Target.String()
	}
	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "HTTPS",
		Scheme:    "https",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		Duration:  duration,
		Tags:      tags,
		BlockedBy: blockedBy,
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
