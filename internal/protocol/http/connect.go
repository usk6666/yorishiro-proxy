package http

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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

// handleCONNECT processes an HTTP CONNECT request.
func (h *Handler) handleCONNECT(ctx context.Context, conn net.Conn, req *parser.RawRequest) error {
	logger := h.connLogger(ctx)

	connectHost := req.Headers.Get("Host")
	if connectHost == "" {
		// For CONNECT, the RequestURI is the host:port.
		connectHost = req.RequestURI
	}

	logger.Debug("CONNECT request received", "host", connectHost)

	hostname, err := parseConnectHost(connectHost)
	if err != nil {
		logger.Warn("invalid CONNECT host", "host", connectHost, "error", err)
		writeHTTPError(conn, statusBadRequest, logger)
		return nil
	}

	connectAuthority := connectHost

	// Target scope enforcement.
	port := parseConnectPort(connectHost)
	if port == 0 {
		logger.Warn("CONNECT with invalid port", "host", connectHost)
		writeHTTPError(conn, statusBadRequest, logger)
		return nil
	}
	if blocked, reason := h.checkTargetScopeHost(hostname, port); blocked {
		h.writeBlockedResponse(conn, hostname, reason, logger)
		h.recordBlockedCONNECTSession(ctx, connectHost, hostname, connectAuthority, "target_scope", logger)
		return nil
	}

	// Rate limit check.
	if denial := h.checkRateLimit(hostname); denial != nil {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedCONNECTSessionWithTags(ctx, connectHost, hostname, connectAuthority, "rate_limit", denial.Tags(), logger)
		return nil
	}

	// Check TLS passthrough.
	if h.passthrough != nil && h.passthrough.Contains(hostname) {
		logger.Debug("TLS passthrough matched", "host", hostname)
		return h.handlePassthrough(ctx, conn, connectAuthority, hostname)
	}
	logger.Debug("TLS passthrough not matched, proceeding with MITM", "host", hostname)

	if h.issuer == nil {
		logger.Warn("CONNECT received but TLS issuer not configured", "host", connectHost)
		writeHTTPError(conn, statusNotImplemented, logger)
		return nil
	}

	// Send 200 Connection Established.
	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("write CONNECT 200: %w", err)
	}

	// Peek to detect TLS vs plaintext.
	peekConn := proxy.NewPeekConn(conn)
	peek, peekErr := peekConn.Peek(2)
	if peekErr != nil {
		logger.Debug("CONNECT tunnel peek failed", "host", connectAuthority, "error", peekErr)
		return nil
	}

	if peek[0] == 0x16 && peek[1] == 0x03 {
		return h.HandleTunnelMITM(ctx, peekConn, connectAuthority)
	}

	logger.Info("CONNECT tunnel plaintext HTTP detected", "host", connectAuthority)
	return h.handlePlaintextCONNECT(ctx, peekConn, connectAuthority)
}

// handlePlaintextCONNECT processes plaintext HTTP requests inside a CONNECT tunnel.
func (h *Handler) handlePlaintextCONNECT(ctx context.Context, conn net.Conn, connectAuthority string) error {
	reader := bufio.NewReader(conn)

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
			return fmt.Errorf("read plaintext CONNECT request: %w", err)
		}

		logAnomalyWarnings(h.Logger, req.Anomalies, req.Method, req.RequestURI)
		conn.SetReadDeadline(time.Time{})

		// Ensure absolute URL.
		reqURL := parseRequestURL(ctx, req, "http")
		if reqURL.Host == "" {
			reqURL.Host = connectAuthority
		}

		if isWebSocketUpgradeRaw(req.Headers) {
			return h.handleWebSocket(ctx, conn, req, reqURL)
		}

		if err := h.handlePlaintextCONNECTRequest(ctx, conn, connectAuthority, req, reqURL); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

// handlePlaintextCONNECTRequest forwards a single plaintext HTTP request from
// inside a CONNECT tunnel to the upstream server.
func (h *Handler) handlePlaintextCONNECTRequest(ctx context.Context, conn net.Conn, connectHost string, req *parser.RawRequest, reqURL *url.URL) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Host header mismatch check.
	if blocked := h.checkPlaintextScopeRewrite(ctx, conn, connectHost, req, reqURL, start, connID, clientAddr, logger); blocked {
		return nil
	}

	if blocked, reason := h.checkTargetScope(reqURL); blocked {
		h.writeBlockedResponse(conn, reqURL.Hostname(), reason, logger)
		h.recordBlockedSession(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, "target_scope", nil, logger)
		return nil
	}

	if denial := h.checkRateLimit(reqURL.Hostname()); denial != nil {
		h.writeRateLimitResponse(conn, logger)
		h.recordBlockedSessionWithTags(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, "rate_limit", nil, denial.Tags(), logger)
		return nil
	}

	bodyResult := readAndCaptureBody(req, logger)

	safetyHeaders := httputil.RawHeadersToHTTPHeader(req.Headers)
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, reqURL.String(), safetyHeaders); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedSession(ctx, req, reqURL, bodyResult.recordBody, req.RawBytes, bodyResult.truncated, req.Anomalies, start, connID, clientAddr, "safety_filter", violation, logger)
			return nil
		}
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", violation.MatchedOn)
	}

	removeHopByHopHeadersRaw(&req.Headers)

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

	snap := snapshotRawRequest(req.Headers, bodyResult.recordBody)

	iResult := h.applyIntercept(ctx, conn, req, reqURL, bodyResult.recordBody, req.RawBytes, logger)
	if iResult.Dropped {
		sp.reqBody = iResult.RecordBody
		h.recordInterceptDrop(ctx, sp, logger)
		return nil
	}
	req = iResult.Req
	bodyResult.recordBody = iResult.RecordBody

	// Re-derive reqURL after intercept URL override (CP-7/CP-8).
	if iResult.ModURL != nil {
		reqURL = iResult.ModURL
	} else {
		reqURL = parseRequestURL(ctx, req, "http")
	}
	sp.reqURL = reqURL

	if iResult.IsRaw {
		return h.handleRawForward(ctx, conn, req, reqURL, iResult, sp, &snap, start, logger)
	}

	bodyResult.recordBody = h.applyTransform(req, bodyResult.recordBody)
	sp.req = req
	sp.reqBody = bodyResult.recordBody

	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	sendStart := time.Now()
	fwd, err := h.forwardUpstream(ctx, conn, req, reqURL, false, logger)
	if err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}

	if isSSEResponseRaw(fwd.resp) {
		sendResult.tags = addSSETags(sendResult.tags)
		return h.handleSSEStream(ctx, conn, req, reqURL, fwd, start, sendResult, nil, logger)
	}

	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	rawResponse := serializeRawResponseBytes(fwd.resp, fullRespBody)
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

	goHeaders := httputil.RawHeadersToHTTPHeader(fwd.resp.Headers)
	fullRespBody, goHeaders = h.ApplyOutputFilter(fullRespBody, goHeaders, logger)
	fwd.resp.Headers = httputil.HTTPHeaderToRawHeaders(goHeaders)

	if err := writeRawResponse(conn, fwd.resp, fullRespBody); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	duration := time.Since(start)
	sendMs, waitMs, receiveMs := httputil.ComputeTiming(sendStart, fwd.timing, receiveEnd)

	goResp := httputil.RawResponseToHTTP(fwd.resp, rawRespBody)
	h.recordReceive(ctx, sendResult, receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  fwd.serverAddr,
		resp:        goResp,
		rawResponse: rawResponse,
		respBody:    rawRespBody,
		sendMs:      sendMs,
		waitMs:      waitMs,
		receiveMs:   receiveMs,
	}, logger)

	logHTTPRequest(logger, req.Method, reqURL.String(), fwd.resp.StatusCode, duration)
	return nil
}

// HandleTunnelMITM performs TLS MITM on a tunneled connection.
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

	logger.Debug("client TLS handshake starting", "host", hostname)
	tlsConn, err := h.tlsHandshake(ctx, conn, hostname)
	if err != nil {
		logger.Error("TLS handshake failed", "host", hostname, "error", err)
		return nil
	}
	defer tlsConn.Close()

	tlsMeta := extractTLSMetadata(tlsConn)
	logger.Debug("client TLS handshake complete", "host", hostname,
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite,
		"alpn", tlsMeta.ALPN)

	h.dispatchOnTLSHandshake(ctx, hostname, tlsMeta)

	logger.Info("TLS tunnel established", "host", authority,
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite,
		"alpn", tlsMeta.ALPN)

	if tlsMeta.ALPN == "h2" && h.h2Handler != nil {
		return h.h2Handler.HandleH2(ctx, tlsConn, authority,
			tlsMeta.Version, tlsMeta.CipherSuite, tlsMeta.ALPN)
	}

	return h.httpsLoop(ctx, tlsConn, authority, tlsMeta)
}

// handlePassthrough relays encrypted bytes directly.
func (h *Handler) handlePassthrough(ctx context.Context, clientConn net.Conn, authority, hostname string) error {
	logger := h.connLogger(ctx)
	logger.Info("TLS passthrough", "host", authority)

	upstream, err := h.dialUpstream(ctx, authority, 30*time.Second)
	if err != nil {
		logger.Error("passthrough upstream dial failed", "host", authority, "error", err)
		writeHTTPError(clientConn, statusBadGateway, logger)
		return nil
	}
	defer upstream.Close()

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return fmt.Errorf("write passthrough CONNECT 200: %w", err)
	}

	return relay(ctx, clientConn, upstream)
}

func relay(ctx context.Context, a, b net.Conn) error {
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
		b.SetReadDeadline(time.Now())
	}()
	go func() {
		_, err := io.Copy(a, b)
		errCh <- err
		a.SetReadDeadline(time.Now())
	}()

	err := <-errCh
	relayCancel()
	<-errCh

	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}

func parseConnectHost(hostPort string) (string, error) {
	if hostPort == "" {
		return "", fmt.Errorf("empty host")
	}
	host, _, err := net.SplitHostPort(hostPort)
	if err != nil {
		host = hostPort
	}
	if host == "" {
		return "", fmt.Errorf("empty hostname in %q", hostPort)
	}
	return host, nil
}

func (h *Handler) tlsHandshake(ctx context.Context, conn net.Conn, hostname string) (*tls.Conn, error) {
	logger := h.connLogger(ctx)
	tlsConfig := &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
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
	if h.h2Handler != nil {
		tlsConfig.NextProtos = []string{"h2", "http/1.1"}
	}
	tlsConn := tls.Server(conn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("TLS handshake for %s: %w", hostname, err)
	}
	return tlsConn, nil
}

func extractTLSMetadata(tlsConn *tls.Conn) tlsMetadata {
	state := tlsConn.ConnectionState()
	return tlsMetadata{
		Version:     httputil.TLSVersionName(state.Version),
		CipherSuite: tls.CipherSuiteName(state.CipherSuite),
		ALPN:        state.NegotiatedProtocol,
	}
}

// httpsLoop reads HTTP requests from the decrypted TLS connection in a loop.
func (h *Handler) httpsLoop(ctx context.Context, tlsConn *tls.Conn, connectHost string, tlsMeta tlsMetadata) error {
	reader := bufio.NewReader(tlsConn)

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

		if timeout := h.effectiveRequestTimeout(); timeout > 0 {
			tlsConn.SetReadDeadline(time.Now().Add(timeout))
		}

		req, err := parser.ParseRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read HTTPS request: %w", err)
		}

		logAnomalyWarnings(h.Logger, req.Anomalies, req.Method, req.RequestURI)
		tlsConn.SetReadDeadline(time.Time{})

		if err := h.handleHTTPSRequest(ctx, tlsConn, connectHost, req, tlsMeta); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

// handleHTTPSRequest forwards a single decrypted HTTPS request.
func (h *Handler) handleHTTPSRequest(ctx context.Context, conn net.Conn, connectHost string, req *parser.RawRequest, tlsMeta tlsMetadata) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	effectiveHost := h.resolveEffectiveHost(ctx, connectHost, req)

	// Build HTTPS URL.
	reqURL := &url.URL{
		Scheme: "https",
		Host:   effectiveHost,
		Path:   "/",
	}
	if u, err := url.ParseRequestURI(req.RequestURI); err == nil {
		reqURL.Path = u.Path
		reqURL.RawQuery = u.RawQuery
		reqURL.Fragment = u.Fragment
	}
	if reqURL.Host == "" {
		reqURL.Host = effectiveHost
	}

	// Target scope enforcement for HTTPS.
	if blocked := h.checkHTTPSScopeRewrite(ctx, conn, effectiveHost, req, reqURL, start, connID, clientAddr, tlsMeta, logger); blocked {
		return nil
	}

	// WebSocket upgrade.
	if isWebSocketUpgradeRaw(req.Headers) {
		return h.handleWebSocketTLS(ctx, conn, effectiveHost, req, reqURL, tlsMeta)
	}

	bodyResult := readAndCaptureBody(req, logger)

	// Safety filter enforcement.
	httpsURL := (&url.URL{Scheme: "https", Host: reqURL.Host, Path: reqURL.Path, RawQuery: reqURL.RawQuery}).String()
	safetyHeaders := httputil.RawHeadersToHTTPHeader(req.Headers)
	if violation := h.CheckSafetyFilter(bodyResult.recordBody, httpsURL, safetyHeaders); violation != nil {
		if h.SafetyFilterAction(violation) == safety.ActionBlock {
			h.writeSafetyFilterResponse(conn, violation, logger)
			h.recordBlockedHTTPSSession(ctx, req, reqURL, bodyResult.recordBody, req.RawBytes, bodyResult.truncated, req.Anomalies, start, connID, clientAddr, tlsMeta, "safety_filter", violation, logger)
			return nil
		}
		logger.Warn("safety filter violation (log_only)",
			"rule_id", violation.RuleID, "rule_name", violation.RuleName,
			"target", violation.Target.String(), "matched_on", violation.MatchedOn)
	}

	removeHopByHopHeadersRaw(&req.Headers)

	// Build plugin ConnInfo.
	pluginConnInfo := &plugin.ConnInfo{ClientAddr: clientAddr}
	txCtx := plugin.NewTxCtx()

	sp := sendRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		protocol:   socks5Protocol(ctx, "HTTPS"),
		scheme:     "https",
		start:      start,
		tags:       mergeSOCKS5Tags(ctx, anomalyTags(req.Anomalies)),
		connInfo: &flow.ConnectionInfo{
			ClientAddr: clientAddr,
			TLSVersion: tlsMeta.Version,
			TLSCipher:  tlsMeta.CipherSuite,
			TLSALPN:    tlsMeta.ALPN,
		},
		req:          req,
		reqURL:       reqURL,
		reqBody:      bodyResult.recordBody,
		rawRequest:   req.RawBytes,
		reqTruncated: bodyResult.truncated,
	}

	snap := snapshotRawRequest(req.Headers, bodyResult.recordBody)

	iResult := h.applyIntercept(ctx, conn, req, reqURL, bodyResult.recordBody, req.RawBytes, logger)
	if iResult.Dropped {
		sp.reqBody = iResult.RecordBody
		h.recordInterceptDrop(ctx, sp, logger)
		return nil
	}
	req = iResult.Req
	bodyResult.recordBody = iResult.RecordBody

	// Re-derive reqURL after intercept URL override (CP-7/CP-8).
	if iResult.ModURL != nil {
		reqURL = iResult.ModURL
	} else {
		reqURL = parseRequestURL(ctx, req, "https")
	}
	sp.reqURL = reqURL

	if iResult.IsRaw {
		return h.handleRawForward(ctx, conn, req, reqURL, iResult, sp, &snap, start, logger)
	}

	bodyResult.recordBody = h.applyTransform(req, bodyResult.recordBody)
	sp.reqBody = bodyResult.recordBody

	// Plugin hook: on_before_send_to_server.
	req, bodyResult.recordBody = h.dispatchOnBeforeSendToServer(ctx, req, bodyResult.recordBody, pluginConnInfo, txCtx, logger)

	sendResult := h.recordSendWithVariant(ctx, sp, &snap, logger)

	sendStart := time.Now()
	fwd, err := h.forwardUpstream(ctx, conn, req, reqURL, true, logger)
	if err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return err
	}

	if isSSEResponseRaw(fwd.resp) {
		sendResult.tags = addSSETags(sendResult.tags)
		return h.handleSSEStreamTLS(ctx, conn, req, reqURL, fwd, start, sendResult, logger)
	}

	fullRespBody := h.readResponseBody(fwd.resp, logger)
	receiveEnd := time.Now()

	// Plugin hook: on_receive_from_server.
	fwd.resp, fullRespBody = h.dispatchOnReceiveFromServer(ctx, fwd.resp, fullRespBody, req, pluginConnInfo, txCtx, logger)

	respSnap := snapshotRawResponse(fwd.resp.StatusCode, fwd.resp.Headers, fullRespBody)

	var respDropped bool
	fwd.resp, fullRespBody, respDropped = h.applyInterceptResponse(ctx, conn, req, reqURL, fwd.resp, fullRespBody, logger)
	if respDropped {
		return nil
	}

	// Plugin hook: on_before_send_to_client.
	fwd.resp, fullRespBody = h.dispatchOnBeforeSendToClient(ctx, fwd.resp, fullRespBody, req, pluginConnInfo, txCtx, logger)

	rawResponse := serializeRawResponseBytes(fwd.resp, fullRespBody)
	rawRespBody := make([]byte, len(fullRespBody))
	copy(rawRespBody, fullRespBody)

	goHeaders := httputil.RawHeadersToHTTPHeader(fwd.resp.Headers)
	fullRespBody, goHeaders = h.ApplyOutputFilter(fullRespBody, goHeaders, logger)
	fwd.resp.Headers = httputil.HTTPHeaderToRawHeaders(goHeaders)

	if err := writeRawResponse(conn, fwd.resp, fullRespBody); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	duration := time.Since(start)
	sendMs, waitMs, receiveMs := httputil.ComputeTiming(sendStart, fwd.timing, receiveEnd)

	goResp := httputil.RawResponseToHTTP(fwd.resp, rawRespBody)
	// NOTE: Since we now use ConnPool/UpstreamRouter, the TLS cert info
	// from the upstream connection is not directly accessible via resp.TLS.
	// This information should be obtained from the ConnPool result in the future.
	h.recordReceiveWithVariant(ctx, sendResult, receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  fwd.serverAddr,
		resp:        goResp,
		rawResponse: rawResponse,
		respBody:    rawRespBody,
		sendMs:      sendMs,
		waitMs:      waitMs,
		receiveMs:   receiveMs,
	}, &respSnap, logger)

	logHTTPRequest(logger, req.Method, reqURL.String(), fwd.resp.StatusCode, duration)
	return nil
}

// resolveEffectiveHost determines the effective upstream host for an HTTPS request.
func (h *Handler) resolveEffectiveHost(ctx context.Context, connectHost string, req *parser.RawRequest) string {
	effectiveHost := proxy.ResolveUpstreamTarget(ctx, connectHost)
	if _, ok := proxy.ForwardTargetFromContext(ctx); ok {
		req.Headers.Set("Host", effectiveHost)
	}
	return effectiveHost
}

// checkHTTPSScopeRewrite re-checks the target scope when the Host header differs.
func (h *Handler) checkHTTPSScopeRewrite(ctx context.Context, conn net.Conn, connectHost string, req *parser.RawRequest, reqURL *url.URL, start time.Time, connID, clientAddr string, tlsMeta tlsMetadata, logger *slog.Logger) bool {
	requestHost := req.Headers.Get("Host")
	if requestHost == "" {
		return false
	}
	if strings.EqualFold(requestHost, connectHost) {
		return false
	}

	checkURL := &url.URL{
		Scheme: "https",
		Host:   requestHost,
		Path:   reqURL.Path,
	}
	blocked, reason := h.checkTargetScope(checkURL)
	if !blocked {
		return false
	}

	reqURL.Scheme = "https"
	if reqURL.Host == "" {
		reqURL.Host = requestHost
	}
	h.writeBlockedResponse(conn, checkURL.Hostname(), reason, logger)
	h.recordBlockedHTTPSSession(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, tlsMeta, "target_scope", nil, logger)
	return true
}

// checkPlaintextScopeRewrite re-checks the target scope for plaintext CONNECT.
func (h *Handler) checkPlaintextScopeRewrite(ctx context.Context, conn net.Conn, connectHost string, req *parser.RawRequest, reqURL *url.URL, start time.Time, connID, clientAddr string, logger *slog.Logger) bool {
	requestHost := req.Headers.Get("Host")
	if requestHost == "" {
		return false
	}
	if strings.EqualFold(requestHost, connectHost) {
		return false
	}

	checkURL := &url.URL{
		Scheme: "http",
		Host:   requestHost,
		Path:   reqURL.Path,
	}
	blocked, reason := h.checkTargetScope(checkURL)
	if !blocked {
		return false
	}

	reqURL.Scheme = "http"
	if reqURL.Host == "" {
		reqURL.Host = requestHost
	}
	h.writeBlockedResponse(conn, checkURL.Hostname(), reason, logger)
	h.recordBlockedSession(ctx, req, reqURL, nil, nil, false, req.Anomalies, start, connID, clientAddr, "target_scope", nil, logger)
	return true
}

// dialUpstream dials the target address, optionally via upstream proxy.
func (h *Handler) dialUpstream(ctx context.Context, addr string, timeout time.Duration) (net.Conn, error) {
	proxyURL := h.UpstreamProxy()
	if proxyURL != nil {
		return proxy.DialViaUpstreamProxy(ctx, proxyURL, addr, timeout)
	}
	dialer := &net.Dialer{Timeout: timeout}
	return dialer.DialContext(ctx, "tcp", addr)
}

func parseConnectPort(hostPort string) int {
	_, portStr, err := net.SplitHostPort(hostPort)
	if err != nil {
		return 443
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0
	}
	return port
}

// recordBlockedCONNECTSession records a blocked CONNECT request.
func (h *Handler) recordBlockedCONNECTSession(ctx context.Context, reqHost, hostname, authority, blockedBy string, logger *slog.Logger) {
	h.recordBlockedCONNECTSessionWithTags(ctx, reqHost, hostname, authority, blockedBy, nil, logger)
}

func (h *Handler) recordBlockedCONNECTSessionWithTags(ctx context.Context, reqHost, hostname, authority, blockedBy string, extraTags map[string]string, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)
	start := time.Now()

	connectURL := &url.URL{Scheme: "https", Host: authority}
	if !h.shouldCapture("CONNECT", connectURL) {
		return
	}

	tags := mergeSOCKS5Tags(ctx, nil)
	for k, v := range extraTags {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags[k] = v
	}

	protocol := socks5Protocol(ctx, "HTTPS")

	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  protocol,
		Scheme:    "https",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: start,
		Tags:      tags,
		BlockedBy: blockedBy,
		ConnInfo:  &flow.ConnectionInfo{ClientAddr: clientAddr},
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

const hookTimeout = 5 * time.Second

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

// recordBlockedHTTPSSession records a blocked HTTPS request.
func (h *Handler) recordBlockedHTTPSSession(ctx context.Context, req *parser.RawRequest, reqURL *url.URL, reqBody, rawRequest []byte, reqTruncated bool, anomalies []parser.Anomaly, start time.Time, connID, clientAddr string, tlsMeta tlsMetadata, blockedBy string, violation *safety.InputViolation, logger *slog.Logger) {
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
		logger.Error("blocked HTTPS flow save failed", "method", req.Method, "url", reqURL.String(), "error", err)
		return
	}
	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     start,
		Method:        req.Method,
		URL:           reqURL,
		Headers:       httputil.RawHeadersToHTTPHeader(req.Headers),
		Body:          reqBody,
		RawBytes:      rawRequest,
		BodyTruncated: reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("blocked HTTPS send message save failed", "error", err)
	}
}
