package http

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
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
		if _, err := conn.Write([]byte("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
		return nil
	}

	// Preserve the full host:port for upstream forwarding.
	// req.Host contains the original "host:port" from the CONNECT request.
	connectAuthority := req.Host

	// Check if the target host is in the TLS passthrough list.
	// If so, relay encrypted bytes directly without MITM interception.
	if h.passthrough != nil && h.passthrough.Contains(hostname) {
		return h.handlePassthrough(ctx, conn, connectAuthority, hostname)
	}

	// Validate that the issuer is configured for TLS interception.
	if h.issuer == nil {
		logger.Warn("CONNECT received but TLS issuer not configured", "host", req.Host)
		if _, err := conn.Write([]byte("HTTP/1.1 501 Not Implemented\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
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
		"tls_version", tlsMeta.Version, "tls_cipher", tlsMeta.CipherSuite)

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

	// Connect to the upstream server.
	upstream, err := net.DialTimeout("tcp", authority, 30*time.Second)
	if err != nil {
		logger.Error("passthrough upstream dial failed", "host", authority, "error", err)
		if _, err := clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
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
	go func() {
		<-ctx.Done()
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
func (h *Handler) tlsHandshake(ctx context.Context, conn net.Conn, hostname string) (*tls.Conn, error) {
	tlsConfig := &tls.Config{
		GetCertificate: h.issuer.GetCertificateForClientHello,
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
	go func() {
		<-ctx.Done()
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
			return fmt.Errorf("read HTTPS request: %w", err)
		}

		// Log any detected smuggling patterns.
		logSmugglingWarnings(h.logger, smuggling, req)

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
// server, records the session, and writes the response back to the client.
func (h *Handler) handleHTTPSRequest(ctx context.Context, conn net.Conn, connectHost string, req *gohttp.Request, smuggling *smugglingFlags, tlsMeta tlsMetadata, capture *captureReader, captureStart int, reader *bufio.Reader) error {
	start := time.Now()
	logger := h.connLogger(ctx)
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	// Read the full request body so the upstream receives uncorrupted data.
	var recordReqBody []byte
	var reqTruncated bool
	if req.Body != nil {
		fullBody, _ := io.ReadAll(req.Body)
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(fullBody))

		recordReqBody = fullBody
		if len(fullBody) > maxBodyRecordSize {
			recordReqBody = fullBody[:maxBodyRecordSize]
			reqTruncated = true
		}
	}

	// Extract raw request bytes captured by the captureReader.
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

	// Reconstruct the full URL for the upstream request.
	// Requests read from the TLS connection have relative URIs;
	// we need to set the scheme and host from the CONNECT target.
	if req.URL.Host == "" {
		req.URL.Host = connectHost
	}
	req.URL.Scheme = "https"

	// Remove hop-by-hop headers.
	removeHopByHopHeaders(req.Header)

	// Forward request to upstream over HTTPS.
	outReq := req.WithContext(ctx)
	outReq.RequestURI = ""

	resp, serverAddr, err := roundTripWithTrace(h.transport, outReq)
	if err != nil {
		logger.Error("HTTPS upstream request failed", "method", req.Method, "url", req.URL.String(), "error", err)
		errResp := "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
		if _, err := conn.Write([]byte(errResp)); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
		return fmt.Errorf("HTTPS upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Read the full response body so the client receives uncorrupted data.
	fullRespBody, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Warn("failed to read response body", "error", err)
	}

	// Capture raw response bytes by serializing the response as received.
	rawResponse := serializeRawResponse(resp, fullRespBody)

	// Extract the upstream server's TLS certificate subject if available.
	var tlsCertSubject string
	if resp.TLS != nil && len(resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = resp.TLS.PeerCertificates[0].Subject.String()
	}

	// Write response back to the client over the TLS connection (full body).
	if err := writeResponse(conn, resp, fullRespBody); err != nil {
		return fmt.Errorf("write HTTPS response: %w", err)
	}

	// Truncate for recording.
	recordRespBody := fullRespBody
	var respTruncated bool
	if len(fullRespBody) > maxBodyRecordSize {
		recordRespBody = fullRespBody[:maxBodyRecordSize]
		respTruncated = true
	}

	duration := time.Since(start)

	// Record session with HTTPS protocol and the full reconstructed URL.
	entry := &session.Entry{
		ConnID:      connID,
		Protocol:    "HTTPS",
		Timestamp:   start,
		Duration:    duration,
		RawRequest:  rawRequest,
		RawResponse: rawResponse,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr:           clientAddr,
			ServerAddr:           serverAddr,
			TLSVersion:           tlsMeta.Version,
			TLSCipher:            tlsMeta.CipherSuite,
			TLSALPN:              tlsMeta.ALPN,
			TLSServerCertSubject: tlsCertSubject,
		},
		Request: session.RecordedRequest{
			Method: req.Method,
			URL: &url.URL{
				Scheme:   "https",
				Host:     req.URL.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
				Fragment: req.URL.Fragment,
			},
			Headers:       req.Header,
			Body:          recordReqBody,
			BodyTruncated: reqTruncated,
		},
		Response: session.RecordedResponse{
			StatusCode:    resp.StatusCode,
			Headers:       resp.Header,
			Body:          recordRespBody,
			BodyTruncated: respTruncated,
		},
		Tags: smugglingTags(smuggling),
	}
	if h.store != nil && h.shouldCapture(req.Method, entry.Request.URL) {
		if err := h.store.Save(ctx, entry); err != nil {
			logger.Error("HTTPS session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		}
	}

	logger.Info("https request", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration_ms", duration.Milliseconds())

	return nil
}
