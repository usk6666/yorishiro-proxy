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
	"net/url"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/proxy"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

const maxBodyRecordSize = 1 << 20 // 1MB

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

// Handler processes HTTP/1.x connections.
type Handler struct {
	store          session.Store
	issuer         *cert.Issuer
	transport      *gohttp.Transport
	logger         *slog.Logger
	requestTimeout time.Duration
	scope          *proxy.CaptureScope
}

// NewHandler creates a new HTTP handler with session recording.
// If issuer is non-nil, CONNECT requests are handled for HTTPS MITM;
// otherwise CONNECT requests receive a 501 Not Implemented response.
func NewHandler(store session.Store, issuer *cert.Issuer, logger *slog.Logger) *Handler {
	return &Handler{
		store:     store,
		issuer:    issuer,
		transport: &gohttp.Transport{},
		logger:    logger,
	}
}

// SetTransport replaces the handler's HTTP transport. This is primarily
// useful for testing, where the upstream server uses a self-signed certificate.
func (h *Handler) SetTransport(t *gohttp.Transport) {
	h.transport = t
}

// SetInsecureSkipVerify configures whether the handler skips TLS certificate
// verification when connecting to upstream servers. When enabled, a warning
// is logged because this disables important security checks.
// This is intended for vulnerability assessments against targets using
// self-signed or expired certificates.
func (h *Handler) SetInsecureSkipVerify(skip bool) {
	if skip {
		h.logger.Warn("upstream TLS certificate verification is disabled — connections to upstream servers will not verify certificates")
		if h.transport.TLSClientConfig == nil {
			h.transport.TLSClientConfig = &tls.Config{}
		}
		h.transport.TLSClientConfig.InsecureSkipVerify = true
	}
}

// SetRequestTimeout sets the timeout for reading HTTP request headers.
func (h *Handler) SetRequestTimeout(d time.Duration) {
	h.requestTimeout = d
}

// SetCaptureScope sets the capture scope used to filter which requests
// are recorded to the session store. If scope is nil, all requests are recorded.
func (h *Handler) SetCaptureScope(scope *proxy.CaptureScope) {
	h.scope = scope
}

// CaptureScope returns the handler's capture scope, or nil if not set.
func (h *Handler) CaptureScope() *proxy.CaptureScope {
	return h.scope
}

func (h *Handler) effectiveRequestTimeout() time.Duration {
	if h.requestTimeout > 0 {
		return h.requestTimeout
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
	return proxy.LoggerFromContext(ctx, h.logger)
}

// Handle processes HTTP connections in a loop (keep-alive support).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	capture := &captureReader{r: conn}
	reader := bufio.NewReader(capture)

	// Watch for context cancellation and interrupt blocking reads.
	// When the proxy is shutting down, ReadRequest may be blocked waiting
	// for the next request on a keep-alive connection. Setting an immediate
	// read deadline causes it to return with a timeout error.
	go func() {
		<-ctx.Done()
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
			return fmt.Errorf("read request: %w", err)
		}

		// Log any detected smuggling patterns.
		logSmugglingWarnings(h.logger, smuggling, req)

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
	// The raw bytes span from captureStart to the current capture position,
	// minus any bytes buffered by the bufio.Reader (which belong to the next request).
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

	// Ensure absolute URL for forward proxy.
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}

	// Remove hop-by-hop headers.
	removeHopByHopHeaders(req.Header)

	// Forward request upstream.
	outReq := req.WithContext(ctx)
	outReq.RequestURI = ""

	resp, err := h.transport.RoundTrip(outReq)
	if err != nil {
		logger.Error("upstream request failed", "method", req.Method, "url", req.URL.String(), "error", err)
		// Send 502 Bad Gateway to client.
		errResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write([]byte(errResp)); err != nil {
			logger.Debug("failed to write error response", "error", err)
		}
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Read the full response body so the client receives uncorrupted data.
	fullRespBody, _ := io.ReadAll(resp.Body)

	// Capture raw response bytes by serializing the response as received.
	rawResponse := serializeRawResponse(resp, fullRespBody)

	// Write response back to client (full body).
	if err := writeResponse(conn, resp, fullRespBody); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	// Truncate for recording.
	recordRespBody := fullRespBody
	var respTruncated bool
	if len(fullRespBody) > maxBodyRecordSize {
		recordRespBody = fullRespBody[:maxBodyRecordSize]
		respTruncated = true
	}

	duration := time.Since(start)

	// Record session.
	entry := &session.Entry{
		ConnID:      connID,
		Protocol:    "HTTP/1.x",
		Timestamp:   start,
		Duration:    duration,
		RawRequest:  rawRequest,
		RawResponse: rawResponse,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr: clientAddr,
		},
		Request: session.RecordedRequest{
			Method:        req.Method,
			URL:           req.URL,
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
	if h.store != nil && h.shouldCapture(req.Method, req.URL) {
		if err := h.store.Save(ctx, entry); err != nil {
			logger.Error("session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		}
	}

	logger.Info("http request", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration_ms", duration.Milliseconds())

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
	if h.scope == nil {
		return true
	}
	return h.scope.ShouldCapture(method, u)
}

func removeHopByHopHeaders(header gohttp.Header) {
	for _, h := range hopByHopHeaders {
		header.Del(h)
	}
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
