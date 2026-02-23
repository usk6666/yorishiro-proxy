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
	"time"

	"github.com/usk6666/katashiro-proxy/internal/cert"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

const maxBodyRecordSize = 1 << 20 // 1MB

const defaultRequestTimeout = 60 * time.Second

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

// Handle processes HTTP connections in a loop (keep-alive support).
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	reader := bufio.NewReader(conn)

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

		req, err := gohttp.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}

		// Reset deadline after successful read.
		conn.SetReadDeadline(time.Time{})

		// CONNECT method starts HTTPS MITM tunnel.
		if req.Method == gohttp.MethodConnect {
			return h.handleCONNECT(ctx, conn, req)
		}

		if err := h.handleRequest(ctx, conn, req); err != nil {
			return err
		}

		if req.Close {
			return nil
		}
	}
}

func (h *Handler) handleRequest(ctx context.Context, conn net.Conn, req *gohttp.Request) error {
	start := time.Now()

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
		h.logger.Error("upstream request failed", "method", req.Method, "url", req.URL.String(), "error", err)
		// Send 502 Bad Gateway to client.
		errResp := fmt.Sprintf("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		if _, err := conn.Write([]byte(errResp)); err != nil {
			h.logger.Debug("failed to write error response", "error", err)
		}
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Read the full response body so the client receives uncorrupted data.
	fullRespBody, _ := io.ReadAll(resp.Body)

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
		Protocol:  "HTTP/1.x",
		Timestamp: start,
		Duration:  duration,
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
	}
	if h.store != nil {
		if err := h.store.Save(ctx, entry); err != nil {
			h.logger.Error("session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
		}
	}

	h.logger.Info("http request", "method", req.Method, "url", req.URL.String(), "status", resp.StatusCode, "duration_ms", duration.Milliseconds())

	return nil
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
