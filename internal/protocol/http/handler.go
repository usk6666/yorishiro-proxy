package http

import (
	"bufio"
	"bytes"
	"context"
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
	store     session.Store
	issuer    *cert.Issuer
	transport *gohttp.Transport
	logger    *slog.Logger
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

		req, err := gohttp.ReadRequest(reader)
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("read request: %w", err)
		}

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

	// Capture request body for recording.
	var reqBody []byte
	if req.Body != nil {
		reqBody, _ = io.ReadAll(io.LimitReader(req.Body, maxBodyRecordSize))
		req.Body.Close()
		req.Body = io.NopCloser(bytes.NewReader(reqBody))
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
		conn.Write([]byte(errResp))
		return fmt.Errorf("upstream request: %w", err)
	}
	defer resp.Body.Close()

	// Capture response body for recording.
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyRecordSize))

	// Write response back to client.
	if err := writeResponse(conn, resp, respBody); err != nil {
		return fmt.Errorf("write response: %w", err)
	}

	duration := time.Since(start)

	// Record session.
	entry := &session.Entry{
		Protocol:  "HTTP/1.x",
		Timestamp: start,
		Duration:  duration,
		Request: session.RecordedRequest{
			Method:  req.Method,
			URL:     req.URL,
			Headers: req.Header,
			Body:    reqBody,
		},
		Response: session.RecordedResponse{
			StatusCode: resp.StatusCode,
			Headers:    resp.Header,
			Body:       respBody,
		},
	}
	if h.store != nil {
		if err := h.store.Save(ctx, entry); err != nil {
			h.logger.Error("session save failed", "method", req.Method, "url", req.URL.String(), "error", err)
			return fmt.Errorf("save session: %w", err)
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
	fmt.Fprintf(w, "HTTP/%d.%d %d %s\r\n", resp.ProtoMajor, resp.ProtoMinor, resp.StatusCode, gohttp.StatusText(resp.StatusCode))
	resp.Header.Set("Content-Length", fmt.Sprintf("%d", len(body)))
	resp.Header.Del("Transfer-Encoding")
	for key, vals := range resp.Header {
		for _, val := range vals {
			fmt.Fprintf(w, "%s: %s\r\n", key, val)
		}
	}
	fmt.Fprintf(w, "\r\n")
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Flush()
}
