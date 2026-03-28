package http

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// UpstreamRouter routes HTTP requests to the appropriate upstream transport
// based on the ALPN protocol negotiated during the TLS handshake. When the
// upstream negotiates "h2", requests are forwarded via the HTTP/2 frame engine;
// otherwise the HTTP/1.x transport is used.
//
// This replaces the HTTP1OnlyTransport workaround (USK-479) which restricted
// ALPN to HTTP/1.1 to prevent Go's http.Transport from receiving HTTP/2 frames
// it could not handle.
type UpstreamRouter struct {
	// H1 is the HTTP/1.x transport.
	H1 *H1Transport

	// H2 is the HTTP/2 transport.
	H2 *http2.Transport

	// Pool manages upstream connections (TCP dial + TLS handshake).
	// Must have AllowH2 set to true.
	Pool *ConnPool
}

// RoundTrip sends an HTTP request to the upstream server, automatically
// selecting the transport based on ALPN negotiation.
//
// For h2 ALPN: the request is converted to HTTP/2 pseudo-headers and sent via
// the HTTP/2 frame engine. The response is converted back to RoundTripResult
// with a parser.RawResponse.
//
// For http/1.1 or no ALPN: the request is sent via H1Transport over the raw
// connection.
func (r *UpstreamRouter) RoundTrip(ctx context.Context, req *parser.RawRequest, addr string, useTLS bool, hostname string) (*RoundTripResult, error) {
	cr, err := r.Pool.Get(ctx, addr, useTLS, hostname)
	if err != nil {
		return nil, fmt.Errorf("upstream router dial %s: %w", addr, err)
	}

	switch cr.ALPN {
	case "h2":
		defer cr.Conn.Close()
		slog.Debug("upstream router: routing to h2 transport", "addr", addr, "alpn", cr.ALPN)
		result, h2Err := r.roundTripH2(ctx, cr.Conn, req, addr, hostname)
		if h2Err != nil {
			return nil, fmt.Errorf("upstream router h2 round trip: %w", h2Err)
		}
		result.ConnectDuration = cr.ConnectDuration
		return result, nil
	default:
		slog.Debug("upstream router: routing to h1 transport", "addr", addr, "alpn", cr.ALPN)
		result, h1Err := r.H1.RoundTripOnConn(ctx, cr.Conn, req)
		if h1Err != nil {
			cr.Conn.Close()
			return nil, fmt.Errorf("upstream router h1 round trip: %w", h1Err)
		}
		result.ConnectDuration = cr.ConnectDuration
		// Wrap the response body so the connection is closed after the body
		// is fully consumed. This avoids buffering the entire response body
		// in memory and prevents premature connection closure.
		if result.Response != nil && result.Response.Body != nil {
			result.Response.Body = &connClosingReader{
				Reader: result.Response.Body,
				conn:   cr.Conn,
			}
		} else {
			cr.Conn.Close()
		}
		return result, nil
	}
}

// connClosingReader wraps an io.Reader and closes the connection when Read
// returns any error (including io.EOF) or when Close is called. This ensures
// the upstream connection stays open while the response body is being read.
type connClosingReader struct {
	io.Reader
	conn   net.Conn
	closed bool
}

func (r *connClosingReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err != nil && !r.closed {
		r.closed = true
		r.conn.Close()
	}
	return n, err
}

// Close implements io.Closer to allow explicit cleanup.
func (r *connClosingReader) Close() error {
	if !r.closed {
		r.closed = true
		return r.conn.Close()
	}
	return nil
}

// roundTripH2 performs an HTTP/2 round trip using a pre-established h2
// connection. It converts the RawRequest to HTTP/2 pseudo-headers, sends
// the request via the frame engine, and converts the response back to
// a parser.RawResponse wrapped in RoundTripResult.
func (r *UpstreamRouter) roundTripH2(ctx context.Context, conn net.Conn, req *parser.RawRequest, addr, hostname string) (*RoundTripResult, error) {
	// Use the h2Transport to perform the round trip on the pre-established
	// connection. RoundTripOnConn handles the HTTP/2 handshake, header
	// encoding, data frame transmission, and response parsing.
	h2Headers, err := buildH2Headers(req, hostname)
	if err != nil {
		return nil, err
	}
	h2Result, err := r.H2.RoundTripOnConn(ctx, conn, h2Headers, req.Body)
	if err != nil {
		return nil, err
	}

	// Convert the HTTP/2 response (header fields + data) to a RawResponse.
	resp := h2ResultToRawResponse(h2Result)

	return &RoundTripResult{
		Response:   resp,
		ServerAddr: conn.RemoteAddr().String(),
		Timing:     &httputil.RoundTripTiming{},
		KeepAlive:  false, // HTTP/2 connections are multiplexed, not keep-alive in the H1 sense.
	}, nil
}

// buildH2Headers converts a parser.RawRequest into HTTP/2 HPACK header fields,
// constructing the required pseudo-headers (:method, :scheme, :authority, :path)
// from the request fields and mapping regular headers with case preserved as
// lowercase (HTTP/2 requirement per RFC 9113 Section 8.2).
//
// Returns an error if :authority would be empty (both Host header and hostname
// are missing).
func buildH2Headers(req *parser.RawRequest, hostname string) ([]hpack.HeaderField, error) {
	// Determine path from RequestURI. For forward-proxy requests the
	// request-target may be absolute-form (e.g. "http://example.com/path").
	// HTTP/2 :path must be origin-form (path+query only).
	path := req.RequestURI
	if path == "" {
		path = "/"
	} else if u, err := url.Parse(path); err == nil && u.Host != "" {
		// Absolute-form: extract origin-form (path + query).
		path = u.RequestURI()
	}
	if path == "" {
		path = "/"
	}

	// Determine authority from Host header or hostname parameter.
	authority := req.Headers.Get("Host")
	if authority == "" {
		authority = hostname
	}
	if authority == "" {
		return nil, fmt.Errorf("cannot build h2 headers: empty :authority (no Host header and no hostname)")
	}

	headers := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: "https"}, // h2 is always over TLS
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}

	// Build the set of Connection-nominated headers to skip (CP-5).
	connNominated := parseConnNominatedHeaders(req.Headers)

	// Add regular headers, lowercased per HTTP/2 spec.
	for _, h := range req.Headers {
		lower := strings.ToLower(h.Name)
		// Skip Host (mapped to :authority), hop-by-hop headers, and connection headers.
		if lower == "host" {
			continue
		}
		if isH2HopByHopHeader(lower) {
			// te: trailers is allowed in HTTP/2 (RFC 9113 Section 8.2.2).
			if lower == "te" && strings.EqualFold(h.Value, "trailers") {
				headers = append(headers, hpack.HeaderField{Name: lower, Value: h.Value})
			}
			continue
		}
		// Skip headers nominated by the Connection header.
		if connNominated[lower] {
			continue
		}
		headers = append(headers, hpack.HeaderField{Name: lower, Value: h.Value})
	}

	return headers, nil
}

// parseConnNominatedHeaders extracts the set of header names nominated by the
// Connection header (RFC 9110 Section 7.6.1). These headers must not be
// forwarded in HTTP/2.
func parseConnNominatedHeaders(headers parser.RawHeaders) map[string]bool {
	nominated := make(map[string]bool)
	for _, h := range headers {
		if !strings.EqualFold(h.Name, "Connection") {
			continue
		}
		for _, token := range strings.Split(h.Value, ",") {
			token = strings.TrimSpace(token)
			if token != "" {
				nominated[strings.ToLower(token)] = true
			}
		}
	}
	return nominated
}

// isH2HopByHopHeader reports whether the header is an HTTP/1 hop-by-hop header
// that must not be forwarded in HTTP/2.
func isH2HopByHopHeader(name string) bool {
	switch name {
	case "connection", "keep-alive", "proxy-connection",
		"transfer-encoding", "upgrade", "te":
		return true
	}
	return false
}

// h2ResultToRawResponse converts an http2.RoundTripResult into a parser.RawResponse.
func h2ResultToRawResponse(h2r *http2.RoundTripResult) *parser.RawResponse {
	resp := &parser.RawResponse{
		Proto:      "HTTP/2.0",
		StatusCode: h2r.StatusCode,
		Status:     formatStatus(h2r.StatusCode),
		Headers:    make(parser.RawHeaders, 0, len(h2r.Headers)),
		Body:       io.NopCloser(h2r.Body),
	}

	for _, hf := range h2r.Headers {
		if strings.HasPrefix(hf.Name, ":") {
			continue // skip pseudo-headers
		}
		resp.Headers = append(resp.Headers, parser.RawHeader{
			Name:  hf.Name,
			Value: hf.Value,
		})
	}

	return resp
}

// formatStatus formats an HTTP status code into a status line string.
// For known status codes it includes the reason phrase (e.g. "200 OK").
// For unknown codes where http.StatusText returns empty, it omits the
// reason phrase to avoid a trailing space (e.g. "599" instead of "599 ").
func formatStatus(code int) string {
	reason := statusText(code)
	if reason == "" {
		return fmt.Sprintf("%d", code)
	}
	return fmt.Sprintf("%d %s", code, reason)
}
