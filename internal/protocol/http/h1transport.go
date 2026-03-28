package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// defaultRoundTripTimeout is the fallback deadline for RoundTripOnConn when
// the caller's context has no deadline, to prevent indefinite blocking.
const defaultRoundTripTimeout = 30 * time.Second

// H1Transport sends HTTP/1.x requests over raw connections and reads
// responses using the custom parser, bypassing net/http entirely.
// It supports both structured mode (serializing from RawRequest) and raw
// mode (sending RawRequest.RawBytes verbatim).
type H1Transport struct{}

// RoundTripResult holds the result of an HTTP/1.x round trip.
type RoundTripResult struct {
	// Response is the parsed HTTP/1.x response.
	Response *parser.RawResponse

	// ServerAddr is the remote address of the upstream connection.
	ServerAddr string

	// Timing contains per-phase timing measurements.
	Timing *httputil.RoundTripTiming

	// KeepAlive indicates whether the connection can be reused according to
	// the response's Connection header and HTTP version.
	KeepAlive bool
}

// RoundTripOnConn sends an HTTP/1.x request over conn and reads the response.
// In structured mode (req.RawBytes is nil or empty), the request is serialized
// from the parsed fields with header order preserved. In raw mode (req.RawBytes
// is set), the raw bytes are sent verbatim for smuggling test support.
//
// The caller is responsible for closing conn.
func (t *H1Transport) RoundTripOnConn(ctx context.Context, conn net.Conn, req *parser.RawRequest) (*RoundTripResult, error) {
	timing := &httputil.RoundTripTiming{}

	// Apply context deadline to the connection. If the context has no deadline,
	// use a default timeout to prevent indefinite blocking.
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("h1transport set deadline: %w", err)
		}
	} else {
		if err := conn.SetDeadline(time.Now().Add(defaultRoundTripTimeout)); err != nil {
			return nil, fmt.Errorf("h1transport set default deadline: %w", err)
		}
	}

	// Choose between raw mode and structured mode.
	var payload []byte
	var body io.Reader
	if len(req.RawBytes) > 0 {
		// Raw mode: send the captured bytes verbatim. Body is set to nil
		// because RawBytes already contains the complete wire data; passing
		// req.Body would append extra bytes and break verbatim semantics.
		payload = req.RawBytes
	} else {
		// Structured mode: serialize the request preserving header order.
		// Body is written separately to allow streaming.
		payload = serializeRequest(req)
		body = req.Body
	}

	// Write payload + body to connection.
	if err := writeRequest(conn, payload, body); err != nil {
		return nil, fmt.Errorf("h1transport write: %w", err)
	}
	timing.SetWroteRequest(time.Now())

	// Read response using the custom parser.
	reader := bufio.NewReaderSize(conn, 4096)

	// Detect first byte to record timing.
	if _, err := reader.Peek(1); err != nil {
		return nil, fmt.Errorf("h1transport read first byte: %w", err)
	}
	timing.SetGotFirstByte(time.Now())

	resp, err := parser.ParseResponse(reader)
	if err != nil {
		return nil, fmt.Errorf("h1transport parse response: %w", err)
	}

	// Determine keep-alive status from the response.
	keepAlive := isKeepAlive(resp)

	return &RoundTripResult{
		Response:   resp,
		ServerAddr: conn.RemoteAddr().String(),
		Timing:     timing,
		KeepAlive:  keepAlive,
	}, nil
}

// serializeRequest converts a RawRequest into wire-format bytes (request-line +
// headers + CRLF). Header order is preserved exactly as in RawHeaders. The
// body is NOT included in the returned bytes — it is written separately to
// allow streaming.
func serializeRequest(req *parser.RawRequest) []byte {
	var buf bytes.Buffer

	// Request line: METHOD SP RequestURI SP Proto CRLF
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.RequestURI)
	buf.WriteByte(' ')
	buf.WriteString(proto)
	buf.WriteString("\r\n")

	// Headers in wire order.
	for _, h := range req.Headers {
		buf.WriteString(h.Name)
		if h.RawValue != "" {
			// RawValue includes the original whitespace after the colon,
			// so we write only ":" to preserve exact wire bytes.
			buf.WriteByte(':')
			buf.WriteString(h.RawValue)
		} else {
			buf.WriteString(": ")
			buf.WriteString(h.Value)
		}
		buf.WriteString("\r\n")
	}

	// End of headers.
	buf.WriteString("\r\n")

	return buf.Bytes()
}

// writeRequest writes the serialized header payload and then streams the body
// (if any) to the connection.
func writeRequest(conn net.Conn, header []byte, body io.Reader) error {
	if _, err := io.Copy(conn, bytes.NewReader(header)); err != nil {
		return err
	}
	if body != nil {
		if _, err := io.Copy(conn, body); err != nil {
			return err
		}
	}
	return nil
}

// isKeepAlive determines whether the connection should be kept alive based on
// the response's HTTP version and Connection header.
//
// HTTP/1.1 default: keep-alive (unless "Connection: close")
// HTTP/1.0 default: close (unless "Connection: keep-alive")
//
// When both "close" and "keep-alive" tokens are present (e.g.,
// "Connection: keep-alive, close"), "close" takes precedence.
func isKeepAlive(resp *parser.RawResponse) bool {
	// Scan all Connection header tokens, giving "close" precedence.
	var sawClose, sawKeepAlive bool
	connValues := resp.Headers.Values("Connection")
	for _, val := range connValues {
		for _, token := range strings.Split(val, ",") {
			token = strings.TrimSpace(token)
			if strings.EqualFold(token, "close") {
				sawClose = true
			}
			if strings.EqualFold(token, "keep-alive") {
				sawKeepAlive = true
			}
		}
	}

	if sawClose {
		return false
	}
	if sawKeepAlive {
		return true
	}

	// Default based on protocol version.
	return strings.HasPrefix(resp.Proto, "HTTP/1.1")
}
