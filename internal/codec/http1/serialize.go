package http1

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// SerializeRequest converts a RawRequest into wire-format bytes (request-line +
// headers + CRLF). Header order is preserved exactly as in RawHeaders. The
// body is NOT included in the returned bytes — it is written separately to
// allow streaming.
func SerializeRequest(req *parser.RawRequest) []byte {
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
	writeRawHeaders(&buf, req.Headers)

	// End of headers.
	buf.WriteString("\r\n")

	return buf.Bytes()
}

// serializeRequest is the unexported version used by the Codec internally.
func serializeRequest(req *parser.RawRequest) []byte {
	return SerializeRequest(req)
}

// WriteRequest writes the serialized header payload and then streams the body
// (if any) to the connection. Used for raw mode where the entire request
// (including body) is in the header parameter.
func WriteRequest(conn net.Conn, header []byte, body io.Reader) error {
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

// serializeResponse converts a RawResponse into wire-format bytes (status-line +
// headers + CRLF). Header order and OWS are preserved. Body is NOT included.
func serializeResponse(resp *parser.RawResponse) []byte {
	var buf bytes.Buffer

	// Status line: HTTP-VERSION SP STATUS CRLF
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if resp.Status != "" {
		fmt.Fprintf(&buf, "%s %s\r\n", proto, resp.Status)
	} else {
		text := httputil.StatusText(resp.StatusCode)
		if text == "" {
			text = "Unknown"
		}
		fmt.Fprintf(&buf, "%s %d %s\r\n", proto, resp.StatusCode, text)
	}

	// Headers in wire order, preserving OWS via RawValue.
	writeRawHeaders(&buf, resp.Headers)

	// End of headers.
	buf.WriteString("\r\n")

	return buf.Bytes()
}

// writeRawHeaders writes headers to a buffer, preserving wire order and OWS.
func writeRawHeaders(buf *bytes.Buffer, headers parser.RawHeaders) {
	for _, h := range headers {
		if h.RawValue != "" {
			buf.WriteString(h.Name)
			buf.WriteByte(':')
			buf.WriteString(h.RawValue)
		} else {
			buf.WriteString(h.Name)
			buf.WriteString(": ")
			buf.WriteString(h.Value)
		}
		buf.WriteString("\r\n")
	}
}
