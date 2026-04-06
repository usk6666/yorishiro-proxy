package http1

import (
	"bytes"
	"fmt"
	"io"
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// SerializeRequest delegates to httputil.SerializeRequest. The canonical
// implementation lives in httputil to avoid circular imports (codec/http1
// imports httputil for StatusText).
func SerializeRequest(req *parser.RawRequest) []byte {
	return httputil.SerializeRequest(req)
}

// serializeRequest is the unexported version used by the Codec internally.
func serializeRequest(req *parser.RawRequest) []byte {
	return httputil.SerializeRequest(req)
}

// WriteRequest delegates to httputil.WriteRequest. The canonical
// implementation lives in httputil to avoid circular imports.
func WriteRequest(conn net.Conn, header []byte, body io.Reader) error {
	return httputil.WriteRequest(conn, header, body)
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
