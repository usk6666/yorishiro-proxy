package http1

import (
	"bytes"
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// serializeRequest converts a RawRequest into wire-format bytes (request-line +
// headers + CRLF). Header order and OWS are preserved. Body is NOT included.
//
// This delegates to httputil.SerializeRequest which already implements the
// correct wire-fidelity serialization.
func serializeRequest(req *parser.RawRequest) []byte {
	return httputil.SerializeRequest(req)
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
	for _, h := range resp.Headers {
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

	// End of headers.
	buf.WriteString("\r\n")

	return buf.Bytes()
}
