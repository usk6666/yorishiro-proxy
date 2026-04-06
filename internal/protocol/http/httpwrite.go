package http

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"

	http1codec "github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
)

// writeHTTPError writes a minimal HTTP error response to the connection.
// This replaces httputil.WriteHTTPError calls to avoid importing net/http.
func writeHTTPError(conn net.Conn, code int, logger *slog.Logger) {
	text := statusText(code)
	if text == "" {
		text = "Unknown"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		code, text)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write error response", "status", code, "error", err)
	}
}

// writeRawResponse delegates to http1codec.WriteRawResponse.
func writeRawResponse(conn net.Conn, resp *parser.RawResponse, body []byte, autoContentLength bool) error {
	return http1codec.WriteRawResponse(conn, resp, body, autoContentLength)
}

// writeResponseHeaders delegates to http1codec.WriteResponseHeaders.
func writeResponseHeaders(w *bufio.Writer, headers parser.RawHeaders, bodyLen int, autoContentLength bool) error {
	return http1codec.WriteResponseHeaders(w, headers, bodyLen, autoContentLength)
}

// writeRawResponseHeaders delegates to http1codec.WriteRawResponseHeaders.
func writeRawResponseHeaders(conn net.Conn, resp *parser.RawResponse) error {
	return http1codec.WriteRawResponseHeaders(conn, resp)
}

// serializeRawResponseBytes delegates to http1codec.SerializeRawResponseBytes.
func serializeRawResponseBytes(resp *parser.RawResponse, body []byte) []byte {
	return http1codec.SerializeRawResponseBytes(resp, body)
}
