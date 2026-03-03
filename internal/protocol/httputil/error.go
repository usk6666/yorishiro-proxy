package httputil

import (
	"fmt"
	"log/slog"
	"net"
	gohttp "net/http"
)

// WriteHTTPError writes a minimal HTTP/1.1 error response to conn and logs
// any write failure at debug level. This centralises the boilerplate that was
// previously repeated across handler.go, connect.go and websocket.go.
//
// The response contains no body (Content-Length: 0) and signals the client to
// close the connection (Connection: close).
func WriteHTTPError(conn net.Conn, statusCode int, logger *slog.Logger) {
	statusText := gohttp.StatusText(statusCode)
	if statusText == "" {
		statusText = "Unknown"
	}
	resp := fmt.Sprintf("HTTP/1.1 %d %s\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
		statusCode, statusText)
	if _, err := conn.Write([]byte(resp)); err != nil {
		logger.Debug("failed to write error response", "status", statusCode, "error", err)
	}
}
