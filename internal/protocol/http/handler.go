package http

import (
	"bytes"
	"context"
	"net"
)

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

// Handler processes HTTP/1.x connections.
type Handler struct{}

// NewHandler creates a new HTTP handler.
func NewHandler() *Handler {
	return &Handler{}
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

// Handle processes an HTTP connection.
func (h *Handler) Handle(ctx context.Context, conn net.Conn) error {
	// TODO: Implement HTTP MITM proxy
	_ = ctx
	_ = conn
	return nil
}
