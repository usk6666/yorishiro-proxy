package http

import (
	"io"
	"net"

	http1codec "github.com/usk6666/yorishiro-proxy/internal/codec/http1"
	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// H1Transport is an alias for httputil.H1Transport, re-exported for backward
// compatibility within the protocol/http package. New code should import
// httputil.H1Transport directly.
type H1Transport = httputil.H1Transport

// RoundTripResult is an alias for httputil.RoundTripResult, re-exported for
// backward compatibility within the protocol/http package. New code should
// import httputil.RoundTripResult directly.
type RoundTripResult = httputil.RoundTripResult

// serializeRequest delegates to http1codec.SerializeRequest. This unexported
// wrapper exists for callers within the protocol/http package (e.g.,
// websocket.go) that use the original name.
func serializeRequest(req *parser.RawRequest) []byte {
	return http1codec.SerializeRequest(req)
}

// writeRequest delegates to http1codec.WriteRequest. This unexported wrapper
// exists for callers within the protocol/http package (e.g., websocket.go)
// that use the original name.
func writeRequest(conn net.Conn, header []byte, body io.Reader) error {
	return http1codec.WriteRequest(conn, header, body)
}
