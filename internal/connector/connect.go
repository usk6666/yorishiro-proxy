// connect.go implements the HTTP CONNECT negotiator.
//
// CONNECT is the first half of the HTTPS MITM dance: the client sends
// "CONNECT host:port HTTP/1.1" + headers, we reply with
// "HTTP/1.1 200 Connection Established", and from that point on the
// connection becomes an opaque tunnel that the post-CONNECT handler takes
// over (see connect_handler.go::NewCONNECTHandler).
//
// This file only handles the HTTP verb parsing + reply. It does NOT perform
// TLS MITM or inner protocol detection; that is BuildConnectionStack's job.
package connector

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// connectOKResponse is the fixed 200 reply sent once CONNECT has been parsed.
// RFC 9110 says the response body is empty and any entity headers are ignored
// by the client, so a minimal response is sufficient.
const connectOKResponse = "HTTP/1.1 200 Connection Established\r\n\r\n"

// CONNECTNegotiator parses the HTTP CONNECT verb off a freshly accepted
// connection, writes the 200 OK reply, and returns the target host:port so
// the caller can hand the raw tunnel off to the post-CONNECT handler.
//
// The negotiator is stateless; a single instance can be shared by the entire
// listener. The Logger is used for anomaly warnings only; detailed per-conn
// logging is the caller's responsibility.
//
// CONNECTNegotiator is consumed by NewCONNECTHandler (connect_handler.go).
type CONNECTNegotiator struct {
	Logger *slog.Logger
}

// NewCONNECTNegotiator returns a negotiator with the given logger. A nil
// logger is replaced with slog.Default().
func NewCONNECTNegotiator(logger *slog.Logger) *CONNECTNegotiator {
	if logger == nil {
		logger = slog.Default()
	}
	return &CONNECTNegotiator{Logger: logger}
}

// ErrNotCONNECT is returned when the parsed request is not a CONNECT verb.
// The listener should close the connection.
var ErrNotCONNECT = errors.New("connector: expected CONNECT request")

// Negotiate parses the CONNECT request, sends the 200 reply, and returns
// the target host:port in canonical form.
//
// The reader inside pc already holds the peeked first bytes, so callers must
// pass the PeekConn they received from Dispatcher.Dispatch. After Negotiate
// returns, pc still wraps the same underlying net.Conn and is safe to use
// for the tunnel phase.
//
// The context is used only for logging; the underlying I/O uses any
// deadlines that have already been set on the connection.
func (n *CONNECTNegotiator) Negotiate(ctx context.Context, pc *PeekConn) (string, error) {
	if pc == nil {
		return "", fmt.Errorf("connector: CONNECTNegotiator.Negotiate: nil conn")
	}

	// Parse directly off the PeekConn's internal bufio.Reader so that any
	// bytes the client sent after the CONNECT headers (e.g. a TLS
	// ClientHello packed into the same TCP segment) remain buffered and
	// are picked up by the tunnel phase that follows.
	req, err := parser.ParseRequest(pc.Reader())
	if err != nil {
		return "", fmt.Errorf("connector: parse CONNECT request: %w", err)
	}
	if !strings.EqualFold(req.Method, "CONNECT") {
		return "", fmt.Errorf("%w: got method %q", ErrNotCONNECT, req.Method)
	}

	target, err := normalizeCONNECTTarget(req)
	if err != nil {
		return "", err
	}

	if n.Logger != nil && n.Logger.Enabled(ctx, slog.LevelDebug) {
		n.Logger.Debug("CONNECT request parsed", "target", target,
			"anomaly_count", len(req.Anomalies))
	}

	if _, err := pc.Write([]byte(connectOKResponse)); err != nil {
		return "", fmt.Errorf("connector: write CONNECT 200: %w", err)
	}

	return target, nil
}

// normalizeCONNECTTarget extracts host:port from a parsed CONNECT request.
// RFC 9110 §9.3.6 says the request-target MUST be authority-form ("host:port")
// but some clients put the same value in the Host header. We accept either
// and reject anything that cannot be parsed as a host:port with a numeric
// port in [1, 65535].
func normalizeCONNECTTarget(req *parser.RawRequest) (string, error) {
	candidates := []string{req.RequestURI, req.Headers.Get("Host")}
	for _, c := range candidates {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if strings.ContainsAny(c, "\r\n") {
			// CR/LF in the target would let an attacker smuggle bytes
			// into the tunnel reply. Rejecting outright is safer than
			// sanitizing.
			return "", fmt.Errorf("connector: CONNECT target contains CR/LF")
		}
		host, port, err := net.SplitHostPort(c)
		if err != nil {
			continue
		}
		if host == "" {
			continue
		}
		p, err := strconv.Atoi(port)
		if err != nil || p <= 0 || p > 65535 {
			continue
		}
		return net.JoinHostPort(host, port), nil
	}
	return "", fmt.Errorf("connector: CONNECT request missing valid host:port (uri=%q host=%q)",
		req.RequestURI, req.Headers.Get("Host"))
}
