package http

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// extractTLSState returns the TLS connection state if conn is a *tls.Conn, nil otherwise.
func extractTLSState(conn net.Conn) *tls.ConnectionState {
	if tlsConn, ok := conn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		return &state
	}
	return nil
}

// isGRPCWebRequest reports whether the request has a gRPC-Web Content-Type
// and the handler has a gRPC-Web handler configured.
func (h *Handler) isGRPCWebRequest(headers parser.RawHeaders) bool {
	if h.grpcWebHandler == nil {
		return false
	}
	ct := headers.Get("Content-Type")
	return grpcweb.IsGRPCWebContentType(ct)
}

// handleGRPCWeb forwards a gRPC-Web request upstream as-is and records the
// session via the gRPC-Web handler instead of the normal HTTP flow recording.
// The request body must already be read into reqBody.
func (h *Handler) handleGRPCWeb(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, reqBody []byte, useTLS bool, tlsState *tls.ConnectionState, logger *slog.Logger) error {
	start := time.Now()

	// Forward upstream as normal HTTP/1.1 (no protocol conversion).
	fwd, err := h.forwardUpstream(ctx, conn, req, reqURL, useTLS, logger)
	if err != nil {
		return err
	}

	// Read the full response body for gRPC-Web frame parsing.
	var fullRespBody []byte
	if fwd.resp.Body != nil {
		fullRespBody, err = io.ReadAll(io.LimitReader(fwd.resp.Body, config.MaxBodySize))
		if err != nil {
			logger.Warn("failed to read gRPC-Web response body", "error", err)
		}
		if closer, ok := fwd.resp.Body.(io.Closer); ok {
			closer.Close()
		}
	}

	// Write response to client as-is.
	if writeErr := writeRawResponse(conn, fwd.resp, fullRespBody, true); writeErr != nil {
		return fmt.Errorf("write gRPC-Web response: %w", writeErr)
	}

	duration := time.Since(start)

	// Determine scheme.
	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Build StreamInfo for gRPC-Web recording.
	info := &grpcweb.StreamInfo{
		ConnID:          proxy.ConnIDFromContext(ctx),
		ClientAddr:      proxy.ClientAddrFromContext(ctx),
		ServerAddr:      fwd.serverAddr,
		RequestHeaders:  req.Headers,
		ResponseHeaders: fwd.resp.Headers,
		RequestBody:     reqBody,
		ResponseBody:    fullRespBody,
		TLS:             tlsState,
		Start:           start,
		Duration:        duration,
		StatusCode:      fwd.resp.StatusCode,
		Method:          req.Method,
		URL:             reqURL,
		Scheme:          scheme,
	}

	if err := h.grpcWebHandler.RecordSession(ctx, info); err != nil {
		logger.Error("gRPC-Web flow recording failed", "error", err)
	}

	logger.Debug("grpc-web request",
		"method", req.Method,
		"url", reqURL.String(),
		"status", fwd.resp.StatusCode,
		"duration_ms", duration.Milliseconds())

	return nil
}
