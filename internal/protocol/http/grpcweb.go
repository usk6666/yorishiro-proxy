package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
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

// handleGRPCWeb forwards a gRPC-Web request upstream with intercept, transform,
// and variant recording support. The request body must already be read into reqBody.
//
// Pipeline order:
//  1. Snapshot headers/body for variant detection
//  2. Intercept check (hold/release/modify) — reuses applyIntercept
//  3. Transform rules
//  4. Forward upstream
//  5. Response intercept
//  6. Write response to client
//  7. Record session via gRPC-Web handler
func (h *Handler) handleGRPCWeb(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, reqBody []byte, useTLS bool, tlsState *tls.ConnectionState, logger *slog.Logger) error {
	start := time.Now()
	connID := proxy.ConnIDFromContext(ctx)
	clientAddr := proxy.ClientAddrFromContext(ctx)

	scheme := "http"
	if useTLS {
		scheme = "https"
	}

	// Snapshot headers/body before intercept/transform for variant recording.
	snap := snapshotRawRequest(req.Headers, reqBody)

	// --- Intercept check (reuses existing HTTP/1.x intercept infrastructure) ---
	iResult := h.applyIntercept(ctx, conn, req, reqURL, reqBody, req.RawBytes, logger)
	if iResult.Dropped {
		return nil
	}
	req = iResult.Req
	reqBody = iResult.RecordBody

	// Re-derive reqURL after intercept — the intercept action may have
	// overridden the URL.
	if iResult.ModURL != nil {
		reqURL = iResult.ModURL
	} else {
		reqURL = parseRequestURL(ctx, req, scheme)
	}

	// Raw mode: bypass normal forwarding and forward raw bytes directly.
	if iResult.IsRaw {
		return h.handleGRPCWebRawForward(ctx, conn, req, reqURL, iResult, start, connID, clientAddr, scheme, &snap, logger)
	}

	// --- Transform rules ---
	reqBody = h.applyTransform(req, reqURL, reqBody)

	// Re-seat the body reader so forwardUpstream sends the (possibly modified) body.
	req.Body = bytes.NewReader(reqBody)

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

	// Apply response transform.
	if h.transformPipeline != nil {
		kv := rawHeadersToKeyValues(fwd.resp.Headers)
		kv, fullRespBody = h.transformPipeline.TransformResponse(fwd.resp.StatusCode, kv, fullRespBody)
		fwd.resp.Headers = keyValuesToRawHeaders(kv)
	}

	// --- Response intercept ---
	rir := h.applyInterceptResponse(ctx, conn, req, reqURL, fwd.resp, fullRespBody, logger)
	if rir.dropped {
		return nil
	}
	fwd.resp = rir.resp
	fullRespBody = rir.body

	// Output filter: mask sensitive data.
	fullRespBody, fwd.resp.Headers = h.ApplyOutputFilter(fullRespBody, fwd.resp.Headers, logger)

	// Write response to client.
	if writeErr := writeRawResponse(conn, fwd.resp, fullRespBody, rir.autoContentLength); writeErr != nil {
		return fmt.Errorf("write gRPC-Web response: %w", writeErr)
	}

	duration := time.Since(start)

	// Build StreamInfo for gRPC-Web recording.
	// Use the snapshot (original) body for recording when intercept/transform modified it,
	// so the recording reflects the wire-observed data before modification.
	recordReqBody := reqBody
	recordReqHeaders := req.Headers
	modified := requestModified(snap, req.Headers, reqBody)
	if modified {
		recordReqHeaders = snap.headers
		recordReqBody = snap.body
	}

	info := &grpcweb.StreamInfo{
		ConnID:          connID,
		ClientAddr:      clientAddr,
		ServerAddr:      fwd.serverAddr,
		RequestHeaders:  recordReqHeaders,
		ResponseHeaders: fwd.resp.Headers,
		RequestBody:     recordReqBody,
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

// handleGRPCWebRawForward handles the raw mode forwarding path for intercepted
// gRPC-Web requests. This bypasses UpstreamRouter and sends raw bytes directly
// to the upstream server.
func (h *Handler) handleGRPCWebRawForward(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, iResult interceptResult, start time.Time, connID, clientAddr, scheme string, snap *requestSnapshot, logger *slog.Logger) error {
	sp := sendRecordParams{
		connID:     connID,
		clientAddr: clientAddr,
		protocol:   socks5Protocol(ctx, "gRPC-Web"),
		scheme:     scheme,
		start:      start,
		tags:       mergeSOCKS5Tags(ctx, nil),
		connInfo:   &flow.ConnectionInfo{ClientAddr: clientAddr},
		req:        req,
		reqURL:     reqURL,
		reqBody:    iResult.RecordBody,
		rawRequest: iResult.RawBytes,
	}

	if iResult.OriginalRawBytes != nil {
		sp.rawVariant = true
		sp.originalRawBytes = iResult.OriginalRawBytes
	}

	return h.handleRawForward(ctx, conn, req, reqURL, iResult, sp, snap, start, logger)
}
