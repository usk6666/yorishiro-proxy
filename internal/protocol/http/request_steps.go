package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// interceptResult holds the outcome of applyIntercept. When raw mode is
// selected (IsRaw == true), the caller must bypass UpstreamRouter and
// write RawBytes directly to the upstream connection.
type interceptResult struct {
	Req              *parser.RawRequest
	RecordBody       []byte
	Dropped          bool
	IsRaw            bool
	RawBytes         []byte
	OriginalRawBytes []byte
	// ModURL is the modified URL after intercept URL override processing.
	// Non-nil only when the intercept action overrides the URL.
	ModURL *url.URL
}

// applyIntercept checks intercept rules and applies any modifications.
func (h *Handler) applyIntercept(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, recordReqBody []byte, rawRequest []byte, logger *slog.Logger) interceptResult {
	action, intercepted := h.interceptRequest(ctx, conn, req, reqURL, recordReqBody, rawRequest, logger)
	if !intercepted {
		return interceptResult{Req: req, RecordBody: recordReqBody}
	}

	switch action.Type {
	case intercept.ActionDrop:
		writeHTTPError(conn, statusBadGateway, logger)
		logger.Info("intercepted request dropped", "method", req.Method, "url", reqURL.String())
		return interceptResult{Req: req, RecordBody: recordReqBody, Dropped: true}
	case intercept.ActionModifyAndForward:
		// Raw mode: bypass L7 modifications and forward raw bytes directly.
		if action.IsRawMode() {
			logger.Info("intercept raw mode modify_and_forward",
				"method", req.Method, "url", reqURL.String(),
				"raw_override_size", len(action.RawOverride))
			return interceptResult{
				Req:              req,
				RecordBody:       recordReqBody,
				IsRaw:            true,
				RawBytes:         action.RawOverride,
				OriginalRawBytes: rawRequest,
			}
		}
		modReq, modBody, modURL, modErr := httputil.ApplyRequestModificationsRaw(req, recordReqBody, action)
		if modErr != nil {
			logger.Error("intercept modification failed", "error", modErr)
			writeHTTPError(conn, statusBadRequest, logger)
			return interceptResult{Req: req, RecordBody: recordReqBody, Dropped: true}
		}
		// Re-check target scope after URL override to prevent SSRF (CWE-918, S-1).
		if action.OverrideURL != "" && modURL != nil {
			if blocked, reason := h.checkTargetScope(modURL); blocked {
				h.writeBlockedResponse(conn, modURL.Hostname(), reason, logger)
				logger.Warn("intercept override_url blocked by target scope",
					"url", modURL.String(), "reason", reason)
				return interceptResult{Req: req, RecordBody: recordReqBody, Dropped: true}
			}
		}
		req = modReq
		recordReqBody = modBody
		result := interceptResult{Req: req, RecordBody: recordReqBody, ModURL: modURL}
		return result
	case intercept.ActionRelease:
		// Raw mode release: forward original raw bytes as-is.
		if action.IsRawMode() {
			logger.Info("intercept raw mode release",
				"method", req.Method, "url", reqURL.String(),
				"raw_bytes_size", len(rawRequest))
			return interceptResult{
				Req:        req,
				RecordBody: recordReqBody,
				IsRaw:      true,
				RawBytes:   rawRequest,
			}
		}
	}

	return interceptResult{Req: req, RecordBody: recordReqBody}
}

// applyTransform applies auto-transform rules to the request before forwarding
// upstream. It modifies request headers and body in place. The caller must pass
// the fully normalized reqURL (including scheme and host) so that URL-based
// transform rules can match correctly even for origin-form RequestURIs.
func (h *Handler) applyTransform(req *parser.RawRequest, reqURL *url.URL, recordReqBody []byte) []byte {
	if h.transformPipeline == nil {
		return recordReqBody
	}
	rh := req.Headers
	rh, recordReqBody = h.transformPipeline.TransformRequest(req.Method, reqURL, rh, recordReqBody)
	req.Headers = rh
	req.Body = bytes.NewReader(recordReqBody)
	return recordReqBody
}

// parseRawRequestURI parses the request URI from a RawRequest into a *url.URL.
func parseRawRequestURI(req *parser.RawRequest) *url.URL {
	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		return &url.URL{Path: req.RequestURI}
	}
	return u
}

// interceptRequest checks if the request matches any intercept rules.
func (h *Handler) interceptRequest(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, body []byte, rawBytes []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchRequestRules(req.Method, reqURL, req.Headers)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("request intercepted", "method", req.Method, "url", reqURL.String(), "matched_rules", matchedRules)

	var opts []intercept.EnqueueOpts
	if len(rawBytes) > 0 {
		opts = append(opts, intercept.EnqueueOpts{RawBytes: rawBytes})
	}

	id, actionCh := h.InterceptQueue.Enqueue(req.Method, reqURL, req.Headers, body, matchedRules, opts...)
	defer h.InterceptQueue.Remove(id)

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action, true
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			logger.Info("intercepted request cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted request timed out", "id", id, "behavior", string(behavior))
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		default:
			return intercept.InterceptAction{Type: intercept.ActionRelease}, true
		}
	}
}

// interceptResponse checks if the response matches any intercept rules.
func (h *Handler) interceptResponse(ctx context.Context, req *parser.RawRequest, reqURL *url.URL, resp *parser.RawResponse, body []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, resp.Headers)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("response intercepted",
		"method", req.Method,
		"url", reqURL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, reqURL, resp.StatusCode, resp.Headers, body, matchedRules,
	)
	defer h.InterceptQueue.Remove(id)

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action, true
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			logger.Info("intercepted response cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		}
		logger.Info("intercepted response timed out", "id", id, "behavior", string(behavior))
		switch behavior {
		case intercept.TimeoutAutoDrop:
			return intercept.InterceptAction{Type: intercept.ActionDrop}, true
		default:
			return intercept.InterceptAction{Type: intercept.ActionRelease}, true
		}
	}
}

// applyInterceptResponse checks response intercept rules and applies modifications.
func (h *Handler) applyInterceptResponse(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, resp *parser.RawResponse, body []byte, logger *slog.Logger) (*parser.RawResponse, []byte, bool) {
	action, intercepted := h.interceptResponse(ctx, req, reqURL, resp, body, logger)
	if !intercepted {
		return resp, body, false
	}

	switch action.Type {
	case intercept.ActionDrop:
		writeHTTPError(conn, statusBadGateway, logger)
		logger.Info("intercepted response dropped",
			"method", req.Method, "url", reqURL.String(), "status", resp.StatusCode)
		return resp, body, true
	case intercept.ActionModifyAndForward:
		modResp, modBody, modErr := httputil.ApplyResponseModificationsRaw(resp, body, action)
		if modErr != nil {
			logger.Error("response intercept modification failed", "error", modErr)
			writeHTTPError(conn, statusBadGateway, logger)
			return resp, body, true
		}
		return modResp, modBody, false
	case intercept.ActionRelease:
		// Continue with the original response.
	}

	return resp, body, false
}

// requestSnapshot holds a copy of the request headers and body taken before
// intercept/transform processing. Used for variant detection.
type requestSnapshot struct {
	headers parser.RawHeaders
	body    []byte
}

// snapshotRawRequest creates a deep copy of the request headers and body.
func snapshotRawRequest(headers parser.RawHeaders, body []byte) requestSnapshot {
	snap := requestSnapshot{}
	if headers != nil {
		snap.headers = headers.Clone()
	}
	if body != nil {
		snap.body = make([]byte, len(body))
		copy(snap.body, body)
	}
	return snap
}

// requestModified reports whether the request headers or body have been changed.
func requestModified(snap requestSnapshot, currentHeaders parser.RawHeaders, currentBody []byte) bool {
	if !bytes.Equal(snap.body, currentBody) {
		return true
	}
	return httputil.HeadersModified(snap.headers, currentHeaders)
}

// responseSnapshot holds a copy of the response status code, headers, and body.
type responseSnapshot struct {
	statusCode int
	headers    parser.RawHeaders
	body       []byte
}

// snapshotRawResponse creates a deep copy of the response status code, headers,
// and body for later comparison.
func snapshotRawResponse(statusCode int, headers parser.RawHeaders, body []byte) responseSnapshot {
	snap := responseSnapshot{statusCode: statusCode}
	if headers != nil {
		snap.headers = headers.Clone()
	}
	if body != nil {
		snap.body = make([]byte, len(body))
		copy(snap.body, body)
	}
	return snap
}

// handleRawForward performs raw bytes forwarding for intercepted requests.
func (h *Handler) handleRawForward(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, iResult interceptResult, sp sendRecordParams, snap *requestSnapshot, start time.Time, logger *slog.Logger) error {
	// Record the send phase with variant support for raw forwarding.
	sendResult := h.recordRawSend(ctx, sp, iResult, snap, logger)

	// Forward raw bytes to the upstream server.
	sendStart := time.Now()
	rawFwd, err := h.forwardRawUpstream(ctx, req, reqURL, iResult.RawBytes, logger)
	if err != nil {
		logger.Error("raw forward upstream failed", "method", req.Method, "url", reqURL.String(), "error", err)
		writeHTTPError(conn, statusBadGateway, logger)
		h.recordSendError(ctx, sendResult, start, err, logger)
		return nil
	}

	// Write raw response back to the client.
	if err := writeRawResponseToClient(conn, rawFwd.rawResponse); err != nil {
		return err
	}

	// Record the receive phase.
	duration := time.Since(start)
	sendMs := time.Since(sendStart).Milliseconds()
	h.recordRawReceive(ctx, sendResult, rawFwd, start, duration, sendMs, logger)

	statusCode := 0
	if rawFwd.resp != nil {
		statusCode = rawFwd.resp.StatusCode
	}
	logHTTPRequest(logger, req.Method, reqURL.String(), statusCode, duration)

	return nil
}

// rawForwardResult holds the result of raw forwarding to the upstream server.
type rawForwardResult struct {
	rawResponse []byte
	resp        *parser.RawResponse
	respBody    []byte
	serverAddr  string
}

// forwardRawUpstream dials the upstream server, writes rawBytes directly,
// reads the raw response, and returns both raw bytes and a best-effort parsed
// HTTP response.
func (h *Handler) forwardRawUpstream(ctx context.Context, req *parser.RawRequest, reqURL *url.URL, rawBytes []byte, logger *slog.Logger) (*rawForwardResult, error) {
	host := reqURL.Host
	if host == "" {
		host = req.Headers.Get("Host")
	}
	addr := host
	scheme := reqURL.Scheme
	if scheme == "" {
		scheme = "http"
	}

	if _, _, err := net.SplitHostPort(addr); err != nil {
		switch scheme {
		case "https":
			addr = addr + ":443"
		default:
			addr = addr + ":80"
		}
	}

	useTLS := scheme == "https"
	hostname := host
	if h, _, splitErr := net.SplitHostPort(addr); splitErr == nil {
		hostname = h
	}

	pool := h.connPool
	if pool == nil {
		pool = &ConnPool{
			TLSTransport:   h.effectiveTLSTransport(),
			UpstreamProxy:  h.GetUpstreamProxy(),
			DialViaProxy:   proxy.DialViaUpstreamProxy,
			RedactProxyURL: proxy.RedactProxyURL,
		}
	}

	cr, err := pool.Get(ctx, addr, useTLS, hostname)
	if err != nil {
		return nil, fmt.Errorf("raw forward dial upstream %s: %w", addr, err)
	}
	defer cr.Conn.Close()

	serverAddr := cr.Conn.RemoteAddr().String()

	// Set a deadline for the entire raw forwarding operation.
	if deadline, ok := ctx.Deadline(); ok {
		cr.Conn.SetDeadline(deadline)
	} else {
		cr.Conn.SetDeadline(time.Now().Add(60 * time.Second))
	}

	// Write the raw bytes directly.
	if _, err := cr.Conn.Write(rawBytes); err != nil {
		return nil, fmt.Errorf("raw forward write: %w", err)
	}

	// Read the raw response from upstream using the parser.
	rawResponse, resp, respBody, readErr := readRawResponseFromConn(cr.Conn)
	if readErr != nil {
		return nil, fmt.Errorf("raw forward read response: %w", readErr)
	}

	return &rawForwardResult{
		rawResponse: rawResponse,
		resp:        resp,
		respBody:    respBody,
		serverAddr:  serverAddr,
	}, nil
}

// readRawResponseFromConn reads the complete response from the upstream connection,
// capturing raw bytes while attempting a best-effort parser parse.
func readRawResponseFromConn(conn net.Conn) (rawResponse []byte, resp *parser.RawResponse, respBody []byte, err error) {
	// Capture all bytes from upstream.
	var captured bytes.Buffer
	tee := io.TeeReader(conn, &captured)
	reader := bufio.NewReader(tee)

	resp, parseErr := parser.ParseResponse(reader)
	if parseErr != nil {
		// If parsing fails, read whatever is available as raw bytes.
		remaining, _ := io.ReadAll(io.LimitReader(reader, int64(intercept.MaxRawBytesSize)))
		rawResponse = captured.Bytes()
		if len(remaining) > 0 && len(rawResponse) == 0 {
			rawResponse = remaining
		}
		return rawResponse, nil, nil, nil
	}

	if resp.Body != nil {
		respBody, err = io.ReadAll(io.LimitReader(resp.Body, int64(maxRawCaptureSize)))
		if err != nil {
			rawResponse = captured.Bytes()
			return rawResponse, resp, respBody, nil
		}
	}

	rawResponse = captured.Bytes()
	return rawResponse, resp, respBody, nil
}

// writeRawResponseToClient writes raw response bytes directly to the client
// connection, bypassing HTTP serialization.
func writeRawResponseToClient(conn net.Conn, rawResponse []byte) error {
	if _, err := conn.Write(rawResponse); err != nil {
		return fmt.Errorf("write raw response: %w", err)
	}
	return nil
}

// recordRawSend records the send phase for raw forwarding.
func (h *Handler) recordRawSend(ctx context.Context, sp sendRecordParams, iResult interceptResult, snap *requestSnapshot, logger *slog.Logger) *sendRecordResult {
	if iResult.OriginalRawBytes != nil {
		sp.rawVariant = true
		sp.originalRawBytes = iResult.OriginalRawBytes
		sp.rawRequest = iResult.RawBytes
		return h.recordSendWithVariant(ctx, sp, snap, logger)
	}
	return h.recordSendWithVariant(ctx, sp, snap, logger)
}

// recordRawReceive records the receive phase for raw forwarding.
func (h *Handler) recordRawReceive(ctx context.Context, sendResult *sendRecordResult, rawFwd *rawForwardResult, start time.Time, duration time.Duration, sendMs int64, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	var goResp *httputil.GoHTTPResponse
	if rawFwd.resp != nil {
		goResp = httputil.RawResponseToHTTP(rawFwd.resp, rawFwd.respBody)
	}

	rp := receiveRecordParams{
		start:       start,
		duration:    duration,
		serverAddr:  rawFwd.serverAddr,
		resp:        goResp,
		rawResponse: rawFwd.rawResponse,
		respBody:    rawFwd.respBody,
		sendMs:      &sendMs,
	}

	h.recordReceive(ctx, sendResult, rp, logger)
}

// isWebSocketUpgradeRaw checks if the raw request headers indicate a WebSocket
// upgrade request.
func isWebSocketUpgradeRaw(headers parser.RawHeaders) bool {
	connection := headers.Get("Connection")
	upgrade := headers.Get("Upgrade")
	return headerContains(connection, "upgrade") &&
		equalsIgnoreCase(trimSpace(upgrade), "websocket")
}

// equalsIgnoreCase performs case-insensitive string comparison.
func equalsIgnoreCase(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i], b[i]
		if 'A' <= ca && ca <= 'Z' {
			ca += 'a' - 'A'
		}
		if 'A' <= cb && cb <= 'Z' {
			cb += 'a' - 'A'
		}
		if ca != cb {
			return false
		}
	}
	return true
}

// trimSpace trims leading and trailing ASCII whitespace.
func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\n' || s[start] == '\r') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\n' || s[end-1] == '\r') {
		end--
	}
	return s[start:end]
}

// headerContains checks if a comma-separated header value contains the given
// token (case-insensitive).
func headerContains(headerValue, token string) bool {
	start := 0
	for start < len(headerValue) {
		end := start
		for end < len(headerValue) && headerValue[end] != ',' {
			end++
		}
		t := trimSpace(headerValue[start:end])
		if equalsIgnoreCase(t, token) {
			return true
		}
		start = end + 1
	}
	return false
}

// isSSEResponseRaw checks if the response is a Server-Sent Events stream.
func isSSEResponseRaw(resp *parser.RawResponse) bool {
	ct := resp.Headers.Get("Content-Type")
	if ct == "" {
		return false
	}
	mediaType := ct
	for i := 0; i < len(ct); i++ {
		if ct[i] == ';' {
			mediaType = ct[:i]
			break
		}
	}
	return equalsIgnoreCase(trimSpace(mediaType), "text/event-stream")
}
