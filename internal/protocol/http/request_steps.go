package http

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// normalizeRequestURL ensures the request URL has an absolute form suitable for
// forward proxy use. This sets the Host and Scheme if they are missing.
func normalizeRequestURL(req *gohttp.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
}

// requestBodyResult holds the result of reading and capturing a request body.
type requestBodyResult struct {
	recordBody []byte
	truncated  bool
}

// readAndCaptureRequestBody reads the full request body, replaces req.Body with
// a re-readable copy, and returns the body bytes for flow recording (truncated
// to MaxBodySize if necessary).
func readAndCaptureRequestBody(req *gohttp.Request, logger *slog.Logger) requestBodyResult {
	if req.Body == nil {
		return requestBodyResult{}
	}

	fullBody, err := io.ReadAll(req.Body)
	if err != nil {
		logger.Warn("failed to read request body", "error", err)
	}
	req.Body.Close()
	req.Body = io.NopCloser(bytes.NewReader(fullBody))

	recordBody := fullBody
	var truncated bool
	if len(fullBody) > int(config.MaxBodySize) {
		recordBody = fullBody[:int(config.MaxBodySize)]
		truncated = true
	}
	return requestBodyResult{recordBody: recordBody, truncated: truncated}
}

// extractRawRequest extracts the raw request bytes from the capture buffer.
// The raw bytes span from captureStart to the current capture position, minus
// any bytes buffered by the bufio.Reader (which belong to the next request).
func extractRawRequest(capture *captureReader, captureStart int, reader *bufio.Reader) []byte {
	if capture == nil {
		return nil
	}
	captureEnd := capture.buf.Len()
	buffered := reader.Buffered()
	rawEnd := captureEnd - buffered
	if rawEnd > captureStart && captureStart < capture.buf.Len() {
		raw := make([]byte, rawEnd-captureStart)
		copy(raw, capture.buf.Bytes()[captureStart:rawEnd])
		return raw
	}
	return nil
}

// applyIntercept checks intercept rules and applies any modifications. It returns
// the (possibly modified) request, updated body for recording, and a boolean
// indicating whether the request was dropped (caller should return early).
func (h *Handler) applyIntercept(ctx context.Context, conn net.Conn, req *gohttp.Request, recordReqBody []byte, logger *slog.Logger) (*gohttp.Request, []byte, bool) {
	action, intercepted := h.interceptRequest(ctx, conn, req, recordReqBody, logger)
	if !intercepted {
		return req, recordReqBody, false
	}

	switch action.Type {
	case intercept.ActionDrop:
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		logger.Info("intercepted request dropped", "method", req.Method, "url", req.URL.String())
		return req, recordReqBody, true
	case intercept.ActionModifyAndForward:
		var modErr error
		req, modErr = applyInterceptModifications(req, action, recordReqBody)
		if modErr != nil {
			logger.Error("intercept modification failed", "error", modErr)
			httputil.WriteHTTPError(conn, gohttp.StatusBadRequest, logger)
			return req, recordReqBody, true
		}
		// Re-check target scope after URL override to prevent SSRF (CWE-918, S-1).
		if action.OverrideURL != "" {
			if blocked, reason := h.checkTargetScope(req.URL); blocked {
				h.writeBlockedResponse(conn, req.URL.Hostname(), reason, logger)
				logger.Warn("intercept override_url blocked by target scope",
					"url", req.URL.String(), "reason", reason)
				return req, recordReqBody, true
			}
		}
		if action.OverrideBody != nil {
			recordReqBody = []byte(*action.OverrideBody)
		}
	case intercept.ActionRelease:
		// Continue with the original request.
	}

	return req, recordReqBody, false
}

// applyTransform applies auto-transform rules to the request before forwarding
// upstream. It modifies request headers and body in place.
func (h *Handler) applyTransform(req *gohttp.Request, recordReqBody []byte) []byte {
	if h.transformPipeline == nil {
		return recordReqBody
	}
	req.Header, recordReqBody = h.transformPipeline.TransformRequest(req.Method, req.URL, req.Header, recordReqBody)
	req.Body = io.NopCloser(bytes.NewReader(recordReqBody))
	req.ContentLength = int64(len(recordReqBody))
	return recordReqBody
}

// forwardResult holds the result of forwarding a request upstream.
type forwardResult struct {
	resp       *gohttp.Response
	serverAddr string
}

// forwardUpstream sends the request to the upstream server and returns the
// response. On failure, it writes a 502 Bad Gateway to the client connection.
func (h *Handler) forwardUpstream(ctx context.Context, conn net.Conn, req *gohttp.Request, logger *slog.Logger) (*forwardResult, error) {
	outReq := req.WithContext(ctx)
	outReq.RequestURI = ""

	resp, serverAddr, err := roundTripWithTrace(h.Transport, outReq)
	if err != nil {
		logger.Error("upstream request failed", "method", req.Method, "url", req.URL.String(), "error", err)
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		return nil, fmt.Errorf("upstream request: %w", err)
	}
	return &forwardResult{resp: resp, serverAddr: serverAddr}, nil
}

// readResponseBody reads the full response body (up to MaxBodySize) and applies
// response transforms if configured.
func (h *Handler) readResponseBody(resp *gohttp.Response, logger *slog.Logger) []byte {
	fullBody, err := io.ReadAll(io.LimitReader(resp.Body, config.MaxBodySize))
	if err != nil {
		logger.Warn("failed to read response body", "error", err)
	}

	if h.transformPipeline != nil {
		resp.Header, fullBody = h.transformPipeline.TransformResponse(resp.StatusCode, resp.Header, fullBody)
	}

	return fullBody
}

// writeResponseToClient writes the HTTP response with body back to the client
// connection.
func writeResponseToClient(conn net.Conn, resp *gohttp.Response, body []byte) error {
	if err := writeResponse(conn, resp, body); err != nil {
		return fmt.Errorf("write response: %w", err)
	}
	return nil
}

// interceptResponse checks if the response matches any intercept rules and,
// if so, enqueues it for AI agent review. It blocks until the agent responds
// or the timeout expires. Returns the action and true if intercepted, or a
// zero-value action and false if not intercepted.
func (h *Handler) interceptResponse(ctx context.Context, req *gohttp.Request, resp *gohttp.Response, body []byte, logger *slog.Logger) (intercept.InterceptAction, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return intercept.InterceptAction{}, false
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, resp.Header)
	if len(matchedRules) == 0 {
		return intercept.InterceptAction{}, false
	}

	logger.Info("response intercepted",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, req.URL, resp.StatusCode, resp.Header, body, matchedRules,
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

// applyInterceptResponse checks response intercept rules and applies any modifications.
// It returns the (possibly modified) response, updated body, and a boolean indicating
// whether the response was dropped (caller should return early with an error response).
func (h *Handler) applyInterceptResponse(ctx context.Context, conn net.Conn, req *gohttp.Request, resp *gohttp.Response, body []byte, logger *slog.Logger) (*gohttp.Response, []byte, bool) {
	action, intercepted := h.interceptResponse(ctx, req, resp, body, logger)
	if !intercepted {
		return resp, body, false
	}

	switch action.Type {
	case intercept.ActionDrop:
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		logger.Info("intercepted response dropped",
			"method", req.Method, "url", req.URL.String(), "status", resp.StatusCode)
		return resp, body, true
	case intercept.ActionModifyAndForward:
		var modErr error
		resp, body, modErr = applyResponseModifications(resp, action, body)
		if modErr != nil {
			logger.Error("response intercept modification failed", "error", modErr)
			httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
			return resp, body, true
		}
		return resp, body, false
	case intercept.ActionRelease:
		// Continue with the original response.
	}

	return resp, body, false
}

// applyResponseModifications applies the modifications from a modify_and_forward
// action to the HTTP response. It delegates to the shared httputil package for
// status code validation, CRLF injection checks, and header/body modifications.
func applyResponseModifications(resp *gohttp.Response, action intercept.InterceptAction, body []byte) (*gohttp.Response, []byte, error) {
	return httputil.ApplyResponseModifications(resp, action, body)
}

// requestSnapshot holds a copy of the request headers and body taken before
// intercept/transform processing. It is used to detect whether modifications
// occurred and, if so, to record the original (unmodified) version as a
// separate send message.
type requestSnapshot struct {
	headers gohttp.Header
	body    []byte
}

// snapshotRequest creates a deep copy of the request headers and body for
// later comparison. The snapshot captures the state before intercept/transform
// processing so that we can detect changes and record both versions.
func snapshotRequest(headers gohttp.Header, body []byte) requestSnapshot {
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

// requestModified reports whether the request headers or body have been changed
// relative to the snapshot taken before intercept/transform processing.
func requestModified(snap requestSnapshot, currentHeaders gohttp.Header, currentBody []byte) bool {
	if !bytes.Equal(snap.body, currentBody) {
		return true
	}
	return headersModified(snap.headers, currentHeaders)
}

// responseSnapshot holds a copy of the response status code, headers, and body
// taken before intercept processing. It is used to detect whether modifications
// occurred and, if so, to record the original (unmodified) version as a
// separate receive message.
type responseSnapshot struct {
	statusCode int
	headers    gohttp.Header
	body       []byte
}

// snapshotResponse creates a deep copy of the response status code, headers,
// and body for later comparison. The snapshot captures the state before
// intercept processing so that we can detect changes and record both versions.
func snapshotResponse(statusCode int, headers gohttp.Header, body []byte) responseSnapshot {
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

// responseModified reports whether the response status code, headers, or body
// have been changed relative to the snapshot taken before intercept processing.
func responseModified(snap responseSnapshot, currentStatusCode int, currentHeaders gohttp.Header, currentBody []byte) bool {
	if snap.statusCode != currentStatusCode {
		return true
	}
	if !bytes.Equal(snap.body, currentBody) {
		return true
	}
	return headersModified(snap.headers, currentHeaders)
}

// headersModified reports whether two header maps differ.
func headersModified(a, b gohttp.Header) bool {
	if len(a) != len(b) {
		return true
	}
	for key, aVals := range a {
		bVals, ok := b[key]
		if !ok || len(aVals) != len(bVals) {
			return true
		}
		for i := range aVals {
			if aVals[i] != bVals[i] {
				return true
			}
		}
	}
	return false
}

// logHTTPRequest logs the completed HTTP request with method, URL, status, and
// duration.
func logHTTPRequest(logger *slog.Logger, req *gohttp.Request, statusCode int, duration time.Duration) {
	logger.Info("http request", "method", req.Method, "url", req.URL.String(), "status", statusCode, "duration_ms", duration.Milliseconds())
}
