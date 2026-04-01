package http

import (
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// rawHeadersToMap converts parser.RawHeaders to map[string][]string without
// going through net/http.Header. This preserves header name casing exactly as
// observed on the wire (MITM wire fidelity principle).
func rawHeadersToMap(rh parser.RawHeaders) map[string][]string {
	if rh == nil {
		return make(map[string][]string)
	}
	m := make(map[string][]string, len(rh))
	for _, h := range rh {
		m[h.Name] = append(m[h.Name], h.Value)
	}
	return m
}

// requestHeaders returns RawHeaders with the Host header explicitly set.
// This ensures accurate flow recording since the parser preserves Host in
// the RawHeaders directly (unlike Go's net/http which strips it).
func requestHeaders(req *parser.RawRequest) parser.RawHeaders {
	return req.Headers
}

// sendRecordParams holds the parameters needed to record the send phase
// (Session + request message) of an HTTP/HTTPS flow.
type sendRecordParams struct {
	connID     string
	clientAddr string
	protocol   string
	scheme     string
	start      time.Time
	tags       map[string]string
	connInfo   *flow.ConnectionInfo

	req          *parser.RawRequest
	reqURL       *url.URL
	reqBody      []byte
	rawRequest   []byte
	reqTruncated bool

	// rawVariant forces variant recording even when parsed headers/body are
	// unchanged. This is needed for raw mode intercept where modifications
	// happen at the raw bytes level, not the parsed HTTP level.
	rawVariant bool
	// originalRawBytes holds the original raw bytes before raw mode modification.
	originalRawBytes []byte
}

// sendRecordResult holds the flow created by recordSend so that
// subsequent recordReceive or recordSendError calls can reference it.
type sendRecordResult struct {
	flowID string
	tags   map[string]string
	// recvSequence is the sequence number to use for the receive message.
	recvSequence int
}

// recordSend records the send phase of a session.
func (h *Handler) recordSend(ctx context.Context, p sendRecordParams, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = parseRawRequestURI(p.req)
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return nil
	}

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
		Scheme:    p.scheme,
		FlowType:  "unary",
		State:     "active",
		Timestamp: p.start,
		Tags:      p.tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("flow save failed", "method", p.req.Method, "url", reqURL.String(), "error", err)
		return nil
	}

	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           reqURL,
		Headers:       rawHeadersToMap(requestHeaders(p.req)),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, tags: p.tags, recvSequence: 1}
}

// recordSendWithVariant records the send phase with variant support.
func (h *Handler) recordSendWithVariant(ctx context.Context, p sendRecordParams, snap *requestSnapshot, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = parseRawRequestURI(p.req)
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return nil
	}

	// Detect whether modification occurred.
	modified := p.rawVariant || (snap != nil && requestModified(*snap, p.req.Headers, p.reqBody))

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
		Scheme:    p.scheme,
		FlowType:  "unary",
		State:     "active",
		Timestamp: p.start,
		Tags:      p.tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("flow save failed", "method", p.req.Method, "url", reqURL.String(), "error", err)
		return nil
	}

	if modified {
		// Determine original headers/body from snapshot or current request.
		var origHeaders parser.RawHeaders
		var origBody []byte
		if snap != nil {
			origHeaders = snap.headers.Clone()
			origBody = snap.body
		} else {
			origHeaders = requestHeaders(p.req)
			origBody = p.reqBody
		}

		// Determine RawBytes for original and modified messages.
		origRawBytes := p.rawRequest
		var modRawBytes []byte
		if p.rawVariant {
			origRawBytes = p.originalRawBytes
			modRawBytes = p.rawRequest
		}

		// Record the original (unmodified) request as sequence 0.
		originalMsg := &flow.Message{
			FlowID:        fl.ID,
			Sequence:      0,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.req.Method,
			URL:           reqURL,
			Headers:       rawHeadersToMap(origHeaders),
			Body:          origBody,
			RawBytes:      origRawBytes,
			BodyTruncated: p.reqTruncated,
			Metadata:      map[string]string{"variant": "original"},
		}
		if err := h.Store.AppendMessage(ctx, originalMsg); err != nil {
			logger.Error("original send message save failed", "error", err)
		}

		// Record the modified request as sequence 1.
		modifiedMsg := &flow.Message{
			FlowID:        fl.ID,
			Sequence:      1,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.req.Method,
			URL:           reqURL,
			Headers:       rawHeadersToMap(requestHeaders(p.req)),
			Body:          p.reqBody,
			RawBytes:      modRawBytes,
			BodyTruncated: p.reqTruncated,
			Metadata:      map[string]string{"variant": "modified"},
		}
		if err := h.Store.AppendMessage(ctx, modifiedMsg); err != nil {
			logger.Error("modified send message save failed", "error", err)
		}

		return &sendRecordResult{flowID: fl.ID, tags: p.tags, recvSequence: 2}
	}

	// No modification: single send message without variant metadata.
	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           reqURL,
		Headers:       rawHeadersToMap(requestHeaders(p.req)),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, tags: p.tags, recvSequence: 1}
}

// receiveRecordParams holds the parameters needed to record the receive phase.
type receiveRecordParams struct {
	start      time.Time
	duration   time.Duration
	serverAddr string

	tlsServerCertSubject string

	resp        *parser.RawResponse
	rawResponse []byte
	respBody    []byte

	sendMs    *int64
	waitMs    *int64
	receiveMs *int64
}

// recordReceive records the receive phase of a session.
func (h *Handler) recordReceive(ctx context.Context, sendResult *sendRecordResult, p receiveRecordParams, logger *slog.Logger) {
	h.recordReceiveWithVariant(ctx, sendResult, p, nil, logger)
}

// recordReceiveWithVariant records the receive phase with variant support.
func (h *Handler) recordReceiveWithVariant(ctx context.Context, sendResult *sendRecordResult, p receiveRecordParams, snap *responseSnapshot, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	if p.resp == nil {
		return
	}

	var sharedSnap *httputil.ResponseSnapshot
	if snap != nil {
		s := httputil.ResponseSnapshot{
			StatusCode: snap.statusCode,
			Headers:    snap.headers,
			Body:       snap.body,
		}
		sharedSnap = &s
	}

	// Merge existing tags with fingerprint detection results.
	tags := httputil.MergeTechnologyTags(sendResult.tags, h.detector, p.resp.Headers, p.respBody)

	httputil.RecordReceiveVariant(ctx, h.Store, httputil.ReceiveVariantParams{
		FlowID:               sendResult.flowID,
		RecvSequence:         sendResult.recvSequence,
		Start:                p.start,
		Duration:             p.duration,
		ServerAddr:           p.serverAddr,
		TLSServerCertSubject: p.tlsServerCertSubject,
		RespStatusCode:       p.resp.StatusCode,
		RespHeaders:          p.resp.Headers,
		RespBody:             p.respBody,
		RawResponse:          p.rawResponse,
		Tags:                 tags,
		SendMs:               p.sendMs,
		WaitMs:               p.waitMs,
		ReceiveMs:            p.receiveMs,
	}, sharedSnap, logger)
}

// recordSendError updates a flow to State="error" after an upstream failure.
func (h *Handler) recordSendError(ctx context.Context, sendResult *sendRecordResult, start time.Time, upstreamErr error, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	duration := time.Since(start)
	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags["error"] = upstreamErr.Error()
	update := flow.FlowUpdate{
		State:    "error",
		Duration: duration,
		Tags:     tags,
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("flow error update failed", "error", err)
	}
}

// recordInterceptDrop records a flow where the request was dropped by intercept.
func (h *Handler) recordInterceptDrop(ctx context.Context, p sendRecordParams, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = parseRawRequestURI(p.req)
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return
	}

	duration := time.Since(p.start)
	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
		Scheme:    p.scheme,
		FlowType:  "unary",
		State:     "complete",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      p.tags,
		BlockedBy: "intercept_drop",
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("intercept drop flow save failed", "method", p.req.Method, "url", reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           reqURL,
		Headers:       rawHeadersToMap(requestHeaders(p.req)),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("intercept drop send message save failed", "error", err)
	}
}

// sessionRecordParams holds all parameters for recording an HTTP/HTTPS session.
//
// Deprecated: Retained for backward compatibility with existing tests.
type sessionRecordParams struct {
	connID     string
	clientAddr string
	serverAddr string
	protocol   string
	scheme     string
	start      time.Time
	duration   time.Duration
	tags       map[string]string
	connInfo   *flow.ConnectionInfo

	req          *parser.RawRequest
	reqURL       *url.URL
	reqBody      []byte
	rawRequest   []byte
	reqTruncated bool

	resp        *parser.RawResponse
	rawResponse []byte
	respBody    []byte
}

// recordHTTPSession records a complete HTTP/HTTPS session.
//
// Deprecated: Retained for backward compatibility with existing tests.
func (h *Handler) recordHTTPSession(ctx context.Context, p sessionRecordParams, logger *slog.Logger) {
	sp := sendRecordParams{
		connID:       p.connID,
		clientAddr:   p.clientAddr,
		protocol:     p.protocol,
		scheme:       p.scheme,
		start:        p.start,
		tags:         p.tags,
		connInfo:     p.connInfo,
		req:          p.req,
		reqURL:       p.reqURL,
		reqBody:      p.reqBody,
		rawRequest:   p.rawRequest,
		reqTruncated: p.reqTruncated,
	}

	sendResult := h.recordSend(ctx, sp, logger)

	if p.resp != nil {
		var tlsCertSubject string
		if p.connInfo != nil {
			tlsCertSubject = p.connInfo.TLSServerCertSubject
		}
		h.recordReceive(ctx, sendResult, receiveRecordParams{
			start:                p.start,
			duration:             p.duration,
			serverAddr:           p.serverAddr,
			tlsServerCertSubject: tlsCertSubject,
			resp:                 p.resp,
			rawResponse:          p.rawResponse,
			respBody:             p.respBody,
		}, logger)
	}
}
