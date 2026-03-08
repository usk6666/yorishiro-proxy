package http2

import (
	"bytes"
	"context"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// requestHeaders returns a clone of the request headers with the Host header
// explicitly set from req.Host. Go's net/http strips the Host header from
// Request.Header and stores it in Request.Host, so we must re-inject it for
// accurate flow recording.
func requestHeaders(req *gohttp.Request) gohttp.Header {
	headers := req.Header.Clone()
	if req.Host != "" {
		headers["Host"] = []string{req.Host}
	}
	return headers
}

// sendRecordParams holds the parameters needed to record the send phase
// (Session + request message) of an HTTP/2 flow.
type sendRecordParams struct {
	connID     string
	clientAddr string
	start      time.Time
	connInfo   *flow.ConnectionInfo

	req          *gohttp.Request
	reqURL       *url.URL
	reqBody      []byte
	reqTruncated bool
}

// sendRecordResult holds the flow created by recordSend so that
// subsequent recordReceive or recordSendError calls can reference it.
type sendRecordResult struct {
	flowID string
	// recvSequence is the sequence number to use for the receive message.
	// Defaults to 1 (send=0, receive=1). When variant recording produces
	// two send messages (original=0, modified=1), this is set to 2.
	recvSequence int
}

// recordSend records the send phase of an HTTP/2 session: creates the flow
// with State="active" and appends the send (request) message. This is called
// after intercept/transform processing but before upstream forwarding, so even
// if the upstream fails, the request is already recorded.
//
// Returns a sendRecordResult containing the flow ID for follow-up calls,
// or nil if recording was skipped (nil store, capture scope miss, etc.).
func (h *Handler) recordSend(ctx context.Context, p sendRecordParams, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	if !h.shouldCapture(p.req.Method, p.reqURL) {
		return nil
	}

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "active",
		Timestamp: p.start,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("HTTP/2 flow save failed",
			"method", p.req.Method, "url", p.reqURL.String(), "error", err)
		return nil
	}

	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           p.reqURL,
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, recvSequence: 1}
}

// requestSnapshot holds a copy of the request headers and body taken before
// intercept processing. It is used to detect whether modifications occurred
// and, if so, to record the original (unmodified) version as a separate send
// message.
type requestSnapshot struct {
	headers gohttp.Header
	body    []byte
}

// snapshotRequest creates a deep copy of the request headers and body for
// later comparison.
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
// relative to the snapshot.
func requestModified(snap requestSnapshot, currentHeaders gohttp.Header, currentBody []byte) bool {
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

// recordSendWithVariant records the send phase with variant support. If the
// request was modified by intercept (detected by comparing snap against the
// current outbound request), it records two send messages:
//   - Sequence 0: original (variant="original") with the snapshot's headers/body
//   - Sequence 1: modified (variant="modified") with the current headers/body
//
// If no modification occurred (snap is nil or headers/body unchanged), this
// behaves identically to recordSend (single send at sequence 0, no variant
// metadata).
func (h *Handler) recordSendWithVariant(ctx context.Context, p sendRecordParams, snap *requestSnapshot, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	if !h.shouldCapture(p.req.Method, p.reqURL) {
		return nil
	}

	// Detect whether modification occurred.
	modified := snap != nil && requestModified(*snap, p.req.Header, p.reqBody)

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "active",
		Timestamp: p.start,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("HTTP/2 flow save failed",
			"method", p.req.Method, "url", p.reqURL.String(), "error", err)
		return nil
	}

	if modified {
		// Inject Host into the snapshot headers (the snapshot was taken from
		// req.Header which does not contain Host per Go's net/http design).
		origHeaders := snap.headers.Clone()
		if p.req.Host != "" {
			origHeaders["Host"] = []string{p.req.Host}
		}
		// Record the original (unmodified) request as sequence 0.
		originalMsg := &flow.Message{
			FlowID:        fl.ID,
			Sequence:      0,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.req.Method,
			URL:           p.reqURL,
			Headers:       origHeaders,
			Body:          snap.body,
			BodyTruncated: p.reqTruncated,
			Metadata:      map[string]string{"variant": "original"},
		}
		if err := h.Store.AppendMessage(ctx, originalMsg); err != nil {
			logger.Error("HTTP/2 original send message save failed", "error", err)
		}

		// Record the modified request as sequence 1.
		modifiedMsg := &flow.Message{
			FlowID:        fl.ID,
			Sequence:      1,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.req.Method,
			URL:           p.reqURL,
			Headers:       requestHeaders(p.req),
			Body:          p.reqBody,
			BodyTruncated: p.reqTruncated,
			Metadata:      map[string]string{"variant": "modified"},
		}
		if err := h.Store.AppendMessage(ctx, modifiedMsg); err != nil {
			logger.Error("HTTP/2 modified send message save failed", "error", err)
		}

		return &sendRecordResult{flowID: fl.ID, recvSequence: 2}
	}

	// No modification: single send message without variant metadata.
	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           p.reqURL,
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, recvSequence: 1}
}

// receiveRecordParams holds the parameters needed to record the receive phase
// (response message + session completion) of an HTTP/2 flow.
type receiveRecordParams struct {
	start      time.Time
	duration   time.Duration
	serverAddr string

	// tlsServerCertSubject is the subject DN of the upstream server's TLS
	// certificate. Only set for HTTPS (h2) connections.
	tlsServerCertSubject string

	resp     *gohttp.Response
	respBody []byte
}

// recordReceive records the receive phase of an HTTP/2 session: appends the
// receive (response) message and updates the flow to State="complete". This
// is called after the response has been written to the client.
//
// If sendResult is nil (recording was skipped in recordSend), this is a no-op.
func (h *Handler) recordReceive(ctx context.Context, sendResult *sendRecordResult, p receiveRecordParams, logger *slog.Logger) {
	h.recordReceiveWithVariant(ctx, sendResult, p, nil, logger)
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
// and body for later comparison.
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

// recordReceiveWithVariant records the receive phase with variant support. If
// the response was modified by intercept (detected by comparing snap against
// the current response), it records two receive messages:
//   - Sequence N:   original (variant="original") with the snapshot's status/headers/body
//   - Sequence N+1: modified (variant="modified") with the current status/headers/body
//
// If no modification occurred (snap is nil or status/headers/body unchanged),
// this behaves identically to recordReceive (single receive, no variant metadata).
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

	httputil.RecordReceiveVariant(ctx, h.Store, httputil.ReceiveVariantParams{
		FlowID:               sendResult.flowID,
		RecvSequence:         sendResult.recvSequence,
		Start:                p.start,
		Duration:             p.duration,
		ServerAddr:           p.serverAddr,
		TLSServerCertSubject: p.tlsServerCertSubject,
		Resp:                 p.resp,
		RespBody:             p.respBody,
	}, sharedSnap, logger)
}

// recordSendError updates an HTTP/2 session to State="error" after an upstream
// failure. The send message is already recorded by recordSend; this only updates
// the flow metadata.
//
// If sendResult is nil (recording was skipped in recordSend), this is a no-op.
func (h *Handler) recordSendError(ctx context.Context, sendResult *sendRecordResult, start time.Time, upstreamErr error, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	duration := time.Since(start)
	tags := map[string]string{
		"error": upstreamErr.Error(),
	}
	update := flow.FlowUpdate{
		State:    "error",
		Duration: duration,
		Tags:     tags,
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("HTTP/2 session error update failed", "error", err)
	}
}

// recordInterceptDrop records an HTTP/2 session where the request was dropped by
// an intercept rule. The session is recorded as State="complete" with
// BlockedBy="intercept_drop" and only a send message (no receive).
func (h *Handler) recordInterceptDrop(ctx context.Context, p sendRecordParams, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	if !h.shouldCapture(p.req.Method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: p.start,
		Duration:  duration,
		BlockedBy: "intercept_drop",
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("HTTP/2 intercept drop flow save failed",
			"method", p.req.Method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           p.reqURL,
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 intercept drop send message save failed", "error", err)
	}
}

// recordOutReqError records an HTTP/2 session where the outbound request
// construction failed. The session is recorded as State="error" with the
// request message and an error tag.
func (h *Handler) recordOutReqError(ctx context.Context, p sendRecordParams, buildErr error, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	if !h.shouldCapture(p.req.Method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	tags := map[string]string{
		"error": buildErr.Error(),
	}
	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "error",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		logger.Error("HTTP/2 outReq error flow save failed",
			"method", p.req.Method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Message{
		FlowID:        fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.req.Method,
		URL:           p.reqURL,
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 outReq error send message save failed", "error", err)
	}
}
