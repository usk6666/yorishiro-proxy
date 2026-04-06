package http2

import (
	"bytes"
	"context"
	"log/slog"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// requestHeadersMap returns a map[string][]string of the request headers for
// recording. It includes the host header from h2req's :authority, preserving
// wire casing (no canonicalization).
func requestHeadersMap(headers []hpack.HeaderField, host string) map[string][]string {
	m := hpackToHeaderMap(headers)
	if host != "" {
		m["host"] = []string{host}
	}
	return m
}

// sendRecordParams holds the parameters needed to record the send phase
// (Session + request message) of an HTTP/2 flow.
type sendRecordParams struct {
	connID     string
	clientAddr string
	scheme     string
	start      time.Time
	connInfo   *flow.ConnectionInfo

	method       string
	reqURL       *url.URL
	host         string
	headers      []hpack.HeaderField
	reqBody      []byte
	reqTruncated bool

	// rawFrames holds the raw HTTP/2 frame bytes received from the client.
	// Each element is the complete wire bytes of one frame (header + payload).
	// These are concatenated into Message.RawBytes for L4 recording.
	rawFrames [][]byte
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

	if !h.shouldCapture(p.method, p.reqURL) {
		return nil
	}

	protocol := proxy.SOCKS5Protocol(ctx, "HTTP/2")
	tags := proxy.MergeSOCKS5Tags(ctx, nil)

	fl := &flow.Stream{
		ConnID:    p.connID,
		Protocol:  protocol,
		Scheme:    p.scheme,
		State:     "active",
		Timestamp: p.start,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("HTTP/2 flow save failed",
			"method", p.method, "url", p.reqURL.String(), "error", err)
		return nil
	}

	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.method,
		URL:           p.reqURL,
		Headers:       requestHeadersMap(p.headers, p.host),
		Body:          p.reqBody,
		RawBytes:      joinRawFrames(p.rawFrames),
		BodyTruncated: p.reqTruncated,
		Metadata:      buildFrameMetadata(p.rawFrames, nil),
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, recvSequence: 1}
}

// requestSnapshot holds a copy of the request headers and body taken before
// intercept processing. It is used to detect whether modifications occurred
// and, if so, to record the original (unmodified) version as a separate send
// message.
type requestSnapshot struct {
	headers []hpack.HeaderField
	body    []byte
}

// snapshotRequest creates a deep copy of the request headers and body for
// later comparison.
func snapshotRequest(headers []hpack.HeaderField, body []byte) requestSnapshot {
	snap := requestSnapshot{}
	if headers != nil {
		snap.headers = make([]hpack.HeaderField, len(headers))
		copy(snap.headers, headers)
	}
	if body != nil {
		snap.body = make([]byte, len(body))
		copy(snap.body, body)
	}
	return snap
}

// requestModified reports whether the request headers or body have been changed
// relative to the snapshot.
func requestModified(snap requestSnapshot, currentHeaders []hpack.HeaderField, currentBody []byte) bool {
	if !bytes.Equal(snap.body, currentBody) {
		return true
	}
	return hpackHeadersModified(snap.headers, currentHeaders)
}

// hpackHeadersModified reports whether two hpack header field slices differ.
// The comparison is order-independent because both slices may originate from
// gohttp.Header (a map) whose iteration order is non-deterministic.
func hpackHeadersModified(a, b []hpack.HeaderField) bool {
	if len(a) != len(b) {
		return true
	}
	// Build a frequency map of name+value pairs from a, then subtract b.
	freq := make(map[string]int, len(a))
	for _, f := range a {
		freq[f.Name+"\x00"+f.Value]++
	}
	for _, f := range b {
		key := f.Name + "\x00" + f.Value
		freq[key]--
		if freq[key] < 0 {
			return true
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

	if !h.shouldCapture(p.method, p.reqURL) {
		return nil
	}

	// Detect whether modification occurred by comparing against regular headers.
	currentRegular := hpackToRawHeaders(p.headers)
	var currentHpack []hpack.HeaderField
	for _, h := range currentRegular {
		currentHpack = append(currentHpack, hpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	modified := snap != nil && requestModified(*snap, currentHpack, p.reqBody)

	protocol := proxy.SOCKS5Protocol(ctx, "HTTP/2")
	tags := proxy.MergeSOCKS5Tags(ctx, nil)

	fl := &flow.Stream{
		ConnID:    p.connID,
		Protocol:  protocol,
		Scheme:    p.scheme,
		State:     "active",
		Timestamp: p.start,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("HTTP/2 flow save failed",
			"method", p.method, "url", p.reqURL.String(), "error", err)
		return nil
	}

	if modified {
		// Build original headers map from snapshot.
		origHpackHeaders := make([]hpack.HeaderField, len(snap.headers))
		copy(origHpackHeaders, snap.headers)
		if p.host != "" {
			origHpackHeaders = append(origHpackHeaders, hpack.HeaderField{Name: "host", Value: p.host})
		}
		origHeaders := hpackToHeaderMap(origHpackHeaders)
		// Record the original (unmodified) request as sequence 0.
		origMeta := buildFrameMetadata(p.rawFrames, map[string]string{"variant": "original"})
		originalMsg := &flow.Flow{
			StreamID:      fl.ID,
			Sequence:      0,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.method,
			URL:           p.reqURL,
			Headers:       origHeaders,
			Body:          snap.body,
			RawBytes:      joinRawFrames(p.rawFrames),
			BodyTruncated: p.reqTruncated,
			Metadata:      origMeta,
		}
		if err := h.Store.SaveFlow(ctx, originalMsg); err != nil {
			logger.Error("HTTP/2 original send message save failed", "error", err)
		}

		// Record the modified request as sequence 1.
		modifiedMsg := &flow.Flow{
			StreamID:      fl.ID,
			Sequence:      1,
			Direction:     "send",
			Timestamp:     p.start,
			Method:        p.method,
			URL:           p.reqURL,
			Headers:       requestHeadersMap(p.headers, p.host),
			Body:          p.reqBody,
			BodyTruncated: p.reqTruncated,
			Metadata:      map[string]string{"variant": "modified"},
		}
		if err := h.Store.SaveFlow(ctx, modifiedMsg); err != nil {
			logger.Error("HTTP/2 modified send message save failed", "error", err)
		}

		return &sendRecordResult{flowID: fl.ID, recvSequence: 2}
	}

	// No modification: single send message without variant metadata.
	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.method,
		URL:           p.reqURL,
		Headers:       requestHeadersMap(p.headers, p.host),
		Body:          p.reqBody,
		RawBytes:      joinRawFrames(p.rawFrames),
		BodyTruncated: p.reqTruncated,
		Metadata:      buildFrameMetadata(p.rawFrames, nil),
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
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

	statusCode  int
	respHeaders []hpack.HeaderField
	respBody    []byte

	// sendMs is the time in milliseconds to send the request upstream.
	sendMs *int64
	// waitMs is the server processing time in milliseconds (TTFB).
	waitMs *int64
	// receiveMs is the time in milliseconds to receive the response.
	receiveMs *int64

	// rawFrames holds the raw HTTP/2 frame bytes received from the upstream.
	// Each element is the complete wire bytes of one frame (header + payload).
	// These are concatenated into Message.RawBytes for L4 recording.
	rawFrames [][]byte
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
	headers    parser.RawHeaders
	body       []byte
}

// snapshotH2Response creates a deep copy of the h2Response for later comparison.
func snapshotH2Response(resp *h2Response) responseSnapshot {
	snap := responseSnapshot{statusCode: resp.StatusCode}
	if resp.Headers != nil {
		snap.headers = hpackToRawHeaders(resp.Headers)
	}
	if resp.Body != nil {
		snap.body = make([]byte, len(resp.Body))
		copy(snap.body, resp.Body)
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

	var sharedSnap *httputil.ResponseSnapshot
	if snap != nil {
		s := httputil.ResponseSnapshot{
			StatusCode: snap.statusCode,
			Headers:    snap.headers,
			Body:       snap.body,
		}
		sharedSnap = &s
	}

	tags := proxy.MergeSOCKS5Tags(ctx, nil)
	respRawHeaders := hpackToRawHeaders(p.respHeaders)
	tags = httputil.MergeTechnologyTags(tags, h.detector, respRawHeaders, p.respBody)

	httputil.RecordReceiveVariant(ctx, h.Store, httputil.ReceiveVariantParams{
		StreamID:             sendResult.flowID,
		RecvSequence:         sendResult.recvSequence,
		Start:                p.start,
		Duration:             p.duration,
		ServerAddr:           p.serverAddr,
		TLSServerCertSubject: p.tlsServerCertSubject,
		RespStatusCode:       p.statusCode,
		RespHeaders:          respRawHeaders,
		RespBody:             p.respBody,
		RawResponse:          joinRawFrames(p.rawFrames),
		RawResponseMetadata:  buildFrameMetadata(p.rawFrames, nil),
		Tags:                 tags,
		SendMs:               p.sendMs,
		WaitMs:               p.waitMs,
		ReceiveMs:            p.receiveMs,
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
	tags := proxy.MergeSOCKS5Tags(ctx, map[string]string{
		"error": upstreamErr.Error(),
	})
	update := flow.StreamUpdate{
		State:    "error",
		Duration: duration,
		Tags:     tags,
	}
	if err := h.Store.UpdateStream(ctx, sendResult.flowID, update); err != nil {
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

	if !h.shouldCapture(p.method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	protocol := proxy.SOCKS5Protocol(ctx, "HTTP/2")
	tags := proxy.MergeSOCKS5Tags(ctx, nil)

	fl := &flow.Stream{
		ConnID:    p.connID,
		Protocol:  protocol,
		Scheme:    p.scheme,
		State:     "complete",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		BlockedBy: "intercept_drop",
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("HTTP/2 intercept drop flow save failed",
			"method", p.method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.method,
		URL:           p.reqURL,
		Headers:       requestHeadersMap(p.headers, p.host),
		Body:          p.reqBody,
		RawBytes:      joinRawFrames(p.rawFrames),
		BodyTruncated: p.reqTruncated,
		Metadata:      buildFrameMetadata(p.rawFrames, nil),
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
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

	if !h.shouldCapture(p.method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	tags := proxy.MergeSOCKS5Tags(ctx, map[string]string{
		"error": buildErr.Error(),
	})
	fl := &flow.Stream{
		ConnID:    p.connID,
		Protocol:  proxy.SOCKS5Protocol(ctx, "HTTP/2"),
		Scheme:    p.scheme,
		State:     "error",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("HTTP/2 outReq error flow save failed",
			"method", p.method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.method,
		URL:           p.reqURL,
		Headers:       requestHeadersMap(p.headers, p.host),
		Body:          p.reqBody,
		RawBytes:      joinRawFrames(p.rawFrames),
		BodyTruncated: p.reqTruncated,
		Metadata:      buildFrameMetadata(p.rawFrames, nil),
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 outReq error send message save failed", "error", err)
	}
}

// recordBlocked records an HTTP/2 session that was blocked by target scope,
// rate limit, or safety filter. The session is recorded as State="complete"
// with BlockedBy set to the blocking reason, and only a send message (no
// receive). For safety_filter blocks, violation tags (safety_rule,
// safety_target) are added. extraTags are merged into the flow tags
// (e.g., rate limit detail tags).
//
// Valid blockedBy values (consistent with HTTP/1.x recordBlockedSession):
//   - "target_scope"  — request hostname not in the allowed target scope
//   - "safety_filter" — request matched a safety filter block rule
//   - "rate_limit"    — request exceeded the configured rate limit
func (h *Handler) recordBlocked(ctx context.Context, p sendRecordParams, blockedBy string, violation *safety.InputViolation, extraTags map[string]string, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	if !h.shouldCapture(p.method, p.reqURL) {
		return
	}

	duration := time.Since(p.start)
	protocol := proxy.SOCKS5Protocol(ctx, "HTTP/2")
	tags := proxy.MergeSOCKS5Tags(ctx, nil)

	if violation != nil {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags["safety_rule"] = violation.RuleID
		tags["safety_target"] = violation.Target.String()
	}
	for k, v := range extraTags {
		if tags == nil {
			tags = make(map[string]string)
		}
		tags[k] = v
	}

	fl := &flow.Stream{
		ConnID:    p.connID,
		Protocol:  protocol,
		Scheme:    p.scheme,
		State:     "complete",
		Timestamp: p.start,
		Duration:  duration,
		Tags:      tags,
		BlockedBy: blockedBy,
		ConnInfo:  p.connInfo,
	}
	if err := h.Store.SaveStream(ctx, fl); err != nil {
		logger.Error("HTTP/2 blocked flow save failed",
			"blocked_by", blockedBy, "method", p.method, "url", p.reqURL.String(), "error", err)
		return
	}

	sendMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     p.start,
		Method:        p.method,
		URL:           p.reqURL,
		Headers:       requestHeadersMap(p.headers, p.host),
		Body:          p.reqBody,
		RawBytes:      joinRawFrames(p.rawFrames),
		BodyTruncated: p.reqTruncated,
		Metadata:      buildFrameMetadata(p.rawFrames, nil),
	}
	if err := h.Store.SaveFlow(ctx, sendMsg); err != nil {
		logger.Error("HTTP/2 blocked send message save failed", "error", err)
	}
}
