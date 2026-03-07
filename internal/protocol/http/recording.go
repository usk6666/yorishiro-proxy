package http

import (
	"context"
	"log/slog"
	gohttp "net/http"
	"net/url"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
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
// (Session + request message) of an HTTP/HTTPS flow.
type sendRecordParams struct {
	connID     string
	clientAddr string
	protocol   string
	start      time.Time
	tags       map[string]string
	connInfo   *flow.ConnectionInfo

	req          *gohttp.Request
	reqURL       *url.URL
	reqBody      []byte
	rawRequest   []byte
	reqTruncated bool
}

// sendRecordResult holds the flow created by recordSend so that
// subsequent recordReceive or recordSendError calls can reference it.
type sendRecordResult struct {
	flowID string
	// tags holds the original session tags set during recordSend, so that
	// recordSendError can merge error tags with them instead of replacing.
	tags map[string]string
	// recvSequence is the sequence number to use for the receive message.
	// Defaults to 1 (send=0, receive=1). When variant recording produces
	// two send messages (original=0, modified=1), this is set to 2.
	recvSequence int
}

// recordSend records the send phase of a session: creates the flow with
// State="active" and appends the send (request) message. This is called after
// intercept/transform processing but before upstream forwarding, so even if the
// upstream fails, the request is already recorded.
//
// Returns a sendRecordResult containing the flow ID for follow-up calls,
// or nil if recording was skipped (nil store, capture scope miss, etc.).
func (h *Handler) recordSend(ctx context.Context, p sendRecordParams, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = p.req.URL
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return nil
	}

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
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
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, tags: p.tags, recvSequence: 1}
}

// recordSendWithVariant records the send phase with variant support. If the
// request was modified by intercept or transform (detected by comparing
// snap against the current request), it records two send messages:
//   - Sequence 0: original (variant="original") with the snapshot's headers/body
//   - Sequence 1: modified (variant="modified") with the current headers/body
//
// If no modification occurred (snap is nil or headers/body unchanged), this
// behaves identically to recordSend (single send at sequence 0, no variant
// metadata).
//
// The returned sendRecordResult.recvSequence is set accordingly: 2 when
// variant recording produced two messages, 1 otherwise.
func (h *Handler) recordSendWithVariant(ctx context.Context, p sendRecordParams, snap *requestSnapshot, logger *slog.Logger) *sendRecordResult {
	if h.Store == nil {
		return nil
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = p.req.URL
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return nil
	}

	// Detect whether modification occurred.
	modified := snap != nil && requestModified(*snap, p.req.Header, p.reqBody)

	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
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
			URL:           reqURL,
			Headers:       origHeaders,
			Body:          snap.body,
			RawBytes:      p.rawRequest,
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
			Headers:       requestHeaders(p.req),
			Body:          p.reqBody,
			RawBytes:      nil, // modified is not wire-observed
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
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("send message save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, tags: p.tags, recvSequence: 1}
}

// receiveRecordParams holds the parameters needed to record the receive phase
// (response message + session completion) of an HTTP/HTTPS flow.
type receiveRecordParams struct {
	start      time.Time
	duration   time.Duration
	serverAddr string

	// tlsServerCertSubject is the subject DN of the upstream server's TLS
	// certificate. Only set for HTTPS connections.
	tlsServerCertSubject string

	resp        *gohttp.Response
	rawResponse []byte
	respBody    []byte
}

// recordReceive records the receive phase of a session: appends the receive
// (response) message and updates the flow to State="complete". This is called
// after the response has been written to the client.
//
// If sendResult is nil (recording was skipped in recordSend), this is a no-op.
func (h *Handler) recordReceive(ctx context.Context, sendResult *sendRecordResult, p receiveRecordParams, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	if p.resp == nil {
		return
	}

	// Decompress response body for recording. The raw (potentially compressed)
	// bytes are preserved in rawResponse for wire-level analysis.
	recordRespBody := p.respBody
	var respTruncated bool
	decompressed := false
	if ce := p.resp.Header.Get("Content-Encoding"); ce != "" {
		decoded, err := httputil.DecompressBody(p.respBody, ce, config.MaxBodySize)
		if err != nil {
			logger.Debug("response body decompression failed, storing as-is", "encoding", ce, "error", err)
		} else {
			recordRespBody = decoded
			decompressed = true
		}
	}
	if len(recordRespBody) > int(config.MaxBodySize) {
		recordRespBody = recordRespBody[:int(config.MaxBodySize)]
		respTruncated = true
	}

	recvMsg := &flow.Message{
		FlowID:        sendResult.flowID,
		Sequence:      sendResult.recvSequence,
		Direction:     "receive",
		Timestamp:     p.start.Add(p.duration),
		StatusCode:    p.resp.StatusCode,
		Headers:       httputil.RecordingHeaders(p.resp.Header, decompressed, len(recordRespBody)),
		Body:          recordRespBody,
		RawBytes:      p.rawResponse,
		BodyTruncated: respTruncated,
	}
	if err := h.Store.AppendMessage(ctx, recvMsg); err != nil {
		logger.Error("receive message save failed", "error", err)
	}

	// Update the flow to complete with the final duration and server address.
	update := flow.FlowUpdate{
		State:      "complete",
		Duration:   p.duration,
		ServerAddr: p.serverAddr,
	}
	if p.tlsServerCertSubject != "" {
		update.TLSServerCertSubject = p.tlsServerCertSubject
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("flow update failed", "error", err)
	}
}

// recordSendError updates a flow to State="error" after an upstream failure.
// The send message is already recorded by recordSend; this only updates the
// flow metadata.
//
// If sendResult is nil (recording was skipped in recordSend), this is a no-op.
func (h *Handler) recordSendError(ctx context.Context, sendResult *sendRecordResult, start time.Time, upstreamErr error, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	duration := time.Since(start)
	// Merge the error tag with any existing tags (e.g., smuggling detection)
	// from the send phase to avoid silently discarding them.
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

// recordInterceptDrop records a flow where the request was dropped by an
// intercept rule. The session is recorded as State="complete" with
// BlockedBy="intercept_drop" and only a send message (no receive).
func (h *Handler) recordInterceptDrop(ctx context.Context, p sendRecordParams, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	reqURL := p.reqURL
	if reqURL == nil {
		reqURL = p.req.URL
	}

	if !h.shouldCapture(p.req.Method, reqURL) {
		return
	}

	duration := time.Since(p.start)
	fl := &flow.Flow{
		ConnID:    p.connID,
		Protocol:  p.protocol,
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
		Headers:       requestHeaders(p.req),
		Body:          p.reqBody,
		RawBytes:      p.rawRequest,
		BodyTruncated: p.reqTruncated,
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		logger.Error("intercept drop send message save failed", "error", err)
	}
}

// sessionRecordParams holds all the parameters needed to record an HTTP/HTTPS
// session and its request/response messages to the flow store.
//
// Deprecated: This type is retained for backward compatibility with existing
// tests. New code should use the progressive recording functions (recordSend +
// recordReceive) directly.
type sessionRecordParams struct {
	// Session-level fields
	connID     string
	clientAddr string
	serverAddr string
	protocol   string
	start      time.Time
	duration   time.Duration
	tags       map[string]string
	connInfo   *flow.ConnectionInfo

	// Request fields
	req          *gohttp.Request
	reqURL       *url.URL
	reqBody      []byte
	rawRequest   []byte
	reqTruncated bool

	// Response fields
	resp        *gohttp.Response
	rawResponse []byte
	respBody    []byte
}

// recordHTTPSession records a complete HTTP/HTTPS session (request + response)
// to the flow store in a single call. It delegates to the progressive
// recording functions (recordSend + recordReceive) internally.
//
// Deprecated: This method is retained for backward compatibility with existing
// tests. Production code uses the progressive recording pattern directly.
func (h *Handler) recordHTTPSession(ctx context.Context, p sessionRecordParams, logger *slog.Logger) {
	sp := sendRecordParams{
		connID:       p.connID,
		clientAddr:   p.clientAddr,
		protocol:     p.protocol,
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

// socks5Protocol returns the protocol string with a "SOCKS5+" prefix if the
// request arrived through a SOCKS5 tunnel (detected via context metadata).
// For example, "HTTPS" becomes "SOCKS5+HTTPS" and "HTTP/1.x" becomes "SOCKS5+HTTP".
func socks5Protocol(ctx context.Context, base string) string {
	if proxy.SOCKS5TargetFromContext(ctx) != "" {
		switch base {
		case "HTTP/1.x":
			return "SOCKS5+HTTP"
		default:
			return "SOCKS5+" + base
		}
	}
	return base
}

// mergeSOCKS5Tags adds SOCKS5 metadata tags to the given tags map if the
// request arrived through a SOCKS5 tunnel. If tags is nil, a new map is
// created. Returns the (possibly new) tags map.
func mergeSOCKS5Tags(ctx context.Context, tags map[string]string) map[string]string {
	target := proxy.SOCKS5TargetFromContext(ctx)
	if target == "" {
		return tags
	}
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["socks5_target"] = target
	if authMethod := proxy.SOCKS5AuthMethodFromContext(ctx); authMethod != "" {
		tags["socks5_auth_method"] = authMethod
	}
	if authUser := proxy.SOCKS5AuthUserFromContext(ctx); authUser != "" {
		tags["socks5_auth_user"] = authUser
	}
	return tags
}
