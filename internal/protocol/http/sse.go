package http

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// sseMaxStreamDuration is the maximum duration an SSE stream can remain open.
// This is a safety net to prevent indefinite resource consumption if the
// upstream server never closes the connection. The value is intentionally
// long (24 hours) to accommodate legitimate long-lived SSE streams while
// still providing a resource consumption bound.
const sseMaxStreamDuration = 24 * time.Hour

// isSSEResponse checks if the HTTP response is a Server-Sent Events stream
// by examining the Content-Type header. SSE responses use the MIME type
// "text/event-stream" as defined in the HTML Living Standard.
func isSSEResponse(resp *gohttp.Response) bool {
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		return false
	}
	// Parse out the media type, ignoring parameters like charset.
	mediaType := ct
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		mediaType = ct[:idx]
	}
	return strings.TrimSpace(strings.ToLower(mediaType)) == "text/event-stream"
}

// addSSETags adds the streaming_type=sse tag to the given tags map.
// If tags is nil, a new map is created. Returns the (possibly new) tags map.
func addSSETags(tags map[string]string) map[string]string {
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["streaming_type"] = "sse"
	return tags
}

// sseHookContext holds the plugin hook context for SSE stream processing.
// This carries the plugin ConnInfo and transaction context through to the
// SSE handler so that on_receive_from_server and on_before_send_to_client
// hooks can be dispatched at the header level and per-event level.
type sseHookContext struct {
	connInfo *plugin.ConnInfo
	txCtx    map[string]any
}

// sseStreamContext carries all context needed for event-level processing
// within the SSE event loop (streamSSEEvents). It holds the original HTTP
// request (for intercept rule matching) and the plugin hook context (for
// per-event plugin dispatch).
type sseStreamContext struct {
	req     *gohttp.Request
	hookCtx *sseHookContext
}

// handleSSEStream handles Server-Sent Events responses by writing the response
// headers to the client and then streaming events from upstream, forwarding
// each to the client while recording them as flow.Message entries.
//
// Each SSE event is parsed, forwarded to the client, and recorded as a
// separate flow.Message with direction="receive". This follows the same
// progressive recording pattern used by WebSocket frame recording.
//
// Before writing response headers, this function applies:
//   - Plugin hook: on_receive_from_server (header-level, no body)
//   - Response intercept check (header-level, DROP or RELEASE)
//   - Plugin hook: on_before_send_to_client (header-level, no body)
//
// Output filter (PII masking) is applied per-event to the SSE data field
// before forwarding to the client. If a block-action rule matches, the
// stream is terminated. Flow recording always stores the original (unfiltered)
// event data.
//
// NOTE: The following processing steps are intentionally skipped for SSE streams
// because they require the full response body to be buffered in memory:
//   - Response auto-transform rules
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStream(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, hookCtx *sseHookContext, logger *slog.Logger) error {
	// Plugin hook: on_receive_from_server — header-level dispatch for SSE.
	// Body is nil since the SSE body is a stream that cannot be buffered.
	if hookCtx != nil {
		fwd.resp, _ = h.dispatchOnReceiveFromServer(ctx, fwd.resp, nil, req, hookCtx.connInfo, hookCtx.txCtx, logger)
	}

	// Response intercept: check if the SSE response matches any intercept
	// rules at the header level. For SSE, only DROP and RELEASE are meaningful;
	// MODIFY is not supported since the body is a stream.
	if dropped := h.applySSEIntercept(ctx, conn, req, fwd.resp, logger); dropped {
		// Update flow to complete state so it does not remain "active" forever.
		h.completeSSEFlowOnDrop(ctx, sendResult, fwd, start, "", logger)
		return nil
	}

	// Plugin hook: on_before_send_to_client — header-level dispatch for SSE.
	// Body is nil since the SSE body is a stream that cannot be buffered.
	if hookCtx != nil {
		fwd.resp, _ = h.dispatchOnBeforeSendToClient(ctx, fwd.resp, nil, req, hookCtx.connInfo, hookCtx.txCtx, logger)
	}

	// Write the response headers to the client.
	if err := writeSSEResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	logger.Info("SSE stream started", "method", req.Method, "url", req.URL.String())

	// Record the initial receive message (response headers) and update flow
	// type to "stream" for SSE event-level recording.
	h.recordSSEReceive(ctx, sendResult, fwd, start, "", logger)

	// Apply maximum stream duration to prevent indefinite resource consumption.
	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	// Stream and record SSE events from upstream to client.
	var eventSeq atomic.Int64
	// Start event sequence after the receive header message.
	eventSeq.Store(int64(sendResult.recvSequence) + 1)

	sseCtx := &sseStreamContext{req: req, hookCtx: hookCtx}
	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, sseCtx, logger)

	// Update flow to complete state with final duration.
	duration := time.Since(start)
	h.completeSSEFlow(ctx, sendResult, fwd, duration, "", &eventSeq, logger)

	if streamErr != nil && ctx.Err() == nil {
		logger.Debug("SSE stream ended", "method", req.Method, "url", req.URL.String(), "error", streamErr)
	} else {
		logger.Info("SSE stream ended", "method", req.Method, "url", req.URL.String(), "duration_ms", duration.Milliseconds())
	}

	return nil
}

// handleSSEStreamTLS handles SSE responses in the HTTPS MITM path. It uses
// the same streaming approach as handleSSEStream but includes TLS certificate
// information in the flow recording.
//
// Before writing response headers, this function applies:
//   - Response intercept check (header-level, DROP or RELEASE)
//
// Note: Per-event plugin hooks (on_receive_from_server, on_before_send_to_client)
// are NOT dispatched in the TLS path because hookCtx is not propagated from the
// CONNECT tunnel handler. Event-level intercept and variant tracking still work.
// This is a known limitation; extending plugin hooks to the TLS SSE path requires
// plumbing ConnInfo through the CONNECT handler.
//
// See handleSSEStream for details on output filter application and skipped
// processing steps.
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStreamTLS(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
	// Extract TLS certificate info from the upstream connection.
	var tlsCertSubject string
	if fwd.resp.TLS != nil && len(fwd.resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = fwd.resp.TLS.PeerCertificates[0].Subject.String()
	}

	// Response intercept: check if the SSE response matches any intercept
	// rules at the header level. Same as handleSSEStream.
	if dropped := h.applySSEIntercept(ctx, conn, req, fwd.resp, logger); dropped {
		// Update flow to complete state so it does not remain "active" forever.
		h.completeSSEFlowOnDrop(ctx, sendResult, fwd, start, tlsCertSubject, logger)
		return nil
	}

	// Write the response headers to the client.
	if err := writeSSEResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	logger.Info("SSE stream started (TLS)", "method", req.Method, "url", req.URL.String())

	// Record the initial receive message (response headers) and update flow
	// type to "stream" for SSE event-level recording.
	h.recordSSEReceive(ctx, sendResult, fwd, start, tlsCertSubject, logger)

	// Apply maximum stream duration to prevent indefinite resource consumption.
	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	// Stream and record SSE events from upstream to client.
	var eventSeq atomic.Int64
	eventSeq.Store(int64(sendResult.recvSequence) + 1)

	sseCtx := &sseStreamContext{req: req}
	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, sseCtx, logger)

	// Update flow to complete state with final duration.
	duration := time.Since(start)
	h.completeSSEFlow(ctx, sendResult, fwd, duration, tlsCertSubject, &eventSeq, logger)

	if streamErr != nil && ctx.Err() == nil {
		logger.Debug("SSE stream ended (TLS)", "method", req.Method, "url", req.URL.String(), "error", streamErr)
	} else {
		logger.Info("SSE stream ended (TLS)", "method", req.Method, "url", req.URL.String(), "duration_ms", duration.Milliseconds())
	}

	return nil
}

// writeSSEResponseHeaders writes the HTTP response status line and headers to
// the client connection without buffering the body. This allows the client to
// begin processing SSE events as they arrive.
func writeSSEResponseHeaders(conn net.Conn, resp *gohttp.Response) error {
	w := bufio.NewWriter(conn)
	if _, err := fmt.Fprintf(w, "HTTP/%d.%d %d %s\r\n",
		resp.ProtoMajor, resp.ProtoMinor,
		resp.StatusCode, gohttp.StatusText(resp.StatusCode)); err != nil {
		return err
	}
	for key, vals := range resp.Header {
		for _, val := range vals {
			if _, err := fmt.Fprintf(w, "%s: %s\r\n", key, val); err != nil {
				return err
			}
		}
	}
	if _, err := fmt.Fprintf(w, "\r\n"); err != nil {
		return err
	}
	return w.Flush()
}

// errSSEOutputFilterBlocked is returned when an output filter rule with
// action=block matches an SSE event's data, causing the stream to be
// terminated.
var errSSEOutputFilterBlocked = errors.New("SSE stream blocked by output filter")

// streamSSEEvents reads SSE events from src, processes each event through
// the intercept / plugin / output-filter pipeline, and forwards it to the
// client connection. Each event is also recorded as a flow.Message.
// It respects context cancellation by setting a write deadline on the connection.
//
// Processing order for each event:
//  1. parser.Next() — parse event
//  2. on_receive_from_server plugin hook — event received
//  3. Snapshot (for variant tracking)
//  4. Intercept check → hold → AI decision → release/drop/modify
//  5. on_before_send_to_client plugin hook — before forwarding
//  6. Record event (raw data + variant if modified)
//  7. Output filter (PII masking) — applied to data sent to client
//  8. Forward to client
//
// The sseCtx parameter carries the original HTTP request (for intercept rule
// matching), plugin hook context, and the destination connection. It may be
// nil, in which case intercept and plugin hooks are skipped.
//
// Recording stops after config.MaxSSEEventsPerStream events to prevent
// unbounded DB growth, but forwarding (with filtering) continues.
func (h *Handler) streamSSEEvents(ctx context.Context, dst net.Conn, src io.Reader, flowID string, seq *atomic.Int64, sseCtx *sseStreamContext, logger *slog.Logger) error {
	// Watch for context cancellation and interrupt blocking reads.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			dst.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	parser := NewSSEParser(src, config.MaxSSEEventSize)
	var eventCount int
	var recordingDisabled bool

	for {
		select {
		case <-ctx.Done():
			dst.SetWriteDeadline(time.Time{})
			return ctx.Err()
		default:
		}

		event, err := parser.Next()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			if ctx.Err() != nil {
				dst.SetWriteDeadline(time.Time{})
				return ctx.Err()
			}
			return fmt.Errorf("SSE parse: %w", err)
		}

		// Step 1: Plugin hook — on_receive_from_server (event-level).
		event = h.dispatchSSEOnReceiveFromServer(ctx, event, sseCtx, logger)

		// Step 2: Snapshot for variant tracking (before intercept/plugin modifications).
		snap := snapshotSSEEvent(event)

		// Step 3: Intercept check — hold → AI decision → release/drop/modify.
		event, dropped := h.applySSEEventIntercept(ctx, event, flowID, sseCtx, logger)
		if dropped {
			// Event was dropped. Skip forwarding and recording, continue to next event.
			logger.Info("SSE event dropped by intercept",
				"flow_id", flowID,
				"event_type", snap.eventType)
			continue
		}

		// Step 4: Plugin hook — on_before_send_to_client (event-level).
		event = h.dispatchSSEOnBeforeSendToClient(ctx, event, sseCtx, logger)

		// Step 5: Record the event as a flow message (always with original data).
		// If the event was modified by intercept or plugin, record both versions.
		eventCount++
		if !recordingDisabled {
			if eventCount > config.MaxSSEEventsPerStream {
				logger.Info("SSE event recording limit reached, forwarding only",
					"flow_id", flowID,
					"limit", config.MaxSSEEventsPerStream)
				recordingDisabled = true
			} else {
				h.recordSSEEventWithVariant(ctx, flowID, event, &snap, seq, logger)
			}
		}

		// Step 6: Apply output filter to the event data before forwarding.
		sendBytes, blocked := h.applySSEOutputFilter(event, logger)
		if blocked {
			logger.Warn("SSE stream terminated by output filter (action=block)",
				"flow_id", flowID,
				"event_type", event.EventType)
			return errSSEOutputFilterBlocked
		}

		// Step 7: Forward the (possibly filtered) event bytes to the client.
		if _, writeErr := dst.Write(sendBytes); writeErr != nil {
			if ctx.Err() != nil {
				dst.SetWriteDeadline(time.Time{})
				return ctx.Err()
			}
			return fmt.Errorf("SSE write to client: %w", writeErr)
		}
	}
}

// sseEventSnapshot holds a copy of SSE event data before intercept/plugin
// processing, used for variant tracking.
type sseEventSnapshot struct {
	eventType string
	data      string
	id        string
	retry     string
}

// snapshotSSEEvent creates a snapshot of the SSE event for variant tracking.
func snapshotSSEEvent(event *SSEEvent) sseEventSnapshot {
	return sseEventSnapshot{
		eventType: event.EventType,
		data:      event.Data,
		id:        event.ID,
		retry:     event.Retry,
	}
}

// sseEventModified reports whether the SSE event was changed relative to the
// snapshot taken before intercept/plugin processing.
func sseEventModified(snap sseEventSnapshot, event *SSEEvent) bool {
	return snap.eventType != event.EventType ||
		snap.data != event.Data ||
		snap.id != event.ID ||
		snap.retry != event.Retry
}

// dispatchSSEOnReceiveFromServer dispatches the on_receive_from_server plugin
// hook for a single SSE event. The event data is passed as the response body,
// and event metadata (event type, id, retry) is passed as headers.
// Returns the (possibly modified) event.
func (h *Handler) dispatchSSEOnReceiveFromServer(ctx context.Context, event *SSEEvent, sseCtx *sseStreamContext, logger *slog.Logger) *SSEEvent {
	if h.pluginEngine == nil || sseCtx == nil || sseCtx.hookCtx == nil {
		return event
	}

	resp, body := sseEventToHTTPResponse(event)
	resp, body = h.dispatchOnReceiveFromServer(ctx, resp, body, sseCtx.req, sseCtx.hookCtx.connInfo, sseCtx.hookCtx.txCtx, logger)
	return applyHTTPResponseToSSEEvent(event, resp, body)
}

// dispatchSSEOnBeforeSendToClient dispatches the on_before_send_to_client plugin
// hook for a single SSE event. Same mapping as dispatchSSEOnReceiveFromServer.
// Returns the (possibly modified) event.
func (h *Handler) dispatchSSEOnBeforeSendToClient(ctx context.Context, event *SSEEvent, sseCtx *sseStreamContext, logger *slog.Logger) *SSEEvent {
	if h.pluginEngine == nil || sseCtx == nil || sseCtx.hookCtx == nil {
		return event
	}

	resp, body := sseEventToHTTPResponse(event)
	resp, body = h.dispatchOnBeforeSendToClient(ctx, resp, body, sseCtx.req, sseCtx.hookCtx.connInfo, sseCtx.hookCtx.txCtx, logger)
	return applyHTTPResponseToSSEEvent(event, resp, body)
}

// sseEventToHTTPResponse converts an SSE event into a synthetic HTTP response
// suitable for passing to plugin hooks. The event data is the response body,
// and event metadata (event type, id, retry) is encoded as pseudo-headers
// with an "X-SSE-" prefix.
func sseEventToHTTPResponse(event *SSEEvent) (*gohttp.Response, []byte) {
	headers := gohttp.Header{}
	headers.Set("Content-Type", "text/event-stream")
	if event.EventType != "" {
		headers.Set("X-SSE-Event", event.EventType)
	}
	if event.ID != "" {
		headers.Set("X-SSE-Id", event.ID)
	}
	if event.Retry != "" {
		headers.Set("X-SSE-Retry", event.Retry)
	}

	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     headers,
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	return resp, []byte(event.Data)
}

// applyHTTPResponseToSSEEvent applies changes from a plugin-modified HTTP
// response back to the SSE event. If the response body or metadata headers
// changed, the event is updated accordingly. RawBytes is regenerated for the
// modified event.
func applyHTTPResponseToSSEEvent(original *SSEEvent, resp *gohttp.Response, body []byte) *SSEEvent {
	if resp == nil {
		return original
	}

	newEvent := &SSEEvent{
		EventType: original.EventType,
		Data:      original.Data,
		ID:        original.ID,
		Retry:     original.Retry,
		RawBytes:  original.RawBytes,
	}

	// Update fields only when the plugin actually set them.
	// body=nil means "no change"; header key absent means "no change".
	if body != nil {
		newEvent.Data = string(body)
	}
	if vals, ok := resp.Header["X-Sse-Event"]; ok {
		if len(vals) > 0 {
			newEvent.EventType = vals[0]
		} else {
			newEvent.EventType = ""
		}
	}
	if vals, ok := resp.Header["X-Sse-Id"]; ok {
		if len(vals) > 0 {
			newEvent.ID = vals[0]
		} else {
			newEvent.ID = ""
		}
	}
	if vals, ok := resp.Header["X-Sse-Retry"]; ok {
		if len(vals) > 0 {
			newEvent.Retry = vals[0]
		} else {
			newEvent.Retry = ""
		}
	}

	// Regenerate RawBytes if the event content changed.
	if newEvent.EventType != original.EventType ||
		newEvent.Data != original.Data ||
		newEvent.ID != original.ID ||
		newEvent.Retry != original.Retry {
		newEvent.RawBytes = []byte(newEvent.String())
	}

	return newEvent
}

// applySSEEventIntercept checks if the SSE event matches any intercept rules
// and, if so, enqueues it for AI agent review. The event data is sent as the
// response body, and event metadata is encoded as headers.
//
// For SSE events, all three actions are supported:
//   - Release: event is forwarded unchanged
//   - Drop: event is skipped (not forwarded to client)
//   - ModifyAndForward: event fields are updated from the action's response
//     modification fields
//
// Returns the (possibly modified) event and true if dropped.
func (h *Handler) applySSEEventIntercept(ctx context.Context, event *SSEEvent, flowID string, sseCtx *sseStreamContext, logger *slog.Logger) (*SSEEvent, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil || sseCtx == nil || sseCtx.req == nil {
		return event, false
	}

	// Build synthetic response headers for rule matching.
	// We use the real response headers (Content-Type: text/event-stream) plus
	// SSE metadata for matching. The intercept rules match on response status
	// code and headers.
	matchHeaders := gohttp.Header{}
	matchHeaders.Set("Content-Type", "text/event-stream")
	if event.EventType != "" {
		matchHeaders.Set("X-SSE-Event", event.EventType)
	}
	if event.ID != "" {
		matchHeaders.Set("X-SSE-Id", event.ID)
	}
	if event.Retry != "" {
		matchHeaders.Set("X-SSE-Retry", event.Retry)
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(200, httpHeaderToRawHeaders(matchHeaders))
	if len(matchedRules) == 0 {
		return event, false
	}

	logger.Info("SSE event intercepted",
		"flow_id", flowID,
		"event_type", event.EventType,
		"matched_rules", matchedRules)

	// Build the body to enqueue. For intercept display, apply output filter
	// so the AI sees masked data (USK-368 pattern).
	eventBody := []byte(event.Data)
	filteredBody := h.filterSSEEventBodyForIntercept(eventBody, logger)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		sseCtx.req.Method, sseCtx.req.URL, 200, httpHeaderToRawHeaders(matchHeaders), filteredBody, matchedRules,
	)
	defer h.InterceptQueue.Remove(id)

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var action intercept.InterceptAction
	select {
	case action = <-actionCh:
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			logger.Info("intercepted SSE event cancelled (proxy shutdown)", "id", id)
			action = intercept.InterceptAction{Type: intercept.ActionDrop}
		} else {
			logger.Info("intercepted SSE event timed out", "id", id, "behavior", string(behavior))
			switch behavior {
			case intercept.TimeoutAutoDrop:
				action = intercept.InterceptAction{Type: intercept.ActionDrop}
			default:
				action = intercept.InterceptAction{Type: intercept.ActionRelease}
			}
		}
	}

	switch action.Type {
	case intercept.ActionDrop:
		return event, true
	case intercept.ActionModifyAndForward:
		modified := applySSEEventModifications(event, action)
		return modified, false
	default:
		// ActionRelease or unknown: continue with original event.
		return event, false
	}
}

// filterSSEEventBodyForIntercept applies the safety engine's output filter to
// the event body for display in the intercept queue. This ensures the AI sees
// masked data (USK-368 pattern). Returns the filtered body, or the original
// body if no filter is configured.
func (h *Handler) filterSSEEventBodyForIntercept(body []byte, logger *slog.Logger) []byte {
	if h.SafetyEngine == nil || len(h.SafetyEngine.OutputRules()) == 0 {
		return body
	}

	result := h.SafetyEngine.FilterOutput(body)
	if result.Masked {
		return result.Data
	}
	return body
}

// applySSEEventModifications applies modify_and_forward modifications from an
// intercept action to an SSE event. It uses the response modification fields:
//   - OverrideResponseBody: replaces the event Data
//   - OverrideResponseHeaders: can set X-SSE-Event, X-SSE-Id, X-SSE-Retry
//   - AddResponseHeaders: same as override for SSE pseudo-headers
//
// Returns a new SSEEvent with the modifications applied.
func applySSEEventModifications(event *SSEEvent, action intercept.InterceptAction) *SSEEvent {
	modified := &SSEEvent{
		EventType: event.EventType,
		Data:      event.Data,
		ID:        event.ID,
		Retry:     event.Retry,
	}

	// Apply body override.
	if action.OverrideResponseBody != nil {
		modified.Data = *action.OverrideResponseBody
	}

	// Apply header overrides for SSE metadata.
	for key, val := range action.OverrideResponseHeaders {
		switch gohttp.CanonicalHeaderKey(key) {
		case "X-Sse-Event":
			modified.EventType = val
		case "X-Sse-Id":
			modified.ID = val
		case "X-Sse-Retry":
			modified.Retry = val
		}
	}

	// Apply added headers for SSE metadata.
	for key, val := range action.AddResponseHeaders {
		switch gohttp.CanonicalHeaderKey(key) {
		case "X-Sse-Event":
			modified.EventType = val
		case "X-Sse-Id":
			modified.ID = val
		case "X-Sse-Retry":
			modified.Retry = val
		}
	}

	// Regenerate RawBytes for the modified event.
	modified.RawBytes = []byte(modified.String())
	return modified
}

// recordSSEEventWithVariant records a single SSE event as a flow.Message,
// including variant tracking if the event was modified by intercept or plugin.
// When the event was modified, two messages are recorded:
//   - Sequence N:   original (variant="original") with the snapshot data
//   - Sequence N+1: modified (variant="modified") with the current event data
//
// When no modification occurred, a single message is recorded without variant
// metadata (same as the original recordSSEEvent behavior).
func (h *Handler) recordSSEEventWithVariant(ctx context.Context, flowID string, event *SSEEvent, snap *sseEventSnapshot, seq *atomic.Int64, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	modified := snap != nil && sseEventModified(*snap, event)

	if modified {
		// Record the original (unmodified) event.
		origEvent := &SSEEvent{
			EventType: snap.eventType,
			Data:      snap.data,
			ID:        snap.id,
			Retry:     snap.retry,
		}
		origEvent.RawBytes = []byte(origEvent.String())

		origSeq := int(seq.Add(1) - 1)
		origMsg := buildSSEEventMessage(flowID, origSeq, origEvent)
		origMsg.Metadata["variant"] = "original"
		if err := h.Store.AppendMessage(ctx, origMsg); err != nil {
			logger.Error("SSE original event message save failed",
				"flow_id", flowID,
				"sequence", origSeq,
				"error", err,
			)
		}

		// Record the modified event.
		modSeq := int(seq.Add(1) - 1)
		modMsg := buildSSEEventMessage(flowID, modSeq, event)
		modMsg.Metadata["variant"] = "modified"
		if err := h.Store.AppendMessage(ctx, modMsg); err != nil {
			logger.Error("SSE modified event message save failed",
				"flow_id", flowID,
				"sequence", modSeq,
				"error", err,
			)
		}
	} else {
		// No modification: single event message without variant metadata.
		h.recordSSEEvent(ctx, flowID, event, seq, logger)
	}
}

// streamSSEBody copies the SSE body from upstream to the client connection.
// It respects context cancellation by closing the done channel which triggers
// the context watcher to set a read deadline on the connection.
//
// Deprecated: This function is retained for backward compatibility with existing
// tests. Production code uses streamSSEEvents for event-level recording.
func streamSSEBody(ctx context.Context, dst net.Conn, src io.Reader) error {
	// Watch for context cancellation and interrupt blocking reads.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			// Interrupt the io.Copy by setting a deadline on the destination.
			dst.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	_, err := io.Copy(dst, src)
	if ctx.Err() != nil {
		// Reset the write deadline so the connection can be reused
		// for keep-alive if applicable.
		dst.SetWriteDeadline(time.Time{})
		return ctx.Err()
	}
	return err
}

// applySSEOutputFilter applies the safety engine's output filter rules to an
// SSE event's Data field. It returns the bytes to send to the client and
// whether a block-action rule was matched.
//
// When no safety engine is configured or no rules match, the original
// event.RawBytes are returned unchanged. When a mask-action rule matches,
// the event is reconstructed with masked data. When a block-action rule
// matches, blocked is true and the returned bytes are nil.
func (h *Handler) applySSEOutputFilter(event *SSEEvent, logger *slog.Logger) (sendBytes []byte, blocked bool) {
	if h.SafetyEngine == nil || len(h.SafetyEngine.OutputRules()) == 0 {
		return event.RawBytes, false
	}

	result := h.SafetyEngine.FilterOutput([]byte(event.Data))

	// Log matches for observability.
	for _, m := range result.Matches {
		logger.Info("SSE output filter matched event data",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String(),
			"event_type", event.EventType)

		if m.Action == safety.ActionBlock {
			return nil, true
		}
	}

	// If data was masked, reconstruct the event with filtered data.
	if result.Masked {
		filtered := &SSEEvent{
			EventType: event.EventType,
			Data:      string(result.Data),
			ID:        event.ID,
			Retry:     event.Retry,
		}
		return []byte(filtered.String()), false
	}

	return event.RawBytes, false
}

// applySSEIntercept checks if the SSE response matches any intercept rules at
// the header level. For SSE streams, only DROP and RELEASE are meaningful since
// the response body is a stream that cannot be buffered for modification.
// Returns true if the response was dropped (caller should return early).
func (h *Handler) applySSEIntercept(ctx context.Context, conn net.Conn, req *gohttp.Request, resp *gohttp.Response, logger *slog.Logger) bool {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return false
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, httpHeaderToRawHeaders(resp.Header))
	if len(matchedRules) == 0 {
		return false
	}

	logger.Info("SSE response intercepted (header-level)",
		"method", req.Method,
		"url", req.URL.String(),
		"status", resp.StatusCode,
		"matched_rules", matchedRules)

	// Enqueue with nil body since SSE body is a stream.
	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, req.URL, resp.StatusCode, httpHeaderToRawHeaders(resp.Header), nil, matchedRules,
	)
	defer h.InterceptQueue.Remove(id)

	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	var action intercept.InterceptAction
	select {
	case action = <-actionCh:
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if ctx.Err() != nil {
			logger.Info("intercepted SSE response cancelled (proxy shutdown)", "id", id)
			action = intercept.InterceptAction{Type: intercept.ActionDrop}
		} else {
			logger.Info("intercepted SSE response timed out", "id", id, "behavior", string(behavior))
			switch behavior {
			case intercept.TimeoutAutoDrop:
				action = intercept.InterceptAction{Type: intercept.ActionDrop}
			default:
				action = intercept.InterceptAction{Type: intercept.ActionRelease}
			}
		}
	}

	switch action.Type {
	case intercept.ActionDrop:
		httputil.WriteHTTPError(conn, gohttp.StatusBadGateway, logger)
		logger.Info("intercepted SSE response dropped",
			"method", req.Method, "url", req.URL.String(), "status", resp.StatusCode)
		return true
	case intercept.ActionModifyAndForward:
		// ModifyAndForward is not supported for SSE streams since the body
		// is a stream. Treat as release and log a warning.
		logger.Warn("SSE response intercept modify_and_forward not supported, releasing",
			"method", req.Method, "url", req.URL.String())
		return false
	default:
		// ActionRelease or unknown: continue with normal processing.
		return false
	}
}

// recordSSEReceive records the initial receive phase for an SSE flow.
// This records the response headers as the first receive message and updates
// the flow type to "stream" to indicate event-level recording.
// The tlsCertSubject is empty for non-TLS connections.
func (h *Handler) recordSSEReceive(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, start time.Time, tlsCertSubject string, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	if fwd.resp == nil {
		return
	}

	// Merge SSE tags with existing tags from the send phase.
	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags = addSSETags(tags)

	// Update flow with SSE tags and stream flow type. State remains "active"
	// since events are still being recorded. Duration and completion state
	// are set by completeSSEFlow when the stream ends.
	update := flow.FlowUpdate{
		State:                "active",
		FlowType:             "stream",
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow update failed", "error", err)
	}

	// Record receive message with headers only (no body).
	recvMsg := &flow.Message{
		FlowID:     sendResult.flowID,
		Sequence:   sendResult.recvSequence,
		Direction:  "receive",
		Timestamp:  start,
		StatusCode: fwd.resp.StatusCode,
		Headers:    fwd.resp.Header,
		Metadata: map[string]string{
			"sse_type": "headers",
		},
	}
	if err := h.Store.AppendMessage(ctx, recvMsg); err != nil {
		logger.Error("SSE receive message save failed", "error", err)
	}
}

// completeSSEFlow updates the SSE flow to "complete" state with the final
// duration and event count.
func (h *Handler) completeSSEFlow(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, duration time.Duration, tlsCertSubject string, eventSeq *atomic.Int64, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	// Merge SSE tags with existing tags from the send phase.
	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags = addSSETags(tags)

	// Calculate the number of events recorded.
	// eventSeq starts at recvSequence+1, so the count is currentSeq - (recvSequence+1).
	eventsRecorded := int(eventSeq.Load()) - sendResult.recvSequence - 1
	if eventsRecorded > 0 {
		tags["sse_events_recorded"] = strconv.Itoa(eventsRecorded)
	}

	update := flow.FlowUpdate{
		State:                "complete",
		Duration:             duration,
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow completion failed", "error", err)
	}
}

// completeSSEFlowOnDrop updates the SSE flow to "complete" state when the
// response was intercepted and dropped. This prevents flows from remaining
// in "active" state indefinitely after a DROP action.
func (h *Handler) completeSSEFlowOnDrop(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, start time.Time, tlsCertSubject string, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	duration := time.Since(start)

	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags = addSSETags(tags)
	tags["intercept_action"] = "drop"

	update := flow.FlowUpdate{
		State:                "complete",
		Duration:             duration,
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateFlow(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow completion after drop failed", "error", err)
	}
}

// buildSSEEventMessage constructs a flow.Message for a single SSE event.
// The event data is stored in the message Body, and event metadata (type, id,
// retry) is stored in Metadata. Body is truncated to MaxSSERecordPayloadSize.
func buildSSEEventMessage(flowID string, msgSeq int, event *SSEEvent) *flow.Message {
	metadata := map[string]string{
		"sse_type": "event",
	}
	if event.EventType != "" {
		metadata["sse_event"] = event.EventType
	}
	if event.ID != "" {
		metadata["sse_id"] = event.ID
	}
	if event.Retry != "" {
		metadata["sse_retry"] = event.Retry
	}

	body := []byte(event.Data)
	truncated := false
	if len(body) > config.MaxSSERecordPayloadSize {
		body = body[:config.MaxSSERecordPayloadSize]
		truncated = true
	}

	return &flow.Message{
		FlowID:        flowID,
		Sequence:      msgSeq,
		Direction:     "receive",
		Timestamp:     time.Now(),
		Body:          body,
		RawBytes:      event.RawBytes,
		BodyTruncated: truncated,
		Metadata:      metadata,
	}
}

// recordSSEEvent records a single SSE event as a flow.Message with
// direction="receive". The event data is stored in the message Body,
// and event metadata (type, id, retry) is stored in Metadata.
func (h *Handler) recordSSEEvent(ctx context.Context, flowID string, event *SSEEvent, seq *atomic.Int64, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)
	msg := buildSSEEventMessage(flowID, msgSeq, event)

	if err := h.Store.AppendMessage(ctx, msg); err != nil {
		logger.Error("SSE event message save failed",
			"flow_id", flowID,
			"sequence", msgSeq,
			"error", err,
		)
	}
}
