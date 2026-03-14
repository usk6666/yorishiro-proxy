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

// handleSSEStream handles Server-Sent Events responses by writing the response
// headers to the client and then streaming events from upstream, forwarding
// each to the client while recording them as flow.Message entries.
//
// Each SSE event is parsed, forwarded to the client, and recorded as a
// separate flow.Message with direction="receive". This follows the same
// progressive recording pattern used by WebSocket frame recording.
//
// Output filter (PII masking) is applied per-event to the SSE data field
// before forwarding to the client. If a block-action rule matches, the
// stream is terminated. Flow recording always stores the original (unfiltered)
// event data.
//
// NOTE: The following processing steps are intentionally skipped for SSE streams
// because they require the full response body to be buffered in memory:
//   - Plugin hooks: on_receive_from_server, on_before_send_to_client
//   - Response intercept (modify/drop)
//   - Response auto-transform rules
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStream(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
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

	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, logger)

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
// See handleSSEStream for details on output filter application and skipped
// processing steps.
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStreamTLS(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
	// Write the response headers to the client.
	if err := writeSSEResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	logger.Info("SSE stream started (TLS)", "method", req.Method, "url", req.URL.String())

	// Extract TLS certificate info from the upstream connection.
	var tlsCertSubject string
	if fwd.resp.TLS != nil && len(fwd.resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = fwd.resp.TLS.PeerCertificates[0].Subject.String()
	}

	// Record the initial receive message (response headers) and update flow
	// type to "stream" for SSE event-level recording.
	h.recordSSEReceive(ctx, sendResult, fwd, start, tlsCertSubject, logger)

	// Apply maximum stream duration to prevent indefinite resource consumption.
	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	// Stream and record SSE events from upstream to client.
	var eventSeq atomic.Int64
	eventSeq.Store(int64(sendResult.recvSequence) + 1)

	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, logger)

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

// streamSSEEvents reads SSE events from src, forwards each event's raw bytes
// to the client connection, and records each event as a flow.Message.
// It respects context cancellation by setting a write deadline on the connection.
//
// Events are parsed using the SSE parser. Before forwarding to the client,
// output filter rules are applied to the event data:
//   - action=mask: The event data is masked and the event is reconstructed
//     with filtered data before forwarding. Flow recording stores the
//     original (unfiltered) data.
//   - action=block: The stream is immediately terminated.
//   - action=log_only: A log entry is emitted but the event is forwarded
//     unchanged.
//
// Recording stops after config.MaxSSEEventsPerStream events to prevent
// unbounded DB growth, but forwarding (with filtering) continues.
func (h *Handler) streamSSEEvents(ctx context.Context, dst net.Conn, src io.Reader, flowID string, seq *atomic.Int64, logger *slog.Logger) error {
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

		// Apply output filter to the event data before forwarding.
		sendBytes, blocked := h.applySSEOutputFilter(event, logger)
		if blocked {
			logger.Warn("SSE stream terminated by output filter (action=block)",
				"flow_id", flowID,
				"event_type", event.EventType)
			return errSSEOutputFilterBlocked
		}

		// Forward the (possibly filtered) event bytes to the client.
		if _, writeErr := dst.Write(sendBytes); writeErr != nil {
			if ctx.Err() != nil {
				dst.SetWriteDeadline(time.Time{})
				return ctx.Err()
			}
			return fmt.Errorf("SSE write to client: %w", writeErr)
		}

		// Record the event as a flow message (always with original data).
		eventCount++
		if !recordingDisabled {
			if eventCount > config.MaxSSEEventsPerStream {
				logger.Info("SSE event recording limit reached, forwarding only",
					"flow_id", flowID,
					"limit", config.MaxSSEEventsPerStream)
				recordingDisabled = true
			} else {
				h.recordSSEEvent(ctx, flowID, event, seq, logger)
			}
		}
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

// recordSSEEvent records a single SSE event as a flow.Message with
// direction="receive". The event data is stored in the message Body,
// and event metadata (type, id, retry) is stored in Metadata.
func (h *Handler) recordSSEEvent(ctx context.Context, flowID string, event *SSEEvent, seq *atomic.Int64, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

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

	msg := &flow.Message{
		FlowID:        flowID,
		Sequence:      msgSeq,
		Direction:     "receive",
		Timestamp:     time.Now(),
		Body:          body,
		RawBytes:      event.RawBytes,
		BodyTruncated: truncated,
		Metadata:      metadata,
	}

	if err := h.Store.AppendMessage(ctx, msg); err != nil {
		logger.Error("SSE event message save failed",
			"flow_id", flowID,
			"sequence", msgSeq,
			"error", err,
		)
	}
}
