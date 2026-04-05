package http

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

const sseMaxStreamDuration = 24 * time.Hour

func addSSETags(tags map[string]string) map[string]string {
	if tags == nil {
		tags = make(map[string]string)
	}
	tags["streaming_type"] = "sse"
	return tags
}

type sseHookContext struct {
	connInfo *plugin.ConnInfo
	txCtx    map[string]any
}

type sseStreamContext struct {
	req     *parser.RawRequest
	reqURL  *url.URL
	hookCtx *sseHookContext
}

// handleSSEStream handles Server-Sent Events responses.
func (h *Handler) handleSSEStream(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, hookCtx *sseHookContext, logger *slog.Logger) error {
	// Plugin hook: on_receive_from_server (header-level).
	if hookCtx != nil {
		fwd.resp, _ = h.dispatchOnReceiveFromServer(ctx, fwd.resp, nil, req, hookCtx.connInfo, hookCtx.txCtx, logger)
	}

	// Response intercept.
	if dropped := h.applySSEIntercept(ctx, conn, req, reqURL, fwd.resp, logger); dropped {
		h.completeSSEFlowOnDrop(ctx, sendResult, fwd, start, "", logger)
		return nil
	}

	// Plugin hook: on_before_send_to_client (header-level).
	if hookCtx != nil {
		fwd.resp, _ = h.dispatchOnBeforeSendToClient(ctx, fwd.resp, nil, req, hookCtx.connInfo, hookCtx.txCtx, logger)
	}

	if err := writeRawResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	logger.Info("SSE stream started", "method", req.Method, "url", reqURL.String())

	h.recordSSEReceive(ctx, sendResult, fwd, start, "", logger)

	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	var eventSeq atomic.Int64
	eventSeq.Store(int64(sendResult.recvSequence) + 1)

	sseCtx := &sseStreamContext{req: req, reqURL: reqURL, hookCtx: hookCtx}
	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, sseCtx, logger)

	duration := time.Since(start)
	h.completeSSEFlow(ctx, sendResult, fwd, duration, "", &eventSeq, logger)

	if streamErr != nil && ctx.Err() == nil {
		logger.Debug("SSE stream ended", "method", req.Method, "url", reqURL.String(), "error", streamErr)
	} else {
		logger.Info("SSE stream ended", "method", req.Method, "url", reqURL.String(), "duration_ms", duration.Milliseconds())
	}

	return nil
}

// handleSSEStreamTLS handles SSE responses in the HTTPS MITM path.
func (h *Handler) handleSSEStreamTLS(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
	// NOTE: TLS cert subject info is not available via UpstreamRouter.
	var tlsCertSubject string

	if dropped := h.applySSEIntercept(ctx, conn, req, reqURL, fwd.resp, logger); dropped {
		h.completeSSEFlowOnDrop(ctx, sendResult, fwd, start, tlsCertSubject, logger)
		return nil
	}

	if err := writeRawResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	logger.Info("SSE stream started (TLS)", "method", req.Method, "url", reqURL.String())

	h.recordSSEReceive(ctx, sendResult, fwd, start, tlsCertSubject, logger)

	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	var eventSeq atomic.Int64
	eventSeq.Store(int64(sendResult.recvSequence) + 1)

	sseCtx := &sseStreamContext{req: req, reqURL: reqURL}
	streamErr := h.streamSSEEvents(streamCtx, conn, fwd.resp.Body, sendResult.flowID, &eventSeq, sseCtx, logger)

	duration := time.Since(start)
	h.completeSSEFlow(ctx, sendResult, fwd, duration, tlsCertSubject, &eventSeq, logger)

	if streamErr != nil && ctx.Err() == nil {
		logger.Debug("SSE stream ended (TLS)", "method", req.Method, "url", reqURL.String(), "error", streamErr)
	} else {
		logger.Info("SSE stream ended (TLS)", "method", req.Method, "url", reqURL.String(), "duration_ms", duration.Milliseconds())
	}

	return nil
}

var errSSEOutputFilterBlocked = errors.New("SSE stream blocked by output filter")

func (h *Handler) streamSSEEvents(ctx context.Context, dst net.Conn, src io.Reader, flowID string, seq *atomic.Int64, sseCtx *sseStreamContext, logger *slog.Logger) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			dst.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	sseParser := NewSSEParser(src, config.MaxSSEEventSize)
	var eventCount int
	var recordingDisabled bool

	for {
		select {
		case <-ctx.Done():
			dst.SetWriteDeadline(time.Time{})
			return ctx.Err()
		default:
		}

		event, err := sseParser.Next()
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

		event = h.dispatchSSEOnReceiveFromServer(ctx, event, sseCtx, logger)
		snap := snapshotSSEEvent(event)

		event, dropped := h.applySSEEventIntercept(ctx, event, flowID, sseCtx, logger)
		if dropped {
			logger.Info("SSE event dropped by intercept",
				"flow_id", flowID, "event_type", snap.eventType)
			continue
		}

		event = h.dispatchSSEOnBeforeSendToClient(ctx, event, sseCtx, logger)

		eventCount++
		if !recordingDisabled {
			if eventCount > config.MaxSSEEventsPerStream {
				logger.Info("SSE event recording limit reached, forwarding only",
					"flow_id", flowID, "limit", config.MaxSSEEventsPerStream)
				recordingDisabled = true
			} else {
				h.recordSSEEventWithVariant(ctx, flowID, event, &snap, seq, logger)
			}
		}

		sendBytes, blocked := h.applySSEOutputFilter(event, logger)
		if blocked {
			logger.Warn("SSE stream terminated by output filter (action=block)",
				"flow_id", flowID, "event_type", event.EventType)
			return errSSEOutputFilterBlocked
		}

		if _, writeErr := dst.Write(sendBytes); writeErr != nil {
			if ctx.Err() != nil {
				dst.SetWriteDeadline(time.Time{})
				return ctx.Err()
			}
			return fmt.Errorf("SSE write to client: %w", writeErr)
		}
	}
}

type sseEventSnapshot struct {
	eventType string
	data      string
	id        string
	retry     string
}

func snapshotSSEEvent(event *SSEEvent) sseEventSnapshot {
	return sseEventSnapshot{
		eventType: event.EventType,
		data:      event.Data,
		id:        event.ID,
		retry:     event.Retry,
	}
}

func sseEventModified(snap sseEventSnapshot, event *SSEEvent) bool {
	return snap.eventType != event.EventType ||
		snap.data != event.Data ||
		snap.id != event.ID ||
		snap.retry != event.Retry
}

func (h *Handler) dispatchSSEOnReceiveFromServer(ctx context.Context, event *SSEEvent, sseCtx *sseStreamContext, logger *slog.Logger) *SSEEvent {
	if h.pluginEngine == nil || sseCtx == nil || sseCtx.hookCtx == nil {
		return event
	}
	resp, body := sseEventToRawResponse(event)
	resp, body = h.dispatchOnReceiveFromServer(ctx, resp, body, sseCtx.req, sseCtx.hookCtx.connInfo, sseCtx.hookCtx.txCtx, logger)
	return applyRawResponseToSSEEvent(event, resp, body)
}

func (h *Handler) dispatchSSEOnBeforeSendToClient(ctx context.Context, event *SSEEvent, sseCtx *sseStreamContext, logger *slog.Logger) *SSEEvent {
	if h.pluginEngine == nil || sseCtx == nil || sseCtx.hookCtx == nil {
		return event
	}
	resp, body := sseEventToRawResponse(event)
	resp, body = h.dispatchOnBeforeSendToClient(ctx, resp, body, sseCtx.req, sseCtx.hookCtx.connInfo, sseCtx.hookCtx.txCtx, logger)
	return applyRawResponseToSSEEvent(event, resp, body)
}

// sseEventToRawResponse converts an SSE event into a synthetic RawResponse.
func sseEventToRawResponse(event *SSEEvent) (*parser.RawResponse, []byte) {
	var headers parser.RawHeaders
	headers = append(headers, parser.RawHeader{Name: "Content-Type", Value: "text/event-stream"})
	if event.EventType != "" {
		headers = append(headers, parser.RawHeader{Name: "X-SSE-Event", Value: event.EventType})
	}
	if event.ID != "" {
		headers = append(headers, parser.RawHeader{Name: "X-SSE-Id", Value: event.ID})
	}
	if event.Retry != "" {
		headers = append(headers, parser.RawHeader{Name: "X-SSE-Retry", Value: event.Retry})
	}

	resp := &parser.RawResponse{
		Proto:      "HTTP/1.1",
		StatusCode: 200,
		Status:     "200 OK",
		Headers:    headers,
	}
	return resp, []byte(event.Data)
}

// applyRawResponseToSSEEvent applies changes from a RawResponse back to the SSE event.
func applyRawResponseToSSEEvent(original *SSEEvent, resp *parser.RawResponse, body []byte) *SSEEvent {
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

	if body != nil {
		newEvent.Data = string(body)
	}
	if v := resp.Headers.Get("X-SSE-Event"); v != "" || headerExists(resp.Headers, "X-SSE-Event") {
		newEvent.EventType = v
	}
	if v := resp.Headers.Get("X-SSE-Id"); v != "" || headerExists(resp.Headers, "X-SSE-Id") {
		newEvent.ID = v
	}
	if v := resp.Headers.Get("X-SSE-Retry"); v != "" || headerExists(resp.Headers, "X-SSE-Retry") {
		newEvent.Retry = v
	}

	if newEvent.EventType != original.EventType ||
		newEvent.Data != original.Data ||
		newEvent.ID != original.ID ||
		newEvent.Retry != original.Retry {
		newEvent.RawBytes = []byte(newEvent.String())
	}

	return newEvent
}

// headerExists checks if a header name exists (even with empty value).
func headerExists(headers parser.RawHeaders, name string) bool {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return true
		}
	}
	return false
}

func (h *Handler) applySSEEventIntercept(ctx context.Context, event *SSEEvent, flowID string, sseCtx *sseStreamContext, logger *slog.Logger) (*SSEEvent, bool) {
	if h.InterceptEngine == nil || h.InterceptQueue == nil || sseCtx == nil || sseCtx.req == nil {
		return event, false
	}

	var matchHeaders []exchange.KeyValue
	matchHeaders = append(matchHeaders, exchange.KeyValue{Name: "Content-Type", Value: "text/event-stream"})
	if event.EventType != "" {
		matchHeaders = append(matchHeaders, exchange.KeyValue{Name: "X-SSE-Event", Value: event.EventType})
	}
	if event.ID != "" {
		matchHeaders = append(matchHeaders, exchange.KeyValue{Name: "X-SSE-Id", Value: event.ID})
	}
	if event.Retry != "" {
		matchHeaders = append(matchHeaders, exchange.KeyValue{Name: "X-SSE-Retry", Value: event.Retry})
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(200, matchHeaders)
	if len(matchedRules) == 0 {
		return event, false
	}

	logger.Info("SSE event intercepted", "flow_id", flowID,
		"event_type", event.EventType, "matched_rules", matchedRules)

	eventBody := []byte(event.Data)
	filteredBody := h.filterSSEEventBodyForIntercept(eventBody, logger)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		sseCtx.req.Method, sseCtx.reqURL, 200, matchHeaders, filteredBody, matchedRules,
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
		return event, false
	}
}

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

func applySSEEventModifications(event *SSEEvent, action intercept.InterceptAction) *SSEEvent {
	modified := &SSEEvent{
		EventType: event.EventType,
		Data:      event.Data,
		ID:        event.ID,
		Retry:     event.Retry,
	}

	if action.OverrideResponseBody != nil {
		modified.Data = *action.OverrideResponseBody
	}

	for key, val := range action.OverrideResponseHeaders {
		switch strings.ToLower(key) {
		case "x-sse-event":
			modified.EventType = val
		case "x-sse-id":
			modified.ID = val
		case "x-sse-retry":
			modified.Retry = val
		}
	}

	for key, val := range action.AddResponseHeaders {
		switch strings.ToLower(key) {
		case "x-sse-event":
			modified.EventType = val
		case "x-sse-id":
			modified.ID = val
		case "x-sse-retry":
			modified.Retry = val
		}
	}

	modified.RawBytes = []byte(modified.String())
	return modified
}

func (h *Handler) recordSSEEventWithVariant(ctx context.Context, flowID string, event *SSEEvent, snap *sseEventSnapshot, seq *atomic.Int64, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	modified := snap != nil && sseEventModified(*snap, event)

	if modified {
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
		if err := h.Store.SaveFlow(ctx, origMsg); err != nil {
			logger.Error("SSE original event message save failed",
				"flow_id", flowID, "sequence", origSeq, "error", err)
		}

		modSeq := int(seq.Add(1) - 1)
		modMsg := buildSSEEventMessage(flowID, modSeq, event)
		modMsg.Metadata["variant"] = "modified"
		if err := h.Store.SaveFlow(ctx, modMsg); err != nil {
			logger.Error("SSE modified event message save failed",
				"flow_id", flowID, "sequence", modSeq, "error", err)
		}
	} else {
		h.recordSSEEvent(ctx, flowID, event, seq, logger)
	}
}

func streamSSEBody(ctx context.Context, dst net.Conn, src io.Reader) error {
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			dst.SetWriteDeadline(time.Now())
		case <-done:
		}
	}()

	_, err := io.Copy(dst, src)
	if ctx.Err() != nil {
		dst.SetWriteDeadline(time.Time{})
		return ctx.Err()
	}
	return err
}

func (h *Handler) applySSEOutputFilter(event *SSEEvent, logger *slog.Logger) (sendBytes []byte, blocked bool) {
	if h.SafetyEngine == nil || len(h.SafetyEngine.OutputRules()) == 0 {
		return event.RawBytes, false
	}

	result := h.SafetyEngine.FilterOutput([]byte(event.Data))

	for _, m := range result.Matches {
		logger.Info("SSE output filter matched event data",
			"rule_id", m.RuleID, "count", m.Count, "action", m.Action.String(),
			"event_type", event.EventType)

		if m.Action == safety.ActionBlock {
			return nil, true
		}
	}

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

func (h *Handler) applySSEIntercept(ctx context.Context, conn net.Conn, req *parser.RawRequest, reqURL *url.URL, resp *parser.RawResponse, logger *slog.Logger) bool {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return false
	}

	kvHeaders := rawHeadersToKV(resp.Headers)
	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, kvHeaders)
	if len(matchedRules) == 0 {
		return false
	}

	logger.Info("SSE response intercepted (header-level)",
		"method", req.Method, "url", reqURL.String(),
		"status", resp.StatusCode, "matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		req.Method, reqURL, resp.StatusCode, kvHeaders, nil, matchedRules,
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
		writeHTTPError(conn, statusBadGateway, logger)
		logger.Info("intercepted SSE response dropped",
			"method", req.Method, "url", reqURL.String(), "status", resp.StatusCode)
		return true
	case intercept.ActionModifyAndForward:
		logger.Warn("SSE response intercept modify_and_forward not supported, releasing",
			"method", req.Method, "url", reqURL.String())
		return false
	default:
		return false
	}
}

func (h *Handler) recordSSEReceive(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, start time.Time, tlsCertSubject string, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	if fwd.resp == nil {
		return
	}

	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags = addSSETags(tags)

	update := flow.StreamUpdate{
		State:                "active",
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateStream(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow update failed", "error", err)
	}

	recvMsg := &flow.Flow{
		StreamID:   sendResult.flowID,
		Sequence:   sendResult.recvSequence,
		Direction:  "receive",
		Timestamp:  start,
		StatusCode: fwd.resp.StatusCode,
		Headers:    rawHeadersToMap(fwd.resp.Headers),
		Metadata:   map[string]string{"sse_type": "headers"},
	}
	if err := h.Store.SaveFlow(ctx, recvMsg); err != nil {
		logger.Error("SSE receive message save failed", "error", err)
	}
}

func (h *Handler) completeSSEFlow(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, duration time.Duration, tlsCertSubject string, eventSeq *atomic.Int64, logger *slog.Logger) {
	if sendResult == nil || h.Store == nil {
		return
	}

	tags := make(map[string]string)
	for k, v := range sendResult.tags {
		tags[k] = v
	}
	tags = addSSETags(tags)

	eventsRecorded := int(eventSeq.Load()) - sendResult.recvSequence - 1
	if eventsRecorded > 0 {
		tags["sse_events_recorded"] = strconv.Itoa(eventsRecorded)
	}

	update := flow.StreamUpdate{
		State:                "complete",
		Duration:             duration,
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateStream(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow completion failed", "error", err)
	}
}

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

	update := flow.StreamUpdate{
		State:                "complete",
		Duration:             duration,
		ServerAddr:           fwd.serverAddr,
		TLSServerCertSubject: tlsCertSubject,
		Tags:                 tags,
	}
	if err := h.Store.UpdateStream(ctx, sendResult.flowID, update); err != nil {
		logger.Error("SSE flow completion after drop failed", "error", err)
	}
}

func buildSSEEventMessage(flowID string, msgSeq int, event *SSEEvent) *flow.Flow {
	metadata := map[string]string{"sse_type": "event"}
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

	return &flow.Flow{
		StreamID:      flowID,
		Sequence:      msgSeq,
		Direction:     "receive",
		Timestamp:     time.Now(),
		Body:          body,
		RawBytes:      event.RawBytes,
		BodyTruncated: truncated,
		Metadata:      metadata,
	}
}

func (h *Handler) recordSSEEvent(ctx context.Context, flowID string, event *SSEEvent, seq *atomic.Int64, logger *slog.Logger) {
	if h.Store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)
	msg := buildSSEEventMessage(flowID, msgSeq, event)

	if err := h.Store.SaveFlow(ctx, msg); err != nil {
		logger.Error("SSE event message save failed",
			"flow_id", flowID, "sequence", msgSeq, "error", err)
	}
}
