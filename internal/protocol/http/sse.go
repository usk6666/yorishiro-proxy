package http

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
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
// headers to the client and then streaming the body using io.Copy. This avoids
// the store-and-forward buffering that would cause SSE connections to hang.
//
// The flow is recorded with metadata only (request + response headers, no body)
// and tagged with streaming_type=sse for identification.
//
// NOTE: The following processing steps are intentionally skipped for SSE streams
// because they require the full response body to be buffered in memory:
//   - Plugin hooks: on_receive_from_server, on_before_send_to_client
//   - Response intercept (modify/drop)
//   - Response auto-transform rules
//   - Output filter (PII masking)
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStream(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
	// Write the response headers to the client.
	if err := writeSSEResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	// Warn if PII output filter rules are configured but will not apply to SSE.
	h.warnSSEOutputFilterBypass(logger)

	logger.Info("SSE stream started", "method", req.Method, "url", req.URL.String())

	// Apply maximum stream duration to prevent indefinite resource consumption.
	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	// Stream the response body from upstream to client.
	// This blocks until the upstream closes the connection or the context
	// is cancelled.
	streamErr := streamSSEBody(streamCtx, conn, fwd.resp.Body)

	// Record the receive phase (response headers only, no body).
	duration := time.Since(start)
	h.recordSSEReceive(ctx, sendResult, fwd, start, duration, "", logger)

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
// See handleSSEStream for details on skipped processing steps.
//
// The sendResult parameter is the result from the already-recorded send phase;
// this function must NOT call recordSendWithVariant again.
func (h *Handler) handleSSEStreamTLS(ctx context.Context, conn net.Conn, req *gohttp.Request, fwd *forwardResult, start time.Time, sendResult *sendRecordResult, logger *slog.Logger) error {
	// Write the response headers to the client.
	if err := writeSSEResponseHeaders(conn, fwd.resp); err != nil {
		h.recordSendError(ctx, sendResult, start, err, logger)
		return fmt.Errorf("write SSE response headers: %w", err)
	}

	// Warn if PII output filter rules are configured but will not apply to SSE.
	h.warnSSEOutputFilterBypass(logger)

	logger.Info("SSE stream started (TLS)", "method", req.Method, "url", req.URL.String())

	// Apply maximum stream duration to prevent indefinite resource consumption.
	streamCtx, streamCancel := context.WithTimeout(ctx, sseMaxStreamDuration)
	defer streamCancel()

	// Stream the response body from upstream to client.
	streamErr := streamSSEBody(streamCtx, conn, fwd.resp.Body)

	// Record the receive phase (response headers only, no body).
	// Include TLS certificate info from the upstream connection.
	duration := time.Since(start)
	var tlsCertSubject string
	if fwd.resp.TLS != nil && len(fwd.resp.TLS.PeerCertificates) > 0 {
		tlsCertSubject = fwd.resp.TLS.PeerCertificates[0].Subject.String()
	}
	h.recordSSEReceive(ctx, sendResult, fwd, start, duration, tlsCertSubject, logger)

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

// streamSSEBody copies the SSE body from upstream to the client connection.
// It respects context cancellation by closing the done channel which triggers
// the context watcher to set a read deadline on the connection.
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

// warnSSEOutputFilterBypass logs a warning if the safety engine has output
// filter rules configured, since SSE streams bypass PII masking.
func (h *Handler) warnSSEOutputFilterBypass(logger *slog.Logger) {
	if h.SafetyEngine == nil {
		return
	}
	if len(h.SafetyEngine.OutputRules()) > 0 {
		logger.Warn("SSE stream bypasses output filter (PII masking not applied)",
			"output_rule_count", len(h.SafetyEngine.OutputRules()))
	}
}

// recordSSEReceive records the receive phase for an SSE flow. The response is
// recorded with headers only (no body) since SSE streams are not buffered.
// The tlsCertSubject is empty for non-TLS connections.
func (h *Handler) recordSSEReceive(ctx context.Context, sendResult *sendRecordResult, fwd *forwardResult, start time.Time, duration time.Duration, tlsCertSubject string, logger *slog.Logger) {
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

	// Update flow with SSE tags, duration, and completion state.
	update := flow.FlowUpdate{
		State:                "complete",
		Duration:             duration,
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
	}
	if err := h.Store.AppendMessage(ctx, recvMsg); err != nil {
		logger.Error("SSE receive message save failed", "error", err)
	}
}
