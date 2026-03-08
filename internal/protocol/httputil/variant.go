package httputil

import (
	"context"
	"log/slog"
	gohttp "net/http"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// VariantRecordWriter is the subset of flow.FlowWriter needed by variant
// recording helpers. Defining a minimal interface here avoids importing the
// full proxy package and keeps the dependency graph clean.
type VariantRecordWriter interface {
	AppendMessage(ctx context.Context, msg *flow.Message) error
	UpdateFlow(ctx context.Context, id string, update flow.FlowUpdate) error
}

// ResponseSnapshot holds a copy of the response status code, headers, and body
// taken before intercept processing. It is used to detect whether modifications
// occurred and, if so, to record the original (unmodified) version as a
// separate receive message.
type ResponseSnapshot struct {
	StatusCode int
	Headers    gohttp.Header
	Body       []byte
}

// ReceiveVariantParams holds the parameters needed to record the receive phase
// with variant support, independent of the HTTP protocol version.
type ReceiveVariantParams struct {
	// FlowID is the ID of the flow being recorded.
	FlowID string
	// RecvSequence is the sequence number to use for the first receive message.
	RecvSequence int
	// Start is the time the flow was initiated.
	Start time.Time
	// Duration is the total duration of the flow.
	Duration time.Duration
	// ServerAddr is the resolved address of the upstream server.
	ServerAddr string
	// TLSServerCertSubject is the subject DN of the upstream server's TLS
	// certificate. Only set for TLS connections.
	TLSServerCertSubject string
	// Resp is the (possibly modified) response.
	Resp *gohttp.Response
	// RespBody is the (possibly modified) response body bytes.
	RespBody []byte
	// RawResponse holds the raw wire bytes of the response. May be nil for
	// protocols that do not capture raw bytes (e.g., HTTP/2).
	RawResponse []byte
}

// RecordReceiveVariant records the receive phase with variant support. When
// snap is non-nil and the response was modified (detected via ResponseModified),
// two receive messages are recorded:
//   - Sequence N:   original (variant="original")
//   - Sequence N+1: modified (variant="modified")
//
// When no modification occurred, a single receive message is recorded without
// variant metadata.
//
// After recording message(s), the flow is updated to State="complete".
func RecordReceiveVariant(
	ctx context.Context,
	store VariantRecordWriter,
	p ReceiveVariantParams,
	snap *ResponseSnapshot,
	logger *slog.Logger,
) {
	modified := snap != nil && ResponseModified(
		*snap, p.Resp.StatusCode, p.Resp.Header, p.RespBody,
	)

	if !modified {
		recordSingleReceive(ctx, store, p, logger)
		return
	}

	recordOriginalReceive(ctx, store, p, snap, logger)
	recordModifiedReceive(ctx, store, p, logger)
	completeFlow(ctx, store, p, logger)
}

// recordSingleReceive records a single (non-variant) receive message and
// completes the flow.
func recordSingleReceive(
	ctx context.Context,
	store VariantRecordWriter,
	p ReceiveVariantParams,
	logger *slog.Logger,
) {
	body, decompressed, truncated := decompressAndTruncate(
		p.RespBody, p.Resp.Header.Get("Content-Encoding"), logger,
	)

	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    p.Resp.StatusCode,
		Headers:       RecordingHeaders(p.Resp.Header, decompressed, len(body)),
		Body:          body,
		RawBytes:      p.RawResponse,
		BodyTruncated: truncated,
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		logger.Error("receive message save failed", "error", err)
	}

	completeFlow(ctx, store, p, logger)
}

// recordOriginalReceive records the original (unmodified) response as a
// variant="original" message.
func recordOriginalReceive(
	ctx context.Context,
	store VariantRecordWriter,
	p ReceiveVariantParams,
	snap *ResponseSnapshot,
	logger *slog.Logger,
) {
	body, decompressed, truncated := decompressAndTruncate(
		snap.Body, snap.Headers.Get("Content-Encoding"), logger,
	)

	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    snap.StatusCode,
		Headers:       RecordingHeaders(snap.Headers, decompressed, len(body)),
		Body:          body,
		RawBytes:      p.RawResponse,
		BodyTruncated: truncated,
		Metadata:      map[string]string{"variant": "original"},
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		logger.Error("original receive message save failed", "error", err)
	}
}

// recordModifiedReceive records the modified response as a
// variant="modified" message.
func recordModifiedReceive(
	ctx context.Context,
	store VariantRecordWriter,
	p ReceiveVariantParams,
	logger *slog.Logger,
) {
	body, decompressed, truncated := decompressAndTruncate(
		p.RespBody, p.Resp.Header.Get("Content-Encoding"), logger,
	)

	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence + 1,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    p.Resp.StatusCode,
		Headers:       RecordingHeaders(p.Resp.Header, decompressed, len(body)),
		Body:          body,
		BodyTruncated: truncated,
		Metadata:      map[string]string{"variant": "modified"},
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		logger.Error("modified receive message save failed", "error", err)
	}
}

// completeFlow updates the flow to State="complete" with duration and server
// address metadata.
func completeFlow(
	ctx context.Context,
	store VariantRecordWriter,
	p ReceiveVariantParams,
	logger *slog.Logger,
) {
	update := flow.FlowUpdate{
		State:      "complete",
		Duration:   p.Duration,
		ServerAddr: p.ServerAddr,
	}
	if p.TLSServerCertSubject != "" {
		update.TLSServerCertSubject = p.TLSServerCertSubject
	}
	if err := store.UpdateFlow(ctx, p.FlowID, update); err != nil {
		logger.Error("flow update failed", "error", err)
	}
}

// decompressAndTruncate decompresses the body based on Content-Encoding
// and truncates to MaxBodySize. Returns the processed body, whether
// decompression occurred, and whether truncation occurred.
func decompressAndTruncate(body []byte, contentEncoding string, logger *slog.Logger) ([]byte, bool, bool) {
	result := body
	decompressed := false
	if contentEncoding != "" {
		decoded, err := DecompressBody(body, contentEncoding, config.MaxBodySize)
		if err != nil {
			logger.Debug("response body decompression failed, storing as-is",
				"encoding", contentEncoding, "error", err)
		} else {
			result = decoded
			decompressed = true
		}
	}

	var truncated bool
	if len(result) > int(config.MaxBodySize) {
		result = result[:int(config.MaxBodySize)]
		truncated = true
	}
	return result, decompressed, truncated
}

// ResponseModified reports whether the response status code, headers, or body
// have been changed relative to the snapshot.
func ResponseModified(snap ResponseSnapshot, currentStatusCode int, currentHeaders gohttp.Header, currentBody []byte) bool {
	if snap.StatusCode != currentStatusCode {
		return true
	}
	if len(snap.Body) != len(currentBody) {
		return true
	}
	for i := range snap.Body {
		if snap.Body[i] != currentBody[i] {
			return true
		}
	}
	return HeadersModified(snap.Headers, currentHeaders)
}

// HeadersModified reports whether two header maps differ.
func HeadersModified(a, b gohttp.Header) bool {
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

// SnapshotResponse creates a deep copy of the response status code, headers,
// and body for later comparison.
func SnapshotResponse(statusCode int, headers gohttp.Header, body []byte) ResponseSnapshot {
	snap := ResponseSnapshot{StatusCode: statusCode}
	if headers != nil {
		snap.Headers = headers.Clone()
	}
	if body != nil {
		snap.Body = make([]byte, len(body))
		copy(snap.Body, body)
	}
	return snap
}
