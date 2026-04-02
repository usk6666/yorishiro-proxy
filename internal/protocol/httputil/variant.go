package httputil

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// rawHeadersToMap converts parser.RawHeaders to map[string][]string without
// going through net/http.Header. Header name casing is preserved as-is.
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
	Headers    parser.RawHeaders
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
	// RespStatusCode is the HTTP response status code.
	RespStatusCode int
	// RespHeaders holds the (possibly modified) response headers.
	RespHeaders parser.RawHeaders
	// RespBody is the (possibly modified) response body bytes.
	RespBody []byte
	// RawResponse holds the raw wire bytes of the response. May be nil for
	// protocols that do not capture raw bytes.
	RawResponse []byte
	// RawResponseMetadata holds protocol-specific metadata about the raw
	// response bytes (e.g., HTTP/2 frame count and total wire bytes).
	// These entries are merged into the receive Message.Metadata.
	// May be nil if no raw response metadata is available.
	RawResponseMetadata map[string]string
	// Tags holds additional key-value metadata to merge into the flow on
	// completion (e.g., technology fingerprint results). May be nil.
	Tags map[string]string
	// SendMs is the time in milliseconds to send the request.
	// Nil when not measured.
	SendMs *int64
	// WaitMs is the server processing time in milliseconds (TTFB).
	// Nil when not measured.
	WaitMs *int64
	// ReceiveMs is the time in milliseconds to receive the response.
	// Nil when not measured.
	ReceiveMs *int64
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
		*snap, p.RespStatusCode, p.RespHeaders, p.RespBody,
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
		p.RespBody, p.RespHeaders.Get("Content-Encoding"), logger,
	)

	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    p.RespStatusCode,
		Headers:       rawHeadersToMap(RecordingHeadersRaw(p.RespHeaders, decompressed, len(body))),
		Body:          body,
		RawBytes:      p.RawResponse,
		BodyTruncated: truncated,
		Metadata:      cloneMetadata(p.RawResponseMetadata),
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

	origMeta := mergeMetadata(p.RawResponseMetadata, map[string]string{"variant": "original"})
	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    snap.StatusCode,
		Headers:       rawHeadersToMap(RecordingHeadersRaw(snap.Headers, decompressed, len(body))),
		Body:          body,
		RawBytes:      p.RawResponse,
		BodyTruncated: truncated,
		Metadata:      origMeta,
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
		p.RespBody, p.RespHeaders.Get("Content-Encoding"), logger,
	)

	msg := &flow.Message{
		FlowID:        p.FlowID,
		Sequence:      p.RecvSequence + 1,
		Direction:     "receive",
		Timestamp:     p.Start.Add(p.Duration),
		StatusCode:    p.RespStatusCode,
		Headers:       rawHeadersToMap(RecordingHeadersRaw(p.RespHeaders, decompressed, len(body))),
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
		SendMs:     p.SendMs,
		WaitMs:     p.WaitMs,
		ReceiveMs:  p.ReceiveMs,
	}
	if p.TLSServerCertSubject != "" {
		update.TLSServerCertSubject = p.TLSServerCertSubject
	}
	if len(p.Tags) > 0 {
		update.Tags = p.Tags
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
func ResponseModified(snap ResponseSnapshot, currentStatusCode int, currentHeaders parser.RawHeaders, currentBody []byte) bool {
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

// HeadersModified reports whether two header sets differ in content.
// The comparison is order-insensitive: only the set of (lowercased name, value)
// pairs matters, not their position. This avoids false positives when headers
// originate from net/http.Header map iteration (non-deterministic order).
func HeadersModified(a, b parser.RawHeaders) bool {
	if len(a) != len(b) {
		return true
	}
	freq := make(map[string]int, len(a))
	for _, h := range a {
		key := strings.ToLower(h.Name) + "\x00" + h.Value
		freq[key]++
	}
	for _, h := range b {
		key := strings.ToLower(h.Name) + "\x00" + h.Value
		freq[key]--
		if freq[key] < 0 {
			return true
		}
	}
	return false
}

// cloneMetadata creates a shallow copy of a metadata map. Returns nil if the
// input is nil or empty.
func cloneMetadata(m map[string]string) map[string]string {
	if len(m) == 0 {
		return nil
	}
	clone := make(map[string]string, len(m))
	for k, v := range m {
		clone[k] = v
	}
	return clone
}

// mergeMetadata creates a new map containing entries from both base and
// override. Keys in override take precedence over keys in base. Returns nil
// if both maps are empty.
func mergeMetadata(base, override map[string]string) map[string]string {
	total := len(base) + len(override)
	if total == 0 {
		return nil
	}
	result := make(map[string]string, total)
	for k, v := range base {
		result[k] = v
	}
	for k, v := range override {
		result[k] = v
	}
	return result
}

// SnapshotResponse creates a deep copy of the response status code, headers,
// and body for later comparison.
func SnapshotResponse(statusCode int, headers parser.RawHeaders, body []byte) ResponseSnapshot {
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
