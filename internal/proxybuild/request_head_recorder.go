package proxybuild

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// requestHeadRecordTimeout bounds the Stream + Flow writes for one record.
const requestHeadRecordTimeout = 5 * time.Second

// requestHeadFailure identifies one request head the proxy closed before an
// Envelope existed (USK-1181).
type requestHeadFailure struct {
	// ConnID is the connection-stack ConnID, shared with every Stream
	// recorded on the same connection.
	ConnID string
	// ClientAddr is the client's remote address.
	ClientAddr string
	// Target is the authority the connection was bound for (CONNECT /
	// plain-forward target / tcp_forwards target). May be empty.
	Target string
	// Head describes what the wire showed. Callers outside the HTTP/1
	// Layer (e.g. a connector-side request-line reader) build one
	// directly; only Reason is required.
	Head *http1.RequestHeadError
}

// requestHeadRecorder persists a requestHeadFailure. Synchronous; safe for
// concurrent use.
type requestHeadRecorder func(ctx context.Context, f requestHeadFailure)

// buildRequestHeadRecorder returns the recorder for request heads the
// proxy itself closed before an Envelope existed (USK-1181): the request
// head deadline expired after bytes arrived, or the request line / header
// section exceeded a parser limit and the proxy answered 414 / 431.
// Without a record a client of a transparent gateway — which does not know
// a proxy is there — has no way to learn why its connection was dropped.
//
// The record bypasses the Pipeline (no plugins, intercept or TargetScope:
// there is no request to act on) and is shaped like the other
// pre-Envelope recorders (buildTLSStackBuildErrorRecorder, USK-1142):
//
//   - Stream: Protocol="http", State="error", Scheme from the Layer,
//     FailureReason = the RequestHeadReason label, Tags{closed_by:"proxy",
//     phase, request_timeout_ms (when a deadline was armed), target,
//     error, listener, wrote_response (414 / 431 only)}.
//   - Send Flow (sequence 0): RawBytes = the bytes received, capped at
//     max_raw_capture_size; Metadata raw_captured_bytes, and
//     raw_truncated="true" when the cap cut the capture. Method / URL /
//     headers are a best-effort overlay, set only when the request line
//     was complete; RawBytes is authoritative.
//   - Receive Flow (sequence 1), only when the 414 / 431 was written:
//     RawBytes = the exact bytes written, StatusCode, Metadata
//     proxy_generated="true" (mirrors the USK-829 proxy-generated 403).
//
// capture_scope applies with a synthetic envelope built from what was
// observed; with no authority at all and a hostname exclude rule set the
// record is dropped (fail closed, as USK-1142).
//
// Writes run synchronously on a background-derived context bounded by
// requestHeadRecordTimeout so a cancelled connection does not abort the
// audit record. Nil store yields a nil recorder.
func buildRequestHeadRecorder(store flow.Writer, scope *flow.RecordScope, listenerName string, logger *slog.Logger) requestHeadRecorder {
	if store == nil {
		return nil
	}
	if listenerName == "" {
		listenerName = DefaultListenerName
	}
	if logger == nil {
		logger = slog.Default()
	}
	return func(_ context.Context, f requestHeadFailure) {
		head := f.Head
		if head == nil || head.Reason == "" {
			return
		}
		authority := head.Authority
		if authority == "" {
			authority = f.Target
		}
		if !requestHeadInScope(scope, head, authority) {
			logger.Debug("proxybuild: proxy-closed request head out of capture_scope; skipped recording",
				"listener", listenerName, "target", f.Target, "reason", string(head.Reason))
			return
		}

		connID := f.ConnID
		if connID == "" {
			connID = uuid.New().String()
		}
		started := head.Started
		if started.IsZero() {
			started = time.Now()
		}
		st := &flow.Stream{
			ID:            uuid.New().String(),
			ConnID:        connID,
			Protocol:      string(envelope.ProtocolHTTP),
			Scheme:        head.Scheme,
			State:         "error",
			FailureReason: string(head.Reason),
			Timestamp:     started,
			Duration:      time.Since(started),
			Tags:          requestHeadTags(f, head, listenerName),
			ConnInfo: &flow.ConnectionInfo{
				ClientAddr: f.ClientAddr,
				ServerAddr: f.Target,
			},
		}

		ctx, cancel := context.WithTimeout(context.Background(), requestHeadRecordTimeout)
		defer cancel()
		if err := store.SaveStream(ctx, st); err != nil {
			logger.Error("proxybuild: proxy-closed request head stream save failed",
				"listener", listenerName, "conn_id", connID, "target", f.Target, "error", err)
			return
		}
		if err := store.SaveFlow(ctx, requestHeadSendFlow(st, head, authority)); err != nil {
			logger.Error("proxybuild: proxy-closed request head flow save failed",
				"listener", listenerName, "stream_id", st.ID, "direction", "send", "error", err)
		}
		if head.Status > 0 && head.ResponseWritten {
			if err := store.SaveFlow(ctx, requestHeadResponseFlow(st, head)); err != nil {
				logger.Error("proxybuild: proxy-closed request head flow save failed",
					"listener", listenerName, "stream_id", st.ID, "direction", "receive", "error", err)
			}
		}
	}
}

// requestHeadInScope applies capture_scope to a request head that never
// became an Envelope.
func requestHeadInScope(scope *flow.RecordScope, head *http1.RequestHeadError, authority string) bool {
	if scope.IsEmpty() {
		return true
	}
	if authority == "" && scope.HasHostnameExclude() {
		return false
	}
	env := &envelope.Envelope{
		Context: envelope.EnvelopeContext{TargetHost: authority},
		Message: &envelope.HTTPMessage{Method: head.Method, Authority: authority, Path: head.Path},
	}
	return scope.ShouldRecord(env)
}

// requestHeadTags builds the Stream tags.
func requestHeadTags(f requestHeadFailure, head *http1.RequestHeadError, listenerName string) map[string]string {
	tags := map[string]string{
		"closed_by": "proxy",
		"listener":  listenerName,
	}
	if head.Phase != "" {
		tags["phase"] = head.Phase
	}
	if head.Timeout > 0 {
		tags["request_timeout_ms"] = strconv.FormatInt(head.Timeout.Milliseconds(), 10)
	}
	if f.Target != "" {
		target, truncated := truncateRequestHeadTag(f.Target)
		tags["target"] = target
		if truncated {
			tags["target_truncated"] = "true"
		}
	}
	if head.Err != nil {
		tags["error"] = head.Err.Error()
	}
	if head.Status > 0 {
		tags["wrote_response"] = strconv.FormatBool(head.ResponseWritten)
	}
	return tags
}

// truncateRequestHeadTag caps a tag value at connector.MaxRejectTargetLen
// bytes on a UTF-8 boundary, as USK-1142 does for rejected targets.
func truncateRequestHeadTag(s string) (string, bool) {
	if len(s) <= connector.MaxRejectTargetLen {
		return s, false
	}
	cut := connector.MaxRejectTargetLen
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}

// requestHeadSendFlow builds the send Flow carrying the received bytes.
func requestHeadSendFlow(st *flow.Stream, head *http1.RequestHeadError, authority string) *flow.Flow {
	fl := &flow.Flow{
		ID:        uuid.New().String(),
		StreamID:  st.ID,
		Sequence:  0,
		Direction: envelope.Send.String(),
		Timestamp: st.Timestamp,
		RawBytes:  head.Raw,
		Metadata: map[string]string{
			"protocol":           string(envelope.ProtocolHTTP),
			"raw_captured_bytes": strconv.Itoa(len(head.Raw)),
		},
	}
	if head.RawTruncated {
		fl.Metadata["raw_truncated"] = "true"
	}
	if head.Method == "" && head.RequestTarget == "" {
		return fl
	}
	fl.Method = head.Method
	fl.HTTPVersion = requestHeadHTTPVersion(head.Proto)
	if head.Path != "" || authority != "" {
		fl.URL = envelope.URLFromWirePath(head.Scheme, authority, head.Path, head.RawQuery)
	}
	if len(head.Headers) > 0 {
		hdrs := make(map[string][]string, len(head.Headers))
		for _, h := range head.Headers {
			hdrs[h.Name] = append(hdrs[h.Name], h.Value)
		}
		fl.Headers = hdrs
	}
	return fl
}

// requestHeadResponseFlow builds the receive Flow for the proxy-generated
// 414 / 431.
func requestHeadResponseFlow(st *flow.Stream, head *http1.RequestHeadError) *flow.Flow {
	return &flow.Flow{
		ID:          uuid.New().String(),
		StreamID:    st.ID,
		Sequence:    1,
		Direction:   envelope.Receive.String(),
		Timestamp:   time.Now(),
		RawBytes:    head.Response,
		StatusCode:  head.Status,
		HTTPVersion: envelope.HTTPVersion11,
		Metadata: map[string]string{
			"protocol":        string(envelope.ProtocolHTTP),
			"proxy_generated": "true",
		},
	}
}

// requestHeadHTTPVersion maps the wire HTTP-version token to the canonical
// Flow.HTTPVersion value, empty when it is neither HTTP/1.0 nor HTTP/1.1.
func requestHeadHTTPVersion(proto string) string {
	switch {
	case strings.EqualFold(proto, "HTTP/1.0"):
		return envelope.HTTPVersion10
	case strings.EqualFold(proto, "HTTP/1.1"):
		return envelope.HTTPVersion11
	default:
		return ""
	}
}

// recordH1RequestHead records err when it is a *http1.RequestHeadError and
// reports whether it was one. rec may be nil (no flow store): the error is
// still classified so callers log it uniformly.
func recordH1RequestHead(ctx context.Context, rec requestHeadRecorder, connID, target string, err error) bool {
	var head *http1.RequestHeadError
	if !errors.As(err, &head) {
		return false
	}
	if rec != nil {
		rec(ctx, requestHeadFailure{
			ConnID:     connID,
			ClientAddr: connector.ClientAddrFromContext(ctx),
			Target:     target,
			Head:       head,
		})
	}
	return true
}
