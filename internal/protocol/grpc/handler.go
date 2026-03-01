package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxBodyRecordSize limits the body size recorded per message to 1MB.
const maxBodyRecordSize = 1 << 20

// Handler processes gRPC sessions recorded from HTTP/2 streams.
// It is not a standalone ProtocolHandler — it is invoked by the HTTP/2 handler
// when Content-Type: application/grpc is detected on a stream.
type Handler struct {
	store  session.Store
	logger *slog.Logger
}

// NewHandler creates a new gRPC handler with session recording.
func NewHandler(store session.Store, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// IsGRPC reports whether the given Content-Type indicates a gRPC request.
// gRPC uses "application/grpc", "application/grpc+proto", "application/grpc+json", etc.
func IsGRPC(contentType string) bool {
	ct := strings.TrimSpace(contentType)
	// Normalize: take only the media type, ignore parameters.
	if idx := strings.Index(ct, ";"); idx != -1 {
		ct = strings.TrimSpace(ct[:idx])
	}
	return ct == "application/grpc" || strings.HasPrefix(ct, "application/grpc+")
}

// ParseServiceMethod extracts the gRPC service and method names from a URL path.
// gRPC paths follow the pattern: /package.Service/Method
// Returns (service, method, error).
func ParseServiceMethod(path string) (string, string, error) {
	// Remove leading slash.
	path = strings.TrimPrefix(path, "/")
	if path == "" {
		return "", "", fmt.Errorf("empty grpc path")
	}

	idx := strings.LastIndex(path, "/")
	if idx < 0 || idx == 0 || idx == len(path)-1 {
		return "", "", fmt.Errorf("invalid grpc path: %q", "/"+path)
	}

	service := path[:idx]
	method := path[idx+1:]
	return service, method, nil
}

// StreamInfo holds the information extracted from an HTTP/2 stream for gRPC recording.
type StreamInfo struct {
	// ConnID is the connection ID for log correlation.
	ConnID string
	// ClientAddr is the remote address of the client.
	ClientAddr string
	// ServerAddr is the resolved address of the upstream server.
	ServerAddr string
	// Method is the HTTP method (always POST for gRPC).
	Method string
	// URL is the request URL (scheme://host/package.Service/Method).
	URL *url.URL
	// RequestHeaders are the HTTP/2 request headers.
	RequestHeaders map[string][]string
	// ResponseHeaders are the HTTP/2 response headers.
	ResponseHeaders map[string][]string
	// Trailers are the HTTP/2 trailers (gRPC sends grpc-status and grpc-message here).
	Trailers map[string][]string
	// RequestBody is the raw request body (may contain multiple gRPC frames).
	RequestBody []byte
	// ResponseBody is the raw response body (may contain multiple gRPC frames).
	ResponseBody []byte
	// StatusCode is the HTTP status code from the response.
	StatusCode int
	// Start is the time the request started.
	Start time.Time
	// Duration is the total duration of the request.
	Duration time.Duration
	// TLSVersion is the negotiated TLS version (if any).
	TLSVersion string
	// TLSCipher is the negotiated TLS cipher suite (if any).
	TLSCipher string
	// TLSALPN is the negotiated ALPN protocol (if any).
	TLSALPN string
	// TLSServerCertSubject is the subject of the upstream server's TLS certificate.
	TLSServerCertSubject string
}

// RecordSession records a gRPC session from the given stream info.
// It parses gRPC frames from the request/response bodies, determines the
// session type (unary or streaming), and stores the session and messages.
func (h *Handler) RecordSession(ctx context.Context, info *StreamInfo) error {
	if h.store == nil {
		return nil
	}

	service, method, err := ParseServiceMethod(info.URL.Path)
	if err != nil {
		h.logger.Warn("gRPC failed to parse service/method", "path", info.URL.Path, "error", err)
		service = "unknown"
		method = "unknown"
	}

	// Parse gRPC frames from request and response bodies.
	reqFrames, reqErr := ReadAllFrames(info.RequestBody)
	if reqErr != nil {
		h.logger.Debug("gRPC request frame parse warning", "error", reqErr)
	}

	respFrames, respErr := ReadAllFrames(info.ResponseBody)
	if respErr != nil {
		h.logger.Debug("gRPC response frame parse warning", "error", respErr)
	}

	// Determine session type based on frame counts.
	sessionType := classifySessionType(len(reqFrames), len(respFrames))

	// Extract grpc-status from trailers or response headers.
	grpcStatus := extractGRPCStatus(info.Trailers, info.ResponseHeaders)
	grpcMessage := extractGRPCMessage(info.Trailers, info.ResponseHeaders)
	grpcEncoding := extractHeader(info.RequestHeaders, "grpc-encoding")

	// Save session.
	sess := &session.Session{
		ConnID:      info.ConnID,
		Protocol:    "gRPC",
		SessionType: sessionType,
		State:       "complete",
		Timestamp:   info.Start,
		Duration:    info.Duration,
		ConnInfo: &session.ConnectionInfo{
			ClientAddr:           info.ClientAddr,
			ServerAddr:           info.ServerAddr,
			TLSVersion:           info.TLSVersion,
			TLSCipher:            info.TLSCipher,
			TLSALPN:              info.TLSALPN,
			TLSServerCertSubject: info.TLSServerCertSubject,
		},
	}

	if err := h.store.SaveSession(ctx, sess); err != nil {
		return fmt.Errorf("save grpc session: %w", err)
	}

	logger := h.logger.With("session_id", sess.ID, "service", service, "method", method)

	// Record messages based on session type.
	seq := 0

	if sessionType == "unary" {
		// Unary: one send message (seq=0), one receive message (seq=1).
		seq = h.recordSendMessages(ctx, logger, sess.ID, info, service, method, grpcEncoding, reqFrames, seq)
		h.recordReceiveMessages(ctx, logger, sess.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames, seq)
	} else {
		// Streaming: record all request frames as send, all response frames as receive.
		seq = h.recordSendMessages(ctx, logger, sess.ID, info, service, method, grpcEncoding, reqFrames, seq)
		h.recordReceiveMessages(ctx, logger, sess.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames, seq)
	}

	logger.Info("gRPC session recorded",
		"session_type", sessionType,
		"grpc_status", grpcStatus,
		"req_frames", len(reqFrames),
		"resp_frames", len(respFrames),
		"duration_ms", info.Duration.Milliseconds())

	return nil
}

// recordSendMessages records gRPC request frames as send messages.
// Returns the next sequence number.
func (h *Handler) recordSendMessages(
	ctx context.Context,
	logger *slog.Logger,
	sessionID string,
	info *StreamInfo,
	service, method, grpcEncoding string,
	frames []*Frame,
	startSeq int,
) int {
	seq := startSeq

	if len(frames) == 0 {
		// Even with no frames, record the request metadata.
		msg := &session.Message{
			SessionID: sessionID,
			Sequence:  seq,
			Direction: "send",
			Timestamp: info.Start,
			Method:    info.Method,
			URL:       info.URL,
			Headers:   info.RequestHeaders,
			Metadata:  buildSendMetadata(service, method, grpcEncoding, false),
		}
		if err := h.store.AppendMessage(ctx, msg); err != nil {
			logger.Error("gRPC send message save failed", "sequence", seq, "error", err)
		}
		return seq + 1
	}

	for i, frame := range frames {
		msg := &session.Message{
			SessionID: sessionID,
			Sequence:  seq,
			Direction: "send",
			Timestamp: info.Start,
			Metadata:  buildSendMetadata(service, method, grpcEncoding, frame.Compressed),
		}

		// First send message carries HTTP metadata.
		if i == 0 {
			msg.Method = info.Method
			msg.URL = info.URL
			msg.Headers = info.RequestHeaders
		}

		body := frame.Payload
		if len(body) > maxBodyRecordSize {
			msg.Body = body[:maxBodyRecordSize]
			msg.BodyTruncated = true
		} else {
			msg.Body = body
		}

		if err := h.store.AppendMessage(ctx, msg); err != nil {
			logger.Error("gRPC send message save failed", "sequence", seq, "error", err)
		}
		seq++
	}

	return seq
}

// recordReceiveMessages records gRPC response frames as receive messages.
func (h *Handler) recordReceiveMessages(
	ctx context.Context,
	logger *slog.Logger,
	sessionID string,
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, grpcEncoding string,
	frames []*Frame,
	startSeq int,
) {
	seq := startSeq

	if len(frames) == 0 {
		// Record the response metadata even without frames (e.g., error responses).
		msg := &session.Message{
			SessionID:  sessionID,
			Sequence:   seq,
			Direction:  "receive",
			Timestamp:  info.Start.Add(info.Duration),
			StatusCode: info.StatusCode,
			Headers:    mergeHeaders(info.ResponseHeaders, info.Trailers),
			Metadata:   buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding, false),
		}
		if err := h.store.AppendMessage(ctx, msg); err != nil {
			logger.Error("gRPC receive message save failed", "sequence", seq, "error", err)
		}
		return
	}

	for i, frame := range frames {
		isLast := i == len(frames)-1
		msg := &session.Message{
			SessionID: sessionID,
			Sequence:  seq,
			Direction: "receive",
			Timestamp: info.Start.Add(info.Duration),
		}

		// First receive message carries HTTP response metadata.
		if i == 0 {
			msg.StatusCode = info.StatusCode
			msg.Headers = info.ResponseHeaders
		}

		// Last receive message carries trailers and grpc-status.
		if isLast {
			msg.Metadata = buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding, frame.Compressed)
			// Merge trailers into headers if this is the last frame.
			if msg.Headers == nil {
				msg.Headers = info.Trailers
			} else {
				msg.Headers = mergeHeaders(msg.Headers, info.Trailers)
			}
		} else {
			msg.Metadata = buildReceiveMetadata(service, method, "", "", grpcEncoding, frame.Compressed)
		}

		body := frame.Payload
		if len(body) > maxBodyRecordSize {
			msg.Body = body[:maxBodyRecordSize]
			msg.BodyTruncated = true
		} else {
			msg.Body = body
		}

		if err := h.store.AppendMessage(ctx, msg); err != nil {
			logger.Error("gRPC receive message save failed", "sequence", seq, "error", err)
		}
		seq++
	}
}

// classifySessionType determines the gRPC session type based on frame counts.
func classifySessionType(reqFrames, respFrames int) string {
	if reqFrames <= 1 && respFrames <= 1 {
		return "unary"
	}
	if reqFrames > 1 && respFrames > 1 {
		return "bidirectional"
	}
	// Client streaming (multiple request frames, single response) or
	// server streaming (single request, multiple response frames).
	return "stream"
}

// buildSendMetadata builds metadata for a gRPC send message.
func buildSendMetadata(service, method, grpcEncoding string, compressed bool) map[string]string {
	meta := map[string]string{
		"service": service,
		"method":  method,
	}
	if grpcEncoding != "" {
		meta["grpc_encoding"] = grpcEncoding
	}
	if compressed {
		meta["compressed"] = "true"
	}
	return meta
}

// buildReceiveMetadata builds metadata for a gRPC receive message.
func buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding string, compressed bool) map[string]string {
	meta := map[string]string{
		"service": service,
		"method":  method,
	}
	if grpcStatus != "" {
		meta["grpc_status"] = grpcStatus
	}
	if grpcMessage != "" {
		meta["grpc_message"] = grpcMessage
	}
	if grpcEncoding != "" {
		meta["grpc_encoding"] = grpcEncoding
	}
	if compressed {
		meta["compressed"] = "true"
	}
	return meta
}

// extractGRPCStatus extracts the grpc-status value from trailers or response headers.
// gRPC typically sends grpc-status in trailers, but it may appear in headers
// for Trailers-Only responses.
func extractGRPCStatus(trailers, headers map[string][]string) string {
	if v := extractHeader(trailers, "grpc-status"); v != "" {
		return v
	}
	return extractHeader(headers, "grpc-status")
}

// extractGRPCMessage extracts the grpc-message value from trailers or response headers.
func extractGRPCMessage(trailers, headers map[string][]string) string {
	if v := extractHeader(trailers, "grpc-message"); v != "" {
		return v
	}
	return extractHeader(headers, "grpc-message")
}

// extractHeader returns the first value for the given header key (case-insensitive).
func extractHeader(headers map[string][]string, key string) string {
	if headers == nil {
		return ""
	}
	// Try exact match first (common case for canonicalized headers).
	if vals, ok := headers[key]; ok && len(vals) > 0 {
		return vals[0]
	}
	// Try canonical HTTP header form.
	canonical := strings.ToLower(key)
	for k, vals := range headers {
		if strings.ToLower(k) == canonical && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// mergeHeaders creates a new header map that combines two header maps.
// Values from the second map are appended to the first.
func mergeHeaders(a, b map[string][]string) map[string][]string {
	if a == nil && b == nil {
		return nil
	}
	result := make(map[string][]string)
	for k, vals := range a {
		result[k] = append([]string{}, vals...)
	}
	for k, vals := range b {
		result[k] = append(result[k], vals...)
	}
	return result
}

// GRPCStatusName returns a human-readable name for common gRPC status codes.
func GRPCStatusName(code int) string {
	switch code {
	case 0:
		return "OK"
	case 1:
		return "CANCELLED"
	case 2:
		return "UNKNOWN"
	case 3:
		return "INVALID_ARGUMENT"
	case 4:
		return "DEADLINE_EXCEEDED"
	case 5:
		return "NOT_FOUND"
	case 6:
		return "ALREADY_EXISTS"
	case 7:
		return "PERMISSION_DENIED"
	case 8:
		return "RESOURCE_EXHAUSTED"
	case 9:
		return "FAILED_PRECONDITION"
	case 10:
		return "ABORTED"
	case 11:
		return "OUT_OF_RANGE"
	case 12:
		return "UNIMPLEMENTED"
	case 13:
		return "INTERNAL"
	case 14:
		return "UNAVAILABLE"
	case 15:
		return "DATA_LOSS"
	case 16:
		return "UNAUTHENTICATED"
	default:
		return strconv.Itoa(code)
	}
}
