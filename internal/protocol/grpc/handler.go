package grpc

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// Handler processes gRPC sessions recorded from HTTP/2 streams.
// It is not a standalone ProtocolHandler — it is invoked by the HTTP/2 handler
// when Content-Type: application/grpc is detected on a stream.
type Handler struct {
	store  flow.Writer
	logger *slog.Logger
}

// NewHandler creates a new gRPC handler with flow recording.
func NewHandler(store flow.Writer, logger *slog.Logger) *Handler {
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
	// Scheme is the URL scheme ("https" for TLS, "http" for plaintext).
	Scheme string
}

// RecordSession records a gRPC session from the given stream info.
// It parses gRPC frames from the request/response bodies, determines the
// session type (unary or streaming), and stores the flow and messages.
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

	// Detect trailers-only: no parsed frames AND no response body data.
	// Using len(respFrames)==0 alone would false-positive when frames exist
	// but failed to parse (e.g., MaxBodySize truncation, incomplete frames).
	trailersOnly := len(respFrames) == 0 && len(info.ResponseBody) == 0

	// Extract grpc-status from trailers or response headers.
	grpcStatus := ExtractGRPCStatus(info.Trailers, info.ResponseHeaders)
	grpcMessage := ExtractGRPCMessage(info.Trailers, info.ResponseHeaders)
	grpcEncoding := extractHeader(info.RequestHeaders, "grpc-encoding")

	// Save flow.
	fl := &flow.Stream{
		ConnID:    info.ConnID,
		Protocol:  "gRPC",
		Scheme:    info.Scheme,
		State:     "complete",
		Timestamp: info.Start,
		Duration:  info.Duration,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr:           info.ClientAddr,
			ServerAddr:           info.ServerAddr,
			TLSVersion:           info.TLSVersion,
			TLSCipher:            info.TLSCipher,
			TLSALPN:              info.TLSALPN,
			TLSServerCertSubject: info.TLSServerCertSubject,
		},
	}

	if err := h.store.SaveStream(ctx, fl); err != nil {
		return fmt.Errorf("save grpc session: %w", err)
	}

	logger := h.logger.With("flow_id", fl.ID, "service", service, "method", method)

	// Record flows: all request frames as send, all response frames as receive.
	seq := 0
	seq = h.recordSendMessages(ctx, logger, fl.ID, info, service, method, grpcEncoding, reqFrames, seq)
	h.recordReceiveMessages(ctx, logger, fl.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames, seq, trailersOnly)

	logger.Info("gRPC stream recorded",
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
	flowID string,
	info *StreamInfo,
	service, method, grpcEncoding string,
	frames []*Frame,
	startSeq int,
) int {
	seq := startSeq

	if len(frames) == 0 {
		// Even with no frames, record the request metadata.
		msg := &flow.Flow{
			StreamID:  flowID,
			Sequence:  seq,
			Direction: "send",
			Timestamp: info.Start,
			Method:    info.Method,
			URL:       info.URL,
			Headers:   info.RequestHeaders,
			Metadata:  buildSendMetadata(service, method, grpcEncoding, false),
		}
		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC send message save failed", "sequence", seq, "error", err)
		}
		return seq + 1
	}

	for i, frame := range frames {
		msg := &flow.Flow{
			StreamID:  flowID,
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
		if len(body) > int(config.MaxBodySize) {
			msg.Body = body[:int(config.MaxBodySize)]
			msg.BodyTruncated = true
		} else {
			msg.Body = body
		}

		if err := h.store.SaveFlow(ctx, msg); err != nil {
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
	flowID string,
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, grpcEncoding string,
	frames []*Frame,
	startSeq int,
	trailersOnly bool,
) {
	seq := startSeq

	if len(frames) == 0 {
		// Record the response metadata even without frames (e.g., error responses).
		meta := buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding, false)
		// Only mark as trailers-only when the response body was truly empty.
		// len(frames)==0 alone could be a false positive from parse failure.
		if trailersOnly {
			meta["grpc_trailers_only"] = "true"
		}
		msg := &flow.Flow{
			StreamID:   flowID,
			Sequence:   seq,
			Direction:  "receive",
			Timestamp:  info.Start.Add(info.Duration),
			StatusCode: info.StatusCode,
			Headers:    mergeHeaders(info.ResponseHeaders, info.Trailers),
			Metadata:   meta,
		}
		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC receive message save failed", "sequence", seq, "error", err)
		}
		return
	}

	for i, frame := range frames {
		isLast := i == len(frames)-1
		msg := &flow.Flow{
			StreamID:  flowID,
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
		if len(body) > int(config.MaxBodySize) {
			msg.Body = body[:int(config.MaxBodySize)]
			msg.BodyTruncated = true
		} else {
			msg.Body = body
		}

		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC receive message save failed", "sequence", seq, "error", err)
		}
		seq++
	}
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

// ExtractGRPCStatus extracts the grpc-status value from trailers or response headers.
// gRPC typically sends grpc-status in trailers, but it may appear in headers
// for Trailers-Only responses.
func ExtractGRPCStatus(trailers, headers map[string][]string) string {
	if v := extractHeader(trailers, "grpc-status"); v != "" {
		return v
	}
	return extractHeader(headers, "grpc-status")
}

// ExtractGRPCMessage extracts the grpc-message value from trailers or response headers.
func ExtractGRPCMessage(trailers, headers map[string][]string) string {
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

// grpcStatusNames maps gRPC status codes to their human-readable names.
var grpcStatusNames = map[int]string{
	0:  "OK",
	1:  "CANCELLED",
	2:  "UNKNOWN",
	3:  "INVALID_ARGUMENT",
	4:  "DEADLINE_EXCEEDED",
	5:  "NOT_FOUND",
	6:  "ALREADY_EXISTS",
	7:  "PERMISSION_DENIED",
	8:  "RESOURCE_EXHAUSTED",
	9:  "FAILED_PRECONDITION",
	10: "ABORTED",
	11: "OUT_OF_RANGE",
	12: "UNIMPLEMENTED",
	13: "INTERNAL",
	14: "UNAVAILABLE",
	15: "DATA_LOSS",
	16: "UNAUTHENTICATED",
}

// GRPCStatusName returns a human-readable name for common gRPC status codes.
func GRPCStatusName(code int) string {
	if name, ok := grpcStatusNames[code]; ok {
		return name
	}
	return strconv.Itoa(code)
}
