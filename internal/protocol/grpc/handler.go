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
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// Handler processes gRPC sessions recorded from HTTP/2 streams.
// It is not a standalone ProtocolHandler — it is invoked by the HTTP/2 handler
// when Content-Type: application/grpc is detected on a stream.
type Handler struct {
	store        flow.FlowWriter
	logger       *slog.Logger
	pluginEngine *plugin.Engine
}

// NewHandler creates a new gRPC handler with flow recording.
func NewHandler(store flow.FlowWriter, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// SetPluginEngine sets the plugin engine for hook dispatch.
// When set, the handler dispatches plugin hooks for each gRPC frame
// during session recording.
func (h *Handler) SetPluginEngine(engine *plugin.Engine) {
	h.pluginEngine = engine
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

	// Determine session type based on frame counts.
	sessionType := classifyFlowType(len(reqFrames), len(respFrames))

	// Extract grpc-status from trailers or response headers.
	grpcStatus := extractGRPCStatus(info.Trailers, info.ResponseHeaders)
	grpcMessage := extractGRPCMessage(info.Trailers, info.ResponseHeaders)
	grpcEncoding := extractHeader(info.RequestHeaders, "grpc-encoding")

	// Save flow.
	fl := &flow.Flow{
		ConnID:    info.ConnID,
		Protocol:  "gRPC",
		FlowType:  sessionType,
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

	if err := h.store.SaveFlow(ctx, fl); err != nil {
		return fmt.Errorf("save grpc session: %w", err)
	}

	logger := h.logger.With("flow_id", fl.ID, "service", service, "method", method)

	// Dispatch plugin hooks for request frames (on_receive_from_client).
	h.dispatchRequestHooks(ctx, logger, info, service, method, grpcEncoding, reqFrames)

	// Dispatch plugin hooks for response frames (on_receive_from_server).
	h.dispatchResponseHooks(ctx, logger, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames)

	// Record messages based on session type.
	seq := 0

	if sessionType == "unary" {
		// Unary: one send message (seq=0), one receive message (seq=1).
		seq = h.recordSendMessages(ctx, logger, fl.ID, info, service, method, grpcEncoding, reqFrames, seq)
		h.recordReceiveMessages(ctx, logger, fl.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames, seq)
	} else {
		// Streaming: record all request frames as send, all response frames as receive.
		seq = h.recordSendMessages(ctx, logger, fl.ID, info, service, method, grpcEncoding, reqFrames, seq)
		h.recordReceiveMessages(ctx, logger, fl.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respFrames, seq)
	}

	logger.Info("gRPC flow recorded",
		"flow_type", sessionType,
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
		msg := &flow.Message{
			FlowID:    flowID,
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
		msg := &flow.Message{
			FlowID:    flowID,
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
	flowID string,
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, grpcEncoding string,
	frames []*Frame,
	startSeq int,
) {
	seq := startSeq

	if len(frames) == 0 {
		// Record the response metadata even without frames (e.g., error responses).
		msg := &flow.Message{
			FlowID:     flowID,
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
		msg := &flow.Message{
			FlowID:    flowID,
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

		if err := h.store.AppendMessage(ctx, msg); err != nil {
			logger.Error("gRPC receive message save failed", "sequence", seq, "error", err)
		}
		seq++
	}
}

// dispatchRequestHooks dispatches on_receive_from_client hooks for each gRPC request frame.
// Plugin results are logged but do not modify the request data, as gRPC frames
// are recorded after being received from the upstream connection.
func (h *Handler) dispatchRequestHooks(
	ctx context.Context,
	logger *slog.Logger,
	info *StreamInfo,
	service, method, grpcEncoding string,
	frames []*Frame,
) {
	if h.pluginEngine == nil {
		return
	}

	connInfo := buildConnInfo(info)

	if len(frames) == 0 {
		data := buildGRPCRequestData(info, service, method, grpcEncoding, nil, false, connInfo)
		h.dispatchHook(ctx, logger, plugin.HookOnReceiveFromClient, data)
		return
	}

	for _, frame := range frames {
		data := buildGRPCRequestData(info, service, method, grpcEncoding, frame.Payload, frame.Compressed, connInfo)
		h.dispatchHook(ctx, logger, plugin.HookOnReceiveFromClient, data)
	}
}

// dispatchResponseHooks dispatches on_receive_from_server hooks for each gRPC response frame.
func (h *Handler) dispatchResponseHooks(
	ctx context.Context,
	logger *slog.Logger,
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, grpcEncoding string,
	frames []*Frame,
) {
	if h.pluginEngine == nil {
		return
	}

	connInfo := buildConnInfo(info)

	if len(frames) == 0 {
		data := buildGRPCResponseData(info, service, method, grpcStatus, grpcMessage, grpcEncoding, nil, false, connInfo)
		h.dispatchHook(ctx, logger, plugin.HookOnReceiveFromServer, data)
		return
	}

	for _, frame := range frames {
		data := buildGRPCResponseData(info, service, method, grpcStatus, grpcMessage, grpcEncoding, frame.Payload, frame.Compressed, connInfo)
		h.dispatchHook(ctx, logger, plugin.HookOnReceiveFromServer, data)
	}
}

// dispatchHook dispatches a single plugin hook and logs any errors.
func (h *Handler) dispatchHook(ctx context.Context, logger *slog.Logger, hook plugin.Hook, data map[string]any) {
	result, err := h.pluginEngine.Dispatch(ctx, hook, data)
	if err != nil {
		logger.Warn("gRPC plugin hook error",
			slog.String("hook", string(hook)),
			slog.String("error", err.Error()),
		)
		return
	}
	if result != nil && result.Action != plugin.ActionContinue {
		logger.Info("gRPC plugin hook returned non-continue action (ignored for gRPC)",
			slog.String("hook", string(hook)),
			slog.String("action", result.Action.String()),
		)
	}
}

// buildGRPCRequestData constructs the plugin data map for a gRPC request frame.
func buildGRPCRequestData(
	info *StreamInfo,
	service, method, encoding string,
	body []byte,
	compressed bool,
	connInfo map[string]any,
) map[string]any {
	headers := flattenHeaders(info.RequestHeaders)

	data := map[string]any{
		"protocol":   "grpc",
		"service":    service,
		"method":     method,
		"url":        info.URL.String(),
		"headers":    headers,
		"compressed": compressed,
		"conn_info":  connInfo,
	}
	if encoding != "" {
		data["encoding"] = encoding
	}
	if body != nil {
		data["body"] = body
	}
	return data
}

// buildGRPCResponseData constructs the plugin data map for a gRPC response frame.
func buildGRPCResponseData(
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, encoding string,
	body []byte,
	compressed bool,
	connInfo map[string]any,
) map[string]any {
	headers := flattenHeaders(info.ResponseHeaders)
	trailers := flattenHeaders(info.Trailers)

	data := map[string]any{
		"protocol":    "grpc",
		"service":     service,
		"method":      method,
		"status_code": info.StatusCode,
		"headers":     headers,
		"trailers":    trailers,
		"compressed":  compressed,
		"conn_info":   connInfo,
	}
	if grpcStatus != "" {
		data["grpc_status"] = grpcStatus
	}
	if grpcMessage != "" {
		data["grpc_message"] = grpcMessage
	}
	if encoding != "" {
		data["encoding"] = encoding
	}
	if body != nil {
		data["body"] = body
	}
	return data
}

// buildConnInfo constructs a connection info map from StreamInfo.
func buildConnInfo(info *StreamInfo) map[string]any {
	ci := map[string]any{
		"client_addr": info.ClientAddr,
		"server_addr": info.ServerAddr,
	}
	if info.TLSVersion != "" {
		ci["tls_version"] = info.TLSVersion
	}
	if info.TLSCipher != "" {
		ci["tls_cipher"] = info.TLSCipher
	}
	if info.TLSALPN != "" {
		ci["tls_alpn"] = info.TLSALPN
	}
	if info.TLSServerCertSubject != "" {
		ci["tls_server_cert_subject"] = info.TLSServerCertSubject
	}
	return ci
}

// flattenHeaders converts multi-value headers to single-value strings
// for use in plugin data maps. Multiple values are joined with ", ".
func flattenHeaders(headers map[string][]string) map[string]any {
	if headers == nil {
		return map[string]any{}
	}
	result := make(map[string]any, len(headers))
	for k, vals := range headers {
		if len(vals) == 1 {
			result[k] = vals[0]
		} else {
			result[k] = strings.Join(vals, ", ")
		}
	}
	return result
}

// classifyFlowType determines the gRPC session type based on frame counts.
func classifyFlowType(reqFrames, respFrames int) string {
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
