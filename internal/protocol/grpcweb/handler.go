package grpcweb

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
)

// Handler processes gRPC-Web sessions recorded from HTTP/1.x or HTTP/2 streams.
// It is not a standalone ProtocolHandler — it is invoked by the HTTP handler
// when a gRPC-Web Content-Type is detected on a request.
type Handler struct {
	store  flow.Writer
	logger *slog.Logger
}

// NewHandler creates a new gRPC-Web handler with flow recording.
func NewHandler(store flow.Writer, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// StreamInfo holds the information extracted from an HTTP/1.x or HTTP/2 stream
// for gRPC-Web recording.
//
// This type uses parser.RawHeaders (ordered []RawHeader) instead of
// map[string][]string to preserve header order and case as observed on the wire.
// HTTP/1.x handlers construct this directly from parser.RawHeaders.
// HTTP/2 handlers convert via httputil.HpackToRawHeaders().
type StreamInfo struct {
	// ConnID is the connection ID for log correlation.
	ConnID string
	// ClientAddr is the remote address of the client.
	ClientAddr string
	// ServerAddr is the resolved address of the upstream server.
	ServerAddr string

	// RequestHeaders are the HTTP request headers in wire order.
	RequestHeaders parser.RawHeaders
	// ResponseHeaders are the HTTP response headers in wire order.
	ResponseHeaders parser.RawHeaders

	// RequestBody is the raw request body bytes (before base64 decode).
	RequestBody []byte
	// ResponseBody is the raw response body bytes (before base64 decode).
	ResponseBody []byte

	// TLS holds the TLS connection state, if present.
	TLS *tls.ConnectionState
	// Start is the time the request started.
	Start time.Time
	// Duration is the total duration of the request.
	Duration time.Duration
	// StatusCode is the HTTP status code from the response.
	StatusCode int
	// Method is the HTTP request method (always POST for gRPC-Web).
	Method string
	// URL is the request URL (scheme://host/package.Service/Method).
	URL *url.URL
	// Scheme is the URL scheme ("https" for TLS, "http" for plaintext).
	Scheme string
}

// RecordSession records a gRPC-Web session from the given stream info.
// It decodes the gRPC-Web framing (base64 if needed), parses frames,
// determines session type, and stores the flow and messages.
func (h *Handler) RecordSession(ctx context.Context, info *StreamInfo) error {
	if h.store == nil {
		return nil
	}

	// Extract service/method from URL path.
	service, method, err := grpc.ParseServiceMethod(info.URL.Path)
	if err != nil {
		h.logger.Warn("gRPC-Web failed to parse service/method", "path", info.URL.Path, "error", err)
		service = "unknown"
		method = "unknown"
	}

	// Determine Content-Type to detect base64 encoding.
	contentType := info.RequestHeaders.Get("content-type")
	isBase64 := IsBase64Encoded(contentType)

	// Decode request body frames.
	reqResult, reqErr := DecodeBody(info.RequestBody, isBase64)
	if reqErr != nil {
		h.logger.Debug("gRPC-Web request frame parse warning", "error", reqErr)
		if reqResult == nil {
			reqResult = &ParseResult{}
		}
	}

	// Decode response body frames (response Content-Type may differ).
	respContentType := info.ResponseHeaders.Get("content-type")
	respIsBase64 := IsBase64Encoded(respContentType)
	respResult, respErr := DecodeBody(info.ResponseBody, respIsBase64)
	if respErr != nil {
		h.logger.Debug("gRPC-Web response frame parse warning", "error", respErr)
		if respResult == nil {
			respResult = &ParseResult{}
		}
	}

	// Determine session type based on data frame counts.

	// Detect trailers-only: no data frames AND no response body.
	trailersOnly := len(respResult.DataFrames) == 0 && len(info.ResponseBody) == 0

	// Extract grpc-status/grpc-message from embedded trailers or response headers.
	grpcStatus := extractGRPCWebStatus(respResult.Trailers, info.ResponseHeaders)
	grpcMessage := extractGRPCWebMessage(respResult.Trailers, info.ResponseHeaders)
	grpcEncoding := info.RequestHeaders.Get("grpc-encoding")

	// Build TLS metadata.
	tlsVersion, tlsCipher, tlsALPN, tlsCertSubject := extractTLSInfo(info.TLS)

	// Save flow.
	fl := &flow.Stream{
		ConnID:    info.ConnID,
		Protocol:  "gRPC-Web",
		Scheme:    info.Scheme,
		State:     "complete",
		Timestamp: info.Start,
		Duration:  info.Duration,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr:           info.ClientAddr,
			ServerAddr:           info.ServerAddr,
			TLSVersion:           tlsVersion,
			TLSCipher:            tlsCipher,
			TLSALPN:              tlsALPN,
			TLSServerCertSubject: tlsCertSubject,
		},
	}

	if err := h.store.SaveStream(ctx, fl); err != nil {
		return fmt.Errorf("save grpc-web session: %w", err)
	}

	logger := h.logger.With("flow_id", fl.ID, "service", service, "method", method)

	// Record messages.
	seq := 0
	seq = h.recordSendMessages(ctx, logger, fl.ID, info, service, method, grpcEncoding, reqResult.DataFrames, seq)
	h.recordReceiveMessages(ctx, logger, fl.ID, info, service, method, grpcStatus, grpcMessage, grpcEncoding, respResult, seq, trailersOnly)

	logger.Info("gRPC-Web flow recorded",
		"grpc_status", grpcStatus,
		"req_frames", len(reqResult.DataFrames),
		"resp_frames", len(respResult.DataFrames),
		"base64", isBase64,
		"duration_ms", info.Duration.Milliseconds())

	return nil
}

// recordSendMessages records gRPC-Web request data frames as send messages.
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
	headersMap := rawHeadersToMap(info.RequestHeaders)

	if len(frames) == 0 {
		// Even with no frames, record the request metadata.
		msg := &flow.Flow{
			StreamID:  flowID,
			Sequence:  seq,
			Direction: "send",
			Timestamp: info.Start,
			Method:    info.Method,
			URL:       info.URL,
			Headers:   headersMap,
			RawBytes:  info.RequestBody,
			Metadata:  buildSendMetadata(service, method, grpcEncoding, false),
		}
		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC-Web send message save failed", "sequence", seq, "error", err)
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

		// First send message carries HTTP metadata and raw bytes.
		if i == 0 {
			msg.Method = info.Method
			msg.URL = info.URL
			msg.Headers = headersMap
			msg.RawBytes = info.RequestBody
		}

		body := frame.Payload
		if len(body) > int(config.MaxBodySize) {
			msg.Body = body[:int(config.MaxBodySize)]
			msg.BodyTruncated = true
		} else {
			msg.Body = body
		}

		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC-Web send message save failed", "sequence", seq, "error", err)
		}
		seq++
	}

	return seq
}

// recordReceiveMessages records gRPC-Web response data frames as receive messages.
func (h *Handler) recordReceiveMessages(
	ctx context.Context,
	logger *slog.Logger,
	flowID string,
	info *StreamInfo,
	service, method, grpcStatus, grpcMessage, grpcEncoding string,
	result *ParseResult,
	startSeq int,
	trailersOnly bool,
) {
	seq := startSeq
	headersMap := rawHeadersToMap(info.ResponseHeaders)

	// Build trailer headers map from embedded trailers.
	var trailerHeaders map[string][]string
	if result.Trailers != nil {
		trailerHeaders = make(map[string][]string, len(result.Trailers))
		for k, v := range result.Trailers {
			trailerHeaders[k] = []string{v}
		}
	}

	frames := result.DataFrames
	if len(frames) == 0 {
		meta := buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding, false)
		if trailersOnly {
			meta["grpc_trailers_only"] = "true"
		}
		msg := &flow.Flow{
			StreamID:   flowID,
			Sequence:   seq,
			Direction:  "receive",
			Timestamp:  info.Start.Add(info.Duration),
			StatusCode: info.StatusCode,
			Headers:    mergeHeaders(headersMap, trailerHeaders),
			RawBytes:   info.ResponseBody,
			Metadata:   meta,
		}
		if err := h.store.SaveFlow(ctx, msg); err != nil {
			logger.Error("gRPC-Web receive message save failed", "sequence", seq, "error", err)
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

		// First receive message carries HTTP response metadata and raw bytes.
		if i == 0 {
			msg.StatusCode = info.StatusCode
			msg.Headers = headersMap
			msg.RawBytes = info.ResponseBody
		}

		// Last receive message carries embedded trailers and grpc-status.
		if isLast {
			msg.Metadata = buildReceiveMetadata(service, method, grpcStatus, grpcMessage, grpcEncoding, frame.Compressed)
			if msg.Headers == nil {
				msg.Headers = trailerHeaders
			} else {
				msg.Headers = mergeHeaders(msg.Headers, trailerHeaders)
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
			logger.Error("gRPC-Web receive message save failed", "sequence", seq, "error", err)
		}
		seq++
	}
}

// buildSendMetadata builds metadata for a gRPC-Web send message.
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

// buildReceiveMetadata builds metadata for a gRPC-Web receive message.
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

// extractGRPCWebStatus extracts grpc-status from embedded trailers or response headers.
// gRPC-Web sends trailers embedded in the response body, but for trailers-only
// responses the status may appear in the HTTP response headers.
func extractGRPCWebStatus(trailers map[string]string, headers parser.RawHeaders) string {
	if trailers != nil {
		if v, ok := trailers["grpc-status"]; ok {
			return v
		}
	}
	return headers.Get("grpc-status")
}

// extractGRPCWebMessage extracts grpc-message from embedded trailers or response headers.
func extractGRPCWebMessage(trailers map[string]string, headers parser.RawHeaders) string {
	if trailers != nil {
		if v, ok := trailers["grpc-message"]; ok {
			return v
		}
	}
	return headers.Get("grpc-message")
}

// rawHeadersToMap converts parser.RawHeaders to map[string][]string for
// storage in flow.Flow. Header names preserve their original wire casing.
func rawHeadersToMap(rh parser.RawHeaders) map[string][]string {
	if rh == nil {
		return make(map[string][]string)
	}
	m := make(map[string][]string, len(rh))
	for _, hdr := range rh {
		m[hdr.Name] = append(m[hdr.Name], hdr.Value)
	}
	return m
}

// flattenRawHeaders converts parser.RawHeaders to a flat map for plugin data.
// Multiple values for the same header are joined with ", ".
func flattenRawHeaders(headers parser.RawHeaders) map[string]any {
	if headers == nil {
		return map[string]any{}
	}
	// Collect values per header name.
	collected := make(map[string][]string, len(headers))
	order := make([]string, 0, len(headers))
	for _, hdr := range headers {
		if _, seen := collected[hdr.Name]; !seen {
			order = append(order, hdr.Name)
		}
		collected[hdr.Name] = append(collected[hdr.Name], hdr.Value)
	}
	result := make(map[string]any, len(order))
	for _, name := range order {
		vals := collected[name]
		if len(vals) == 1 {
			result[name] = vals[0]
		} else {
			result[name] = strings.Join(vals, ", ")
		}
	}
	return result
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

// extractTLSInfo extracts TLS metadata from a tls.ConnectionState.
func extractTLSInfo(state *tls.ConnectionState) (version, cipher, alpn, certSubject string) {
	if state == nil {
		return "", "", "", ""
	}
	switch state.Version {
	case tls.VersionTLS10:
		version = "TLS 1.0"
	case tls.VersionTLS11:
		version = "TLS 1.1"
	case tls.VersionTLS12:
		version = "TLS 1.2"
	case tls.VersionTLS13:
		version = "TLS 1.3"
	}
	cipher = tls.CipherSuiteName(state.CipherSuite)
	alpn = state.NegotiatedProtocol
	if len(state.PeerCertificates) > 0 {
		certSubject = state.PeerCertificates[0].Subject.String()
	}
	return
}
