package http2

import (
	"context"
	"log/slog"
	gohttp "net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// grpcProgressiveRecorder manages progressive (frame-by-frame) recording
// for a gRPC stream. It creates the flow on first use, appends each frame
// as a separate flow.Message, and updates the flow to "complete" on
// stream termination.
type grpcProgressiveRecorder struct {
	store  flow.FlowWriter
	logger *slog.Logger

	// flowID is set after initFlow. Empty means recording is disabled
	// (nil store or scope miss).
	flowID string

	// seq tracks the next message sequence number.
	seq atomic.Int64

	// messageCount tracks the total messages recorded for limit enforcement.
	messageCount atomic.Int64

	// recordingDisabled is set to true when the message limit is exceeded.
	recordingDisabled atomic.Bool

	// service and method are parsed from the URL path.
	service string
	method  string

	// grpcEncoding is the grpc-encoding header value (e.g., "gzip").
	grpcEncoding string
}

// initGRPCFlow creates the initial flow and send message for a gRPC stream.
// This is called when the gRPC request is first received, before upstream
// forwarding. The flow is created with State="active" and Protocol="gRPC".
//
// Returns the recorder (with flowID set) for use by the FrameBuffer callbacks.
// If recording is skipped (nil store, capture scope miss), the recorder's
// flowID remains empty and all subsequent calls are no-ops.
func (h *Handler) initGRPCFlow(ctx context.Context, sc *streamContext) *grpcProgressiveRecorder {
	rec := &grpcProgressiveRecorder{
		store:  h.Store,
		logger: sc.logger,
	}

	if h.Store == nil || h.grpcHandler == nil {
		return rec
	}

	if !h.shouldCapture(sc.req.Method, sc.reqURL) {
		return rec
	}

	// Parse service/method from URL path.
	service, method, err := protogrpc.ParseServiceMethod(sc.req.URL.Path)
	if err != nil {
		sc.logger.Warn("gRPC failed to parse service/method", "path", sc.req.URL.Path, "error", err)
		service = "unknown"
		method = "unknown"
	}
	rec.service = service
	rec.method = method

	// Extract grpc-encoding from request headers.
	rec.grpcEncoding = sc.req.Header.Get("grpc-encoding")

	// Create flow with State="active".
	protocol := proxy.SOCKS5Protocol(ctx, "gRPC")
	tags := proxy.MergeSOCKS5Tags(ctx, nil)

	fl := &flow.Flow{
		ConnID:    sc.connID,
		Protocol:  protocol,
		Scheme:    sc.flowScheme,
		FlowType:  "unary", // Updated to stream/bidirectional on completion.
		State:     "active",
		Timestamp: sc.start,
		Tags:      tags,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: sc.clientAddr,
			TLSVersion: sc.tlsMeta.Version,
			TLSCipher:  sc.tlsMeta.CipherSuite,
			TLSALPN:    sc.tlsMeta.ALPN,
		},
	}
	if err := h.Store.SaveFlow(ctx, fl); err != nil {
		sc.logger.Error("gRPC progressive flow save failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err)
		return rec
	}

	rec.flowID = fl.ID

	// Record the initial send message with request headers.
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: sc.start,
		Method:    sc.req.Method,
		URL:       sc.reqURL,
		Headers:   requestHeaders(sc.req),
		Metadata: map[string]string{
			"service":   service,
			"method":    method,
			"grpc_type": "headers",
		},
	}
	if rec.grpcEncoding != "" {
		sendMsg.Metadata["grpc_encoding"] = rec.grpcEncoding
	}
	if err := h.Store.AppendMessage(ctx, sendMsg); err != nil {
		sc.logger.Error("gRPC progressive send headers save failed", "error", err)
	}
	rec.seq.Store(1) // Next sequence after the initial send message.

	return rec
}

// recordFrame records a single gRPC frame as a flow.Message.
// direction is "client_to_server" or "server_to_client".
// This is called from the FrameBuffer callbacks.
func (r *grpcProgressiveRecorder) recordFrame(ctx context.Context, frame *protogrpc.Frame, direction string) {
	if r.flowID == "" || r.store == nil {
		return
	}

	if r.recordingDisabled.Load() {
		return
	}

	if r.messageCount.Load() >= int64(config.MaxGRPCMessagesPerStream) {
		if !r.recordingDisabled.Swap(true) {
			r.logger.Info("gRPC message recording limit reached, forwarding only",
				"flow_id", r.flowID,
				"limit", config.MaxGRPCMessagesPerStream)
		}
		return
	}
	r.messageCount.Add(1)

	seq := int(r.seq.Add(1) - 1)

	msgDirection := "send"
	if direction == "server_to_client" {
		msgDirection = "receive"
	}

	metadata := map[string]string{
		"direction":  direction,
		"sequence":   strconv.Itoa(seq),
		"compressed": strconv.FormatBool(frame.Compressed),
		"encoding":   "protobuf",
	}
	if r.grpcEncoding != "" {
		metadata["grpc_encoding"] = r.grpcEncoding
	}

	body := frame.Payload
	truncated := false
	if len(body) > int(config.MaxBodySize) {
		body = body[:int(config.MaxBodySize)]
		truncated = true
	}

	msg := &flow.Message{
		FlowID:        r.flowID,
		Sequence:      seq,
		Direction:     msgDirection,
		Timestamp:     time.Now(),
		Body:          body,
		BodyTruncated: truncated,
		Metadata:      metadata,
	}

	if err := r.store.AppendMessage(ctx, msg); err != nil {
		r.logger.Error("gRPC progressive frame save failed",
			"flow_id", r.flowID,
			"sequence", seq,
			"direction", direction,
			"error", err,
		)
	}
}

// completeFlow updates the flow to State="complete" with final metadata.
// It determines the flow type based on the frame counts and records
// response trailers.
func (r *grpcProgressiveRecorder) completeFlow(
	ctx context.Context,
	resp *gohttp.Response,
	reqFrameCount, respFrameCount int,
	duration time.Duration,
) {
	if r.flowID == "" || r.store == nil {
		return
	}

	flowType := protogrpc.ClassifyFlowType(reqFrameCount, respFrameCount)

	// Extract gRPC metadata from trailers.
	var trailers map[string][]string
	if resp != nil && resp.Trailer != nil {
		trailers = make(map[string][]string, len(resp.Trailer))
		for k, vals := range resp.Trailer {
			trailers[k] = vals
		}
	}

	grpcStatus := protogrpc.ExtractGRPCStatus(trailers, respHeadersMap(resp))
	grpcMessage := protogrpc.ExtractGRPCMessage(trailers, respHeadersMap(resp))

	// Record final receive message with trailers and status.
	finalSeq := int(r.seq.Add(1) - 1)
	finalMeta := map[string]string{
		"grpc_type": "trailers",
		"service":   r.service,
		"method":    r.method,
	}
	if grpcStatus != "" {
		finalMeta["grpc_status"] = grpcStatus
	}
	if grpcMessage != "" {
		finalMeta["grpc_message"] = grpcMessage
	}

	totalMessages := int(r.messageCount.Load())
	finalMeta["message_count"] = strconv.Itoa(totalMessages)

	finalMsg := &flow.Message{
		FlowID:    r.flowID,
		Sequence:  finalSeq,
		Direction: "receive",
		Timestamp: time.Now(),
		Metadata:  finalMeta,
	}
	if resp != nil {
		finalMsg.StatusCode = resp.StatusCode
		if trailers != nil {
			finalMsg.Headers = trailers
		}
	}
	if err := r.store.AppendMessage(ctx, finalMsg); err != nil {
		r.logger.Error("gRPC progressive trailers save failed",
			"flow_id", r.flowID,
			"error", err,
		)
	}

	// Build tags, preserving SOCKS5 metadata from the context.
	tags := proxy.MergeSOCKS5Tags(ctx, map[string]string{
		"streaming_type": "grpc",
		"grpc_service":   r.service,
		"grpc_method":    r.method,
	})
	if grpcStatus != "" {
		tags["grpc_status"] = grpcStatus
	}
	if totalMessages > 0 {
		tags["grpc_messages_recorded"] = strconv.Itoa(totalMessages)
	}

	tlsCertSubject := ""
	if resp != nil {
		tlsCertSubject = extractTLSCertSubject(resp)
	}

	update := flow.FlowUpdate{
		State:                "complete",
		FlowType:             flowType,
		Duration:             duration,
		Tags:                 tags,
		TLSServerCertSubject: tlsCertSubject,
	}
	if err := r.store.UpdateFlow(ctx, r.flowID, update); err != nil {
		r.logger.Error("gRPC progressive flow completion failed",
			"flow_id", r.flowID,
			"error", err,
		)
	}
}

// respHeadersMap safely returns response headers or nil.
func respHeadersMap(resp *gohttp.Response) map[string][]string {
	if resp == nil {
		return nil
	}
	return resp.Header
}
