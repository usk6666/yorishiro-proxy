package http2

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// grpcStreamState holds the mutable state accumulated during gRPC stream
// processing. It is passed between the sub-methods of handleGRPCStream.
type grpcStreamState struct {
	reqFrameBuf  *protogrpc.FrameBuffer
	respFrameBuf *protogrpc.FrameBuffer

	// recorder handles progressive flow recording (frame-by-frame).
	recorder *grpcProgressiveRecorder

	// reqFrameCount and respFrameCount track total frames for flow type
	// classification at completion time.
	reqFrameCount  atomic.Int64
	respFrameCount atomic.Int64

	mu           sync.Mutex
	reqStreamErr error

	// grpcEncoding is the grpc-encoding header value from the request.
	// Used for decompression/recompression of frames during subsystem processing.
	grpcEncoding string

	// Plugin context for the gRPC stream.
	pluginConnInfo *plugin.ConnInfo

	// txCtxMu protects txCtx from concurrent access by request/response goroutines.
	txCtxMu sync.Mutex
	txCtx   map[string]any

	// reqBlocked is set to true if a request frame was blocked by a subsystem
	// (safety filter or plugin drop). When true, the stream is terminated.
	reqBlocked bool

	// respBlocked is set to true if a response frame was blocked by output filter.
	respBlocked bool

	// reqBodyClosed is set before calling sc.req.Body.Close() to signal
	// that the close is intentional. streamGRPCRequestBody checks this
	// flag to distinguish handler-initiated close from real stream errors.
	reqBodyClosed atomic.Bool
}

// handleGRPCStream proxies a gRPC stream using io.Pipe-based bidirectional
// streaming to avoid the deadlock caused by full-body buffering in
// readAndTruncateBody. Instead of reading the entire request body before
// forwarding, it streams data as it arrives.
//
// Architecture:
//
//	Client --> Read+Write --> Pipe Writer --> Upstream
//	                |
//	                v
//	         FrameBuffer (progressive recording)
//
//	Upstream --> Read+Write+Flush --> Client
//	     |
//	     v
//	FrameBuffer (progressive recording)
//
// This function is called from handleStream when gRPC Content-Type is detected.
// Each gRPC frame is recorded progressively as it arrives via the
// grpcProgressiveRecorder, allowing the flow to be visible in State="active"
// before the stream completes.
func (h *Handler) handleGRPCStream(sc *streamContext) {
	state := h.initGRPCStreamState(sc)

	pr, pw := io.Pipe()

	var reqWg sync.WaitGroup
	reqWg.Add(1)
	go h.streamGRPCRequestBody(sc, state, pw, &reqWg)

	result, ok := h.sendGRPCUpstream(sc, state, sc.h2req, pr, &reqWg)
	if !ok {
		// Check if the request was blocked by a subsystem.
		state.mu.Lock()
		blocked := state.reqBlocked
		state.mu.Unlock()
		if blocked {
			writeGRPCStatusH2(sc.w, 7, "request blocked by safety filter", sc.logger) // PERMISSION_DENIED
		}
		return
	}
	defer result.Body.Close()

	// Response intercept check: if response matches intercept rules,
	// buffer the unary response body + trailers for AI agent review.
	if h.handleGRPCResponseInterceptH2(sc, state, result) {
		sc.w.Flush()
		// Close request body to unblock the request-streaming goroutine.
		state.reqBodyClosed.Store(true)
		if sc.h2req.Body != nil {
			sc.h2req.Body.Close()
		}
		reqWg.Wait()
		h.finalizeGRPCStream(sc, state, result)
		return
	}

	// Apply output filter to response headers before writing to client.
	filteredHeaders := h.applyOutputFilterHpackHeaders(result.Headers, sc.logger)

	h.writeGRPCResponseHeadersH2(sc, result.StatusCode, filteredHeaders)
	h.streamGRPCResponseBodyH2(sc, state, result)

	// Skip trailers if response was blocked — we already wrote an error status.
	state.mu.Lock()
	blocked := state.respBlocked
	state.mu.Unlock()
	if !blocked {
		// Read trailers from StreamRoundTripResult (body must be fully read).
		trailers, err := result.Trailers()
		if err != nil {
			sc.logger.Debug("gRPC failed to read trailers", "error", err)
		}
		// Apply output filter to trailers before writing to client.
		if len(trailers) > 0 {
			trailers = h.applyOutputFilterHpackTrailers(trailers, sc.logger)
		}
		h.writeGRPCTrailersH2(sc, result, trailers)
	}

	sc.w.Flush()

	// Close the client request body to unblock the request-streaming
	// goroutine before reqWg.Wait(). The client-side frame engine sends
	// trailers (grpc-status etc.) only when the handler returns — not on
	// Flush(). Without this close, the handler blocks at reqWg.Wait()
	// because the request goroutine is stuck on body.Read(),
	// waiting for more client data. The client in turn waits for the
	// trailers before closing its send-side — a deadlock.
	// Closing the body causes Read() to return immediately with a
	// close-induced error; the goroutine exits, reqWg unblocks,
	// the handler returns, and the trailing HEADERS frame is sent.
	state.reqBodyClosed.Store(true)
	if sc.h2req.Body != nil {
		sc.h2req.Body.Close()
	}

	reqWg.Wait()

	h.finalizeGRPCStream(sc, state, result)
}

// initGRPCStreamState creates the frame buffers, progressive recorder,
// and state for a gRPC stream. The flow is created immediately with
// State="active" so it is visible before the stream completes.
func (h *Handler) initGRPCStreamState(sc *streamContext) *grpcStreamState {
	state := &grpcStreamState{
		grpcEncoding: hpackGetHeader(sc.h2req.AllHeaders, "grpc-encoding"),
		pluginConnInfo: &plugin.ConnInfo{
			ClientAddr: sc.clientAddr,
			TLSVersion: sc.tlsMeta.Version,
			TLSCipher:  sc.tlsMeta.CipherSuite,
			TLSALPN:    sc.tlsMeta.ALPN,
		},
		txCtx: plugin.NewTxCtx(),
	}

	// Initialize progressive recorder — creates the flow with State="active".
	state.recorder = h.initGRPCFlow(sc.ctx, sc)

	// Use a context that survives the full stream lifetime for recording.
	recCtx := sc.ctx

	state.reqFrameBuf = protogrpc.NewFrameBuffer(func(_ []byte, frame *protogrpc.Frame) error {
		state.reqFrameCount.Add(1)

		// Progressive recording: record each request frame immediately.
		// Raw bytes are not accumulated; each frame is persisted individually.
		state.recorder.recordFrame(recCtx, frame, "client_to_server")
		return nil
	})

	state.respFrameBuf = protogrpc.NewFrameBuffer(func(_ []byte, frame *protogrpc.Frame) error {
		state.respFrameCount.Add(1)

		// Progressive recording: record each response frame immediately.
		state.recorder.recordFrame(recCtx, frame, "server_to_client")
		return nil
	})

	return state
}

// streamGRPCRequestBody reads the request body from the client and forwards
// it to the upstream via the pipe writer, while processing each gRPC frame
// through subsystems (safety filter, plugin hooks, auto-transform).
//
// The FrameBuffer reassembles gRPC frames from arbitrary byte chunks. For
// each complete frame, the subsystem pipeline is applied:
//   - protobuf decode to JSON
//   - safety filter (block or log_only)
//   - plugin: on_receive_from_client
//   - auto-transform (request direction)
//   - plugin: on_before_send_to_server
//   - if modified: JSON -> protobuf re-encode -> rebuild frame
//   - if unmodified: forward original bytes
//
// If a subsystem blocks the frame, the stream is terminated with gRPC
// status PERMISSION_DENIED.
func (h *Handler) streamGRPCRequestBody(sc *streamContext, state *grpcStreamState, pw *io.PipeWriter, wg *sync.WaitGroup) {
	defer wg.Done()
	defer func() {
		// Propagate the actual error to the pipe reader so the upstream
		// request sees the real cause rather than io.ErrClosedPipe.
		state.mu.Lock()
		reqErr := state.reqStreamErr
		state.mu.Unlock()
		if reqErr != nil {
			pw.CloseWithError(reqErr)
		} else {
			pw.Close()
		}
	}()

	hasSubsystems := h.SafetyEngine != nil || h.pluginEngine != nil || h.transformPipeline != nil

	// Use a separate FrameBuffer for subsystem processing that intercepts
	// frames and writes processed bytes to the pipe. The state's reqFrameBuf
	// is used purely for recording.
	var subsystemBuf *protogrpc.FrameBuffer
	if hasSubsystems {
		subsystemBuf = h.newGRPCRequestSubsystemBuf(sc, state, pw)
	}

	body := sc.h2req.Body
	if body == nil {
		return
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := body.Read(buf)
		if n > 0 {
			if fbErr := state.reqFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC request frame buffer error", "error", fbErr)
			}
			if err := h.forwardGRPCRequestChunk(sc, state, pw, subsystemBuf, buf[:n], hasSubsystems); err != nil {
				state.mu.Lock()
				state.reqStreamErr = err
				state.mu.Unlock()
				return
			}
		}
		if readErr != nil {
			if readErr != io.EOF && !state.reqBodyClosed.Load() {
				state.mu.Lock()
				state.reqStreamErr = readErr
				state.mu.Unlock()
			}
			return
		}
	}
}

// newGRPCRequestSubsystemBuf creates a FrameBuffer that processes request
// frames through subsystems and writes processed bytes to the pipe writer.
func (h *Handler) newGRPCRequestSubsystemBuf(sc *streamContext, state *grpcStreamState, pw *io.PipeWriter) *protogrpc.FrameBuffer {
	return protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		// Lock txCtx for thread-safe plugin hook access.
		state.txCtxMu.Lock()
		wireBytes, stop := h.processGRPCRequestFrame(
			sc, raw, frame.Compressed, frame.Payload,
			state.grpcEncoding, state.pluginConnInfo, state.txCtx)
		state.txCtxMu.Unlock()
		if stop {
			state.mu.Lock()
			state.reqBlocked = true
			state.mu.Unlock()
			return fmt.Errorf("gRPC request frame blocked by subsystem")
		}
		if _, err := pw.Write(wireBytes); err != nil {
			return err
		}
		return nil
	})
}

// forwardGRPCRequestChunk forwards a chunk of request data through subsystem
// processing (if enabled) or directly to the pipe writer. Returns an error
// if the write fails or the stream was blocked.
func (h *Handler) forwardGRPCRequestChunk(sc *streamContext, state *grpcStreamState, pw *io.PipeWriter, subsystemBuf *protogrpc.FrameBuffer, chunk []byte, hasSubsystems bool) error {
	if !hasSubsystems {
		_, err := pw.Write(chunk)
		return err
	}

	if fbErr := subsystemBuf.Write(chunk); fbErr != nil {
		// Never fall back to raw bytes transfer on subsystem error.
		// Doing so would bypass safety filters and plugin checks.
		sc.logger.Warn("gRPC request subsystem buffer error", "error", fbErr)
		return fbErr
	}
	return nil
}

// sendGRPCUpstream establishes an upstream connection via ConnPool and sends
// the gRPC request using h2Transport.RoundTripStream. Returns the streaming
// result and true on success, or nil and false on failure.
// On failure, it waits for the request goroutine to finish.
func (h *Handler) sendGRPCUpstream(sc *streamContext, state *grpcStreamState, req *h2Request, body io.Reader, reqWg *sync.WaitGroup) (*StreamRoundTripResult, bool) {
	useTLS := req.Scheme == "https"

	// Parse authority using net/url for robust IPv6 bracket handling.
	// net.SplitHostPort fails for bare IPv6 literals like "[::1]" without
	// port, and net.JoinHostPort would double-bracket them.
	authorityURL := &url.URL{Host: req.Authority}
	hostname := authorityURL.Hostname()
	port := authorityURL.Port()
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	addr := net.JoinHostPort(hostname, port)

	h.tlsMu.RLock()
	cr, err := h.connPool.Get(sc.ctx, addr, useTLS, hostname)
	h.tlsMu.RUnlock()
	if err != nil {
		sc.logger.Error("gRPC upstream connection failed",
			"method", req.Method, "url", sc.reqURL.String(), "error", err)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		// Close the pipe reader to unblock the request-streaming goroutine
		// which may be blocked on pw.Write().
		if pr, ok := body.(*io.PipeReader); ok {
			pr.CloseWithError(err)
		}
		reqWg.Wait()
		return nil, false
	}

	// For TLS connections, verify ALPN negotiated h2. For cleartext (h2c),
	// ALPN is not negotiated — the connection is used as-is.
	if useTLS && cr.ALPN != "h2" {
		cr.Conn.Close()
		alpnErr := fmt.Errorf("gRPC requires h2 ALPN, got %q", cr.ALPN)
		sc.logger.Error("gRPC requires h2 ALPN",
			"method", req.Method, "url", sc.reqURL.String(), "alpn", cr.ALPN)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		if pr, ok := body.(*io.PipeReader); ok {
			pr.CloseWithError(alpnErr)
		}
		reqWg.Wait()
		return nil, false
	}

	return h.sendGRPCUpstreamOnConn(sc, state, req, body, cr.Conn, reqWg)
}

// sendGRPCUpstreamOnConn performs the actual gRPC upstream round trip on
// an established connection.
func (h *Handler) sendGRPCUpstreamOnConn(sc *streamContext, state *grpcStreamState, req *h2Request, body io.Reader, conn net.Conn, reqWg *sync.WaitGroup) (*StreamRoundTripResult, bool) {

	// Build upstream headers from h2Request, filtering hop-by-hop headers.
	upstreamHeaders := buildUpstreamGRPCHeaders(req)

	// StreamOptions for the upstream round trip. Raw frame recording via
	// OnSendFrame/OnRecvFrame is intentionally not used here — the existing
	// gRPC progressive recorder (FrameBuffer callbacks) already records
	// each gRPC frame as a flow message. Raw HTTP/2 frame recording would
	// create duplicate messages with conflicting semantics.
	opts := StreamOptions{}

	result, err := h.h2Transport.RoundTripStream(sc.ctx, conn, upstreamHeaders, body, opts)
	if err != nil {
		sc.logger.Error("gRPC upstream request failed",
			"method", req.Method, "url", sc.reqURL.String(), "error", err)
		writeErrorResponse(sc.w, gohttp.StatusBadGateway)
		// Close the pipe reader to unblock the request-streaming goroutine
		// which may be blocked on pw.Write() if RoundTripStream failed
		// before consuming the pipe.
		if pr, ok := body.(*io.PipeReader); ok {
			pr.CloseWithError(err)
		}
		reqWg.Wait()
		return nil, false
	}

	return result, true
}

// buildUpstreamGRPCHeaders constructs the upstream HPACK headers for a gRPC
// request, preserving pseudo-headers and filtering HTTP/2 hop-by-hop headers.
func buildUpstreamGRPCHeaders(req *h2Request) []hpack.HeaderField {
	var headers []hpack.HeaderField
	for _, hf := range req.AllHeaders {
		if strings.HasPrefix(hf.Name, ":") {
			headers = append(headers, hf)
			continue
		}
		lower := strings.ToLower(hf.Name)
		// Skip "host" to avoid conflict with :authority in HTTP/2.
		if lower == "host" {
			continue
		}
		if isHopByHopHeader(lower) {
			// Allow "te: trailers" which is the only TE value permitted in HTTP/2.
			if lower == "te" && strings.EqualFold(hf.Value, "trailers") {
				headers = append(headers, hf)
			}
			continue
		}
		headers = append(headers, hf)
	}
	return headers
}

// writeGRPCResponseHeadersH2 writes the upstream response headers to the
// client using h2ResponseWriter with hpack native types.
func (h *Handler) writeGRPCResponseHeadersH2(sc *streamContext, statusCode int, headers []hpack.HeaderField) {
	// Filter out pseudo-headers, trailer declaration headers, and gRPC
	// trailer fields (grpc-status, grpc-message, grpc-status-details-bin).
	// gRPC trailer fields must only appear in the trailing HEADERS frame
	// (written by writeGRPCTrailersH2), not in the initial response HEADERS.
	// Including them here would cause duplication in Trailers-Only responses.
	var filtered []hpack.HeaderField
	for _, hf := range headers {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		switch strings.ToLower(hf.Name) {
		case "trailer", "grpc-status", "grpc-message", "grpc-status-details-bin":
			continue
		}
		filtered = append(filtered, hf)
	}
	if err := sc.w.WriteHeaders(statusCode, filtered); err != nil {
		sc.logger.Debug("gRPC failed to write response headers", "error", err)
	}
}

// streamGRPCResponseBodyH2 reads the response body from the
// StreamRoundTripResult and streams it to the client via h2ResponseWriter,
// while processing each gRPC frame through response-side subsystems.
//
// For each complete response frame, the subsystem pipeline is applied:
//   - protobuf decode to JSON
//   - plugin: on_receive_from_server
//   - auto-transform (response direction)
//   - output filter (mask or block)
//   - plugin: on_before_send_to_client
//   - if modified: JSON -> protobuf re-encode -> rebuild frame
//   - if unmodified: forward original bytes
//
// If the output filter blocks a frame, the stream is terminated.
func (h *Handler) streamGRPCResponseBodyH2(sc *streamContext, state *grpcStreamState, result *StreamRoundTripResult) {
	hasSubsystems := h.SafetyEngine != nil || h.pluginEngine != nil || h.transformPipeline != nil

	var subsystemBuf *protogrpc.FrameBuffer

	if hasSubsystems {
		subsystemBuf = h.newGRPCResponseSubsystemBufH2(sc, state, result)
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := result.Body.Read(buf)
		if n > 0 {
			if fbErr := state.respFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC response frame buffer error", "error", fbErr)
			}
			if done := h.forwardGRPCResponseChunkH2(sc, state, subsystemBuf, buf[:n], hasSubsystems); done {
				break
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				sc.logger.Debug("gRPC response read error", "error", readErr)
			}
			break
		}
	}
}

// newGRPCResponseSubsystemBufH2 creates a FrameBuffer that processes response
// frames through subsystems and writes processed bytes to the client via
// h2ResponseWriter.
func (h *Handler) newGRPCResponseSubsystemBufH2(sc *streamContext, state *grpcStreamState, result *StreamRoundTripResult) *protogrpc.FrameBuffer {
	respEncoding := hpackGetHeader(result.Headers, "grpc-encoding")
	return protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		// Lock txCtx for thread-safe plugin hook access.
		state.txCtxMu.Lock()
		wireBytes, blocked := h.processGRPCResponseFrameH2(
			sc, raw, frame.Compressed, frame.Payload,
			respEncoding, result.StatusCode, result.Headers,
			state.pluginConnInfo, state.txCtx)
		state.txCtxMu.Unlock()
		if blocked {
			state.mu.Lock()
			state.respBlocked = true
			state.mu.Unlock()
			return fmt.Errorf("gRPC response frame blocked by output filter")
		}
		if err := sc.w.WriteData(wireBytes); err != nil {
			return err
		}
		sc.w.Flush()
		return nil
	})
}

// forwardGRPCResponseChunkH2 forwards a chunk of response data. If subsystems
// are enabled, the chunk is processed through the subsystem buffer. Otherwise
// it is written directly to the client. Returns true if the stream should stop.
func (h *Handler) forwardGRPCResponseChunkH2(sc *streamContext, state *grpcStreamState, subsystemBuf *protogrpc.FrameBuffer, chunk []byte, hasSubsystems bool) bool {
	if !hasSubsystems {
		if writeErr := sc.w.WriteData(chunk); writeErr != nil {
			sc.logger.Debug("gRPC failed to write response to client", "error", writeErr)
			return true
		}
		sc.w.Flush()
		return false
	}

	if fbErr := subsystemBuf.Write(chunk); fbErr != nil {
		// Never fall back to raw bytes transfer on subsystem error.
		// Doing so would bypass safety filters and plugin checks.
		state.mu.Lock()
		blocked := state.respBlocked
		if !blocked {
			state.respBlocked = true
		}
		state.mu.Unlock()
		if blocked {
			sc.logger.Warn("gRPC response stream terminated by output filter")
		} else {
			sc.logger.Warn("gRPC response subsystem buffer error", "error", fbErr)
		}
		// Write error trailers to signal the client.
		errMsg := "response subsystem processing error"
		if blocked {
			errMsg = "response blocked by output filter"
		}
		errorTrailers := []hpack.HeaderField{
			{Name: "grpc-status", Value: "13"},
			{Name: "grpc-message", Value: percentEncodeGRPCMessage(errMsg)},
		}
		if err := sc.w.WriteTrailers(errorTrailers); err != nil {
			sc.logger.Debug("gRPC failed to write error trailers", "error", err)
		}
		return true
	}
	return false
}

// writeGRPCTrailersH2 writes the upstream response trailers to the client
// using h2ResponseWriter.WriteTrailers with hpack native types.
//
// For Trailers-Only responses (where the upstream sends a single
// HEADERS+END_STREAM frame), StreamRoundTripResult puts those fields
// in Headers (no separate trailers). In this case, gRPC trailer keys
// are extracted from the response Headers as a fallback.
func (h *Handler) writeGRPCTrailersH2(sc *streamContext, result *StreamRoundTripResult, trailers []hpack.HeaderField) {
	if len(trailers) > 0 {
		if err := sc.w.WriteTrailers(trailers); err != nil {
			sc.logger.Debug("gRPC failed to write trailers", "error", err)
		}
		return
	}

	// Trailers-Only fallback: extract gRPC trailer keys from the response
	// HEADERS frame. This handles the case where the upstream sends a single
	// HEADERS+END_STREAM frame containing both response headers and trailer
	// fields (the Trailers-Only encoding per gRPC spec).
	var fallbackTrailers []hpack.HeaderField
	for _, hf := range result.Headers {
		if isGRPCTrailerKey(hf.Name) {
			fallbackTrailers = append(fallbackTrailers, hf)
		}
	}
	if len(fallbackTrailers) > 0 {
		if err := sc.w.WriteTrailers(fallbackTrailers); err != nil {
			sc.logger.Debug("gRPC failed to write fallback trailers", "error", err)
		}
	}
}

// finalizeGRPCStream logs stream completion, flushes incomplete frames,
// completes the progressive recording, and logs the final status.
func (h *Handler) finalizeGRPCStream(sc *streamContext, state *grpcStreamState, result *StreamRoundTripResult) {
	state.mu.Lock()
	reqStreamErr := state.reqStreamErr
	state.mu.Unlock()

	if reqStreamErr != nil {
		sc.logger.Debug("gRPC request stream error", "error", reqStreamErr)
	}

	if remaining := state.reqFrameBuf.Flush(); remaining != nil {
		sc.logger.Debug("gRPC request stream ended with incomplete frame",
			"remaining_bytes", len(remaining))
	}
	if remaining := state.respFrameBuf.Flush(); remaining != nil {
		sc.logger.Debug("gRPC response stream ended with incomplete frame",
			"remaining_bytes", len(remaining))
	}

	reqFrames := int(state.reqFrameCount.Load())
	respFrames := int(state.respFrameCount.Load())
	duration := time.Since(sc.start)

	// Complete the progressive recording flow.
	state.recorder.completeFlowH2(sc.ctx, result, reqFrames, respFrames, duration)

	sc.logger.Info("grpc streaming request",
		"method", sc.h2req.Method,
		"url", sc.reqURL.String(),
		"status", result.StatusCode,
		"req_frames", reqFrames,
		"resp_frames", respFrames,
		"duration_ms", duration.Milliseconds())
}

// grpcTrailerKeyList is the canonical list of gRPC trailer header keys.
var grpcTrailerKeyList = []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"}

// isGRPCTrailersOnly detects a gRPC Trailers-Only response. Per the gRPC
// HTTP/2 spec, a Trailers-Only response is a single HEADERS frame containing
// both response headers and trailers (including grpc-status) with END_STREAM.
//
// Go's http2.Transport maps this into resp.Header containing grpc-status and
// resp.Trailer being empty, because there is no separate trailing HEADERS frame.
func isGRPCTrailersOnly(resp *gohttp.Response) bool {
	if len(resp.Trailer) > 0 {
		return false
	}
	// Check if Grpc-Status is present in resp.Header (case-insensitive via
	// Go's canonical header key format).
	_, ok := resp.Header["Grpc-Status"]
	return ok
}

// isGRPCTrailerKey reports whether the header key is a gRPC trailer key
// (case-insensitive comparison).
func isGRPCTrailerKey(key string) bool {
	for _, gk := range grpcTrailerKeyList {
		if strings.EqualFold(key, gk) {
			return true
		}
	}
	return false
}

// tryHandleGRPCStream checks whether the request is a gRPC stream and, if so,
// handles it via the streaming transport path. Returns true if handled.
//
// The gRPC streaming path uses per-frame subsystem processing instead of
// full-body buffering. Each gRPC frame is decoded to JSON and passed through
// safety filter, plugin hooks, auto-transform, and output filter.
//
// For intercept, gRPC unary requests (single frame) are fully buffered, the
// protobuf payload is decoded to JSON, and the item is enqueued with the JSON
// body so the AI agent can inspect and modify it. Streaming requests (multiple
// frames) fall back to release with a warning log.
func (h *Handler) tryHandleGRPCStream(sc *streamContext) bool {
	ct := hpackGetHeader(sc.h2req.AllHeaders, "content-type")
	if h.grpcHandler == nil || !isGRPCContentType(ct) {
		return false
	}

	h.resolveSchemeAndHost(sc)

	if h.checkTargetScope(sc) {
		return true
	}
	if h.checkRateLimit(sc) {
		return true
	}

	// Intercept check for gRPC requests.
	if h.InterceptEngine != nil && h.InterceptQueue != nil {
		matchedRules := h.InterceptEngine.MatchRequestRules(sc.h2req.Method, sc.req.URL, hpackToRawHeaders(sc.h2req.AllHeaders))
		if len(matchedRules) > 0 {
			handled := h.handleGRPCIntercept(sc, matchedRules)
			if handled {
				return true
			}
			// Not handled means the request was released or modified;
			// continue to streaming path with possibly modified request.
		}
	}

	sc.logger.Debug("gRPC stream: per-frame subsystem processing enabled",
		"url", sc.reqURL.String(),
		"has_safety_filter", h.SafetyEngine != nil,
		"has_plugins", h.pluginEngine != nil,
		"has_transform", h.transformPipeline != nil)
	h.handleGRPCStream(sc)
	return true
}

// handleGRPCIntercept handles the intercept logic for gRPC requests.
// It buffers the request body, checks whether it is a unary RPC (single frame),
// and enqueues the decoded JSON body for AI agent review.
//
// Returns true if the request was fully handled (dropped), false if processing
// should continue to the streaming path (released or modified).
func (h *Handler) handleGRPCIntercept(sc *streamContext, matchedRules []string) bool {
	body, jsonBody, frame, ok := h.bufferGRPCUnaryBody(sc)
	if !ok {
		return false
	}

	action := h.enqueueGRPCIntercept(sc, body, jsonBody, frame, matchedRules)
	return h.applyGRPCInterceptAction(sc, action, body)
}

// bufferGRPCUnaryBody reads and validates the request body as a gRPC unary
// request using frame-level reading to avoid blocking on streaming RPCs.
// Instead of io.ReadAll (which blocks until END_STREAM), it reads the first
// gRPC frame header+payload, then probes for additional data to distinguish
// unary from streaming.
//
// It returns the raw body, decoded JSON, the single frame, and true
// if the body is a valid unary request. On failure, the request body is restored
// and false is returned.
func (h *Handler) bufferGRPCUnaryBody(sc *streamContext) (body []byte, jsonBody string, frame protobuf.Frame, ok bool) {
	reqBody := io.LimitReader(sc.req.Body, intercept.MaxRawBytesSize+1)

	// Step 1: Read the 5-byte gRPC frame header.
	var header [5]byte
	n, err := io.ReadFull(reqBody, header[:])
	if err != nil {
		sc.logger.Debug("gRPC intercept: failed to read frame header", "error", err)
		// Restore any partial data + remaining body for streaming fallback.
		sc.req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(header[:n]), sc.req.Body))
		return nil, "", protobuf.Frame{}, false
	}

	compressed := header[0]
	if compressed > 1 {
		sc.logger.Debug("gRPC intercept: invalid compressed flag", "flag", compressed)
		sc.req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(header[:]), sc.req.Body))
		return nil, "", protobuf.Frame{}, false
	}

	msgLen := binary.BigEndian.Uint32(header[1:5])
	if msgLen > config.MaxGRPCMessageSize {
		sc.logger.Warn("gRPC intercept: frame payload too large, releasing",
			"msg_len", msgLen, "max", config.MaxGRPCMessageSize)
		sc.req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(header[:]), sc.req.Body))
		return nil, "", protobuf.Frame{}, false
	}

	// Check total frame size against intercept limit.
	totalFrameSize := 5 + int(msgLen)
	if totalFrameSize > intercept.MaxRawBytesSize {
		sc.logger.Warn("gRPC intercept: request body too large, releasing",
			"body_len", totalFrameSize, "max", intercept.MaxRawBytesSize)
		sc.req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(header[:]), sc.req.Body))
		return nil, "", protobuf.Frame{}, false
	}

	// Step 2: Read the payload.
	payloadLen := int(msgLen)
	payload := make([]byte, payloadLen)
	if payloadLen > 0 {
		pn, pErr := io.ReadFull(reqBody, payload)
		if pErr != nil {
			sc.logger.Debug("gRPC intercept: failed to read frame payload", "error", pErr, "expected", payloadLen)
			// Restore header + actually-read partial payload + remaining body.
			var read []byte
			read = append(read, header[:]...)
			read = append(read, payload[:pn]...)
			sc.req.Body = io.NopCloser(io.MultiReader(bytes.NewReader(read), sc.req.Body))
			return nil, "", protobuf.Frame{}, false
		}
	}

	// Build the first frame's raw bytes (header + payload).
	firstFrame := make([]byte, totalFrameSize)
	copy(firstFrame, header[:])
	copy(firstFrame[5:], payload)

	// Step 3: Check END_STREAM signal to distinguish unary vs streaming.
	// Instead of a blocking 1-byte probe read (which deadlocks on bidirectional
	// streaming RPCs where the client waits for a server response before sending
	// the next frame), we use the endStreamCh channel set by client_conn.go
	// when END_STREAM is received on a DATA frame.
	endStreamCh := endStreamChFromContext(sc.ctx)
	if endStreamCh == nil {
		// No endStreamCh means HEADERS had END_STREAM (no body expected).
		// This shouldn't happen since we already read a frame, but handle
		// gracefully by treating as unary.
		sc.logger.Debug("gRPC intercept: no endStreamCh in context, assuming unary")
	} else {
		// Wait briefly for the END_STREAM signal. In unary RPCs, the DATA
		// frame carrying END_STREAM is received very close to the first frame
		// read (often the same frame). A short timeout handles goroutine
		// scheduling delays.
		select {
		case <-endStreamCh:
			// END_STREAM received — unary RPC confirmed.
		case <-time.After(100 * time.Millisecond):
			// Timeout — likely a streaming RPC. Restore body and fall back.
			sc.logger.Warn("gRPC streaming intercept modify_and_forward not supported, releasing",
				"method", sc.req.Method, "url", sc.reqURL.String())
			sc.req.Body = io.NopCloser(io.MultiReader(
				bytes.NewReader(firstFrame),
				sc.req.Body,
			))
			return nil, "", protobuf.Frame{}, false
		case <-sc.ctx.Done():
			sc.logger.Debug("gRPC intercept: context cancelled during unary detection")
			sc.req.Body = io.NopCloser(bytes.NewReader(firstFrame))
			return nil, "", protobuf.Frame{}, false
		}
	}

	// Unary RPC confirmed — single frame, EOF reached.
	body = firstFrame
	frame = protobuf.Frame{
		Compressed: compressed,
		Payload:    payload,
	}

	grpcEncoding := sc.req.Header.Get("Grpc-Encoding")
	jsonBody, _, decodeErr := decodeGRPCPayload(frame.Payload, frame.Compressed != 0, grpcEncoding)
	if decodeErr != nil {
		sc.logger.Debug("gRPC intercept: protobuf decode failed, releasing", "error", decodeErr)
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
		return nil, "", protobuf.Frame{}, false
	}

	return body, jsonBody, frame, true
}

// enqueueGRPCIntercept enqueues the decoded gRPC unary request for AI agent
// review and waits for the agent's action (or timeout).
func (h *Handler) enqueueGRPCIntercept(sc *streamContext, body []byte, jsonBody string, frame protobuf.Frame, matchedRules []string) intercept.InterceptAction {
	sc.logger.Info("gRPC unary request intercepted",
		"method", sc.h2req.Method, "url", sc.reqURL.String(), "matched_rules", matchedRules)

	opts := intercept.EnqueueOpts{
		RawBytes: body,
		Metadata: h.buildGRPCInterceptMetadata(sc, frame),
	}

	id, actionCh := h.InterceptQueue.Enqueue(sc.h2req.Method, sc.req.URL, hpackToRawHeaders(sc.h2req.AllHeaders), []byte(jsonBody), matchedRules, opts)
	defer h.InterceptQueue.Remove(id)

	return h.waitGRPCInterceptAction(sc, id, actionCh)
}

// buildGRPCInterceptMetadata returns gRPC-specific metadata for attaching
// to an enqueued intercept item so the MCP tool layer can re-encode the
// body correctly.
func (h *Handler) buildGRPCInterceptMetadata(sc *streamContext, frame protobuf.Frame) map[string]string {
	contentType := hpackGetHeader(sc.h2req.AllHeaders, "content-type")
	grpcEncoding := hpackGetHeader(sc.h2req.AllHeaders, "grpc-encoding")
	compressed := "false"
	if frame.Compressed != 0 {
		compressed = "true"
	}
	return map[string]string{
		"grpc_content_type": contentType,
		"grpc_encoding":     grpcEncoding,
		"grpc_compressed":   compressed,
		"original_frames":   "1",
	}
}

// waitGRPCInterceptAction waits for the AI agent's action on the enqueued
// gRPC intercept item, handling timeout and context cancellation.
func (h *Handler) waitGRPCInterceptAction(sc *streamContext, id string, actionCh <-chan intercept.InterceptAction) intercept.InterceptAction {
	timeout := h.InterceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(sc.ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action
	case <-timeoutCtx.Done():
		behavior := h.InterceptQueue.TimeoutBehaviorValue()
		if sc.ctx.Err() != nil {
			sc.logger.Info("intercepted gRPC request cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}
		}
		sc.logger.Info("intercepted gRPC request timed out", "id", id, "behavior", string(behavior))
		if behavior == intercept.TimeoutAutoDrop {
			return intercept.InterceptAction{Type: intercept.ActionDrop}
		}
		return intercept.InterceptAction{Type: intercept.ActionRelease}
	}
}

// applyGRPCInterceptAction applies the AI agent's action to the gRPC request.
// Returns true if the request was fully handled (dropped), false if processing
// should continue to the streaming path.
func (h *Handler) applyGRPCInterceptAction(sc *streamContext, action intercept.InterceptAction, body []byte) bool {
	switch action.Type {
	case intercept.ActionDrop:
		writeGRPCStatusH2(sc.w, 10, "intercepted request dropped", sc.logger) // ABORTED
		sc.logger.Info("intercepted gRPC request dropped",
			"method", sc.h2req.Method, "url", sc.reqURL.String())
		return true

	case intercept.ActionModifyAndForward:
		if action.IsRawMode() {
			sc.logger.Warn("gRPC intercept raw mode not supported, releasing",
				"method", sc.h2req.Method, "url", sc.reqURL.String())
			sc.req.Body = io.NopCloser(bytes.NewReader(body))
			sc.h2req.Body = sc.req.Body
			return false
		}
		if action.OverrideBody != nil {
			sc.req.Body = io.NopCloser(bytes.NewReader([]byte(*action.OverrideBody)))
		} else {
			sc.req.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.applyGRPCInterceptHeaderMods(sc, action)
		// Sync modifications back to h2req so the streaming upstream path
		// (which reads from sc.h2req) picks up the changes.
		sc.h2req.Body = sc.req.Body
		// Sync pseudo-headers if intercept changed Host or URL.
		if host := sc.req.Host; host != "" {
			sc.h2req.Authority = host
		} else if host := sc.req.Header.Get("Host"); host != "" {
			sc.h2req.Authority = host
		}
		if sc.req.URL != nil {
			sc.h2req.Path = sc.req.URL.RequestURI()
		}
		// Rebuild AllHeaders: update pseudo-header values from h2req fields,
		// then replace non-pseudo headers from gohttp.Header.
		sc.h2req.AllHeaders = syncH2ReqHeaders(sc.h2req, sc.req.Header)
		return false

	default:
		// Release: restore original body and sync to h2req.
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
		sc.h2req.Body = sc.req.Body
		return false
	}
}

// applyGRPCInterceptHeaderMods applies header modifications from an intercept
// action to the gRPC request. Only header-level modifications are applied here;
// body modifications are handled by the caller.
func (h *Handler) applyGRPCInterceptHeaderMods(sc *streamContext, action intercept.InterceptAction) {
	for k, v := range action.OverrideHeaders {
		sc.req.Header.Set(k, v)
	}
	for k, v := range action.AddHeaders {
		sc.req.Header.Add(k, v)
	}
	for _, k := range action.RemoveHeaders {
		sc.req.Header.Del(k)
	}
}

// writeGRPCStatus writes a gRPC error response with the given status code
// and message. This is used when subsystems block a gRPC stream.
// The message is percent-encoded per the gRPC specification for grpc-message.
func writeGRPCStatus(w gohttp.ResponseWriter, httpStatus int, grpcStatus int, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", fmt.Sprintf("%d", grpcStatus))
	w.Header().Set("Grpc-Message", percentEncodeGRPCMessage(message))
	w.WriteHeader(httpStatus)
}

// writeGRPCStatusH2 writes a gRPC error response using h2ResponseWriter
// with hpack native types. Per the gRPC Trailers-Only pattern, content-type
// is sent in the initial HEADERS frame, and grpc-status/grpc-message are
// sent as trailers (HEADERS frame with END_STREAM).
func writeGRPCStatusH2(w h2ResponseWriter, grpcStatus int, message string, logger *slog.Logger) {
	headers := []hpack.HeaderField{
		{Name: "content-type", Value: "application/grpc"},
	}
	if err := w.WriteHeaders(gohttp.StatusOK, headers); err != nil {
		logger.Error("failed to write gRPC status headers over HTTP/2", "error", err)
		return
	}

	trailers := []hpack.HeaderField{
		{Name: "grpc-status", Value: fmt.Sprintf("%d", grpcStatus)},
		{Name: "grpc-message", Value: percentEncodeGRPCMessage(message)},
	}
	if err := w.WriteTrailers(trailers); err != nil {
		logger.Error("failed to write gRPC status trailers",
			"error", err,
			"grpc_status", grpcStatus,
			"message", message,
		)
	}
}

// applyOutputFilterHpackHeaders applies the output filter to hpack response
// headers. Returns the filtered headers.
func (h *Handler) applyOutputFilterHpackHeaders(headers []hpack.HeaderField, logger *slog.Logger) []hpack.HeaderField {
	if h.SafetyEngine == nil {
		return headers
	}
	// Convert to gohttp.Header for the existing output filter API.
	goHeaders := hpackToGoHTTPHeader(headers)
	_, goHeaders = h.ApplyOutputFilter(nil, goHeaders, logger)
	// Convert back, preserving pseudo-headers from the original.
	var result []hpack.HeaderField
	for _, hf := range headers {
		if strings.HasPrefix(hf.Name, ":") {
			result = append(result, hf)
		}
	}
	result = append(result, goHTTPHeaderToHpack(goHeaders)...)
	return result
}

// applyOutputFilterHpackTrailers applies the output filter to hpack trailer
// header fields. Returns the filtered trailers.
func (h *Handler) applyOutputFilterHpackTrailers(trailers []hpack.HeaderField, logger *slog.Logger) []hpack.HeaderField {
	if h.SafetyEngine == nil {
		return trailers
	}
	goHeaders := hpackToGoHTTPHeader(trailers)
	goHeaders = h.ApplyOutputFilterHeaders(goHeaders, logger)
	return goHTTPHeaderToHpack(goHeaders)
}

// syncH2ReqHeadersFromGoHTTP rebuilds h2req.AllHeaders by preserving
// pseudo-headers from the original hpack headers and replacing non-pseudo
// headers with the values from gohttp.Header (which may have been modified
// by intercept actions).
// syncH2ReqHeaders rebuilds AllHeaders from the h2req's pseudo-header fields
// and the modified gohttp.Header. This ensures both pseudo-headers and regular
// headers in AllHeaders reflect intercept modifications.
func syncH2ReqHeaders(req *h2Request, goHeaders gohttp.Header) []hpack.HeaderField {
	// Rebuild pseudo-headers from the h2req convenience fields.
	var result []hpack.HeaderField
	if req.Method != "" {
		result = append(result, hpack.HeaderField{Name: ":method", Value: req.Method})
	}
	if req.Scheme != "" {
		result = append(result, hpack.HeaderField{Name: ":scheme", Value: req.Scheme})
	}
	if req.Authority != "" {
		result = append(result, hpack.HeaderField{Name: ":authority", Value: req.Authority})
	}
	if req.Path != "" {
		result = append(result, hpack.HeaderField{Name: ":path", Value: req.Path})
	}
	// Append non-pseudo headers from gohttp.Header (intercept-modified).
	result = append(result, goHTTPHeaderToHpack(goHeaders)...)
	return result
}

// percentEncodeGRPCMessage percent-encodes a gRPC status message per the
// gRPC wire format specification. Only unreserved characters (RFC 3986)
// and space are passed through; all others are percent-encoded.
func percentEncodeGRPCMessage(msg string) string {
	var buf bytes.Buffer
	for i := 0; i < len(msg); i++ {
		c := msg[i]
		switch {
		case (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9'):
			buf.WriteByte(c)
		case c == '-' || c == '_' || c == '.' || c == '~' || c == ' ':
			buf.WriteByte(c)
		default:
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

// handleGRPCResponseIntercept checks whether the gRPC response matches
// intercept rules and, if so, buffers the unary response body + trailers
// for AI agent review. This function takes a gohttp.Response for
// compatibility with the intercept API and tests.
func (h *Handler) handleGRPCResponseIntercept(sc *streamContext, state *grpcStreamState, resp *gohttp.Response) bool {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return false
	}

	if isGRPCTrailersOnly(resp) {
		return false
	}

	matchedRules := h.InterceptEngine.MatchResponseRules(resp.StatusCode, httpHeaderToRawHeaders(resp.Header))
	if len(matchedRules) == 0 {
		return false
	}

	body, jsonBody, frame, trailers, ok := h.bufferGRPCUnaryResponseBody(sc, resp)
	if !ok {
		return false
	}

	action := h.enqueueGRPCResponseIntercept(sc, resp, body, jsonBody, frame, trailers, matchedRules)
	h.applyGRPCResponseInterceptActionH2(sc, state, resp, nil, action, body, trailers)
	return true
}

// handleGRPCResponseInterceptH2 checks whether the gRPC response from
// StreamRoundTripResult matches intercept rules and, if so, buffers the
// unary response body + trailers for AI agent review. Returns true if the
// response was fully handled (intercepted), false if the normal streaming
// path should continue.
//
// This function bridges to the gohttp-based intercept API by converting
// the StreamRoundTripResult headers to gohttp.Response temporarily.
func (h *Handler) handleGRPCResponseInterceptH2(sc *streamContext, state *grpcStreamState, result *StreamRoundTripResult) bool {
	if h.InterceptEngine == nil || h.InterceptQueue == nil {
		return false
	}

	// Trailers-Only responses have no body to intercept.
	// Check if grpc-status is in the initial HEADERS (no trailers expected).
	if isGRPCTrailersOnlyH2(result) {
		return false
	}

	respHeaders := hpackToRawHeaders(result.Headers)
	matchedRules := h.InterceptEngine.MatchResponseRules(result.StatusCode, respHeaders)
	if len(matchedRules) == 0 {
		return false
	}

	// Buffer the response body for intercept processing.
	// Convert to gohttp.Response temporarily for the intercept API.
	resp := streamResultToGoHTTPResponse(result)

	body, jsonBody, frame, _, ok := h.bufferGRPCUnaryResponseBody(sc, resp)
	if !ok {
		// Not a unary response or decode failed — fall back to streaming path.
		// Restore the body on the result for the streaming path.
		result.Body = resp.Body
		return false
	}

	// After body is fully consumed by bufferGRPCUnaryResponseBody, trailers
	// become available via result.Trailers(). Populate resp.Trailer so that
	// the intercept enqueue/apply logic has access to them.
	if hpackTrailers, err := result.Trailers(); err == nil {
		for _, hf := range hpackTrailers {
			if strings.HasPrefix(hf.Name, ":") {
				continue
			}
			resp.Trailer.Set(textproto.CanonicalMIMEHeaderKey(hf.Name), hf.Value)
		}
	}

	// Clone trailers from resp.Trailer so enqueue/apply see the final trailers,
	// including grpc-status/grpc-message populated from result.Trailers() above.
	trailers := resp.Trailer.Clone()

	action := h.enqueueGRPCResponseIntercept(sc, resp, body, jsonBody, frame, trailers, matchedRules)
	h.applyGRPCResponseInterceptActionH2(sc, state, resp, result, action, body, trailers)
	return true
}

// isGRPCTrailersOnlyH2 detects a gRPC Trailers-Only response from a
// StreamRoundTripResult. A Trailers-Only response has grpc-status in the
// initial HEADERS frame and no separate trailing HEADERS frame.
func isGRPCTrailersOnlyH2(result *StreamRoundTripResult) bool {
	for _, hf := range result.Headers {
		if strings.EqualFold(hf.Name, "grpc-status") {
			return true
		}
	}
	return false
}

// streamResultToGoHTTPResponse converts a StreamRoundTripResult to a
// gohttp.Response for compatibility with the intercept API.
func streamResultToGoHTTPResponse(result *StreamRoundTripResult) *gohttp.Response {
	resp := &gohttp.Response{
		StatusCode: result.StatusCode,
		Status:     fmt.Sprintf("%d %s", result.StatusCode, gohttp.StatusText(result.StatusCode)),
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
		ProtoMinor: 0,
		Header:     hpackToGoHTTPHeader(result.Headers),
		Body:       result.Body,
		Trailer:    make(gohttp.Header),
	}
	return resp
}

// bufferGRPCUnaryResponseBody reads the response body and validates it as
// a gRPC unary response (single DATA frame). It reads the entire body to
// populate resp.Trailer, then checks for a single frame.
//
// Returns the raw body bytes, decoded JSON, the single frame, trailers,
// and true if the body is a valid unary response. On failure, the response
// body is replaced with unread data and false is returned.
func (h *Handler) bufferGRPCUnaryResponseBody(sc *streamContext, resp *gohttp.Response) (body []byte, jsonBody string, frame protobuf.Frame, trailers gohttp.Header, ok bool) {
	origBody := resp.Body

	fullBody, err := io.ReadAll(io.LimitReader(origBody, intercept.MaxRawBytesSize+1))
	if err != nil {
		sc.logger.Debug("gRPC response intercept: failed to read body", "error", err)
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(fullBody), origBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	if len(fullBody) > intercept.MaxRawBytesSize {
		sc.logger.Warn("gRPC response intercept: body too large, releasing",
			"body_len", len(fullBody), "max", intercept.MaxRawBytesSize)
		resp.Body = io.NopCloser(io.MultiReader(bytes.NewReader(fullBody), origBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	// After reading to EOF, resp.Trailer may be populated by Go's http2.Transport.
	// For StreamRoundTripResult, trailers are accessed via Trailers() after body EOF.
	trailers = cloneHeaders(resp.Trailer)

	if len(fullBody) == 0 {
		sc.logger.Debug("gRPC response intercept: empty body, skipping")
		return nil, "", protobuf.Frame{}, nil, false
	}

	if len(fullBody) < 5 {
		sc.logger.Debug("gRPC response intercept: body too short for frame header",
			"len", len(fullBody))
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	compressed := fullBody[0]
	if compressed > 1 {
		sc.logger.Debug("gRPC response intercept: invalid compressed flag", "flag", compressed)
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	msgLen := binary.BigEndian.Uint32(fullBody[1:5])
	if msgLen > config.MaxGRPCMessageSize {
		sc.logger.Warn("gRPC response intercept: frame payload too large, releasing",
			"msg_len", msgLen, "max", config.MaxGRPCMessageSize)
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	expectedLen := 5 + int(msgLen)

	if len(fullBody) > expectedLen {
		sc.logger.Info("gRPC streaming response intercept not supported, releasing",
			"method", sc.h2req.Method, "url", sc.reqURL.String(),
			"body_len", len(fullBody), "first_frame_len", expectedLen)
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	if len(fullBody) < expectedLen {
		sc.logger.Debug("gRPC response intercept: incomplete frame",
			"body_len", len(fullBody), "expected", expectedLen)
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	payload := fullBody[5:expectedLen]
	frame = protobuf.Frame{
		Compressed: compressed,
		Payload:    payload,
	}

	respEncoding := resp.Header.Get("Grpc-Encoding")
	jsonBody, _, decodeErr := decodeGRPCPayload(frame.Payload, frame.Compressed != 0, respEncoding)
	if decodeErr != nil {
		sc.logger.Debug("gRPC response intercept: protobuf decode failed, releasing", "error", decodeErr)
		resp.Body = io.NopCloser(bytes.NewReader(fullBody))
		return nil, "", protobuf.Frame{}, nil, false
	}

	return fullBody, jsonBody, frame, trailers, true
}

// enqueueGRPCResponseIntercept enqueues the decoded gRPC unary response for
// AI agent review and waits for the agent's action (or timeout).
func (h *Handler) enqueueGRPCResponseIntercept(sc *streamContext, resp *gohttp.Response, body []byte, jsonBody string, frame protobuf.Frame, trailers gohttp.Header, matchedRules []string) intercept.InterceptAction {
	sc.logger.Info("gRPC unary response intercepted",
		"method", sc.h2req.Method, "url", sc.reqURL.String(),
		"status", resp.StatusCode, "matched_rules", matchedRules)

	opts := intercept.EnqueueOpts{
		RawBytes: body,
		Metadata: h.buildGRPCResponseInterceptMetadata(sc, resp, frame, trailers),
	}

	id, actionCh := h.InterceptQueue.EnqueueResponse(
		sc.h2req.Method, sc.req.URL, resp.StatusCode, httpHeaderToRawHeaders(resp.Header), []byte(jsonBody), matchedRules, opts,
	)
	defer h.InterceptQueue.Remove(id)

	return h.waitGRPCInterceptAction(sc, id, actionCh)
}

// buildGRPCResponseInterceptMetadata returns gRPC-specific metadata for
// attaching to an enqueued response intercept item.
func (h *Handler) buildGRPCResponseInterceptMetadata(sc *streamContext, resp *gohttp.Response, frame protobuf.Frame, trailers gohttp.Header) map[string]string {
	contentType := resp.Header.Get("Content-Type")
	respEncoding := resp.Header.Get("Grpc-Encoding")
	compressed := "false"
	if frame.Compressed != 0 {
		compressed = "true"
	}
	metadata := map[string]string{
		"grpc_content_type": contentType,
		"grpc_encoding":     respEncoding,
		"grpc_compressed":   compressed,
		"original_frames":   "1",
	}

	for key, vals := range trailers {
		if len(vals) > 0 {
			metadata["trailer_"+strings.ToLower(key)] = vals[0]
		}
	}

	return metadata
}

// applyGRPCResponseInterceptActionH2 applies the AI agent's action to the
// gRPC response. It writes the (possibly modified) response through
// subsystems and sends it to the client using h2ResponseWriter.
func (h *Handler) applyGRPCResponseInterceptActionH2(sc *streamContext, state *grpcStreamState, resp *gohttp.Response, result *StreamRoundTripResult, action intercept.InterceptAction, body []byte, trailers gohttp.Header) {
	switch action.Type {
	case intercept.ActionDrop:
		writeGRPCStatusH2(sc.w, 10, "intercepted response dropped", sc.logger) // ABORTED
		sc.logger.Info("intercepted gRPC response dropped",
			"method", sc.h2req.Method, "url", sc.reqURL.String())
		return

	case intercept.ActionModifyAndForward:
		if action.IsRawMode() {
			sc.logger.Warn("gRPC response intercept raw mode not supported, releasing",
				"method", sc.h2req.Method, "url", sc.reqURL.String())
		} else {
			if action.OverrideResponseBody != nil {
				body = []byte(*action.OverrideResponseBody)
			}
			h.applyGRPCResponseInterceptHeaderMods(resp, action)
		}
	}

	// Pass through subsystems and write to client.
	body, resp, trailers = h.runGRPCResponseSubsystems(sc, state, resp, body, trailers)
	_, resp.Header = h.ApplyOutputFilter(nil, resp.Header, sc.logger)
	h.writeGRPCInterceptedResponseH2(sc, state, resp, body, trailers)
}

// writeGRPCInterceptedResponseH2 writes a buffered gRPC response (from intercept)
// to the client using h2ResponseWriter.
func (h *Handler) writeGRPCInterceptedResponseH2(sc *streamContext, state *grpcStreamState, resp *gohttp.Response, body []byte, trailers gohttp.Header) {
	// Convert gohttp.Header to hpack for response headers.
	respHpack := goHTTPHeaderToHpack(resp.Header)
	h.writeGRPCResponseHeadersH2(sc, resp.StatusCode, respHpack)

	if len(body) > 0 {
		if err := sc.w.WriteData(body); err != nil {
			sc.logger.Debug("gRPC response intercept: failed to write body", "error", err)
		}
		sc.w.Flush()
	}

	// Record the body frame for progressive recording.
	if fbErr := state.respFrameBuf.Write(body); fbErr != nil {
		sc.logger.Warn("gRPC response intercept frame buffer error", "error", fbErr)
	}

	// Apply output filter to trailers before writing.
	if len(trailers) > 0 {
		trailers = h.ApplyOutputFilterHeaders(trailers, sc.logger)
	}

	// Write trailers using h2ResponseWriter.
	var hpackTrailers []hpack.HeaderField
	for key, vals := range trailers {
		for _, val := range vals {
			hpackTrailers = append(hpackTrailers, hpack.HeaderField{
				Name:  strings.ToLower(key),
				Value: val,
			})
		}
	}
	if len(hpackTrailers) == 0 {
		// Trailers-Only fallback: extract gRPC trailer keys from resp.Header.
		for _, key := range grpcTrailerKeyList {
			if vals, ok := resp.Header[key]; ok {
				for _, val := range vals {
					hpackTrailers = append(hpackTrailers, hpack.HeaderField{
						Name:  strings.ToLower(key),
						Value: val,
					})
				}
			}
		}
	}
	if len(hpackTrailers) > 0 {
		if err := sc.w.WriteTrailers(hpackTrailers); err != nil {
			sc.logger.Debug("gRPC failed to write intercepted trailers", "error", err)
		}
	}
}

// applyGRPCResponseInterceptHeaderMods applies header modifications from
// an intercept action to the gRPC response.
func (h *Handler) applyGRPCResponseInterceptHeaderMods(resp *gohttp.Response, action intercept.InterceptAction) {
	for k, v := range action.OverrideResponseHeaders {
		resp.Header.Set(k, v)
	}
	for k, v := range action.AddResponseHeaders {
		resp.Header.Add(k, v)
	}
	for _, k := range action.RemoveResponseHeaders {
		resp.Header.Del(k)
	}
}

// runGRPCResponseSubsystems passes the buffered gRPC response body through
// the response-side subsystem pipeline for a single frame. Used after
// response intercept when the body has been fully buffered.
func (h *Handler) runGRPCResponseSubsystems(sc *streamContext, state *grpcStreamState, resp *gohttp.Response, body []byte, trailers gohttp.Header) ([]byte, *gohttp.Response, gohttp.Header) {
	hasSubsystems := h.SafetyEngine != nil || h.pluginEngine != nil || h.transformPipeline != nil
	if !hasSubsystems || len(body) < 5 {
		return body, resp, trailers
	}

	compressed := body[0]
	msgLen := binary.BigEndian.Uint32(body[1:5])
	expectedLen := 5 + int(msgLen)
	if len(body) < expectedLen {
		return body, resp, trailers
	}
	payload := body[5:expectedLen]

	respEncoding := resp.Header.Get("Grpc-Encoding")

	state.txCtxMu.Lock()
	wireBytes, blocked := h.processGRPCResponseFrame(
		sc, body, compressed != 0, payload,
		respEncoding, resp, state.pluginConnInfo, state.txCtx)
	state.txCtxMu.Unlock()

	if blocked {
		state.mu.Lock()
		state.respBlocked = true
		state.mu.Unlock()
		return nil, resp, gohttp.Header{
			"Grpc-Status":  {"13"},
			"Grpc-Message": {percentEncodeGRPCMessage("response blocked by output filter")},
		}
	}

	return wireBytes, resp, trailers
}
