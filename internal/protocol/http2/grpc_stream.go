package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
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

	outReq, ok := h.buildGRPCOutboundRequest(sc, pr)
	if !ok {
		reqWg.Wait()
		return
	}

	resp, ok := h.sendGRPCUpstream(sc, outReq, &reqWg)
	if !ok {
		// Check if the request was blocked by a subsystem.
		state.mu.Lock()
		blocked := state.reqBlocked
		state.mu.Unlock()
		if blocked {
			writeGRPCStatus(sc.w, gohttp.StatusOK, 7, "request blocked by safety filter") // PERMISSION_DENIED
		}
		return
	}
	defer resp.Body.Close()

	// Apply output filter to response headers before writing to client.
	_, resp.Header = h.ApplyOutputFilter(nil, resp.Header, sc.logger)

	h.writeGRPCResponseHeaders(sc, resp)
	h.streamGRPCResponseBody(sc, state, resp)

	// Skip trailers if response was blocked — we already wrote an error status.
	state.mu.Lock()
	blocked := state.respBlocked
	state.mu.Unlock()
	if !blocked {
		// Apply output filter to trailers before writing to client.
		if len(resp.Trailer) > 0 {
			resp.Trailer = h.ApplyOutputFilterHeaders(resp.Trailer, sc.logger)
		}
		h.writeGRPCTrailers(sc, resp)
	}

	// Flush response to wire before waiting for request goroutine.
	// This is critical for trailers-only responses where no body Write()/Flush()
	// has occurred: without this, the client never receives the response and
	// cannot close its request stream, causing a deadlock at reqWg.Wait().
	// For normal responses, streamGRPCResponseBody already called Flush(),
	// so this is a harmless no-op.
	if flusher, ok := sc.w.(gohttp.Flusher); ok {
		flusher.Flush()
	}

	reqWg.Wait()

	h.finalizeGRPCStream(sc, state, resp)
}

// initGRPCStreamState creates the frame buffers, progressive recorder,
// and state for a gRPC stream. The flow is created immediately with
// State="active" so it is visible before the stream completes.
func (h *Handler) initGRPCStreamState(sc *streamContext) *grpcStreamState {
	state := &grpcStreamState{
		grpcEncoding: sc.req.Header.Get("Grpc-Encoding"),
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

	buf := make([]byte, 32*1024)
	for {
		n, readErr := sc.req.Body.Read(buf)
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
			if readErr != io.EOF {
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

// buildGRPCOutboundRequest creates the upstream HTTP request with the pipe
// reader as a streaming body. Returns false if the request could not be built.
func (h *Handler) buildGRPCOutboundRequest(sc *streamContext, pr *io.PipeReader) (*gohttp.Request, bool) {
	outURL := cloneURL(sc.req.URL)
	outReq, err := gohttp.NewRequestWithContext(sc.ctx, sc.req.Method, outURL.String(), pr)
	if err != nil {
		sc.logger.Error("gRPC failed to build upstream request", "error", err)
		pr.Close()
		sc.w.WriteHeader(gohttp.StatusBadGateway)
		return nil, false
	}
	for key, vals := range sc.req.Header {
		outReq.Header[key] = vals
	}
	removeHTTP2HopByHop(outReq.Header)
	outReq.ContentLength = -1
	return outReq, true
}

// sendGRPCUpstream sends the outbound request to the upstream server.
// Returns the response and true on success, or nil and false on failure.
// On failure, it waits for the request goroutine to finish.
func (h *Handler) sendGRPCUpstream(sc *streamContext, outReq *gohttp.Request, reqWg *sync.WaitGroup) (*gohttp.Response, bool) {
	// Use the same lock pattern as roundTripWithTrace: only UpstreamMu is
	// needed to protect Transport.Proxy from concurrent SetUpstreamProxy.
	// tlsMu protects DialTLSContext setup which is configured before requests.
	h.UpstreamMu.RLock()
	resp, err := h.Transport.RoundTrip(outReq)
	h.UpstreamMu.RUnlock()

	if err != nil {
		sc.logger.Error("gRPC upstream request failed",
			"method", sc.req.Method, "url", sc.reqURL.String(), "error", err)
		sc.w.WriteHeader(gohttp.StatusBadGateway)
		reqWg.Wait()
		return nil, false
	}
	return resp, true
}

// writeGRPCResponseHeaders writes the upstream response headers to the client,
// declaring known gRPC trailer keys for proper HTTP/2 trailer framing.
//
// For Trailers-Only responses (where Go's http2.Transport places all headers
// including gRPC trailer keys like Grpc-Status into resp.Header with an empty
// resp.Trailer), gRPC trailer keys are excluded from the initial HEADERS frame.
// They will be written as trailers by writeGRPCTrailers instead.
func (h *Handler) writeGRPCResponseHeaders(sc *streamContext, resp *gohttp.Response) {
	trailersOnly := isGRPCTrailersOnly(resp)

	var trailerKeys []string
	for key := range resp.Trailer {
		trailerKeys = append(trailerKeys, key)
	}
	for _, gk := range grpcTrailerKeyList {
		found := false
		for _, tk := range trailerKeys {
			if strings.EqualFold(tk, gk) {
				found = true
				break
			}
		}
		if !found {
			trailerKeys = append(trailerKeys, gk)
		}
	}
	if len(trailerKeys) > 0 {
		sc.w.Header().Set("Trailer", joinTrailerKeys(trailerKeys))
	}

	for key, vals := range resp.Header {
		if strings.EqualFold(key, "Trailer") {
			continue
		}
		// In Trailers-Only responses, gRPC trailer keys appear in resp.Header
		// because Go's http2.Transport merges them. Exclude them from the
		// initial HEADERS so they can be sent as proper trailers.
		if trailersOnly && isGRPCTrailerKey(key) {
			continue
		}
		for _, val := range vals {
			sc.w.Header().Add(key, val)
		}
	}
	sc.w.WriteHeader(resp.StatusCode)
}

// streamGRPCResponseBody reads the response body from upstream and streams
// it to the client, while processing each gRPC frame through response-side
// subsystems (plugin hooks, auto-transform, output filter) and tapping bytes
// into the FrameBuffer for progressive recording.
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
func (h *Handler) streamGRPCResponseBody(sc *streamContext, state *grpcStreamState, resp *gohttp.Response) {
	flusher, _ := sc.w.(gohttp.Flusher)
	hasSubsystems := h.SafetyEngine != nil || h.pluginEngine != nil || h.transformPipeline != nil

	var subsystemBuf *protogrpc.FrameBuffer

	if hasSubsystems {
		subsystemBuf = h.newGRPCResponseSubsystemBuf(sc, state, resp, flusher)
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if fbErr := state.respFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC response frame buffer error", "error", fbErr)
			}
			if done := h.forwardGRPCResponseChunk(sc, state, subsystemBuf, flusher, buf[:n], hasSubsystems); done {
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

// newGRPCResponseSubsystemBuf creates a FrameBuffer that processes response
// frames through subsystems and writes processed bytes to the client.
func (h *Handler) newGRPCResponseSubsystemBuf(sc *streamContext, state *grpcStreamState, resp *gohttp.Response, flusher gohttp.Flusher) *protogrpc.FrameBuffer {
	respEncoding := resp.Header.Get("Grpc-Encoding")
	return protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		// Lock txCtx for thread-safe plugin hook access.
		state.txCtxMu.Lock()
		wireBytes, blocked := h.processGRPCResponseFrame(
			sc, raw, frame.Compressed, frame.Payload,
			respEncoding, resp, state.pluginConnInfo, state.txCtx)
		state.txCtxMu.Unlock()
		if blocked {
			state.mu.Lock()
			state.respBlocked = true
			state.mu.Unlock()
			return fmt.Errorf("gRPC response frame blocked by output filter")
		}
		if _, err := sc.w.Write(wireBytes); err != nil {
			return err
		}
		if flusher != nil {
			flusher.Flush()
		}
		return nil
	})
}

// forwardGRPCResponseChunk forwards a chunk of response data. If subsystems
// are enabled, the chunk is processed through the subsystem buffer. Otherwise
// it is written directly to the client. Returns true if the stream should stop.
func (h *Handler) forwardGRPCResponseChunk(sc *streamContext, state *grpcStreamState, subsystemBuf *protogrpc.FrameBuffer, flusher gohttp.Flusher, chunk []byte, hasSubsystems bool) bool {
	if !hasSubsystems {
		if _, writeErr := sc.w.Write(chunk); writeErr != nil {
			sc.logger.Debug("gRPC failed to write response to client", "error", writeErr)
			return true
		}
		if flusher != nil {
			flusher.Flush()
		}
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
			sc.w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "13")
			sc.w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", percentEncodeGRPCMessage("response blocked by output filter"))
		} else {
			sc.logger.Warn("gRPC response subsystem buffer error", "error", fbErr)
			sc.w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "13")
			sc.w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", percentEncodeGRPCMessage("response subsystem processing error"))
		}
		return true
	}
	return false
}

// writeGRPCTrailers writes the upstream response trailers to the client.
//
// For Trailers-Only responses, Go's http2.Transport places all headers
// (including gRPC trailer keys like Grpc-Status) into resp.Header and leaves
// resp.Trailer empty. In this case, gRPC trailer keys are extracted from
// resp.Header as a fallback and written with the TrailerPrefix so that the
// frameResponseWriter.finish() method can collect and send them as proper
// HTTP/2 trailing HEADERS with END_STREAM.
func (h *Handler) writeGRPCTrailers(sc *streamContext, resp *gohttp.Response) {
	for key, vals := range resp.Trailer {
		for _, val := range vals {
			sc.w.Header().Set(gohttp.TrailerPrefix+key, val)
		}
	}

	// Trailers-Only fallback: if resp.Trailer is empty, extract gRPC trailer
	// keys from resp.Header. This handles the case where Go's http2.Transport
	// merges all headers from a single HEADERS+END_STREAM frame into
	// resp.Header (the Trailers-Only encoding per gRPC spec).
	if len(resp.Trailer) == 0 {
		for _, key := range grpcTrailerKeyList {
			if vals, ok := resp.Header[key]; ok {
				for _, val := range vals {
					sc.w.Header().Set(gohttp.TrailerPrefix+key, val)
				}
			}
		}
	}
}

// finalizeGRPCStream logs stream completion, flushes incomplete frames,
// completes the progressive recording, and logs the final status.
func (h *Handler) finalizeGRPCStream(sc *streamContext, state *grpcStreamState, resp *gohttp.Response) {
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
	state.recorder.completeFlow(sc.ctx, resp, reqFrames, respFrames, duration)

	sc.logger.Info("grpc streaming request",
		"method", sc.req.Method,
		"url", sc.reqURL.String(),
		"status", resp.StatusCode,
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

// joinTrailerKeys joins trailer key names with ", " for the Trailer header.
func joinTrailerKeys(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	var buf bytes.Buffer
	for i, k := range keys {
		if i > 0 {
			buf.WriteString(", ")
		}
		buf.WriteString(k)
	}
	return buf.String()
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
	if h.grpcHandler == nil || !isGRPCContentType(sc.req.Header.Get("Content-Type")) {
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
		matchedRules := h.InterceptEngine.MatchRequestRules(sc.req.Method, sc.req.URL, sc.req.Header)
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
		"url", sc.req.URL.String(),
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
// request. It returns the raw body, decoded JSON, the single frame, and true
// if the body is a valid unary request. On failure, the request body is restored
// and false is returned.
func (h *Handler) bufferGRPCUnaryBody(sc *streamContext) (body []byte, jsonBody string, frame protobuf.Frame, ok bool) {
	// Limit body read to prevent memory exhaustion from oversized payloads
	// disguised as gRPC (CWE-400). Uses the same limit as raw bytes storage.
	var err error
	body, err = io.ReadAll(io.LimitReader(sc.req.Body, intercept.MaxRawBytesSize+1))
	if err != nil {
		sc.logger.Debug("gRPC intercept: failed to buffer request body", "error", err)
		sc.req.Body = io.NopCloser(bytes.NewReader(nil))
		return nil, "", protobuf.Frame{}, false
	}
	if len(body) > intercept.MaxRawBytesSize {
		sc.logger.Warn("gRPC intercept: request body too large, releasing",
			"body_len", len(body), "max", intercept.MaxRawBytesSize)
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
		return nil, "", protobuf.Frame{}, false
	}

	frames, parseErr := protobuf.ParseFrames(body)
	if parseErr != nil || len(frames) == 0 {
		sc.logger.Debug("gRPC intercept: frame parse failed or empty, releasing",
			"error", parseErr, "body_len", len(body))
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
		return nil, "", protobuf.Frame{}, false
	}

	if len(frames) != 1 {
		sc.logger.Warn("gRPC streaming intercept modify_and_forward not supported, releasing",
			"method", sc.req.Method, "url", sc.reqURL.String(), "frame_count", len(frames))
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
		return nil, "", protobuf.Frame{}, false
	}

	frame = frames[0]
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
		"method", sc.req.Method, "url", sc.reqURL.String(), "matched_rules", matchedRules)

	id, actionCh := h.InterceptQueue.Enqueue(sc.req.Method, sc.req.URL, sc.req.Header, []byte(jsonBody), matchedRules)
	defer h.InterceptQueue.Remove(id)

	// Attach raw bytes (the original gRPC wire body).
	if len(body) > 0 {
		if err := h.InterceptQueue.SetRawBytes(id, body); err != nil {
			sc.logger.Warn("gRPC intercept: failed to set raw bytes", "id", id, "error", err)
		}
	}

	// Attach gRPC metadata for re-encoding on modify_and_forward.
	h.attachGRPCInterceptMetadata(sc, id, frame)

	return h.waitGRPCInterceptAction(sc, id, actionCh)
}

// attachGRPCInterceptMetadata sets gRPC-specific metadata on the enqueued
// intercept item so the MCP tool layer can re-encode the body correctly.
func (h *Handler) attachGRPCInterceptMetadata(sc *streamContext, id string, frame protobuf.Frame) {
	contentType := sc.req.Header.Get("Content-Type")
	grpcEncoding := sc.req.Header.Get("Grpc-Encoding")
	compressed := "false"
	if frame.Compressed != 0 {
		compressed = "true"
	}
	metadata := map[string]string{
		"grpc_content_type": contentType,
		"grpc_encoding":     grpcEncoding,
		"grpc_compressed":   compressed,
		"original_frames":   "1",
	}
	if err := h.InterceptQueue.SetMetadata(id, metadata); err != nil {
		sc.logger.Warn("gRPC intercept: failed to set metadata", "id", id, "error", err)
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
		writeGRPCStatus(sc.w, gohttp.StatusOK, 10, "intercepted request dropped") // ABORTED
		sc.logger.Info("intercepted gRPC request dropped",
			"method", sc.req.Method, "url", sc.reqURL.String())
		return true

	case intercept.ActionModifyAndForward:
		if action.OverrideBody != nil {
			sc.req.Body = io.NopCloser(bytes.NewReader([]byte(*action.OverrideBody)))
		} else {
			sc.req.Body = io.NopCloser(bytes.NewReader(body))
		}
		h.applyGRPCInterceptHeaderMods(sc, action)
		return false

	default:
		// Release: restore original body.
		sc.req.Body = io.NopCloser(bytes.NewReader(body))
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
