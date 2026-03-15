package http2

import (
	"bytes"
	"fmt"
	"io"
	gohttp "net/http"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// grpcStreamState holds the mutable state accumulated during gRPC stream
// processing. It is passed between the sub-methods of handleGRPCStream.
type grpcStreamState struct {
	reqFrameBuf  *protogrpc.FrameBuffer
	respFrameBuf *protogrpc.FrameBuffer

	mu               sync.Mutex
	reqFrames        []*protogrpc.Frame
	reqRawBytes      []byte
	reqRawTruncated  bool
	respFrames       []*protogrpc.Frame
	respRawBytes     []byte
	respRawTruncated bool

	reqStreamErr error

	// grpcEncoding is the grpc-encoding header value from the request.
	// Used for decompression/recompression of frames during subsystem processing.
	grpcEncoding string

	// Plugin context for the gRPC stream, shared across all hooks.
	pluginConnInfo *plugin.ConnInfo
	txCtx          map[string]any

	// reqBlocked is set to true if a request frame was blocked by a subsystem
	// (safety filter or plugin drop). When true, the stream is terminated.
	reqBlocked bool
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
//	         FrameBuffer (request recording)
//
//	Upstream --> Read+Write+Flush --> Client
//	     |
//	     v
//	FrameBuffer (response recording)
//
// This function is called from handleStream when gRPC Content-Type is detected.
// Recording of individual frames is delegated to the callback-based FrameBuffer
// which provides a channel/callback interface for downstream consumers
// (USK-364/USK-365).
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
		return
	}
	defer resp.Body.Close()

	// Apply output filter to response headers before writing to client.
	_, resp.Header = h.ApplyOutputFilter(nil, resp.Header, sc.logger)

	h.writeGRPCResponseHeaders(sc, resp)
	h.streamGRPCResponseBody(sc, state, resp)

	// Apply output filter to trailers before writing to client.
	if len(resp.Trailer) > 0 {
		resp.Trailer = h.ApplyOutputFilterHeaders(resp.Trailer, sc.logger)
	}
	h.writeGRPCTrailers(sc, resp)

	reqWg.Wait()

	h.finalizeGRPCStream(sc, state, resp)
}

// initGRPCStreamState creates the frame buffers and state for a gRPC stream.
// Raw bytes are capped at config.MaxBodySize to prevent unbounded memory
// growth during long-lived streaming connections.
//
// The request frame callback integrates subsystem processing: each complete
// gRPC frame is decoded, passed through safety filter / plugin hooks /
// auto-transform, and optionally re-encoded before forwarding.
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
	maxRaw := int(config.MaxBodySize)

	state.reqFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.reqFrames = append(state.reqFrames, frame)
		if !state.reqRawTruncated {
			if len(state.reqRawBytes)+len(raw) > maxRaw {
				remaining := maxRaw - len(state.reqRawBytes)
				if remaining > 0 {
					state.reqRawBytes = append(state.reqRawBytes, raw[:remaining]...)
				}
				state.reqRawTruncated = true
			} else {
				state.reqRawBytes = append(state.reqRawBytes, raw...)
			}
		}
		return nil
	})

	state.respFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.respFrames = append(state.respFrames, frame)
		if !state.respRawTruncated {
			if len(state.respRawBytes)+len(raw) > maxRaw {
				remaining := maxRaw - len(state.respRawBytes)
				if remaining > 0 {
					state.respRawBytes = append(state.respRawBytes, raw[:remaining]...)
				}
				state.respRawTruncated = true
			} else {
				state.respRawBytes = append(state.respRawBytes, raw...)
			}
		}
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
		if state.reqStreamErr != nil {
			pw.CloseWithError(state.reqStreamErr)
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
				state.reqStreamErr = err
				return
			}
		}
		if readErr != nil {
			if readErr != io.EOF {
				state.reqStreamErr = readErr
			}
			return
		}
	}
}

// newGRPCRequestSubsystemBuf creates a FrameBuffer that processes request
// frames through subsystems and writes processed bytes to the pipe writer.
func (h *Handler) newGRPCRequestSubsystemBuf(sc *streamContext, state *grpcStreamState, pw *io.PipeWriter) *protogrpc.FrameBuffer {
	return protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		wireBytes, stop := h.processGRPCRequestFrame(
			sc, raw, frame.Compressed, frame.Payload,
			state.grpcEncoding, state.pluginConnInfo, state.txCtx)
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
		state.mu.Lock()
		blocked := state.reqBlocked
		state.mu.Unlock()
		if blocked {
			return fbErr
		}
		sc.logger.Warn("gRPC request subsystem buffer error", "error", fbErr)
		// Fallback: write raw bytes directly.
		_, err := pw.Write(chunk)
		return err
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
func (h *Handler) writeGRPCResponseHeaders(sc *streamContext, resp *gohttp.Response) {
	var trailerKeys []string
	for key := range resp.Trailer {
		trailerKeys = append(trailerKeys, key)
	}
	grpcTrailerKeys := []string{"Grpc-Status", "Grpc-Message", "Grpc-Status-Details-Bin"}
	for _, gk := range grpcTrailerKeys {
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
		for _, val := range vals {
			sc.w.Header().Add(key, val)
		}
	}
	sc.w.WriteHeader(resp.StatusCode)
}

// streamGRPCResponseBody reads the response body from upstream and streams
// it to the client, while processing each gRPC frame through response-side
// subsystems (plugin hooks, auto-transform, output filter).
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
	var respBlocked bool

	if hasSubsystems {
		subsystemBuf = h.newGRPCResponseSubsystemBuf(sc, state, resp, flusher, &respBlocked)
	}

	buf := make([]byte, 32*1024)
	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if fbErr := state.respFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC response frame buffer error", "error", fbErr)
			}
			if done := h.forwardGRPCResponseChunk(sc, subsystemBuf, flusher, buf[:n], hasSubsystems, &respBlocked); done {
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
func (h *Handler) newGRPCResponseSubsystemBuf(sc *streamContext, state *grpcStreamState, resp *gohttp.Response, flusher gohttp.Flusher, respBlocked *bool) *protogrpc.FrameBuffer {
	respEncoding := resp.Header.Get("Grpc-Encoding")
	return protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		wireBytes, blocked := h.processGRPCResponseFrame(
			sc, raw, frame.Compressed, frame.Payload,
			respEncoding, resp, state.pluginConnInfo, state.txCtx)
		if blocked {
			*respBlocked = true
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
func (h *Handler) forwardGRPCResponseChunk(sc *streamContext, subsystemBuf *protogrpc.FrameBuffer, flusher gohttp.Flusher, chunk []byte, hasSubsystems bool, respBlocked *bool) bool {
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
		if *respBlocked {
			sc.logger.Warn("gRPC response stream terminated by output filter")
			return true
		}
		sc.logger.Warn("gRPC response subsystem buffer error", "error", fbErr)
		if _, writeErr := sc.w.Write(chunk); writeErr != nil {
			sc.logger.Debug("gRPC failed to write response to client", "error", writeErr)
			return true
		}
		if flusher != nil {
			flusher.Flush()
		}
	}
	return false
}

// writeGRPCTrailers writes the upstream response trailers to the client.
func (h *Handler) writeGRPCTrailers(sc *streamContext, resp *gohttp.Response) {
	for key, vals := range resp.Trailer {
		for _, val := range vals {
			sc.w.Header().Set(gohttp.TrailerPrefix+key, val)
		}
	}
}

// finalizeGRPCStream logs stream completion, flushes incomplete frames,
// records the flow, and logs the final status.
func (h *Handler) finalizeGRPCStream(sc *streamContext, state *grpcStreamState, resp *gohttp.Response) {
	if state.reqStreamErr != nil {
		sc.logger.Debug("gRPC request stream error", "error", state.reqStreamErr)
	}

	if remaining := state.reqFrameBuf.Flush(); remaining != nil {
		sc.logger.Debug("gRPC request stream ended with incomplete frame",
			"remaining_bytes", len(remaining))
	}
	if remaining := state.respFrameBuf.Flush(); remaining != nil {
		sc.logger.Debug("gRPC response stream ended with incomplete frame",
			"remaining_bytes", len(remaining))
	}

	state.mu.Lock()
	reqFrames := state.reqFrames
	reqRawBytes := state.reqRawBytes
	respFrames := state.respFrames
	respRawBytes := state.respRawBytes
	state.mu.Unlock()

	duration := time.Since(sc.start)
	h.recordGRPCStreamFlow(sc, resp, reqFrames, reqRawBytes, respFrames, respRawBytes, duration)

	sc.logger.Info("grpc streaming request",
		"method", sc.req.Method,
		"url", sc.reqURL.String(),
		"status", resp.StatusCode,
		"req_frames", len(reqFrames),
		"resp_frames", len(respFrames),
		"duration_ms", duration.Milliseconds())
}

// recordGRPCStreamFlow records the gRPC streaming flow using the frames
// collected by FrameBuffers during streaming.
func (h *Handler) recordGRPCStreamFlow(
	sc *streamContext,
	resp *gohttp.Response,
	reqFrames []*protogrpc.Frame,
	reqRawBytes []byte,
	respFrames []*protogrpc.Frame,
	respRawBytes []byte,
	duration time.Duration,
) {
	if h.grpcHandler == nil {
		return
	}
	if !h.shouldCapture(sc.req.Method, sc.reqURL) {
		return
	}

	tlsCertSubject := extractTLSCertSubject(resp)

	var trailers map[string][]string
	if resp.Trailer != nil {
		trailers = make(map[string][]string, len(resp.Trailer))
		for k, vals := range resp.Trailer {
			trailers[k] = vals
		}
	}

	var reqBody, respBody []byte
	if len(reqRawBytes) > 0 {
		reqBody = reqRawBytes
	}
	if len(respRawBytes) > 0 {
		respBody = respRawBytes
	}

	info := &protogrpc.StreamInfo{
		ConnID:               sc.connID,
		ClientAddr:           sc.clientAddr,
		ServerAddr:           "", // Will be populated by future timing integration (USK-365).
		Method:               sc.req.Method,
		URL:                  sc.reqURL,
		RequestHeaders:       sc.req.Header,
		ResponseHeaders:      resp.Header,
		Trailers:             trailers,
		RequestBody:          reqBody,
		ResponseBody:         respBody,
		StatusCode:           resp.StatusCode,
		Start:                sc.start,
		Duration:             duration,
		TLSVersion:           sc.tlsMeta.Version,
		TLSCipher:            sc.tlsMeta.CipherSuite,
		TLSALPN:              sc.tlsMeta.ALPN,
		TLSServerCertSubject: tlsCertSubject,
	}
	if err := h.grpcHandler.RecordSession(sc.ctx, info); err != nil {
		sc.logger.Error("gRPC streaming flow recording failed", "error", err)
	}
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
// Intercept is applied at the header level (request URL/headers matching).
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

	// Intercept check at header level for gRPC streaming requests.
	// Body-level intercept is not supported since the body is streamed.
	if h.InterceptEngine != nil && h.InterceptQueue != nil {
		matchedRules := h.InterceptEngine.MatchRequestRules(sc.req.Method, sc.req.URL, sc.req.Header)
		if len(matchedRules) > 0 {
			action, intercepted := h.interceptRequest(sc.ctx, sc.req, nil, sc.logger)
			if intercepted {
				switch action.Type {
				case intercept.ActionDrop:
					writeGRPCStatus(sc.w, gohttp.StatusOK, 10, "intercepted request dropped") // ABORTED
					sc.logger.Info("intercepted gRPC request dropped",
						"method", sc.req.Method, "url", sc.reqURL.String())
					return true
				case intercept.ActionModifyAndForward:
					sc.logger.Warn("gRPC streaming intercept modify_and_forward not supported, releasing",
						"method", sc.req.Method, "url", sc.reqURL.String())
				}
			}
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

// writeGRPCStatus writes a gRPC error response with the given status code
// and message. This is used when subsystems block a gRPC stream.
func writeGRPCStatus(w gohttp.ResponseWriter, httpStatus int, grpcStatus int, message string) {
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", fmt.Sprintf("%d", grpcStatus))
	w.Header().Set("Grpc-Message", message)
	w.WriteHeader(httpStatus)
}

// writeGRPCBlockResponse writes a gRPC PERMISSION_DENIED response for
// safety filter violations on gRPC streams. The violation details are
// included in the grpc-message trailer.
func writeGRPCBlockResponse(w gohttp.ResponseWriter, violation *safety.InputViolation) {
	msg := fmt.Sprintf("blocked by safety filter: %s", violation.RuleName)
	w.Header().Set("Content-Type", "application/grpc")
	w.Header().Set("Grpc-Status", "7") // PERMISSION_DENIED
	w.Header().Set("Grpc-Message", msg)
	w.Header().Set("X-Blocked-By", "yorishiro-proxy")
	w.Header().Set("X-Block-Reason", "safety_filter")
	w.WriteHeader(gohttp.StatusOK)
}
