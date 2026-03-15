package http2

import (
	"bytes"
	"io"
	gohttp "net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
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
		return
	}
	defer resp.Body.Close()

	h.writeGRPCResponseHeaders(sc, resp)
	h.streamGRPCResponseBody(sc, state, resp)
	h.writeGRPCTrailers(sc, resp)

	reqWg.Wait()

	h.finalizeGRPCStream(sc, state, resp)
}

// initGRPCStreamState creates the frame buffers, progressive recorder,
// and state for a gRPC stream. The flow is created immediately with
// State="active" so it is visible before the stream completes.
func (h *Handler) initGRPCStreamState(sc *streamContext) *grpcStreamState {
	state := &grpcStreamState{}
	maxRaw := int(config.MaxBodySize)

	// Initialize progressive recorder — creates the flow with State="active".
	state.recorder = h.initGRPCFlow(sc.ctx, sc)

	// Use a context that survives the full stream lifetime for recording.
	recCtx := sc.ctx

	state.reqFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.reqFrameCount.Add(1)

		// Progressive recording: record each request frame immediately.
		state.recorder.recordFrame(recCtx, frame, "client_to_server")

		// Still accumulate raw bytes for backward compatibility with the
		// grpcHandler.RecordSession path (used by plugin hooks).
		_ = raw
		_ = maxRaw
		return nil
	})

	state.respFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.respFrameCount.Add(1)

		// Progressive recording: record each response frame immediately.
		state.recorder.recordFrame(recCtx, frame, "server_to_client")

		_ = raw
		_ = maxRaw
		return nil
	})

	return state
}

// streamGRPCRequestBody reads the request body from the client and forwards
// it to the upstream via the pipe writer, while tapping bytes into the
// FrameBuffer for frame reassembly and progressive recording.
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

	buf := make([]byte, 32*1024)
	for {
		n, readErr := sc.req.Body.Read(buf)
		if n > 0 {
			if fbErr := state.reqFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC request frame buffer error", "error", fbErr)
			}
			if _, writeErr := pw.Write(buf[:n]); writeErr != nil {
				state.mu.Lock()
				state.reqStreamErr = writeErr
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
// it to the client, while tapping bytes into the FrameBuffer for reassembly
// and progressive recording.
func (h *Handler) streamGRPCResponseBody(sc *streamContext, state *grpcStreamState, resp *gohttp.Response) {
	flusher, _ := sc.w.(gohttp.Flusher)
	buf := make([]byte, 32*1024)

	for {
		n, readErr := resp.Body.Read(buf)
		if n > 0 {
			if fbErr := state.respFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC response frame buffer error", "error", fbErr)
			}
			if _, writeErr := sc.w.Write(buf[:n]); writeErr != nil {
				sc.logger.Debug("gRPC failed to write response to client", "error", writeErr)
				break
			}
			if flusher != nil {
				flusher.Flush()
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

// writeGRPCTrailers writes the upstream response trailers to the client.
func (h *Handler) writeGRPCTrailers(sc *streamContext, resp *gohttp.Response) {
	for key, vals := range resp.Trailer {
		for _, val := range vals {
			sc.w.Header().Set(gohttp.TrailerPrefix+key, val)
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
// The gRPC streaming path bypasses full-body buffering to avoid deadlocks
// with bidirectional streaming. Safety filter, intercept, and plugin hooks
// are not yet supported for the streaming path (TODO: USK-365).
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

	sc.logger.Debug("gRPC stream: bypassing full-body buffering, intercept, and plugin hooks",
		"url", sc.req.URL.String())
	h.handleGRPCStream(sc)
	return true
}
