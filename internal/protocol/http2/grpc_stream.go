package http2

import (
	"bytes"
	"io"
	"log/slog"
	gohttp "net/http"
	"sync"
	"time"

	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
)

// grpcStreamState holds the mutable state accumulated during gRPC stream
// processing. It is passed between the sub-methods of handleGRPCStream.
type grpcStreamState struct {
	reqFrameBuf  *protogrpc.FrameBuffer
	respFrameBuf *protogrpc.FrameBuffer

	mu           sync.Mutex
	reqFrames    []*protogrpc.Frame
	reqRawBytes  []byte
	respFrames   []*protogrpc.Frame
	respRawBytes []byte

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
	state := h.initGRPCStreamState()

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

// initGRPCStreamState creates the frame buffers and state for a gRPC stream.
func (h *Handler) initGRPCStreamState() *grpcStreamState {
	state := &grpcStreamState{}

	state.reqFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.reqFrames = append(state.reqFrames, frame)
		state.reqRawBytes = append(state.reqRawBytes, raw...)
		return nil
	})

	state.respFrameBuf = protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
		state.mu.Lock()
		defer state.mu.Unlock()
		state.respFrames = append(state.respFrames, frame)
		state.respRawBytes = append(state.respRawBytes, raw...)
		return nil
	})

	return state
}

// streamGRPCRequestBody reads the request body from the client and forwards
// it to the upstream via the pipe writer, while tapping bytes into the
// FrameBuffer for frame reassembly.
func (h *Handler) streamGRPCRequestBody(sc *streamContext, state *grpcStreamState, pw *io.PipeWriter, wg *sync.WaitGroup) {
	defer wg.Done()
	defer pw.Close()

	buf := make([]byte, 32*1024)
	for {
		n, readErr := sc.req.Body.Read(buf)
		if n > 0 {
			if fbErr := state.reqFrameBuf.Write(buf[:n]); fbErr != nil {
				sc.logger.Warn("gRPC request frame buffer error", "error", fbErr)
			}
			if _, writeErr := pw.Write(buf[:n]); writeErr != nil {
				state.reqStreamErr = writeErr
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
	h.tlsMu.RLock()
	h.UpstreamMu.RLock()
	resp, err := h.Transport.RoundTrip(outReq)
	h.UpstreamMu.RUnlock()
	h.tlsMu.RUnlock()

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
	trailerKeys = append(trailerKeys, grpcTrailerKeys...)
	if len(trailerKeys) > 0 {
		sc.w.Header().Set("Trailer", joinTrailerKeys(trailerKeys))
	}

	for key, vals := range resp.Header {
		for _, val := range vals {
			sc.w.Header().Add(key, val)
		}
	}
	sc.w.WriteHeader(resp.StatusCode)
}

// streamGRPCResponseBody reads the response body from upstream and streams
// it to the client, while tapping bytes into the FrameBuffer for reassembly.
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

// isGRPCStream reports whether the request should use the streaming gRPC
// transport path. Currently all gRPC requests use streaming to avoid the
// full-body-buffering deadlock.
func isGRPCStream(h *Handler, sc *streamContext) bool {
	return h.grpcHandler != nil && isGRPCContentType(sc.req.Header.Get("Content-Type"))
}

// logGRPCStreamBypass logs that the gRPC streaming path is being used,
// noting which processing steps are bypassed.
func logGRPCStreamBypass(logger *slog.Logger, url string) {
	logger.Debug("gRPC stream: bypassing full-body buffering, intercept, and plugin hooks",
		"url", url)
}
