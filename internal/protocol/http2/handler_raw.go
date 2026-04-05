package http2

import (
	"io"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// handleRawForward handles the raw mode forwarding path for intercepted HTTP/2
// requests. It sends the raw frame bytes (original or edited) directly to the
// upstream server using the custom HTTP/2 frame-engine transport, bypassing
// L7 transforms and plugin hooks.
//
// This method is called from handleStream when the intercept action specifies
// raw mode (ModeRaw). It handles:
//   - Variant recording (original vs modified raw frames)
//   - Raw frame forwarding via the custom Transport
//   - Response processing and recording
func (h *Handler) handleRawForward(sc *streamContext, snap *requestSnapshot) {
	action := sc.interceptRawAction
	rawBytes := action.RawOverride
	if len(rawBytes) == 0 {
		sc.logger.Error("HTTP/2 raw forward: no raw bytes to send")
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		return
	}

	if h.h2Transport == nil {
		sc.logger.Error("HTTP/2 raw forward: h2Transport not configured, cannot forward raw frames")
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		return
	}

	// Determine if the raw bytes were modified (modify_and_forward vs release).
	originalRawBytes := joinRawFrames(sc.reqRawFrames)
	isModified := !equalBytes(rawBytes, originalRawBytes)

	// Record the send phase with variant support for raw mode.
	sendResult := h.recordRawSend(sc, rawBytes, isModified)

	// Derive host:port from the request URL for the transport.
	hostname := sc.reqURL.Hostname()
	port := sc.reqURL.Port()
	if port == "" {
		if sc.reqURL.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	hostPort := net.JoinHostPort(hostname, port)

	sendStart := time.Now()
	result, err := h.h2Transport.SendRawFrames(sc.ctx, hostPort, rawBytes)
	if err != nil {
		sc.logger.Error("HTTP/2 raw forward upstream failed",
			"method", sc.h2req.Method, "url", sc.reqURL.String(), "error", err)
		h.recordSendError(sc.ctx, sendResult, sc.start, err, sc.logger)
		writeErrorResponse(sc.w, httputil.StatusBadGateway)
		return
	}

	// Read the response body from the native result.
	var fullRespBody []byte
	if result.Body != nil {
		var readErr error
		fullRespBody, readErr = io.ReadAll(io.LimitReader(result.Body, config.MaxBodySize))
		if readErr != nil {
			sc.logger.Warn("HTTP/2 raw forward: failed to read response body", "error", readErr)
		}
	}
	receiveEnd := time.Now()

	// Compute approximate timing.
	sMs := receiveEnd.Sub(sendStart).Milliseconds()
	wMs := sMs // approximation: no TTFB separation for custom transport
	rMs := int64(0)

	// Build h2Response from native result fields.
	respHeaders := result.Headers
	respTrailers := result.Trailers
	h2resp := &h2Response{
		StatusCode: result.StatusCode,
		Headers:    respHeaders,
		Trailers:   respTrailers,
		Body:       fullRespBody,
	}

	writeH2ResponseToClient(sc, h2resp)

	duration := time.Since(sc.start)

	// Record receive phase.
	h.recordReceiveWithVariant(sc.ctx, sendResult, receiveRecordParams{
		start:       sc.start,
		duration:    duration,
		serverAddr:  result.ServerAddr,
		statusCode:  result.StatusCode,
		respHeaders: respHeaders,
		respBody:    fullRespBody,
		sendMs:      &sMs,
		waitMs:      &wMs,
		receiveMs:   &rMs,
		rawFrames:   result.RawFrames,
	}, nil, sc.logger)

	sc.logger.Info("http/2 raw forward request",
		"method", sc.h2req.Method,
		"url", sc.reqURL.String(),
		"status", result.StatusCode,
		"raw_modified", isModified,
		"duration_ms", duration.Milliseconds())
}

// equalBytes compares two byte slices for equality.
func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// recordRawSend records the send phase for a raw mode forwarded request.
// When the raw bytes were modified (modify_and_forward), it records two
// messages: original (variant="original") and modified (variant="modified").
// When not modified (raw release), it records a single send message.
func (h *Handler) recordRawSend(sc *streamContext, rawBytes []byte, isModified bool) *sendRecordResult {
	if h.Store == nil || !h.shouldCapture(sc.h2req.Method, sc.reqURL) {
		return nil
	}

	if !isModified {
		// Unmodified: use standard recordSend (raw bytes are from wire).
		return h.recordSend(sc.ctx, sc.srp, sc.logger)
	}

	// Modified: record two send messages (original + modified).
	protocol := proxy.SOCKS5Protocol(sc.ctx, "HTTP/2")
	tags := proxy.MergeSOCKS5Tags(sc.ctx, nil)

	fl := &flow.Stream{
		ConnID:    sc.connID,
		Protocol:  protocol,
		Scheme:    sc.flowScheme,
		State:     "active",
		Timestamp: sc.start,
		Tags:      tags,
		ConnInfo:  sc.connInfo,
	}
	if err := h.Store.SaveStream(sc.ctx, fl); err != nil {
		sc.logger.Error("HTTP/2 raw forward: flow save failed",
			"method", sc.h2req.Method, "url", sc.reqURL.String(), "error", err)
		return nil
	}

	reqHeaders := requestHeadersMap(sc.h2req.AllHeaders, sc.h2req.Authority)

	// Sequence 0: original (wire-observed raw frames).
	origMeta := buildFrameMetadata(sc.reqRawFrames, map[string]string{"variant": "original"})
	originalMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      0,
		Direction:     "send",
		Timestamp:     sc.start,
		Method:        sc.h2req.Method,
		URL:           sc.reqURL,
		Headers:       reqHeaders,
		Body:          sc.srp.reqBody,
		RawBytes:      joinRawFrames(sc.reqRawFrames),
		BodyTruncated: sc.srp.reqTruncated,
		Metadata:      origMeta,
	}
	if err := h.Store.SaveFlow(sc.ctx, originalMsg); err != nil {
		sc.logger.Error("HTTP/2 raw forward: original send save failed", "error", err)
	}

	// Sequence 1: modified (edited raw bytes).
	modMeta := map[string]string{"variant": "modified"}
	modifiedMsg := &flow.Flow{
		StreamID:      fl.ID,
		Sequence:      1,
		Direction:     "send",
		Timestamp:     sc.start,
		Method:        sc.h2req.Method,
		URL:           sc.reqURL,
		Headers:       reqHeaders,
		Body:          sc.srp.reqBody,
		RawBytes:      rawBytes,
		BodyTruncated: sc.srp.reqTruncated,
		Metadata:      modMeta,
	}
	if err := h.Store.SaveFlow(sc.ctx, modifiedMsg); err != nil {
		sc.logger.Error("HTTP/2 raw forward: modified send save failed", "error", err)
	}

	return &sendRecordResult{flowID: fl.ID, recvSequence: 2}
}
