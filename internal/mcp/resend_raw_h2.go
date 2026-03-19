package mcp

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// h2ClientPreface is the HTTP/2 connection preface per RFC 9113 Section 3.4.
const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// h2DefaultHeaderTableSize is the default HPACK dynamic table size.
const h2DefaultHeaderTableSize = 4096

// h2DefaultInitialWindowSize is the default HTTP/2 initial window size.
const h2DefaultInitialWindowSize = 65535

// h2DefaultMaxConcurrentStreams is the default max concurrent streams for resend_raw.
const h2DefaultMaxConcurrentStreams = 100

// isHTTP2Protocol reports whether the protocol string indicates an HTTP/2 flow.
func isHTTP2Protocol(protocol string) bool {
	return protocol == "HTTP/2" || protocol == "gRPC"
}

// inferFlowUseTLS returns true if the flow was originally captured over a TLS
// connection. It inspects the flow's ConnInfo for TLS metadata. When ConnInfo is
// nil (e.g., resend-created flows without connection info) or has no TLS fields,
// it falls back to checking the Protocol field ("HTTPS" implies TLS).
func inferFlowUseTLS(fl *flow.Flow) bool {
	if fl.ConnInfo != nil {
		if fl.ConnInfo.TLSVersion != "" || fl.ConnInfo.TLSALPN == "h2" {
			return true
		}
		// ConnInfo is present but has no TLS fields → cleartext.
		return false
	}
	// No ConnInfo available; fall back to protocol name.
	return fl.Protocol == "HTTPS"
}

// buildAndSendRawH2 establishes an HTTP/2 connection, performs the connection
// preface and SETTINGS exchange, sends the raw frame bytes, and reads back
// response frames. This is the HTTP/2 equivalent of buildAndSendRaw.
//
// The raw bytes from the original flow contain serialized HTTP/2 frames
// (HEADERS, DATA, etc.) as captured on the wire. These are written directly
// after the connection handshake, preserving the exact byte representation.
//
// Response frames are read until the server sends END_STREAM or the connection
// is closed/timed out.
func (s *Server) buildAndSendRawH2(ctx context.Context, fl *flow.Flow, params resendParams, targetAddr string, rawBytes []byte) ([]byte, time.Time, time.Duration, error) {
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, start, 0, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	// Determine whether to use TLS. If the caller explicitly set use_tls, honour it.
	// Otherwise infer from the flow's connection metadata: if TLS was negotiated
	// on the original connection the flow is TLS-based; if not, it is h2c (cleartext HTTP/2).
	useTLS := inferFlowUseTLS(fl)
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}
	if useTLS {
		conn, err = upgradeTLSH2(ctx, conn, targetAddr, s.deps.tlsTransport)
		if err != nil {
			return nil, start, 0, err
		}
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, start, 0, fmt.Errorf("set connection deadline: %w", err)
	}

	// Perform the HTTP/2 connection handshake.
	reader, err := h2Handshake(conn)
	if err != nil {
		return nil, start, 0, fmt.Errorf("HTTP/2 handshake: %w", err)
	}

	// Remap stream IDs in the raw frame bytes before sending.
	// The original capture may use arbitrary stream IDs that conflict with the
	// new connection's state. We parse each frame, build a mapping from original
	// stream IDs to new sequential odd IDs (1, 3, 5, ...), and skip connection-
	// level control frames (SETTINGS, PING, WINDOW_UPDATE on stream 0) since
	// the handshake already established those.
	remapped, err := remapH2StreamIDs(rawBytes)
	if err != nil {
		return nil, start, 0, fmt.Errorf("remap HTTP/2 stream IDs: %w", err)
	}
	if _, err := conn.Write(remapped); err != nil {
		return nil, start, 0, fmt.Errorf("send raw HTTP/2 frames: %w", err)
	}

	// Read response frames until END_STREAM or connection close/timeout.
	respData, err := readH2ResponseFrames(reader)
	if err != nil && len(respData) == 0 {
		return nil, start, 0, fmt.Errorf("read HTTP/2 response: %w", err)
	}
	duration := time.Since(start)

	return respData, start, duration, nil
}

// upgradeTLSH2 wraps a connection with TLS, requiring ALPN "h2" negotiation.
// This is distinct from upgradeTLS which does not enforce a specific ALPN protocol.
func upgradeTLSH2(ctx context.Context, conn net.Conn, targetAddr string, transport httputil.TLSTransport) (net.Conn, error) {
	if transport == nil {
		transport = &httputil.StandardTransport{InsecureSkipVerify: true}
	}
	host, _, _ := net.SplitHostPort(targetAddr)
	tlsConn, proto, err := transport.TLSConnect(ctx, conn, host)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake with %s: %w", targetAddr, err)
	}
	if proto != "h2" {
		tlsConn.Close()
		return nil, fmt.Errorf("ALPN negotiation failed for %s: got %q, want \"h2\"", targetAddr, proto)
	}
	return tlsConn, nil
}

// h2Handshake performs the HTTP/2 connection preface and SETTINGS exchange
// on an already-established (optionally TLS) connection. It returns a
// frame.Reader positioned after the handshake, ready to read response frames.
//
// The handshake sequence is:
//  1. Send client connection preface (magic string)
//  2. Send client SETTINGS frame
//  3. Read server SETTINGS frame
//  4. Send SETTINGS ACK for the server's SETTINGS
//  5. Read server's SETTINGS ACK (may arrive later; handled in readH2ResponseFrames)
func h2Handshake(conn net.Conn) (*frame.Reader, error) {
	// Step 1: Send client connection preface.
	if _, err := conn.Write([]byte(h2ClientPreface)); err != nil {
		return nil, fmt.Errorf("send client preface: %w", err)
	}

	writer := frame.NewWriter(conn)
	reader := frame.NewReader(conn)

	// Step 2: Send client initial SETTINGS.
	if err := writer.WriteSettings([]frame.Setting{
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingMaxConcurrentStreams, Value: h2DefaultMaxConcurrentStreams},
		{ID: frame.SettingInitialWindowSize, Value: h2DefaultInitialWindowSize},
	}); err != nil {
		return nil, fmt.Errorf("send client SETTINGS: %w", err)
	}

	// Step 3: Read frames until we get the server's initial SETTINGS (non-ACK).
	if err := h2WaitForServerSettings(reader, writer); err != nil {
		return nil, err
	}

	// Step 4: Send SETTINGS ACK for the server's SETTINGS.
	if err := writer.WriteSettingsAck(); err != nil {
		return nil, fmt.Errorf("send SETTINGS ACK: %w", err)
	}

	return reader, nil
}

// h2WaitForServerSettings reads frames until the server's initial SETTINGS
// (non-ACK) is received. It handles GOAWAY (error), PING (send ACK per RFC
// 9113 Section 6.7), SETTINGS ACK, and WINDOW_UPDATE during the handshake.
func h2WaitForServerSettings(reader *frame.Reader, writer *frame.Writer) error {
	for {
		f, err := reader.ReadFrame()
		if err != nil {
			return fmt.Errorf("read server SETTINGS: %w", err)
		}
		switch {
		case f.Header.Type == frame.TypeSettings && !f.Header.Flags.Has(frame.FlagAck):
			// Server's initial SETTINGS received. Apply max frame size if advertised.
			applyServerMaxFrameSize(f, reader, writer)
			return nil
		case f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck):
			// Server ACK for our SETTINGS; expected during handshake.
		case f.Header.Type == frame.TypeGoAway:
			return fmt.Errorf("server sent GOAWAY during handshake")
		case f.Header.Type == frame.TypePing && !f.Header.Flags.Has(frame.FlagAck):
			// Per RFC 9113 Section 6.7, PING frames must be acknowledged.
			if pingData, pErr := f.PingData(); pErr == nil {
				writer.WritePing(true, pingData) //nolint:errcheck
			}
		case f.Header.Type == frame.TypeWindowUpdate:
			// Window updates during handshake; ignore.
		default:
			// Other frames during handshake; ignore gracefully.
		}
	}
}

// applyServerMaxFrameSize updates the reader/writer max frame size if the
// server advertises a value larger than the default.
func applyServerMaxFrameSize(f *frame.Frame, reader *frame.Reader, writer *frame.Writer) {
	settings, err := f.SettingsParams()
	if err != nil {
		return
	}
	for _, st := range settings {
		if st.ID == frame.SettingMaxFrameSize && st.Value > frame.DefaultMaxFrameSize {
			reader.SetMaxFrameSize(st.Value) //nolint:errcheck
			writer.SetMaxFrameSize(st.Value) //nolint:errcheck
		}
	}
}

// h2FrameAction describes how to handle a response frame.
type h2FrameAction int

const (
	// h2FrameSkip indicates the frame should be skipped (control frames).
	h2FrameSkip h2FrameAction = iota
	// h2FrameCollect indicates the frame's raw bytes should be collected.
	h2FrameCollect
	// h2FrameCollectAndStop indicates the frame should be collected and reading should stop.
	h2FrameCollectAndStop
)

// classifyH2ResponseFrame determines how to handle a response frame.
// It also advances the HPACK decoder state for HEADERS frames.
func classifyH2ResponseFrame(f *frame.Frame, decoder *hpack.Decoder) h2FrameAction {
	switch f.Header.Type {
	case frame.TypeSettings, frame.TypeWindowUpdate, frame.TypePing:
		return h2FrameSkip
	case frame.TypeGoAway, frame.TypeRSTStream:
		return h2FrameCollectAndStop
	case frame.TypeHeaders:
		// Decode the header block to advance HPACK state.
		if f.Header.Flags.Has(frame.FlagEndHeaders) {
			if fragment, err := f.HeaderBlockFragment(); err == nil {
				decoder.Decode(fragment) //nolint:errcheck
			}
		}
		if f.Header.Flags.Has(frame.FlagEndStream) {
			return h2FrameCollectAndStop
		}
		return h2FrameCollect
	case frame.TypeData:
		if f.Header.Flags.Has(frame.FlagEndStream) {
			return h2FrameCollectAndStop
		}
		return h2FrameCollect
	default:
		// CONTINUATION and unknown frame types: collect.
		return h2FrameCollect
	}
}

// readH2ResponseFrames reads HTTP/2 response frames from the reader and
// collects their raw bytes. It stops when:
//   - A frame with END_STREAM flag is received
//   - A GOAWAY frame is received
//   - EOF or connection close
//   - The response data exceeds MaxReplayResponseSize
//
// Control frames (SETTINGS, WINDOW_UPDATE, PING) are skipped automatically.
// The returned bytes are the concatenation of all response frame raw bytes
// (excluding connection-level control frames).
func readH2ResponseFrames(reader *frame.Reader) ([]byte, error) {
	var respData []byte
	decoder := hpack.NewDecoder(h2DefaultHeaderTableSize)

	for {
		f, err := reader.ReadFrame()
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return respData, nil
			}
			return respData, err
		}

		action := classifyH2ResponseFrame(f, decoder)
		switch action {
		case h2FrameSkip:
			continue
		case h2FrameCollect:
			respData = appendRawCapped(respData, f.RawBytes)
		case h2FrameCollectAndStop:
			respData = appendRawCapped(respData, f.RawBytes)
			return respData, nil
		}

		if int64(len(respData)) >= config.MaxReplayResponseSize {
			return respData, nil
		}
	}
}

// remapH2StreamIDs parses raw HTTP/2 frame bytes and remaps stream IDs so they
// are valid for a fresh connection. Client-initiated stream IDs (odd, non-zero)
// are remapped to sequential odd IDs starting from 1. Connection-level control
// frames (SETTINGS, PING, WINDOW_UPDATE/RST_STREAM on stream 0) are dropped
// because the handshake already established the connection state.
//
// Server-initiated stream IDs (even, non-zero) and stream 0 frames that are not
// control frames are preserved with their stream ID remapped or kept at 0.
func remapH2StreamIDs(raw []byte) ([]byte, error) {
	var out []byte
	streamMap := make(map[uint32]uint32) // original stream ID → new stream ID
	var nextClientStream uint32 = 1      // next client-initiated stream ID (odd)

	for len(raw) > 0 {
		if len(raw) < frame.HeaderSize {
			return nil, fmt.Errorf("truncated frame header: %d bytes remaining", len(raw))
		}
		hdr, err := frame.ParseHeader(raw[:frame.HeaderSize])
		if err != nil {
			return nil, fmt.Errorf("parse frame header: %w", err)
		}
		frameLen := frame.HeaderSize + int(hdr.Length)
		if len(raw) < frameLen {
			return nil, fmt.Errorf("truncated frame payload: need %d bytes, have %d", frameLen, len(raw))
		}
		frameBytes := raw[:frameLen]
		raw = raw[frameLen:]

		// Skip connection-level control frames that were already handled by the handshake.
		if shouldDropH2ControlFrame(hdr) {
			continue
		}

		// Remap the stream ID for stream-level frames.
		newStreamID := hdr.StreamID
		if hdr.StreamID != 0 {
			if mapped, ok := streamMap[hdr.StreamID]; ok {
				newStreamID = mapped
			} else {
				// Assign the next available stream ID.
				// Client-initiated streams use odd IDs; server-initiated use even.
				if hdr.StreamID%2 == 1 {
					newStreamID = nextClientStream
					nextClientStream += 2
				}
				// For even (server-initiated) IDs, keep the original since we don't
				// expect the client to be sending server-initiated stream frames, but
				// handle it gracefully.
				streamMap[hdr.StreamID] = newStreamID
			}
		}

		if newStreamID == hdr.StreamID {
			// No remapping needed; append the original bytes.
			out = append(out, frameBytes...)
		} else {
			// Copy the frame and patch the stream ID in bytes 5-8 of the header.
			patched := make([]byte, len(frameBytes))
			copy(patched, frameBytes)
			putStreamID(patched[5:9], newStreamID)
			out = append(out, patched...)
		}
	}
	return out, nil
}

// shouldDropH2ControlFrame reports whether a frame is a connection-level control
// frame that should be dropped during resend (because the handshake already
// established these). This includes SETTINGS, PING, and WINDOW_UPDATE/GOAWAY
// on stream 0.
func shouldDropH2ControlFrame(hdr frame.Header) bool {
	switch hdr.Type {
	case frame.TypeSettings, frame.TypePing:
		// Always connection-level.
		return true
	case frame.TypeWindowUpdate:
		// Stream 0 WINDOW_UPDATE is connection-level flow control.
		return hdr.StreamID == 0
	case frame.TypeGoAway:
		// GOAWAY is connection-level.
		return true
	default:
		return false
	}
}

// putStreamID encodes a stream ID into the 4-byte slice at the position
// corresponding to bytes 5-8 of an HTTP/2 frame header, preserving the
// reserved high bit (always 0 per RFC 9113).
func putStreamID(buf []byte, streamID uint32) {
	_ = buf[3] // bounds check hint
	buf[0] = byte(streamID >> 24)
	buf[1] = byte(streamID >> 16)
	buf[2] = byte(streamID >> 8)
	buf[3] = byte(streamID)
}

// appendRawCapped appends raw bytes to dst, capping at MaxReplayResponseSize.
func appendRawCapped(dst, src []byte) []byte {
	remaining := int(config.MaxReplayResponseSize) - len(dst)
	if remaining <= 0 {
		return dst
	}
	if len(src) > remaining {
		src = src[:remaining]
	}
	return append(dst, src...)
}
