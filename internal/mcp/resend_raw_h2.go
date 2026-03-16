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

	// HTTP/2 requires TLS with ALPN "h2". Use upgradeTLSH2 to enforce this.
	useTLS := true
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

	// Write the raw frame bytes directly to the connection.
	// These are the original HTTP/2 frames captured from the wire.
	if _, err := conn.Write(rawBytes); err != nil {
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
	serverSettingsReceived := false
	for !serverSettingsReceived {
		f, err := reader.ReadFrame()
		if err != nil {
			return nil, fmt.Errorf("read server SETTINGS: %w", err)
		}
		switch {
		case f.Header.Type == frame.TypeSettings && !f.Header.Flags.Has(frame.FlagAck):
			serverSettingsReceived = true
			// Update reader/writer max frame size if the server advertises a larger one.
			settings, sErr := f.SettingsParams()
			if sErr == nil {
				for _, st := range settings {
					if st.ID == frame.SettingMaxFrameSize && st.Value > frame.DefaultMaxFrameSize {
						reader.SetMaxFrameSize(st.Value) //nolint:errcheck
						writer.SetMaxFrameSize(st.Value) //nolint:errcheck
					}
				}
			}
		case f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck):
			// Server ACK for our SETTINGS; expected during handshake.
		case f.Header.Type == frame.TypeWindowUpdate:
			// Window updates during handshake; ignore.
		default:
			// Other frames during handshake; ignore gracefully.
		}
	}

	// Step 4: Send SETTINGS ACK for the server's SETTINGS.
	if err := writer.WriteSettingsAck(); err != nil {
		return nil, fmt.Errorf("send SETTINGS ACK: %w", err)
	}

	return reader, nil
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
