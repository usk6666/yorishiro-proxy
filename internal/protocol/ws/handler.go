package ws

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	gohttp "net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// maxRecordPayloadSize limits the payload size recorded per message.
// Payloads exceeding this size are truncated in the session store.
const maxRecordPayloadSize = 1 << 20 // 1MB

// maxMessageSize limits the total assembled size of a fragmented WebSocket message.
// This prevents unbounded memory growth from continuation frame accumulation (CWE-400).
const maxMessageSize = 64 << 20 // 64MB

// Handler manages a WebSocket connection relay between client and upstream.
// It is not a ProtocolHandler — it is invoked from the HTTP handler when
// an Upgrade: websocket request is detected.
type Handler struct {
	store  session.Store
	logger *slog.Logger
}

// NewHandler creates a new WebSocket relay handler.
func NewHandler(store session.Store, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// HandleUpgrade processes a WebSocket upgrade request. It forwards the upgrade
// to the upstream server, validates the 101 response, then starts a bidirectional
// frame relay with session recording.
//
// Parameters:
//   - ctx: context for cancellation
//   - clientConn: the client-side connection (may be a tls.Conn for WSS)
//   - upstreamConn: the upstream connection to the WebSocket server
//   - upstreamBufReader: optional bufio.Reader wrapping upstreamConn that may contain
//     buffered bytes from HTTP response parsing. If nil, a new bufio.Reader is created.
//   - upgradeReq: the original HTTP Upgrade request
//   - upgradeResp: the 101 Switching Protocols response from upstream
//   - connID: connection identifier for log correlation
//   - clientAddr: client's remote address
//   - connInfo: optional connection metadata (TLS info etc.)
func (h *Handler) HandleUpgrade(ctx context.Context, clientConn net.Conn, upstreamConn net.Conn, upstreamBufReader *bufio.Reader, upgradeReq *gohttp.Request, upgradeResp *gohttp.Response, connID, clientAddr string, connInfo *session.ConnectionInfo) error {
	start := time.Now()

	// Create the WebSocket session record.
	sess := &session.Session{
		ConnID:      connID,
		Protocol:    "WebSocket",
		SessionType: "bidirectional",
		State:       "active",
		Timestamp:   start,
		ConnInfo:    connInfo,
	}

	if h.store != nil {
		if err := h.store.SaveSession(ctx, sess); err != nil {
			h.logger.Error("websocket session save failed", "error", err)
			return fmt.Errorf("save websocket session: %w", err)
		}
	}

	h.logger.Info("websocket session started",
		"session_id", sess.ID,
		"conn_id", connID,
		"url", upgradeReq.URL.String(),
	)

	// Run bidirectional frame relay.
	err := h.relayFrames(ctx, clientConn, upstreamConn, upstreamBufReader, sess.ID, start)

	// Update session state to complete.
	duration := time.Since(start)
	if h.store != nil {
		state := "complete"
		if err != nil && ctx.Err() == nil {
			state = "error"
		}
		if updateErr := h.store.UpdateSession(ctx, sess.ID, session.SessionUpdate{
			State:    state,
			Duration: duration,
		}); updateErr != nil {
			h.logger.Error("websocket session update failed", "session_id", sess.ID, "error", updateErr)
		}
	}

	h.logger.Info("websocket session ended",
		"session_id", sess.ID,
		"duration_ms", duration.Milliseconds(),
	)

	return err
}

// relayFrames runs two goroutines to relay WebSocket frames bidirectionally
// between the client and upstream server. Each frame is recorded to the
// session store. The relay stops when a Close frame is received, a connection
// error occurs, or the context is cancelled.
func (h *Handler) relayFrames(ctx context.Context, clientConn, upstreamConn net.Conn, upstreamBufReader *bufio.Reader, sessionID string, start time.Time) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Watch for context cancellation and interrupt blocking reads.
	go func() {
		<-ctx.Done()
		clientConn.SetReadDeadline(time.Now())
		upstreamConn.SetReadDeadline(time.Now())
	}()

	var seq atomic.Int64
	var wg sync.WaitGroup
	errCh := make(chan error, 2)

	clientReader := bufio.NewReader(clientConn)
	// Reuse the upstream bufio.Reader if provided (preserves buffered bytes from HTTP
	// response parsing). Otherwise create a new one.
	upstreamReader := upstreamBufReader
	if upstreamReader == nil {
		upstreamReader = bufio.NewReader(upstreamConn)
	}

	// Client -> Upstream relay (direction: "send").
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := h.relayDirection(ctx, clientReader, upstreamConn, sessionID, "send", &seq, start)
		errCh <- err
		cancel()
	}()

	// Upstream -> Client relay (direction: "receive").
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := h.relayDirection(ctx, upstreamReader, clientConn, sessionID, "receive", &seq, start)
		errCh <- err
		cancel()
	}()

	// Wait for the first error (or both to finish).
	err := <-errCh

	// Wait for the second goroutine to finish.
	wg.Wait()

	if ctx.Err() != nil {
		return ctx.Err()
	}

	return err
}

// relayDirection reads frames from src, records them, and writes them to dst.
// It handles fragmentation by assembling continuation frames into complete messages.
// Fragment accumulation is capped at maxMessageSize to prevent OOM (CWE-400).
func (h *Handler) relayDirection(ctx context.Context, src io.Reader, dst net.Conn, sessionID, direction string, seq *atomic.Int64, start time.Time) error {
	// Fragment assembly state.
	var fragmentBuf []byte
	var fragmentOpcode byte
	inFragment := false

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		frame, err := ReadFrame(src)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("read %s frame: %w", direction, err)
		}

		// Forward the frame to the destination.
		// For client->server: frames were originally masked; we read them unmasked.
		// We need to write them masked to the server (re-mask with original key).
		// For server->client: frames are unmasked; write them unmasked.
		outFrame := &Frame{
			Fin:    frame.Fin,
			RSV1:   frame.RSV1,
			RSV2:   frame.RSV2,
			RSV3:   frame.RSV3,
			Opcode: frame.Opcode,
			Masked: frame.Masked,
			Payload: frame.Payload,
		}
		if frame.Masked {
			outFrame.MaskKey = frame.MaskKey
		}

		if err := WriteFrame(dst, outFrame); err != nil {
			return fmt.Errorf("write %s frame: %w", direction, err)
		}

		// Handle control frames (these can appear between data frame fragments).
		if frame.IsControl() {
			h.recordControlFrame(ctx, frame, sessionID, direction, seq, start)

			// Close frame: signal end of relay.
			if frame.Opcode == OpcodeClose {
				return nil
			}
			continue
		}

		// Handle data frames (with fragmentation support).
		if frame.Opcode != OpcodeContinuation {
			// Start of a new message (or a single unfragmented message).
			if inFragment {
				// Protocol violation: new data frame while a fragmented message is pending.
				// Record what we have and start fresh.
				h.logger.Warn("websocket protocol violation: new data frame while fragment pending",
					"session_id", sessionID, "direction", direction)
				fragmentBuf = nil
				inFragment = false
			}
			if frame.Fin {
				// Single unfragmented message.
				h.recordDataMessage(ctx, frame.Opcode, frame.Payload, frame.Masked, sessionID, direction, seq, start)
			} else {
				// First fragment: start accumulating (cap checked on continuation).
				fragmentOpcode = frame.Opcode
				fragmentBuf = make([]byte, len(frame.Payload))
				copy(fragmentBuf, frame.Payload)
				inFragment = true
			}
		} else {
			// Continuation frame.
			if !inFragment {
				h.logger.Warn("websocket protocol violation: continuation frame without initial fragment",
					"session_id", sessionID, "direction", direction)
				continue
			}
			if int64(len(fragmentBuf))+int64(len(frame.Payload)) > maxMessageSize {
				h.logger.Warn("websocket message size limit exceeded, closing connection",
					"session_id", sessionID, "direction", direction,
					"accumulated", len(fragmentBuf), "incoming", len(frame.Payload),
					"limit", maxMessageSize)
				// Discard fragment buffer and send Close frame (1009 = message too big).
				fragmentBuf = nil
				inFragment = false
				closePayload := make([]byte, 2)
				closePayload[0] = 0x03
				closePayload[1] = 0xF1 // 1009
				closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: closePayload}
				_ = WriteFrame(dst, closeFrame)
				return fmt.Errorf("fragmented message exceeded maxMessageSize (%d bytes)", maxMessageSize)
			}
			fragmentBuf = append(fragmentBuf, frame.Payload...)
			if frame.Fin {
				// Final fragment: record the assembled message.
				h.recordDataMessage(ctx, fragmentOpcode, fragmentBuf, frame.Masked, sessionID, direction, seq, start)
				fragmentBuf = nil
				inFragment = false
			}
		}
	}
}

// recordDataMessage records a complete WebSocket data message (text or binary)
// to the session store.
func (h *Handler) recordDataMessage(ctx context.Context, opcode byte, payload []byte, masked bool, sessionID, direction string, seq *atomic.Int64, start time.Time) {
	if h.store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

	msg := &session.Message{
		SessionID: sessionID,
		Sequence:  msgSeq,
		Direction: direction,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"opcode": strconv.Itoa(int(opcode)),
			"fin":    "true",
			"masked": strconv.FormatBool(masked),
		},
	}

	recordPayload := payload
	if len(payload) > maxRecordPayloadSize {
		recordPayload = payload[:maxRecordPayloadSize]
		msg.BodyTruncated = true
	}

	if opcode == OpcodeText {
		msg.Body = recordPayload
	} else {
		msg.RawBytes = recordPayload
	}

	if err := h.store.AppendMessage(ctx, msg); err != nil {
		h.logger.Error("websocket message save failed",
			"session_id", sessionID,
			"direction", direction,
			"sequence", msgSeq,
			"error", err,
		)
	}
}

// recordControlFrame records a WebSocket control frame (Close, Ping, Pong)
// to the session store.
func (h *Handler) recordControlFrame(ctx context.Context, frame *Frame, sessionID, direction string, seq *atomic.Int64, start time.Time) {
	if h.store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

	msg := &session.Message{
		SessionID: sessionID,
		Sequence:  msgSeq,
		Direction: direction,
		Timestamp: time.Now(),
		Metadata: map[string]string{
			"opcode": strconv.Itoa(int(frame.Opcode)),
			"fin":    "true",
			"masked": strconv.FormatBool(frame.Masked),
		},
	}

	// Store control frame payload as raw bytes.
	if len(frame.Payload) > 0 {
		msg.RawBytes = make([]byte, len(frame.Payload))
		copy(msg.RawBytes, frame.Payload)
	}

	if err := h.store.AppendMessage(ctx, msg); err != nil {
		h.logger.Error("websocket control frame save failed",
			"session_id", sessionID,
			"direction", direction,
			"sequence", msgSeq,
			"opcode", OpcodeString(frame.Opcode),
			"error", err,
		)
	}
}
