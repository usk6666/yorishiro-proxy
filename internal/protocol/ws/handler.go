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

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
)

// Handler manages a WebSocket connection relay between client and upstream.
// It is not a ProtocolHandler — it is invoked from the HTTP handler when
// an Upgrade: websocket request is detected.
type Handler struct {
	store        flow.FlowWriter
	logger       *slog.Logger
	pluginEngine *plugin.Engine
}

// NewHandler creates a new WebSocket relay handler.
func NewHandler(store flow.FlowWriter, logger *slog.Logger) *Handler {
	return &Handler{
		store:  store,
		logger: logger,
	}
}

// SetPluginEngine sets the plugin engine for dispatching hooks during
// WebSocket frame relay. If engine is nil, plugin hooks are skipped.
func (h *Handler) SetPluginEngine(engine *plugin.Engine) {
	h.pluginEngine = engine
}

// HandleUpgrade processes a WebSocket upgrade request. It forwards the upgrade
// to the upstream server, validates the 101 response, then starts a bidirectional
// frame relay with flow recording.
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
func (h *Handler) HandleUpgrade(ctx context.Context, clientConn net.Conn, upstreamConn net.Conn, upstreamBufReader *bufio.Reader, upgradeReq *gohttp.Request, upgradeResp *gohttp.Response, connID, clientAddr string, connInfo *flow.ConnectionInfo) error {
	start := time.Now()

	// Create the WebSocket flow record.
	fl := &flow.Flow{
		ConnID:    connID,
		Protocol:  "WebSocket",
		FlowType:  "bidirectional",
		State:     "active",
		Timestamp: start,
		ConnInfo:  connInfo,
	}

	if h.store != nil {
		if err := h.store.SaveFlow(ctx, fl); err != nil {
			h.logger.Error("websocket flow save failed", "error", err)
			return fmt.Errorf("save websocket flow: %w", err)
		}
	}

	h.logger.Info("websocket flow started",
		"flow_id", fl.ID,
		"conn_id", connID,
		"url", upgradeReq.URL.String(),
	)

	// Record the Upgrade request as the first message (sequence=0, direction="send").
	// This mirrors the error path in recordWebSocketError so that WebSocket flows
	// have the URL, Method, and Headers available for search and resend.
	h.recordUpgradeRequest(ctx, fl.ID, upgradeReq, start)

	// Record the Upgrade response as the second message (sequence=1, direction="receive").
	h.recordUpgradeResponse(ctx, fl.ID, upgradeResp, start)

	// Run bidirectional frame relay.
	err := h.relayFrames(ctx, clientConn, upstreamConn, upstreamBufReader, fl.ID, start, upgradeReq, connInfo)

	// Update flow state to complete.
	duration := time.Since(start)
	if h.store != nil {
		state := "complete"
		if err != nil && ctx.Err() == nil {
			state = "error"
		}
		if updateErr := h.store.UpdateFlow(ctx, fl.ID, flow.FlowUpdate{
			State:    state,
			Duration: duration,
		}); updateErr != nil {
			h.logger.Error("websocket flow update failed", "flow_id", fl.ID, "error", updateErr)
		}
	}

	h.logger.Info("websocket flow ended",
		"flow_id", fl.ID,
		"duration_ms", duration.Milliseconds(),
	)

	return err
}

// recordUpgradeRequest records the HTTP Upgrade request as a send message
// (sequence=0) so that the flow contains URL, Method, and Headers for search
// and resend. This matches the format used by recordWebSocketError in the
// HTTP handler's error path.
func (h *Handler) recordUpgradeRequest(ctx context.Context, flowID string, req *gohttp.Request, start time.Time) {
	if h.store == nil {
		return
	}

	msg := &flow.Message{
		FlowID:    flowID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    req.Method,
		URL:       req.URL,
		Headers:   req.Header,
	}
	if err := h.store.AppendMessage(ctx, msg); err != nil {
		h.logger.Error("websocket upgrade request message save failed",
			"flow_id", flowID, "error", err)
	}
}

// recordUpgradeResponse records the HTTP 101 Switching Protocols response as a
// receive message (sequence=1) so that the flow contains the response status
// code and headers.
func (h *Handler) recordUpgradeResponse(ctx context.Context, flowID string, resp *gohttp.Response, start time.Time) {
	if h.store == nil {
		return
	}

	msg := &flow.Message{
		FlowID:     flowID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start,
		StatusCode: resp.StatusCode,
		Headers:    resp.Header,
	}
	if err := h.store.AppendMessage(ctx, msg); err != nil {
		h.logger.Error("websocket upgrade response message save failed",
			"flow_id", flowID, "error", err)
	}
}

// relayFrames runs two goroutines to relay WebSocket frames bidirectionally
// between the client and upstream server. Each frame is recorded to the
// flow store. The relay stops when a Close frame is received, a connection
// error occurs, or the context is cancelled.
func (h *Handler) relayFrames(ctx context.Context, clientConn, upstreamConn net.Conn, upstreamBufReader *bufio.Reader, flowID string, start time.Time, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Watch for context cancellation and interrupt blocking reads.
	go func() {
		<-ctx.Done()
		clientConn.SetReadDeadline(time.Now())
		upstreamConn.SetReadDeadline(time.Now())
	}()

	var seq atomic.Int64
	// Data frame sequences start at 2 because sequence 0 and 1 are reserved
	// for the Upgrade request and response messages recorded in HandleUpgrade.
	seq.Store(2)
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
		err := h.relayDirection(ctx, clientReader, upstreamConn, flowID, "send", &seq, start, upgradeReq, connInfo)
		errCh <- err
		cancel()
	}()

	// Upstream -> Client relay (direction: "receive").
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := h.relayDirection(ctx, upstreamReader, clientConn, flowID, "receive", &seq, start, upgradeReq, connInfo)
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

// hookPair holds the plugin hooks for a relay direction.
type hookPair struct {
	receiveHook plugin.Hook
	sendHook    plugin.Hook
	direction   string // "client_to_server" or "server_to_client"
}

// fragmentState tracks the state of fragmented message assembly.
type fragmentState struct {
	buf    []byte
	opcode byte
	active bool
}

// relayDirection reads frames from src, records them, and writes them to dst.
// It handles fragmentation by assembling continuation frames into complete messages.
// Fragment accumulation is capped at config.MaxWebSocketMessageSize to prevent OOM (CWE-400).
//
// Plugin hooks are dispatched per-frame (not per-message):
//   - "send" direction: on_receive_from_client → on_before_send_to_server
//   - "receive" direction: on_receive_from_server → on_before_send_to_client
//
// If a plugin returns ActionDrop, the frame is silently skipped.
// If a plugin modifies the payload via result Data, the modified payload is used.
func (h *Handler) relayDirection(ctx context.Context, src io.Reader, dst net.Conn, flowID, direction string, seq *atomic.Int64, start time.Time, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo) error {
	hooks := resolveHookPair(direction)

	var frag fragmentState
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

		// Skip plugin dispatch for control frames (Close, Ping, Pong) to prevent
		// plugins from dropping Close frames, which would cause the relay to hang
		// until context timeout (CWE-400).
		if !frame.IsControl() {
			if dropped := h.dispatchDataFrameHooks(ctx, hooks, frame, upgradeReq, connInfo, flowID); dropped {
				continue
			}
		}

		if err := forwardFrame(dst, frame, direction); err != nil {
			return err
		}

		if frame.IsControl() {
			h.recordControlFrame(ctx, frame, flowID, direction, seq, start)
			if frame.Opcode == OpcodeClose {
				return nil
			}
			continue
		}

		if err := h.handleDataFrame(ctx, dst, frame, &frag, flowID, direction, seq, start); err != nil {
			return err
		}
	}
}

// resolveHookPair returns the plugin hook pair for the given relay direction.
func resolveHookPair(direction string) hookPair {
	if direction == "send" {
		return hookPair{
			receiveHook: plugin.HookOnReceiveFromClient,
			sendHook:    plugin.HookOnBeforeSendToServer,
			direction:   "client_to_server",
		}
	}
	return hookPair{
		receiveHook: plugin.HookOnReceiveFromServer,
		sendHook:    plugin.HookOnBeforeSendToClient,
		direction:   "server_to_client",
	}
}

// dispatchDataFrameHooks dispatches the receive and send plugin hooks for a
// data frame. Returns true if the frame should be dropped.
func (h *Handler) dispatchDataFrameHooks(ctx context.Context, hooks hookPair, frame *Frame, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo, flowID string) bool {
	frameTxCtx := plugin.NewTxCtx()
	if dropped := h.dispatchFrameHook(ctx, hooks.receiveHook, frame, hooks.direction, upgradeReq, connInfo, flowID, frameTxCtx); dropped {
		return true
	}
	return h.dispatchFrameHook(ctx, hooks.sendHook, frame, hooks.direction, upgradeReq, connInfo, flowID, frameTxCtx)
}

// forwardFrame writes the frame to the destination connection, preserving
// mask state and key.
func forwardFrame(dst net.Conn, frame *Frame, direction string) error {
	outFrame := &Frame{
		Fin:     frame.Fin,
		RSV1:    frame.RSV1,
		RSV2:    frame.RSV2,
		RSV3:    frame.RSV3,
		Opcode:  frame.Opcode,
		Masked:  frame.Masked,
		Payload: frame.Payload,
	}
	if frame.Masked {
		outFrame.MaskKey = frame.MaskKey
	}
	if err := WriteFrame(dst, outFrame); err != nil {
		return fmt.Errorf("write %s frame: %w", direction, err)
	}
	return nil
}

// handleDataFrame processes a data frame for fragment assembly and recording.
// Returns an error if the message size limit was exceeded.
func (h *Handler) handleDataFrame(ctx context.Context, dst net.Conn, frame *Frame, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time) error {
	if frame.Opcode != OpcodeContinuation {
		h.handleNewDataFrame(ctx, frame, frag, flowID, direction, seq, start)
		return nil
	}
	return h.handleContinuationFrame(ctx, dst, frame, frag, flowID, direction, seq, start)
}

// handleNewDataFrame processes a non-continuation data frame, starting a new
// message or recording a single unfragmented message.
func (h *Handler) handleNewDataFrame(ctx context.Context, frame *Frame, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time) {
	if frag.active {
		h.logger.Warn("websocket protocol violation: new data frame while fragment pending",
			"flow_id", flowID, "direction", direction)
		frag.buf = nil
		frag.active = false
	}
	if frame.Fin {
		h.recordDataMessage(ctx, frame.Opcode, frame.Payload, frame.Masked, flowID, direction, seq, start)
	} else {
		frag.opcode = frame.Opcode
		frag.buf = make([]byte, len(frame.Payload))
		copy(frag.buf, frame.Payload)
		frag.active = true
	}
}

// handleContinuationFrame processes a continuation frame for fragment assembly.
// Returns an error if the accumulated message exceeds the size limit.
func (h *Handler) handleContinuationFrame(ctx context.Context, dst net.Conn, frame *Frame, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time) error {
	if !frag.active {
		h.logger.Warn("websocket protocol violation: continuation frame without initial fragment",
			"flow_id", flowID, "direction", direction)
		return nil
	}
	if int64(len(frag.buf))+int64(len(frame.Payload)) > config.MaxWebSocketMessageSize {
		return h.closeOversizedMessage(dst, frag, frame, flowID, direction)
	}
	frag.buf = append(frag.buf, frame.Payload...)
	if frame.Fin {
		h.recordDataMessage(ctx, frag.opcode, frag.buf, frame.Masked, flowID, direction, seq, start)
		frag.buf = nil
		frag.active = false
	}
	return nil
}

// closeOversizedMessage sends a Close frame (1009 = message too big) and
// returns an error indicating the message size limit was exceeded.
func (h *Handler) closeOversizedMessage(dst net.Conn, frag *fragmentState, frame *Frame, flowID, direction string) error {
	h.logger.Warn("websocket message size limit exceeded, closing connection",
		"flow_id", flowID, "direction", direction,
		"accumulated", len(frag.buf), "incoming", len(frame.Payload),
		"limit", config.MaxWebSocketMessageSize)
	closePayload := make([]byte, 2)
	closePayload[0] = 0x03
	closePayload[1] = 0xF1 // 1009
	closeFrame := &Frame{Fin: true, Opcode: OpcodeClose, Payload: closePayload}
	if err := WriteFrame(dst, closeFrame); err != nil {
		h.logger.Debug("failed to send close frame for oversized message", "flow_id", flowID, "error", err)
	}
	return fmt.Errorf("fragmented message exceeded config.MaxWebSocketMessageSize (%d bytes)", config.MaxWebSocketMessageSize)
}

// buildFrameData constructs the plugin hook data map for a WebSocket frame.
func (h *Handler) buildFrameData(frame *Frame, direction string, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo) map[string]any {
	data := map[string]any{
		"opcode":      int(frame.Opcode),
		"opcode_name": OpcodeString(frame.Opcode),
		"payload":     frame.Payload,
		"fin":         frame.Fin,
		"direction":   direction,
	}

	if upgradeReq != nil && upgradeReq.URL != nil {
		data["upgrade_url"] = upgradeReq.URL.String()
	} else {
		data["upgrade_url"] = ""
	}

	connInfoMap := map[string]any{}
	if connInfo != nil {
		connInfoMap["client_addr"] = connInfo.ClientAddr
		connInfoMap["server_addr"] = connInfo.ServerAddr
		connInfoMap["tls_version"] = connInfo.TLSVersion
		connInfoMap["tls_cipher"] = connInfo.TLSCipher
	}
	data["conn_info"] = connInfoMap

	return data
}

// dispatchFrameHook dispatches a plugin hook for a WebSocket frame.
// It returns true if the frame should be dropped (ActionDrop).
// If the plugin modifies the payload, the frame's Payload is updated in place.
//
// Note: ActionDrop is semantically valid only for on_receive_from_client hooks
// (i.e., the "send" direction). In the "receive" direction, the plugin engine
// does not register DROP as a valid action, so ActionDrop will not be returned
// for on_receive_from_server / on_before_send_to_client hooks.
//
// After a plugin modifies the payload, the new size is checked against
// config.MaxWebSocketMessageSize. If exceeded, the modification is discarded
// and the original payload is preserved (CWE-400 mitigation).
func (h *Handler) dispatchFrameHook(ctx context.Context, hook plugin.Hook, frame *Frame, direction string, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo, flowID string, txCtx map[string]any) bool {
	if h.pluginEngine == nil {
		return false
	}

	data := h.buildFrameData(frame, direction, upgradeReq, connInfo)
	plugin.InjectTxCtx(data, txCtx)

	result, err := h.pluginEngine.Dispatch(ctx, hook, data)
	if err != nil {
		h.logger.Warn("websocket plugin hook error",
			"flow_id", flowID,
			"hook", string(hook),
			"error", err,
		)
		return false
	}
	plugin.ExtractTxCtx(result, txCtx)

	if result == nil {
		return false
	}

	if result.Action == plugin.ActionDrop {
		h.logger.Debug("websocket frame dropped by plugin",
			"flow_id", flowID,
			"hook", string(hook),
			"direction", direction,
		)
		return true
	}

	// Apply payload modifications from plugin result.
	if result.Data != nil {
		if newPayload, ok := result.Data["payload"]; ok {
			var modified []byte
			switch p := newPayload.(type) {
			case []byte:
				modified = p
			case string:
				modified = []byte(p)
			}
			if modified != nil {
				if int64(len(modified)) > config.MaxWebSocketMessageSize {
					h.logger.Warn("plugin modified payload exceeds size limit, keeping original",
						"flow_id", flowID,
						"hook", string(hook),
						"modified_size", len(modified),
						"limit", config.MaxWebSocketMessageSize,
					)
				} else {
					frame.Payload = modified
				}
			}
		}
	}

	return false
}

// recordDataMessage records a complete WebSocket data message (text or binary)
// to the flow store.
func (h *Handler) recordDataMessage(ctx context.Context, opcode byte, payload []byte, masked bool, flowID, direction string, seq *atomic.Int64, start time.Time) {
	if h.store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

	msg := &flow.Message{
		FlowID:    flowID,
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
	if len(payload) > config.MaxWebSocketRecordPayloadSize {
		recordPayload = payload[:config.MaxWebSocketRecordPayloadSize]
		msg.BodyTruncated = true
	}

	if opcode == OpcodeText {
		msg.Body = recordPayload
	} else {
		msg.RawBytes = recordPayload
	}

	if err := h.store.AppendMessage(ctx, msg); err != nil {
		h.logger.Error("websocket message save failed",
			"flow_id", flowID,
			"direction", direction,
			"sequence", msgSeq,
			"error", err,
		)
	}
}

// recordControlFrame records a WebSocket control frame (Close, Ping, Pong)
// to the flow store.
func (h *Handler) recordControlFrame(ctx context.Context, frame *Frame, flowID, direction string, seq *atomic.Int64, start time.Time) {
	if h.store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

	msg := &flow.Message{
		FlowID:    flowID,
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
			"flow_id", flowID,
			"direction", direction,
			"sequence", msgSeq,
			"opcode", OpcodeString(frame.Opcode),
			"error", err,
		)
	}
}
