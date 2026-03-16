package ws

import (
	"bufio"
	"bytes"
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
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// Handler manages a WebSocket connection relay between client and upstream.
// It is not a ProtocolHandler — it is invoked from the HTTP handler when
// an Upgrade: websocket request is detected.
type Handler struct {
	store           flow.FlowWriter
	logger          *slog.Logger
	pluginEngine    *plugin.Engine
	safetyEngine    *safety.Engine
	interceptEngine *intercept.Engine
	interceptQueue  *intercept.Queue
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

// SetSafetyEngine sets the safety filter engine for checking WebSocket
// text frames. If engine is nil, safety filtering is skipped.
func (h *Handler) SetSafetyEngine(engine *safety.Engine) {
	h.safetyEngine = engine
}

// SetInterceptEngine sets the intercept rule engine used to determine which
// WebSocket frames should be intercepted.
func (h *Handler) SetInterceptEngine(engine *intercept.Engine) {
	h.interceptEngine = engine
}

// SetInterceptQueue sets the intercept queue used to hold WebSocket frames
// that match intercept rules.
func (h *Handler) SetInterceptQueue(queue *intercept.Queue) {
	h.interceptQueue = queue
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

	// Parse permessage-deflate extension from the upgrade response.
	var clientDeflate, serverDeflate *deflateState
	if upgradeResp != nil {
		extHeader := upgradeResp.Header.Get("Sec-WebSocket-Extensions")
		clientParams, serverParams := parseDeflateExtension(extHeader)
		if clientParams.enabled {
			clientDeflate = newDeflateState(clientParams)
			defer clientDeflate.close()
			h.logger.Debug("websocket permessage-deflate enabled for client->server",
				"flow_id", fl.ID, "context_takeover", clientParams.contextTakeover,
				"window_bits", clientParams.windowBits)
		}
		if serverParams.enabled {
			serverDeflate = newDeflateState(serverParams)
			defer serverDeflate.close()
			h.logger.Debug("websocket permessage-deflate enabled for server->client",
				"flow_id", fl.ID, "context_takeover", serverParams.contextTakeover,
				"window_bits", serverParams.windowBits)
		}
	}

	// Run bidirectional frame relay.
	err := h.relayFrames(ctx, clientConn, upstreamConn, upstreamBufReader, fl.ID, start, upgradeReq, connInfo, clientDeflate, serverDeflate)

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
func (h *Handler) relayFrames(ctx context.Context, clientConn, upstreamConn net.Conn, upstreamBufReader *bufio.Reader, flowID string, start time.Time, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo, clientDeflate, serverDeflate *deflateState) error {
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
		err := h.relayDirection(ctx, clientReader, upstreamConn, flowID, "send", &seq, start, upgradeReq, connInfo, clientDeflate)
		errCh <- err
		cancel()
	}()

	// Upstream -> Client relay (direction: "receive").
	wg.Add(1)
	go func() {
		defer wg.Done()
		err := h.relayDirection(ctx, upstreamReader, clientConn, flowID, "receive", &seq, start, upgradeReq, connInfo, serverDeflate)
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
	buf        []byte
	opcode     byte
	active     bool
	dropping   bool // true when the initial text frame was blocked by safety filter
	compressed bool // true when the initial frame had RSV1 set (permessage-deflate)
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
func (h *Handler) relayDirection(ctx context.Context, src io.Reader, dst net.Conn, flowID, direction string, seq *atomic.Int64, start time.Time, upgradeReq *gohttp.Request, connInfo *flow.ConnectionInfo, ds *deflateState) error {
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

		// Drop continuation frames belonging to a blocked fragmented message.
		if h.handleBlockedFragment(ctx, frame, &frag, flowID, direction, seq, start) {
			continue
		}

		done, err := h.processFrameAfterHooks(ctx, frame, flowID, direction, hooks.direction, seq, start, dst, &frag, upgradeReq, ds)
		if err != nil {
			return err
		}
		if done {
			return nil
		}
	}
}

// processFrameAfterHooks applies safety filter, intercept check, forwarding, and
// recording for a single frame. Returns (done, err) where done=true means a Close
// frame was processed and the relay should terminate.
//
// When permessage-deflate is active (ds != nil and ds.params.enabled), data frames
// with RSV1 set are decompressed for recording but forwarded as-is on the wire.
func (h *Handler) processFrameAfterHooks(ctx context.Context, frame *Frame, flowID, direction, wsDirection string, seq *atomic.Int64, start time.Time, dst net.Conn, frag *fragmentState, upgradeReq *gohttp.Request, ds *deflateState) (bool, error) {
	// Determine if this frame is permessage-deflate compressed.
	compressed := !frame.IsControl() && frame.RSV1 && ds != nil && ds.params.enabled

	// Safety filter: apply to text frames only (opcode 0x1).
	safetyMeta, rawPayload, blocked := h.applySafetyToFrame(frame, direction, upgradeReq, flowID)
	if blocked {
		if !frame.Fin {
			frag.dropping = true
			frag.compressed = compressed
		}
		h.recordDataMessage(ctx, frame.Opcode, frame.Payload, frame.Masked, frame.Fin, flowID, direction, seq, start, safetyMeta, compressed)
		return false, nil
	}

	// Intercept check: evaluate intercept rules for data frames.
	if !frame.IsControl() {
		if intercepted := h.interceptFrame(ctx, frame, flowID, direction, wsDirection, seq, start, dst, frag, safetyMeta, rawPayload, upgradeReq); intercepted {
			return false, nil
		}
	}

	if err := forwardFrame(dst, frame, direction); err != nil {
		return false, err
	}

	if frame.IsControl() {
		h.recordControlFrame(ctx, frame, flowID, direction, seq, start)
		return frame.Opcode == OpcodeClose, nil
	}

	// For output-filtered frames, record the raw (unmasked) payload.
	recordPayload := frame.Payload
	if rawPayload != nil {
		recordPayload = rawPayload
	}

	err := h.handleDataFrameWithPayload(ctx, dst, frame, recordPayload, frag, flowID, direction, seq, start, safetyMeta, ds, compressed)
	return false, err
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

// handleBlockedFragment checks if a continuation frame belongs to a blocked
// fragmented message. When a non-FIN text frame is blocked by the safety filter,
// subsequent continuation frames must also be dropped to avoid protocol violation
// (upstream would receive continuations without the initial text frame).
// Returns true if the frame was dropped and should be skipped.
func (h *Handler) handleBlockedFragment(ctx context.Context, frame *Frame, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time) bool {
	if !frag.dropping || frame.Opcode != OpcodeContinuation {
		return false
	}
	h.logger.Debug("websocket continuation frame dropped (initial fragment was blocked)",
		"flow_id", flowID, "direction", direction, "fin", frame.Fin)
	h.recordDataMessage(ctx, frame.Opcode, frame.Payload, frame.Masked, frame.Fin, flowID, direction, seq, start, nil, frag.compressed)
	if frame.Fin {
		frag.dropping = false
	}
	return true
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

// handleDataFrameWithPayload processes a data frame for fragment assembly and recording,
// using recordPayload for the flow store (which may differ from frame.Payload when the
// output filter has masked the forwarded payload but raw data should be recorded).
func (h *Handler) handleDataFrameWithPayload(ctx context.Context, dst net.Conn, frame *Frame, recordPayload []byte, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time, safetyMeta *safetyMetadata, ds *deflateState, compressed bool) error {
	if frame.Opcode != OpcodeContinuation {
		h.handleNewDataFrameWithPayload(ctx, frame, recordPayload, frag, flowID, direction, seq, start, safetyMeta, ds, compressed)
		return nil
	}
	return h.handleContinuationFrame(ctx, dst, frame, frag, flowID, direction, seq, start, ds, compressed)
}

// handleNewDataFrameWithPayload processes a non-continuation data frame, using
// recordPayload for recording (may differ from frame.Payload when output filter
// has masked the forwarded data).
func (h *Handler) handleNewDataFrameWithPayload(ctx context.Context, frame *Frame, recordPayload []byte, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time, safetyMeta *safetyMetadata, ds *deflateState, compressed bool) {
	if frag.active {
		h.logger.Warn("websocket protocol violation: new data frame while fragment pending",
			"flow_id", flowID, "direction", direction)
		frag.buf = nil
		frag.active = false
	}
	if frame.Fin {
		// Decompress if permessage-deflate is active and RSV1 is set.
		decompressedPayload := h.decompressForRecord(recordPayload, ds, compressed, flowID, direction)
		h.recordDataMessage(ctx, frame.Opcode, decompressedPayload, frame.Masked, frame.Fin, flowID, direction, seq, start, safetyMeta, compressed)
	} else {
		frag.opcode = frame.Opcode
		frag.buf = make([]byte, len(recordPayload))
		copy(frag.buf, recordPayload)
		frag.active = true
		frag.compressed = compressed
	}
}

// handleContinuationFrame processes a continuation frame for fragment assembly.
// Returns an error if the accumulated message exceeds the size limit.
func (h *Handler) handleContinuationFrame(ctx context.Context, dst net.Conn, frame *Frame, frag *fragmentState, flowID, direction string, seq *atomic.Int64, start time.Time, ds *deflateState, compressed bool) error {
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
		// Decompress the assembled message if it was a compressed fragmented message.
		recordBuf := frag.buf
		wasCompressed := frag.compressed
		recordBuf = h.decompressForRecord(recordBuf, ds, wasCompressed, flowID, direction)
		h.recordDataMessage(ctx, frag.opcode, recordBuf, frame.Masked, frame.Fin, flowID, direction, seq, start, nil, wasCompressed)
		frag.buf = nil
		frag.active = false
		frag.compressed = false
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

// applySafetyToFrame applies the safety filter to a data frame if applicable.
// It only processes non-control text frames (opcode 0x1).
// Returns:
//   - safetyMeta: metadata about the safety filter match (nil if no match)
//   - rawPayload: the original unmasked payload for recording (nil unless output filter masked)
//   - blocked: true if the frame should be dropped (not forwarded)
func (h *Handler) applySafetyToFrame(frame *Frame, direction string, upgradeReq *gohttp.Request, flowID string) (*safetyMetadata, []byte, bool) {
	if h.safetyEngine == nil || frame.IsControl() || frame.Opcode != OpcodeText {
		return nil, nil, false
	}

	if direction == "send" {
		meta := h.applySafetyInputFilter(frame, upgradeReq, flowID)
		if meta != nil && meta.blocked {
			return meta, nil, true
		}
		return meta, nil, false
	}

	// Receive direction: preserve raw payload for recording,
	// then mask the frame payload for forwarding to client.
	rawPayload := make([]byte, len(frame.Payload))
	copy(rawPayload, frame.Payload)
	h.applySafetyOutputFilter(frame, flowID)
	// Only return rawPayload if the payload was actually modified by masking.
	if bytes.Equal(rawPayload, frame.Payload) {
		return nil, nil, false
	}
	return nil, rawPayload, false
}

// safetyMetadata holds safety filter results for a WebSocket frame.
type safetyMetadata struct {
	blocked   bool   // true if the frame was blocked (ActionBlock)
	logOnly   bool   // true if the frame matched a log_only rule
	ruleID    string // matched rule ID (e.g. "destructive-sql:drop")
	matchedOn string // the text fragment that triggered the match
}

// applySafetyInputFilter runs CheckInput on a text frame payload in the send direction.
func (h *Handler) applySafetyInputFilter(frame *Frame, upgradeReq *gohttp.Request, flowID string) *safetyMetadata {
	var upgradeURL string
	if upgradeReq != nil && upgradeReq.URL != nil {
		upgradeURL = upgradeReq.URL.String()
	}

	violation := h.safetyEngine.CheckInput(frame.Payload, upgradeURL, nil)
	if violation == nil {
		return nil
	}

	// Determine the action for this rule.
	action := safety.ActionBlock
	for _, r := range h.safetyEngine.InputRules() {
		if r.ID == violation.RuleID {
			action = r.Action
			break
		}
	}

	meta := &safetyMetadata{
		ruleID:    violation.RuleID,
		matchedOn: violation.MatchedOn,
	}

	if action == safety.ActionLogOnly {
		meta.logOnly = true
		h.logger.Warn("websocket safety filter violation (log_only)",
			"flow_id", flowID,
			"rule_id", violation.RuleID,
			"matched_on", truncateForLog(violation.MatchedOn, 256),
		)
	} else {
		meta.blocked = true
		h.logger.Warn("websocket frame blocked by safety filter",
			"flow_id", flowID,
			"rule_id", violation.RuleID,
			"matched_on", truncateForLog(violation.MatchedOn, 256),
		)
	}

	return meta
}

// applySafetyOutputFilter runs FilterOutput on a text frame payload in the receive direction.
// If masking occurs, the frame payload is replaced with masked data.
// The caller is responsible for preserving the raw (unmasked) data for recording.
func (h *Handler) applySafetyOutputFilter(frame *Frame, flowID string) {
	result := h.safetyEngine.FilterOutput(frame.Payload)

	// Log all matches for observability, consistent with HTTP handler's
	// ApplyOutputFilter which logs matches regardless of masking.
	for _, m := range result.Matches {
		h.logger.Info("websocket output filter matched",
			"flow_id", flowID,
			"rule_id", m.RuleID,
			"count", m.Count,
			"action", m.Action.String(),
		)
	}

	if !result.Masked {
		return
	}

	// Replace the frame payload with the masked version.
	// The caller must capture raw payload before calling this if it needs to record raw data.
	frame.Payload = result.Data
}

// interceptFrame checks whether the frame matches any intercept rules and,
// if so, enqueues it and waits for an action from the AI agent. Returns true
// if the frame was consumed by the intercept logic (forwarded, modified, or dropped)
// and should not be processed further by the caller.
//
// Because relayDirection runs a sequential read loop per direction, the relay
// is naturally blocked while waiting for the intercept action. Same-direction
// frames cannot arrive during the hold because the reader goroutine is blocked.
// The reverse direction runs in a separate goroutine and is unaffected.
func (h *Handler) interceptFrame(ctx context.Context, frame *Frame, flowID, direction, wsDirection string, seq *atomic.Int64, start time.Time, dst net.Conn, frag *fragmentState, safetyMeta *safetyMetadata, rawPayload []byte, upgradeReq *gohttp.Request) bool {
	if h.interceptEngine == nil || h.interceptQueue == nil {
		return false
	}

	var upgradeURL string
	if upgradeReq != nil && upgradeReq.URL != nil {
		upgradeURL = upgradeReq.URL.String()
	}

	matchedRules := h.interceptEngine.MatchWebSocketFrameRules(upgradeURL, wsDirection, flowID)
	if len(matchedRules) == 0 {
		return false
	}

	h.logger.Info("websocket frame intercepted",
		"flow_id", flowID,
		"direction", direction,
		"opcode", OpcodeString(frame.Opcode),
		"matched_rules", matchedRules,
	)

	action := h.waitForInterceptAction(ctx, frame, flowID, wsDirection, upgradeURL, seq, matchedRules)
	h.applyInterceptAction(ctx, action, frame, flowID, direction, seq, start, dst, frag, safetyMeta, rawPayload)
	return true
}

// waitForInterceptAction enqueues a frame into the intercept queue and waits
// for an action response (or timeout). Returns the resolved action.
func (h *Handler) waitForInterceptAction(ctx context.Context, frame *Frame, flowID, wsDirection, upgradeURL string, seq *atomic.Int64, matchedRules []string) intercept.InterceptAction {
	frameSeq := seq.Load()
	id, actionCh := h.interceptQueue.EnqueueWebSocketFrame(
		int(frame.Opcode), wsDirection, flowID, upgradeURL, frameSeq, frame.Payload, matchedRules,
	)
	defer h.interceptQueue.Remove(id)

	timeout := h.interceptQueue.Timeout()
	timeoutCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()

	select {
	case action := <-actionCh:
		return action
	case <-timeoutCtx.Done():
		if ctx.Err() != nil {
			h.logger.Info("intercepted websocket frame cancelled (proxy shutdown)", "id", id)
			return intercept.InterceptAction{Type: intercept.ActionDrop}
		}
		behavior := h.interceptQueue.TimeoutBehaviorValue()
		h.logger.Info("intercepted websocket frame timed out", "id", id, "behavior", string(behavior))
		if behavior == intercept.TimeoutAutoDrop {
			return intercept.InterceptAction{Type: intercept.ActionDrop}
		}
		return intercept.InterceptAction{Type: intercept.ActionRelease}
	}
}

// applyInterceptAction applies the resolved intercept action to the frame.
// It handles drop, modify-and-forward, and release actions.
func (h *Handler) applyInterceptAction(ctx context.Context, action intercept.InterceptAction, frame *Frame, flowID, direction string, seq *atomic.Int64, start time.Time, dst net.Conn, frag *fragmentState, safetyMeta *safetyMetadata, rawPayload []byte) {
	switch action.Type {
	case intercept.ActionDrop:
		h.logger.Debug("intercepted websocket frame dropped", "flow_id", flowID)
		// If the dropped frame is non-FIN (start of a fragmented message),
		// mark state to drop subsequent continuation frames (protocol violation fix).
		if !frame.Fin && !frame.IsControl() {
			frag.dropping = true
		}
		h.recordDataMessage(ctx, frame.Opcode, frame.Payload, frame.Masked, frame.Fin, flowID, direction, seq, start, safetyMeta, false)

	case intercept.ActionModifyAndForward:
		modifiedPayload := frame.Payload
		if action.OverrideBody != nil {
			override := []byte(*action.OverrideBody)
			if int64(len(override)) > config.MaxWebSocketMessageSize {
				h.logger.Warn("intercept OverrideBody exceeds size limit, releasing original",
					"flow_id", flowID,
					"override_size", len(override),
					"limit", config.MaxWebSocketMessageSize,
				)
			} else {
				modifiedPayload = override
			}
		}
		frame.Payload = modifiedPayload

		if err := forwardFrame(dst, frame, direction); err != nil {
			h.logger.Error("forward modified intercepted frame failed", "flow_id", flowID, "error", err)
			return
		}
		// Record the modified payload (not the raw/original) so flow store
		// reflects the actual forwarded content.
		recordPayload := modifiedPayload
		if rawPayload != nil {
			recordPayload = rawPayload
		}
		// Intercepted frames are not decompressed here since the intercept
		// operates on the raw wire data.
		h.handleDataFrameWithPayload(ctx, dst, frame, recordPayload, frag, flowID, direction, seq, start, safetyMeta, nil, false)

	default:
		// ActionRelease — forward as-is.
		if err := forwardFrame(dst, frame, direction); err != nil {
			h.logger.Error("forward released intercepted frame failed", "flow_id", flowID, "error", err)
			return
		}
		recordPayload := frame.Payload
		if rawPayload != nil {
			recordPayload = rawPayload
		}
		// Intercepted frames are not decompressed here since the intercept
		// operates on the raw wire data.
		h.handleDataFrameWithPayload(ctx, dst, frame, recordPayload, frag, flowID, direction, seq, start, safetyMeta, nil, false)
	}
}

// truncateForLog truncates a string for logging purposes.
func truncateForLog(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// decompressForRecord decompresses payload for recording when permessage-deflate
// is active. The original compressed frame is forwarded as-is on the wire; only
// the stored copy is decompressed so that query results are human/AI-readable.
func (h *Handler) decompressForRecord(payload []byte, ds *deflateState, compressed bool, flowID, direction string) []byte {
	if !compressed || ds == nil || !ds.params.enabled {
		return payload
	}
	decompressed, err := ds.decompress(payload, config.MaxWebSocketRecordPayloadSize)
	if err != nil {
		h.logger.Warn("websocket permessage-deflate decompress failed, storing compressed",
			"flow_id", flowID, "direction", direction, "error", err)
		return payload
	}
	return decompressed
}

// recordDataMessage records a complete WebSocket data message (text or binary)
// to the flow store. If safetyMeta is non-nil, safety filter metadata is
// attached to the recorded message. If compressed is true, the message was
// originally compressed with permessage-deflate (metadata is annotated).
func (h *Handler) recordDataMessage(ctx context.Context, opcode byte, payload []byte, masked bool, fin bool, flowID, direction string, seq *atomic.Int64, start time.Time, safetyMeta *safetyMetadata, compressed bool) {
	if h.store == nil {
		return
	}

	msgSeq := int(seq.Add(1) - 1)

	metadata := map[string]string{
		"opcode": strconv.Itoa(int(opcode)),
		"fin":    strconv.FormatBool(fin),
		"masked": strconv.FormatBool(masked),
	}

	if compressed {
		metadata["compressed"] = "true"
	}

	// Attach safety filter metadata if present.
	if safetyMeta != nil {
		if safetyMeta.blocked {
			metadata["safety_blocked"] = "true"
		}
		if safetyMeta.logOnly {
			metadata["safety_logged"] = "true"
		}
		metadata["safety_rule_id"] = safetyMeta.ruleID
		metadata["safety_matched_on"] = safetyMeta.matchedOn
	}

	msg := &flow.Message{
		FlowID:    flowID,
		Sequence:  msgSeq,
		Direction: direction,
		Timestamp: time.Now(),
		Metadata:  metadata,
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
