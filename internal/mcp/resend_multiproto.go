package mcp

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/ws"
)

// resendReplayRawResult is the structured output of the tcp_replay action.
type resendReplayRawResult struct {
	// NewFlowID is the flow ID of the replayed flow.
	NewFlowID string `json:"new_flow_id"`
	// MessagesSent is the number of send messages replayed.
	MessagesSent int `json:"messages_sent"`
	// MessagesReceived is the number of response chunks received.
	MessagesReceived int `json:"messages_received"`
	// TotalBytesSent is the total bytes sent to the target.
	TotalBytesSent int `json:"total_bytes_sent"`
	// TotalBytesReceived is the total bytes received from the target.
	TotalBytesReceived int `json:"total_bytes_received"`
	// DurationMs is the total operation duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// Tag is the tag attached to the result session (if specified).
	Tag string `json:"tag,omitempty"`
}

// handleResendReplayRaw handles the tcp_replay action for Raw TCP session replay.
// It retrieves all send messages from the original flow, establishes a TCP connection
// to the target, sends the data, and reads back the response.
func (s *Server) handleResendReplayRaw(ctx context.Context, params resendParams) (*gomcp.CallToolResult, *resendReplayRawResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if params.FlowID == "" {
		return nil, nil, fmt.Errorf("flow_id is required for tcp_replay action")
	}

	fl, err := s.deps.store.GetFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	if fl.Protocol != "TCP" {
		return nil, nil, fmt.Errorf("tcp_replay is only supported for TCP sessions, got protocol %q", fl.Protocol)
	}

	sendMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("flow %s has no send messages to replay", params.FlowID)
	}

	targetAddr, err := resolveTargetAddrFromConnInfo(fl, params)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkTargetScopeAddr("", targetAddr); err != nil {
		return nil, nil, err
	}

	// SafetyFilter input check: validate all send message bodies before replaying.
	for _, msg := range sendMsgs {
		data := msg.Body
		if len(data) == 0 {
			data = msg.RawBytes
		}
		if v := s.checkSafetyInput(data, "", nil); v != nil {
			return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
		}
	}

	useTLS, timeout := determineTLSAndTimeout(false, params)

	totalBytesSent, respData, start, duration, err := s.replayAllMessages(ctx, targetAddr, useTLS, timeout, sendMsgs)
	if err != nil {
		return nil, nil, err
	}

	result, err := s.recordReplay(ctx, targetAddr, params, sendMsgs, respData, totalBytesSent, start, duration)
	if err != nil {
		return nil, nil, err
	}

	return nil, result, nil
}

// resolveTargetAddrFromConnInfo determines the target address from the flow's
// connection info or the explicit target_addr parameter.
func resolveTargetAddrFromConnInfo(fl *flow.Flow, params resendParams) (string, error) {
	if params.TargetAddr != "" {
		return params.TargetAddr, nil
	}
	if fl.ConnInfo != nil && fl.ConnInfo.ServerAddr != "" {
		return fl.ConnInfo.ServerAddr, nil
	}
	return "", fmt.Errorf("flow has no server address and no target_addr was provided")
}

// determineTLSAndTimeout resolves TLS and timeout settings from the default protocol
// state and explicit parameter overrides.
func determineTLSAndTimeout(defaultTLS bool, params resendParams) (bool, time.Duration) {
	useTLS := defaultTLS
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}
	return useTLS, timeout
}

// replayAllMessages establishes a connection and sends all messages sequentially,
// returning the total bytes sent, response data, and timing information.
func (s *Server) replayAllMessages(ctx context.Context, targetAddr string, useTLS bool, timeout time.Duration, sendMsgs []*flow.Message) (int, []byte, time.Time, time.Duration, error) {
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return 0, nil, start, 0, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if useTLS {
		conn, err = upgradeTLS(ctx, conn, targetAddr, s.deps.tlsTransport)
		if err != nil {
			return 0, nil, start, 0, err
		}
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return 0, nil, start, 0, fmt.Errorf("set connection deadline: %w", err)
	}

	totalBytesSent := 0
	for _, msg := range sendMsgs {
		data := msg.Body
		if len(data) == 0 {
			data = msg.RawBytes
		}
		if len(data) > 0 {
			n, err := conn.Write(data)
			if err != nil {
				return totalBytesSent, nil, start, 0, fmt.Errorf("send message seq=%d: %w", msg.Sequence, err)
			}
			totalBytesSent += n
		}
	}

	respData, err := io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	if err != nil && len(respData) == 0 {
		return totalBytesSent, nil, start, 0, fmt.Errorf("read response: %w", err)
	}
	duration := time.Since(start)

	return totalBytesSent, respData, start, duration, nil
}

// recordReplay saves the replayed flow and all its messages to the store.
func (s *Server) recordReplay(ctx context.Context, targetAddr string, params resendParams, sendMsgs []*flow.Message, respData []byte, totalBytesSent int, start time.Time, duration time.Duration) (*resendReplayRawResult, error) {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: "TCP", FlowType: "bidirectional", State: "complete",
		Timestamp: start, Duration: duration, Tags: tags,
		ConnInfo: &flow.ConnectionInfo{ServerAddr: targetAddr},
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return nil, fmt.Errorf("save replay_raw session: %w", err)
	}

	seq := 0
	for _, msg := range sendMsgs {
		data := msg.Body
		if len(data) == 0 {
			data = msg.RawBytes
		}
		if len(data) > 0 {
			if err := s.deps.store.AppendMessage(ctx, &flow.Message{
				FlowID: newFl.ID, Sequence: seq, Direction: "send",
				Timestamp: start, RawBytes: data,
			}); err != nil {
				return nil, fmt.Errorf("save replay_raw send message: %w", err)
			}
			seq++
		}
	}

	if len(respData) > 0 {
		if err := s.deps.store.AppendMessage(ctx, &flow.Message{
			FlowID: newFl.ID, Sequence: seq, Direction: "receive",
			Timestamp: start.Add(duration), RawBytes: respData,
		}); err != nil {
			return nil, fmt.Errorf("save replay_raw receive message: %w", err)
		}
	}

	messagesReceived := 0
	if len(respData) > 0 {
		messagesReceived = 1
	}

	return &resendReplayRawResult{
		NewFlowID: newFl.ID, MessagesSent: len(sendMsgs),
		MessagesReceived: messagesReceived, TotalBytesSent: totalBytesSent,
		TotalBytesReceived: len(respData), DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// resendWebSocketResult is the structured output of a WebSocket resend action.
type resendWebSocketResult struct {
	// NewFlowID is the flow ID of the new flow recording the resend.
	NewFlowID string `json:"new_flow_id"`
	// MessageSequence is the sequence number of the resent message.
	MessageSequence int `json:"message_sequence"`
	// ResponseData is the first response frame body, Base64-encoded.
	ResponseData string `json:"response_data"`
	// ResponseSize is the response body size in bytes.
	ResponseSize int `json:"response_size"`
	// DurationMs is the round-trip duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// Tag is the tag attached to the result flow (if specified).
	Tag string `json:"tag,omitempty"`
}

// handleWebSocketResend handles resend for WebSocket flows.
// It performs a proper HTTP Upgrade handshake with the target server,
// sends the specified message as a WebSocket frame, and reads the response frame.
func (s *Server) handleWebSocketResend(ctx context.Context, fl *flow.Flow, params resendParams) (*gomcp.CallToolResult, *resendWebSocketResult, error) {
	if params.MessageSequence == nil {
		return nil, nil, fmt.Errorf("message_sequence is required for WebSocket resend")
	}

	targetMsg, err := findSendMessage(ctx, s.deps.store, fl.ID, *params.MessageSequence)
	if err != nil {
		return nil, nil, err
	}

	upgradeMsg, err := findUpgradeRequestMessage(ctx, s.deps.store, fl.ID)
	if err != nil {
		return nil, nil, err
	}

	overrideURLParsed, err := parseOverrideURL(params.OverrideURL)
	if err != nil {
		return nil, nil, err
	}

	targetAddr, err := s.resolveWSTargetAddr(ctx, fl, params, overrideURLParsed)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkTargetScopeAddr("", targetAddr); err != nil {
		return nil, nil, err
	}

	defaultTLS := resolveDefaultTLS(fl, overrideURLParsed)
	useTLS, timeout := determineTLSAndTimeout(defaultTLS, params)

	sendBody, err := resolveWebSocketBody(targetMsg, params)
	if err != nil {
		return nil, nil, err
	}

	if v := s.checkSafetyInput(sendBody, "", nil); v != nil {
		return nil, nil, fmt.Errorf("%s", safetyViolationError(v))
	}

	opcode := resolveWebSocketOpcode(targetMsg)

	wsResult, err := s.establishWebSocketAndSend(ctx, targetAddr, useTLS, timeout, upgradeMsg, sendBody, opcode, params)
	if err != nil {
		return nil, nil, err
	}

	result, err := s.recordWebSocketResend(ctx, params, targetMsg, wsResult)
	if err != nil {
		return nil, nil, err
	}

	maskedRespData := s.filterOutputBody(wsResult.responsePayload)
	result.ResponseData = base64.StdEncoding.EncodeToString(maskedRespData)

	return nil, result, nil
}

// parseOverrideURL parses and validates the override_url parameter.
// Returns nil if the parameter is empty.
func parseOverrideURL(overrideURL string) (*url.URL, error) {
	if overrideURL == "" {
		return nil, nil
	}
	parsed, err := url.Parse(overrideURL)
	if err != nil {
		return nil, fmt.Errorf("invalid override_url %q: %w", overrideURL, err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return nil, fmt.Errorf("invalid override_url %q: must include scheme and host", overrideURL)
	}
	return parsed, nil
}

// resolveWSTargetAddr determines the target address for a WebSocket resend,
// deriving it from override_url when target_addr is not explicitly set.
func (s *Server) resolveWSTargetAddr(ctx context.Context, fl *flow.Flow, params resendParams, overrideURL *url.URL) (string, error) {
	if params.TargetAddr == "" && overrideURL != nil {
		return addrFromURL(overrideURL), nil
	}
	return s.resolveWebSocketTargetAddr(ctx, fl, params)
}

// addrFromURL derives a host:port address from a parsed URL, using default
// ports (443 for wss/https, 80 otherwise) when the port is not specified.
func addrFromURL(u *url.URL) string {
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "wss" || u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port)
}

// resolveDefaultTLS determines the default TLS setting from the flow's connection
// info and the override URL scheme.
func resolveDefaultTLS(fl *flow.Flow, overrideURL *url.URL) bool {
	if overrideURL != nil {
		return overrideURL.Scheme == "wss" || overrideURL.Scheme == "https"
	}
	return fl.ConnInfo != nil && fl.ConnInfo.TLSVersion != ""
}

// findUpgradeRequestMessage retrieves the Upgrade request message (seq=0, direction="send")
// from a WebSocket flow. This message contains the URL and Headers needed to reconstruct
// the HTTP Upgrade handshake.
func findUpgradeRequestMessage(ctx context.Context, store flow.Store, flowID string) (*flow.Message, error) {
	allMsgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("get messages for upgrade request: %w", err)
	}
	for _, msg := range allMsgs {
		if msg.Sequence == 0 && msg.Direction == "send" {
			return msg, nil
		}
	}
	return nil, fmt.Errorf("upgrade request message (seq=0) not found in flow %s", flowID)
}

// resolveWebSocketOpcode determines the WebSocket opcode from the message metadata.
// Defaults to OpcodeText if the metadata is missing or invalid.
func resolveWebSocketOpcode(msg *flow.Message) byte {
	if msg.Metadata == nil {
		return ws.OpcodeText
	}
	opcodeStr, ok := msg.Metadata["opcode"]
	if !ok {
		return ws.OpcodeText
	}
	v, err := strconv.Atoi(opcodeStr)
	if err != nil {
		return ws.OpcodeText
	}
	if v < 0 || v > 255 {
		return ws.OpcodeText
	}
	return byte(v)
}

// wsResendResult holds the intermediate results of a WebSocket resend operation.
type wsResendResult struct {
	start           time.Time
	duration        time.Duration
	upgradeResp     *gohttp.Response
	responsePayload []byte
	responseOpcode  byte
	sendBody        []byte
	// upgradeHeaders and upgradeURL capture the actual headers and URL used
	// in the handshake (after overrides), for accurate flow recording.
	upgradeHeaders map[string][]string
	upgradeURL     *url.URL
	upgradeMethod  string
}

// establishWebSocketAndSend performs the full WebSocket handshake and frame exchange:
// 1. Establishes TCP/TLS connection
// 2. Sends HTTP Upgrade request and validates 101 response
// 3. Sends the payload as a masked WebSocket frame
// 4. Reads the first response frame from the server
func (s *Server) establishWebSocketAndSend(ctx context.Context, targetAddr string, useTLS bool, timeout time.Duration, upgradeMsg *flow.Message, sendBody []byte, opcode byte, params resendParams) (*wsResendResult, error) {
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if useTLS {
		conn, err = upgradeTLS(ctx, conn, targetAddr, s.deps.tlsTransport)
		if err != nil {
			return nil, err
		}
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	// Step 1: Perform HTTP Upgrade handshake.
	upgradeResp, bufReader, handshakeHeaders, handshakeURL, err := performUpgradeHandshake(conn, upgradeMsg, targetAddr, params)
	if err != nil {
		return nil, err
	}

	// Step 2: Send the WebSocket frame (client frames must be masked per RFC 6455).
	if err := sendWebSocketFrame(conn, sendBody, opcode); err != nil {
		return nil, err
	}

	// Step 3: Read the first response frame from the server.
	// Pass conn as writer so Pong replies can be sent for Ping frames (RFC 6455).
	respPayload, respOpcode, err := readWebSocketResponseFrame(bufReader, conn)
	if err != nil {
		return nil, err
	}

	duration := time.Since(start)

	return &wsResendResult{
		start:           start,
		duration:        duration,
		upgradeResp:     upgradeResp,
		responsePayload: respPayload,
		responseOpcode:  respOpcode,
		sendBody:        sendBody,
		upgradeHeaders:  handshakeHeaders,
		upgradeURL:      handshakeURL,
		upgradeMethod:   upgradeMsg.Method,
	}, nil
}

// performUpgradeHandshake sends an HTTP Upgrade request and reads the 101 response.
// It returns the response, a buffered reader wrapping the connection for
// subsequent WebSocket frame reads, the actual headers used, and the actual URL used.
// Header overrides (override_headers, add_headers, remove_headers) and URL overrides
// (override_url) from params are applied to the handshake request.
// When targetAddr differs from the original URL host, the Host header and httpReq.Host
// are updated to match the target.
func performUpgradeHandshake(conn net.Conn, upgradeMsg *flow.Message, targetAddr string, params resendParams) (*gohttp.Response, *bufio.Reader, map[string][]string, *url.URL, error) {
	reqURL := upgradeMsg.URL
	if reqURL == nil {
		return nil, nil, nil, nil, fmt.Errorf("upgrade request message has no URL")
	}

	// Apply override_url if specified.
	if params.OverrideURL != "" {
		parsed, err := parseOverrideURL(params.OverrideURL)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		reqURL = parsed
	}

	// Build the HTTP Upgrade request.
	httpReq := &gohttp.Request{
		Method:     "GET",
		URL:        &url.URL{Path: reqURL.Path, RawPath: reqURL.RawPath, RawQuery: reqURL.RawQuery},
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(gohttp.Header),
		Host:       reqURL.Host,
	}

	// Apply header overrides using buildResendHeaders (same as HTTP resend).
	// This handles override_headers, add_headers, and remove_headers consistently.
	headers := buildResendHeaders(upgradeMsg.Headers, params)
	// Use direct map assignment instead of Header.Add so that empty-slice
	// sentinels from buildResendHeaders (remove_headers) are preserved.
	// This suppresses Go net/http auto-added headers like User-Agent,
	// matching the behavior of applyHeaders in HTTP resend.
	for k, vs := range headers {
		httpReq.Header[k] = vs
	}

	// Determine if the user explicitly overrode the Host header.
	hostExplicitlyOverridden := hasHostOverride(params)

	if !hostExplicitlyOverridden {
		// When override_url changes the host, update Host header automatically.
		if params.OverrideURL != "" && reqURL.Host != "" {
			httpReq.Host = reqURL.Host
			httpReq.Header.Set("Host", reqURL.Host)
		} else if targetAddr != "" && targetAddr != reqURL.Host {
			// When target_addr differs from the original URL host, update
			// Host header and httpReq.Host so virtual-hosting servers accept the request.
			httpReq.Host = targetAddr
			httpReq.Header.Set("Host", targetAddr)
		}
	} else {
		// User explicitly set Host via override_headers or add_headers.
		// Sync httpReq.Host with the header value (Go's net/http uses req.Host).
		if hostVal := httpReq.Header.Get("Host"); hostVal != "" {
			httpReq.Host = hostVal
		}
	}

	// Ensure required WebSocket headers are present.
	ensureWebSocketHeaders(httpReq.Header)

	// Remove Sec-WebSocket-Extensions to prevent permessage-deflate negotiation.
	// The stored message bodies are already decompressed plaintext, so resend
	// must use uncompressed frames to avoid double-compression or context mismatch.
	httpReq.Header.Del("Sec-WebSocket-Extensions")

	// Capture the actual headers and URL used for flow recording.
	actualHeaders := copyHeadersMap(gohttp.Header(httpReq.Header))
	actualURL := &url.URL{
		Scheme:   reqURL.Scheme,
		Host:     reqURL.Host,
		Path:     reqURL.Path,
		RawPath:  reqURL.RawPath,
		RawQuery: reqURL.RawQuery,
	}

	// Write the request to the connection.
	if err := httpReq.Write(conn); err != nil {
		return nil, nil, nil, nil, fmt.Errorf("write upgrade request: %w", err)
	}

	// Read the response.
	bufReader := bufio.NewReader(conn)
	resp, err := gohttp.ReadResponse(bufReader, httpReq)
	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("read upgrade response: %w", err)
	}

	if resp.StatusCode != gohttp.StatusSwitchingProtocols {
		resp.Body.Close()
		return nil, nil, nil, nil, fmt.Errorf("upgrade failed: server returned status %d, want 101", resp.StatusCode)
	}

	return resp, bufReader, actualHeaders, actualURL, nil
}

// hasHostOverride checks if the user explicitly set the Host header
// via override_headers or add_headers.
func hasHostOverride(params resendParams) bool {
	for _, entry := range params.OverrideHeaders {
		if gohttp.CanonicalHeaderKey(entry.Key) == "Host" {
			return true
		}
	}
	for _, entry := range params.AddHeaders {
		if gohttp.CanonicalHeaderKey(entry.Key) == "Host" {
			return true
		}
	}
	return false
}

// ensureWebSocketHeaders ensures the required WebSocket Upgrade headers are set.
// If the original request already has them, they are preserved.
func ensureWebSocketHeaders(h gohttp.Header) {
	if h.Get("Upgrade") == "" {
		h.Set("Upgrade", "websocket")
	}
	if h.Get("Connection") == "" {
		h.Set("Connection", "Upgrade")
	}
	if h.Get("Sec-WebSocket-Version") == "" {
		h.Set("Sec-WebSocket-Version", "13")
	}
	if h.Get("Sec-WebSocket-Key") == "" {
		key := generateWebSocketKey()
		h.Set("Sec-WebSocket-Key", key)
	}
}

// generateWebSocketKey generates a random Sec-WebSocket-Key for the handshake.
func generateWebSocketKey() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return base64.StdEncoding.EncodeToString(b)
}

// maxWebSocketResendPayload is the maximum payload size for WebSocket resend frames.
// Matches the read-side limit (maxFramePayloadSize = 16MB) to prevent OOM during masking.
const maxWebSocketResendPayload = 16 << 20 // 16MB

// sendWebSocketFrame sends a single WebSocket frame with the given payload and opcode.
// Client-to-server frames must be masked per RFC 6455 Section 5.3.
func sendWebSocketFrame(w io.Writer, payload []byte, opcode byte) error {
	if len(payload) > maxWebSocketResendPayload {
		return fmt.Errorf("WebSocket resend payload too large: %d bytes exceeds limit of %d bytes", len(payload), maxWebSocketResendPayload)
	}
	var maskKey [4]byte
	if _, err := rand.Read(maskKey[:]); err != nil {
		return fmt.Errorf("generate mask key: %w", err)
	}

	frame := &ws.Frame{
		Fin:     true,
		Opcode:  opcode,
		Masked:  true,
		MaskKey: maskKey,
		Payload: payload,
	}
	if err := ws.WriteFrame(w, frame); err != nil {
		return fmt.Errorf("send WebSocket frame: %w", err)
	}
	return nil
}

// readWebSocketResponseFrame reads the first data frame from the server,
// handling control frames per RFC 6455. Ping frames receive an automatic Pong reply
// using the provided writer. Returns the payload and opcode of the first data frame.
func readWebSocketResponseFrame(r io.Reader, w io.Writer) ([]byte, byte, error) {
	for {
		frame, err := ws.ReadFrame(r)
		if err != nil {
			return nil, 0, fmt.Errorf("read WebSocket response frame: %w", err)
		}

		// Return Close frames as data (the response itself may be a close).
		if frame.Opcode == ws.OpcodeClose {
			return frame.Payload, frame.Opcode, nil
		}

		// Reply to Ping with Pong per RFC 6455 Section 5.5.3.
		if frame.Opcode == ws.OpcodePing {
			pong := &ws.Frame{
				Fin:     true,
				Opcode:  ws.OpcodePong,
				Payload: frame.Payload,
			}
			if err := ws.WriteFrame(w, pong); err != nil {
				return nil, 0, fmt.Errorf("send Pong reply: %w", err)
			}
			continue
		}

		// Skip other control frames (Pong).
		if frame.IsControl() {
			continue
		}

		return frame.Payload, frame.Opcode, nil
	}
}

// findSendMessage locates a specific send message by sequence number within a flow.
func findSendMessage(ctx context.Context, store flow.Store, flowID string, seq int) (*flow.Message, error) {
	allMsgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{})
	if err != nil {
		return nil, fmt.Errorf("get messages: %w", err)
	}

	for _, msg := range allMsgs {
		if msg.Sequence == seq {
			if msg.Direction != "send" {
				return nil, fmt.Errorf("message sequence %d is a %q message, only send messages can be resent", seq, msg.Direction)
			}
			return msg, nil
		}
	}
	return nil, fmt.Errorf("message with sequence %d not found in flow %s", seq, flowID)
}

// resolveWebSocketTargetAddr determines the target address for a WebSocket resend
// from the explicit parameter, flow connection info, or the first send message URL.
func (s *Server) resolveWebSocketTargetAddr(ctx context.Context, fl *flow.Flow, params resendParams) (string, error) {
	if params.TargetAddr != "" {
		return params.TargetAddr, nil
	}

	if fl.ConnInfo != nil && fl.ConnInfo.ServerAddr != "" {
		return fl.ConnInfo.ServerAddr, nil
	}

	sendMsgs, _ := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	for _, m := range sendMsgs {
		if m.URL != nil {
			host := m.URL.Hostname()
			port := m.URL.Port()
			if port == "" {
				if m.URL.Scheme == "wss" || m.URL.Scheme == "https" {
					port = "443"
				} else {
					port = "80"
				}
			}
			return net.JoinHostPort(host, port), nil
		}
	}
	return "", fmt.Errorf("cannot determine target address: no server address in session and no target_addr provided")
}

// resolveWebSocketBody determines the body to send, applying any overrides.
// For binary messages, the body may be stored in RawBytes rather than Body.
func resolveWebSocketBody(targetMsg *flow.Message, params resendParams) ([]byte, error) {
	sendBody := targetMsg.Body
	if len(sendBody) == 0 && len(targetMsg.RawBytes) > 0 {
		sendBody = targetMsg.RawBytes
	}
	if params.OverrideBody != nil {
		sendBody = []byte(*params.OverrideBody)
	}
	if params.OverrideBodyBase64 != nil {
		decoded, err := base64.StdEncoding.DecodeString(*params.OverrideBodyBase64)
		if err != nil {
			return nil, fmt.Errorf("invalid override_body_base64: %w", err)
		}
		sendBody = decoded
	}
	return sendBody, nil
}

// upgradeTLS wraps a connection with TLS using the provided TLSTransport.
// If transport is nil, it falls back to a StandardTransport with InsecureSkipVerify.
func upgradeTLS(ctx context.Context, conn net.Conn, targetAddr string, transport httputil.TLSTransport) (net.Conn, error) {
	if transport == nil {
		transport = &httputil.StandardTransport{InsecureSkipVerify: true}
	}
	host, _, _ := net.SplitHostPort(targetAddr)
	tlsConn, _, err := transport.TLSConnect(ctx, conn, host)
	if err != nil {
		return nil, fmt.Errorf("TLS handshake with %s: %w", targetAddr, err)
	}
	return tlsConn, nil
}

// recordWebSocketResend saves the WebSocket resend flow and messages to the store.
// The flow records: seq=0 Upgrade request, seq=1 Upgrade response, seq=2 sent frame,
// seq=3 received frame (mirroring the structure of live WebSocket flows).
func (s *Server) recordWebSocketResend(ctx context.Context, params resendParams, targetMsg *flow.Message, wr *wsResendResult) (*resendWebSocketResult, error) {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: "WebSocket", FlowType: "bidirectional", State: "complete",
		Timestamp: wr.start, Duration: wr.duration, Tags: tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return nil, fmt.Errorf("save WebSocket resend session: %w", err)
	}

	// seq=0: Upgrade request (send).
	// Use the actual headers and URL from the handshake (after overrides).
	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 0, Direction: "send",
		Timestamp: wr.start, Method: wr.upgradeMethod, URL: wr.upgradeURL,
		Headers: wr.upgradeHeaders,
	}); err != nil {
		return nil, fmt.Errorf("save WebSocket resend upgrade request: %w", err)
	}

	// seq=1: Upgrade response (receive).
	respHeaders := copyHTTPResponseHeaders(wr.upgradeResp)
	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 1, Direction: "receive",
		Timestamp: wr.start, StatusCode: wr.upgradeResp.StatusCode,
		Headers: respHeaders,
	}); err != nil {
		return nil, fmt.Errorf("save WebSocket resend upgrade response: %w", err)
	}

	// seq=2: Sent data frame.
	// Copy metadata to avoid aliasing the original message's map.
	sendMetadata := copyMetadataMap(targetMsg.Metadata)
	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 2, Direction: "send",
		Timestamp: wr.start, Body: wr.sendBody, Metadata: sendMetadata,
	}); err != nil {
		return nil, fmt.Errorf("save WebSocket resend send message: %w", err)
	}

	// seq=3: Received data frame.
	if len(wr.responsePayload) > 0 {
		recvMetadata := map[string]string{
			"opcode": strconv.Itoa(int(wr.responseOpcode)),
			"fin":    "true",
		}
		recvBody, recvRawBytes := classifyWebSocketPayload(wr.responsePayload, wr.responseOpcode)
		if err := s.deps.store.AppendMessage(ctx, &flow.Message{
			FlowID: newFl.ID, Sequence: 3, Direction: "receive",
			Timestamp: wr.start.Add(wr.duration), Body: recvBody,
			RawBytes: recvRawBytes, Metadata: recvMetadata,
		}); err != nil {
			return nil, fmt.Errorf("save WebSocket resend receive message: %w", err)
		}
	}

	return &resendWebSocketResult{
		NewFlowID: newFl.ID, MessageSequence: *params.MessageSequence,
		ResponseData: base64.StdEncoding.EncodeToString(wr.responsePayload),
		ResponseSize: len(wr.responsePayload), DurationMs: wr.duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}

// copyHTTPResponseHeaders extracts headers from an HTTP response into a map.
func copyHTTPResponseHeaders(resp *gohttp.Response) map[string][]string {
	if resp == nil || resp.Header == nil {
		return nil
	}
	result := make(map[string][]string, len(resp.Header))
	for k, vs := range resp.Header {
		cp := make([]string, len(vs))
		copy(cp, vs)
		result[k] = cp
	}
	return result
}

// classifyWebSocketPayload returns (body, rawBytes) based on the opcode.
// Text frames are stored in Body; binary frames are stored in RawBytes.
func classifyWebSocketPayload(payload []byte, opcode byte) ([]byte, []byte) {
	if opcode == ws.OpcodeText {
		return payload, nil
	}
	return nil, payload
}

// copyHeadersMap creates a deep copy of a headers map to prevent cross-flow aliasing.
func copyHeadersMap(src map[string][]string) map[string][]string {
	if src == nil {
		return nil
	}
	dst := make(map[string][]string, len(src))
	for k, vs := range src {
		cp := make([]string, len(vs))
		copy(cp, vs)
		dst[k] = cp
	}
	return dst
}

// copyMetadataMap creates a copy of a metadata map to prevent cross-flow aliasing.
func copyMetadataMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
