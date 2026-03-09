package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
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
		if len(msg.Body) > 0 {
			n, err := conn.Write(msg.Body)
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
		if len(msg.Body) > 0 {
			if err := s.deps.store.AppendMessage(ctx, &flow.Message{
				FlowID: newFl.ID, Sequence: seq, Direction: "send",
				Timestamp: start, Body: msg.Body,
			}); err != nil {
				return nil, fmt.Errorf("save replay_raw send message: %w", err)
			}
			seq++
		}
	}

	if len(respData) > 0 {
		if err := s.deps.store.AppendMessage(ctx, &flow.Message{
			FlowID: newFl.ID, Sequence: seq, Direction: "receive",
			Timestamp: start.Add(duration), Body: respData,
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
// It sends a single message from the original flow to the target server
// over a raw TCP connection, recording the exchange.
func (s *Server) handleWebSocketResend(ctx context.Context, fl *flow.Flow, params resendParams) (*gomcp.CallToolResult, *resendWebSocketResult, error) {
	if params.MessageSequence == nil {
		return nil, nil, fmt.Errorf("message_sequence is required for WebSocket resend")
	}

	targetMsg, err := findSendMessage(ctx, s.deps.store, fl.ID, *params.MessageSequence)
	if err != nil {
		return nil, nil, err
	}

	targetAddr, err := s.resolveWebSocketTargetAddr(ctx, fl, params)
	if err != nil {
		return nil, nil, err
	}

	if err := s.checkTargetScopeAddr("", targetAddr); err != nil {
		return nil, nil, err
	}

	defaultTLS := fl.ConnInfo != nil && fl.ConnInfo.TLSVersion != ""
	useTLS, timeout := determineTLSAndTimeout(defaultTLS, params)

	sendBody, err := resolveWebSocketBody(targetMsg, params)
	if err != nil {
		return nil, nil, err
	}

	respData, start, duration, err := s.establishAndSend(ctx, targetAddr, useTLS, timeout, sendBody)
	if err != nil {
		return nil, nil, err
	}

	result, err := s.recordWebSocketResend(ctx, params, targetMsg, sendBody, respData, start, duration)
	if err != nil {
		return nil, nil, err
	}

	return nil, result, nil
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
func resolveWebSocketBody(targetMsg *flow.Message, params resendParams) ([]byte, error) {
	sendBody := targetMsg.Body
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

// establishAndSend establishes a TCP/TLS connection, sends data, and reads the response.
func (s *Server) establishAndSend(ctx context.Context, targetAddr string, useTLS bool, timeout time.Duration, sendBody []byte) ([]byte, time.Time, time.Duration, error) {
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, start, 0, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if useTLS {
		conn, err = upgradeTLS(ctx, conn, targetAddr, s.deps.tlsTransport)
		if err != nil {
			return nil, start, 0, err
		}
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, start, 0, fmt.Errorf("set deadline: %w", err)
	}

	if len(sendBody) > 0 {
		if _, err := conn.Write(sendBody); err != nil {
			return nil, start, 0, fmt.Errorf("send WebSocket message: %w", err)
		}
	}

	respData, err := io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	if err != nil && len(respData) == 0 {
		return nil, start, 0, fmt.Errorf("read response: %w", err)
	}
	duration := time.Since(start)

	return respData, start, duration, nil
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
func (s *Server) recordWebSocketResend(ctx context.Context, params resendParams, targetMsg *flow.Message, sendBody, respData []byte, start time.Time, duration time.Duration) (*resendWebSocketResult, error) {
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol: "WebSocket", FlowType: "bidirectional", State: "complete",
		Timestamp: start, Duration: duration, Tags: tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return nil, fmt.Errorf("save WebSocket resend session: %w", err)
	}

	if err := s.deps.store.AppendMessage(ctx, &flow.Message{
		FlowID: newFl.ID, Sequence: 0, Direction: "send",
		Timestamp: start, Body: sendBody, Metadata: targetMsg.Metadata,
	}); err != nil {
		return nil, fmt.Errorf("save WebSocket resend send message: %w", err)
	}

	if len(respData) > 0 {
		if err := s.deps.store.AppendMessage(ctx, &flow.Message{
			FlowID: newFl.ID, Sequence: 1, Direction: "receive",
			Timestamp: start.Add(duration), Body: respData,
		}); err != nil {
			return nil, fmt.Errorf("save WebSocket resend receive message: %w", err)
		}
	}

	return &resendWebSocketResult{
		NewFlowID: newFl.ID, MessageSequence: *params.MessageSequence,
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData), DurationMs: duration.Milliseconds(),
		Tag: params.Tag,
	}, nil
}
