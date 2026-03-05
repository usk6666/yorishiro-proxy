package mcp

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
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

	// Retrieve the flow.
	fl, err := s.deps.store.GetFlow(ctx, params.FlowID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	if fl.Protocol != "TCP" {
		return nil, nil, fmt.Errorf("tcp_replay is only supported for TCP sessions, got protocol %q", fl.Protocol)
	}

	// Retrieve all send messages.
	sendMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("flow %s has no send messages to replay", params.FlowID)
	}

	// Determine target address.
	targetAddr := params.TargetAddr
	if targetAddr == "" {
		if fl.ConnInfo != nil && fl.ConnInfo.ServerAddr != "" {
			targetAddr = fl.ConnInfo.ServerAddr
		} else {
			return nil, nil, fmt.Errorf("flow has no server address and no target_addr was provided")
		}
	}

	// Target scope enforcement: check the target address.
	if err := s.checkTargetScopeAddr("", targetAddr); err != nil {
		return nil, nil, err
	}

	// Determine timeout.
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	// Determine TLS.
	useTLS := false
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}

	// Establish connection.
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	// Upgrade to TLS if needed.
	if useTLS {
		host, _, _ := net.SplitHostPort(targetAddr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // tcp_replay intentionally targets test servers
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("TLS handshake with %s: %w", targetAddr, err)
		}
		conn = tlsConn
	}

	// Set deadline.
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("set connection deadline: %w", err)
	}

	// Send all send messages sequentially.
	totalBytesSent := 0
	for _, msg := range sendMsgs {
		if len(msg.Body) > 0 {
			n, err := conn.Write(msg.Body)
			if err != nil {
				return nil, nil, fmt.Errorf("send message seq=%d: %w", msg.Sequence, err)
			}
			totalBytesSent += n
		}
	}

	// Read response.
	respData, err := io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	if err != nil && len(respData) == 0 {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	duration := time.Since(start)

	// Record the replay as a new flow.
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol:    "TCP",
		FlowType: "bidirectional",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        tags,
		ConnInfo: &flow.ConnectionInfo{
			ServerAddr: targetAddr,
		},
	}

	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return nil, nil, fmt.Errorf("save replay_raw session: %w", err)
	}

	// Save send messages.
	seq := 0
	for _, msg := range sendMsgs {
		if len(msg.Body) > 0 {
			newMsg := &flow.Message{
				FlowID: newFl.ID,
				Sequence:  seq,
				Direction: "send",
				Timestamp: start,
				Body:      msg.Body,
			}
			if err := s.deps.store.AppendMessage(ctx, newMsg); err != nil {
				return nil, nil, fmt.Errorf("save replay_raw send message: %w", err)
			}
			seq++
		}
	}

	// Save receive message.
	if len(respData) > 0 {
		newRecvMsg := &flow.Message{
			FlowID: newFl.ID,
			Sequence:  seq,
			Direction: "receive",
			Timestamp: start.Add(duration),
			Body:      respData,
		}
		if err := s.deps.store.AppendMessage(ctx, newRecvMsg); err != nil {
			return nil, nil, fmt.Errorf("save replay_raw receive message: %w", err)
		}
	}

	messagesReceived := 0
	if len(respData) > 0 {
		messagesReceived = 1
	}

	result := &resendReplayRawResult{
		NewFlowID:       newFl.ID,
		MessagesSent:       len(sendMsgs),
		MessagesReceived:   messagesReceived,
		TotalBytesSent:     totalBytesSent,
		TotalBytesReceived: len(respData),
		DurationMs:         duration.Milliseconds(),
		Tag:                params.Tag,
	}

	return nil, result, nil
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

	// Get the specific message.
	allMsgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	var targetMsg *flow.Message
	for _, msg := range allMsgs {
		if msg.Sequence == *params.MessageSequence {
			targetMsg = msg
			break
		}
	}
	if targetMsg == nil {
		return nil, nil, fmt.Errorf("message with sequence %d not found in flow %s", *params.MessageSequence, fl.ID)
	}
	if targetMsg.Direction != "send" {
		return nil, nil, fmt.Errorf("message sequence %d is a %q message, only send messages can be resent", *params.MessageSequence, targetMsg.Direction)
	}

	// Determine target address from session or override.
	targetAddr := params.TargetAddr
	if targetAddr == "" {
		// Try to derive from the flow's first send message URL or ConnInfo.
		if fl.ConnInfo != nil && fl.ConnInfo.ServerAddr != "" {
			targetAddr = fl.ConnInfo.ServerAddr
		} else {
			// Look for URL in first send message.
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
					targetAddr = net.JoinHostPort(host, port)
					break
				}
			}
		}
		if targetAddr == "" {
			return nil, nil, fmt.Errorf("cannot determine target address: no server address in session and no target_addr provided")
		}
	}

	// Target scope enforcement: check the WebSocket target address.
	if err := s.checkTargetScopeAddr("", targetAddr); err != nil {
		return nil, nil, err
	}

	// Determine TLS.
	useTLS := false
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	} else if fl.ConnInfo != nil && fl.ConnInfo.TLSVersion != "" {
		useTLS = true
	}

	// Determine timeout.
	timeout := defaultReplayTimeout
	if params.TimeoutMs != nil && *params.TimeoutMs > 0 {
		timeout = time.Duration(*params.TimeoutMs) * time.Millisecond
	}

	// Connect.
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	if useTLS {
		host, _, _ := net.SplitHostPort(targetAddr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true, //nolint:gosec // WebSocket resend intentionally targets test servers
			MinVersion:         tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("TLS handshake: %w", err)
		}
		conn = tlsConn
	}

	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, nil, fmt.Errorf("set deadline: %w", err)
	}

	// Apply body override if provided.
	sendBody := targetMsg.Body
	if params.OverrideBody != nil {
		sendBody = []byte(*params.OverrideBody)
	}
	if params.OverrideBodyBase64 != nil {
		decoded, err := base64.StdEncoding.DecodeString(*params.OverrideBodyBase64)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid override_body_base64: %w", err)
		}
		sendBody = decoded
	}

	// Send the message body directly.
	if len(sendBody) > 0 {
		if _, err := conn.Write(sendBody); err != nil {
			return nil, nil, fmt.Errorf("send WebSocket message: %w", err)
		}
	}

	// Read response (limited).
	respData, err := io.ReadAll(io.LimitReader(conn, config.MaxReplayResponseSize))
	if err != nil && len(respData) == 0 {
		return nil, nil, fmt.Errorf("read response: %w", err)
	}
	duration := time.Since(start)

	// Record the resend.
	var tags map[string]string
	if params.Tag != "" {
		tags = map[string]string{"tag": params.Tag}
	}

	newFl := &flow.Flow{
		Protocol:    "WebSocket",
		FlowType: "bidirectional",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
		Tags:        tags,
	}
	if err := s.deps.store.SaveFlow(ctx, newFl); err != nil {
		return nil, nil, fmt.Errorf("save WebSocket resend session: %w", err)
	}

	newSendMsg := &flow.Message{
		FlowID: newFl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Body:      sendBody,
		Metadata:  targetMsg.Metadata,
	}
	if err := s.deps.store.AppendMessage(ctx, newSendMsg); err != nil {
		return nil, nil, fmt.Errorf("save WebSocket resend send message: %w", err)
	}

	if len(respData) > 0 {
		newRecvMsg := &flow.Message{
			FlowID: newFl.ID,
			Sequence:  1,
			Direction: "receive",
			Timestamp: start.Add(duration),
			Body:      respData,
		}
		if err := s.deps.store.AppendMessage(ctx, newRecvMsg); err != nil {
			return nil, nil, fmt.Errorf("save WebSocket resend receive message: %w", err)
		}
	}

	result := &resendWebSocketResult{
		NewFlowID:    newFl.ID,
		MessageSequence: *params.MessageSequence,
		ResponseData:    base64.StdEncoding.EncodeToString(respData),
		ResponseSize:    len(respData),
		DurationMs:      duration.Milliseconds(),
		Tag:             params.Tag,
	}

	return nil, result, nil
}
