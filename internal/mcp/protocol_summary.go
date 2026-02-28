package mcp

import (
	"fmt"
	"strconv"

	"github.com/usk6666/katashiro-proxy/internal/session"
)

// buildProtocolSummary generates a protocol-specific summary map for a session.
// The summary provides key information relevant to the session's protocol type.
func buildProtocolSummary(protocol, sessionType string, msgs []*session.Message) map[string]string {
	switch protocol {
	case "WebSocket":
		return buildWebSocketSummary(msgs)
	case "HTTP/2":
		return buildHTTP2Summary(sessionType, msgs)
	case "gRPC":
		return buildGRPCSummary(msgs)
	case "TCP":
		return buildTCPSummary(msgs)
	default:
		return nil
	}
}

// buildWebSocketSummary generates summary info for WebSocket sessions.
func buildWebSocketSummary(msgs []*session.Message) map[string]string {
	summary := map[string]string{
		"message_count": strconv.Itoa(len(msgs)),
	}

	// Find the last frame type from the last message's opcode.
	if len(msgs) > 0 {
		last := msgs[len(msgs)-1]
		if opcode, ok := last.Metadata["opcode"]; ok {
			summary["last_frame_type"] = wsOpcodeLabel(opcode)
		}
	}

	return summary
}

// buildHTTP2Summary generates summary info for HTTP/2 sessions.
func buildHTTP2Summary(sessionType string, msgs []*session.Message) map[string]string {
	// Count streams: in HTTP/2, each send+receive pair is one stream.
	sendCount := 0
	for _, msg := range msgs {
		if msg.Direction == "send" {
			sendCount++
		}
	}
	summary := map[string]string{
		"stream_count": strconv.Itoa(sendCount),
	}

	// Check for ALPN info from session metadata if available.
	// For HTTP/2, the first send message typically has the method and URL.
	if len(msgs) > 0 && msgs[0].Direction == "send" && msgs[0].URL != nil {
		summary["scheme"] = msgs[0].URL.Scheme
	}

	return summary
}

// buildGRPCSummary generates summary info for gRPC sessions.
func buildGRPCSummary(msgs []*session.Message) map[string]string {
	summary := map[string]string{}

	// Extract gRPC service/method from the first send message's metadata.
	for _, msg := range msgs {
		if msg.Direction == "send" {
			if svc, ok := msg.Metadata["service"]; ok {
				summary["service"] = svc
			}
			if method, ok := msg.Metadata["method"]; ok {
				summary["method"] = method
			}
			break
		}
	}

	// Extract grpc_status from the last receive message.
	for i := len(msgs) - 1; i >= 0; i-- {
		if msgs[i].Direction == "receive" {
			if status, ok := msgs[i].Metadata["grpc_status"]; ok {
				summary["grpc_status"] = status
				if name := grpcStatusLabel(status); name != "" {
					summary["grpc_status_name"] = name
				}
			}
			break
		}
	}

	return summary
}

// buildTCPSummary generates summary info for Raw TCP sessions.
func buildTCPSummary(msgs []*session.Message) map[string]string {
	var sendBytes, recvBytes int
	for _, msg := range msgs {
		switch msg.Direction {
		case "send":
			sendBytes += len(msg.Body)
		case "receive":
			recvBytes += len(msg.Body)
		}
	}
	return map[string]string{
		"send_bytes":    strconv.Itoa(sendBytes),
		"receive_bytes": strconv.Itoa(recvBytes),
	}
}

// wsOpcodeLabel returns a human-readable label for a WebSocket opcode string.
func wsOpcodeLabel(opcode string) string {
	switch opcode {
	case "1":
		return "Text"
	case "2":
		return "Binary"
	case "8":
		return "Close"
	case "9":
		return "Ping"
	case "10":
		return "Pong"
	case "0":
		return "Continuation"
	default:
		return fmt.Sprintf("Unknown(%s)", opcode)
	}
}

// grpcStatusLabel returns a human-readable label for a gRPC status code string.
func grpcStatusLabel(status string) string {
	switch status {
	case "0":
		return "OK"
	case "1":
		return "CANCELLED"
	case "2":
		return "UNKNOWN"
	case "3":
		return "INVALID_ARGUMENT"
	case "4":
		return "DEADLINE_EXCEEDED"
	case "5":
		return "NOT_FOUND"
	case "6":
		return "ALREADY_EXISTS"
	case "7":
		return "PERMISSION_DENIED"
	case "8":
		return "RESOURCE_EXHAUSTED"
	case "9":
		return "FAILED_PRECONDITION"
	case "10":
		return "ABORTED"
	case "11":
		return "OUT_OF_RANGE"
	case "12":
		return "UNIMPLEMENTED"
	case "13":
		return "INTERNAL"
	case "14":
		return "UNAVAILABLE"
	case "15":
		return "DATA_LOSS"
	case "16":
		return "UNAUTHENTICATED"
	default:
		return ""
	}
}
