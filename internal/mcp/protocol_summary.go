package mcp

import (
	"fmt"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// buildProtocolSummary generates a protocol-specific summary map for a flow.
// The summary provides key information relevant to the flow's protocol type.
//
// Dispatch is by Message-type family (canonical Envelope.Protocol value), so
// flows recorded with either the new lowercase spelling ("ws", "grpc", ...)
// or the legacy spelling ("WebSocket", "gRPC", ...) yield the same summary
// shape. Unknown or unmapped protocols return nil.
func buildProtocolSummary(protocol string, msgs []*flow.Flow) map[string]string {
	switch canonicalProtocol(protocol) {
	case "ws":
		return buildWebSocketSummary(msgs)
	case "grpc", "grpc-web":
		return buildGRPCSummary(msgs)
	case "raw":
		return buildTCPSummary(msgs)
	case "http":
		// Only HTTP/2 currently has stream-count summary; HTTP/1.x and
		// HTTPS legacy spellings are not surfaced here. Match the legacy
		// behaviour by gating on the literal HTTP/2 spellings.
		switch protocol {
		case "HTTP/2", "SOCKS5+HTTP/2":
			return buildHTTP2Summary(msgs)
		}
		return nil
	default:
		return nil
	}
}

// buildWebSocketSummary generates summary info for WebSocket flows.
func buildWebSocketSummary(msgs []*flow.Flow) map[string]string {
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
func buildHTTP2Summary(msgs []*flow.Flow) map[string]string {
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

	// Check for ALPN info from flow metadata if available.
	// For HTTP/2, the first send message typically has the method and URL.
	if len(msgs) > 0 && msgs[0].Direction == "send" && msgs[0].URL != nil {
		summary["scheme"] = msgs[0].URL.Scheme
	}

	return summary
}

// buildGRPCSummary generates summary info for gRPC sessions.
func buildGRPCSummary(msgs []*flow.Flow) map[string]string {
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
func buildTCPSummary(msgs []*flow.Flow) map[string]string {
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
// It delegates to wsOpcodeNameFromInt to avoid duplicate opcode mappings.
func wsOpcodeLabel(opcode string) string {
	n, err := strconv.Atoi(opcode)
	if err != nil {
		return fmt.Sprintf("Unknown(%s)", opcode)
	}
	return wsOpcodeNameFromInt(n)
}

// grpcStatusLabels maps gRPC status code strings to their human-readable labels.
var grpcStatusLabels = map[string]string{
	"0":  "OK",
	"1":  "CANCELLED",
	"2":  "UNKNOWN",
	"3":  "INVALID_ARGUMENT",
	"4":  "DEADLINE_EXCEEDED",
	"5":  "NOT_FOUND",
	"6":  "ALREADY_EXISTS",
	"7":  "PERMISSION_DENIED",
	"8":  "RESOURCE_EXHAUSTED",
	"9":  "FAILED_PRECONDITION",
	"10": "ABORTED",
	"11": "OUT_OF_RANGE",
	"12": "UNIMPLEMENTED",
	"13": "INTERNAL",
	"14": "UNAVAILABLE",
	"15": "DATA_LOSS",
	"16": "UNAUTHENTICATED",
}

// grpcStatusLabel returns a human-readable label for a gRPC status code string.
func grpcStatusLabel(status string) string {
	return grpcStatusLabels[status]
}

// wsOpcodeNameFromInt returns a human-readable label for a WebSocket opcode integer.
func wsOpcodeNameFromInt(opcode int) string {
	switch opcode {
	case 0:
		return "Continuation"
	case 1:
		return "Text"
	case 2:
		return "Binary"
	case 8:
		return "Close"
	case 9:
		return "Ping"
	case 10:
		return "Pong"
	default:
		return fmt.Sprintf("Unknown(%d)", opcode)
	}
}
