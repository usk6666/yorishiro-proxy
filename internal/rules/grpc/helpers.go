package grpc

import (
	"context"
	"net"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// metadataGet returns the value of the first metadata entry whose name
// matches the given name case-insensitively. Returns "" when not found.
//
// gRPC metadata is conveyed via HTTP/2 headers, which RFC 9113 §8.2.2
// requires to be lowercase on the wire. The proxy preserves whatever
// casing it observed (a non-conforming peer may have sent mixed case),
// and matches case-insensitively to keep behavior consistent with the
// HTTP/1.x rules helpers.
func metadataGet(metadata []envelope.KeyValue, name string) string {
	for _, kv := range metadata {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value
		}
	}
	return ""
}

// metadataDel removes ALL metadata entries whose name matches the given
// name case-insensitively. Mirrors rules/http.headerDel. Returns the
// trimmed slice (in-place rewrite).
func metadataDel(metadata []envelope.KeyValue, name string) []envelope.KeyValue {
	n := 0
	for _, kv := range metadata {
		if !strings.EqualFold(kv.Name, name) {
			metadata[n] = kv
			n++
		}
	}
	for i := n; i < len(metadata); i++ {
		metadata[i] = envelope.KeyValue{}
	}
	return metadata[:n]
}

// metadataAdd appends a metadata entry preserving the supplied casing.
func metadataAdd(metadata []envelope.KeyValue, name, value string) []envelope.KeyValue {
	return append(metadata, envelope.KeyValue{Name: name, Value: value})
}

// materializePayload returns the payload bytes for a GRPCDataMessage.
//
// gRPC payloads are always carried in-memory on GRPCDataMessage.Payload
// (the LPM has been reassembled from HTTP/2 DATA events). This helper
// exists so the SafetyEngine and TransformEngine paths read a single
// helper for body-like data and so the API stays symmetric with the
// HTTP rules helpers, which thread context.Context through
// BodyBuffer.Bytes(ctx). For gRPC the ctx is currently a no-op but is
// kept in the signature for symmetry and future evolution.
func materializePayload(_ context.Context, msg *envelope.GRPCDataMessage) []byte {
	if msg == nil {
		return nil
	}
	return msg.Payload
}

// containsCRLF returns true when s contains CR or LF. Used to reject
// metadata mutations that would inject framing bytes (CWE-113).
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// extractHostname strips a port suffix from a host:port string. Returns
// the input unchanged when no port is present (also handles raw IPv6
// addresses).
func extractHostname(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport
	}
	return host
}

// convertDirection maps envelope.Direction values onto the package-local
// RuleDirection enum. Used at match time to compare against
// InterceptRule.Direction / TransformRule.Direction.
func convertDirection(d envelope.Direction) RuleDirection {
	switch d {
	case envelope.Send:
		return DirectionSend
	case envelope.Receive:
		return DirectionReceive
	default:
		return ""
	}
}

// directionAllowed returns true when an envelope direction d satisfies a
// rule direction r. DirectionBoth always matches. An empty rule
// direction is treated as "both" so callers may leave Direction zeroed
// when they don't care.
func directionAllowed(r RuleDirection, d envelope.Direction) bool {
	if r == "" || r == DirectionBoth {
		return true
	}
	return r == convertDirection(d)
}
