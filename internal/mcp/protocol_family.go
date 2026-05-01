package mcp

// This file is the single source of truth for the MCP query tool's
// "Message-type family" mapping. During the RFC-001 parallel-coexistence
// window the flow store contains a mix of:
//
//   - new pipeline strings written by RecordStep as `string(env.Protocol)`:
//     "http", "ws", "grpc", "grpc-web", "sse", "raw", "tls-handshake".
//   - legacy strings written by internal/protocol/* handlers:
//     "HTTP/1.x", "HTTPS", "HTTP/2", "WebSocket", "gRPC", "gRPC-Web", "TCP"
//     and their "SOCKS5+<base>" variants.
//
// The query tool exposes the seven new lowercase values as *family aliases*
// that expand into the union of new + legacy spellings sharing the same
// envelope.Message type. Legacy values stay literal exact-match for
// callers that intentionally distinguish (e.g. only HTTPS, not HTTP/2).
//
// TODO(N9): when internal/protocol/, internal/proxy/, and the legacy
// recording paths are deleted, remove the legacy entries from the
// expansion table below and from filterProtocolEnumValues so the query
// tool only accepts the canonical Envelope.Protocol values.

// protocolFamilyAliases maps a canonical Envelope.Protocol value (the
// lowercase Message-type family name) to the literal Stream.Protocol
// strings that flows in that family may have been recorded as.
var protocolFamilyAliases = map[string][]string{
	"http": {
		"http",
		"HTTP/1.x", "HTTPS", "HTTP/2",
		"SOCKS5+HTTP/1.x", "SOCKS5+HTTPS", "SOCKS5+HTTP/2",
	},
	"ws":            {"ws", "WebSocket", "SOCKS5+WebSocket"},
	"grpc":          {"grpc", "gRPC", "SOCKS5+gRPC"},
	"grpc-web":      {"grpc-web", "gRPC-Web", "SOCKS5+gRPC-Web"},
	"sse":           {"sse"},
	"raw":           {"raw", "TCP", "SOCKS5+TCP"},
	"tls-handshake": {"tls-handshake"},
}

// protocolCanonical is the inverse of protocolFamilyAliases. Built once at
// package init for O(1) reverse lookup.
var protocolCanonical = func() map[string]string {
	out := make(map[string]string, 32)
	for canon, aliases := range protocolFamilyAliases {
		for _, a := range aliases {
			out[a] = canon
		}
	}
	return out
}()

// canonicalProtocol returns the canonical Envelope.Protocol family name
// for any recorded Stream.Protocol literal (new or legacy spelling), or
// "" if the literal is not known. Used by buildProtocolSummary so the
// summary dispatcher can handle both spellings via the same branch.
func canonicalProtocol(p string) string {
	return protocolCanonical[p]
}

// expandProtocolFilter returns the set of literal Stream.Protocol values
// that match a user-provided filter.protocol value. New canonical names
// (e.g. "http") expand into all known family literals; legacy names stay
// strict (single-element slice equal to the input). Unknown values
// return nil and are rejected upstream by validateEnum.
func expandProtocolFilter(p string) []string {
	if aliases, ok := protocolFamilyAliases[p]; ok {
		return aliases
	}
	if _, isLegacy := protocolCanonical[p]; isLegacy {
		return []string{p}
	}
	return nil
}

// filterProtocolFamilyValues lists the canonical (new) filter.protocol
// values. Listed first in jsonschema enum descriptions so the AI agent
// sees the preferred spelling.
var filterProtocolFamilyValues = []string{
	"http", "ws", "grpc", "grpc-web", "sse", "raw", "tls-handshake",
}

// filterProtocolLegacyValues lists the legacy filter.protocol values
// retained for parallel coexistence until N9.
//
// TODO(N9): delete this slice and its inclusion in filterProtocolEnumValues.
var filterProtocolLegacyValues = []string{
	"HTTP/1.x", "HTTPS", "HTTP/2",
	"WebSocket",
	"gRPC", "gRPC-Web",
	"TCP",
	"SOCKS5+HTTP/1.x", "SOCKS5+HTTPS", "SOCKS5+HTTP/2",
	"SOCKS5+WebSocket",
	"SOCKS5+gRPC", "SOCKS5+gRPC-Web",
	"SOCKS5+TCP",
}
