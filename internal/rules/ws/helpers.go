package ws

import (
	"net"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// containsCRLF reports whether s contains a CR or LF character. Reused by
// any future header-style action; currently unused by the WS rule actions
// but kept for parity with rules/http and to provide a clean injection
// guard if/when WS actions grow header-like surfaces.
func containsCRLF(s string) bool {
	return strings.ContainsAny(s, "\r\n")
}

// extractHostname strips an optional :port suffix from a host:port string.
// IPv6 literals (e.g. "[::1]:8080") are decoded to "::1".
func extractHostname(hostport string) string {
	host, _, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport // no port, return as-is
	}
	return host
}

// convertDirection translates an envelope.Direction (numeric send/receive
// index) into the package-local RuleDirection string used in rule configs.
// envelope.Direction does not have a "both" value — that is a rules-domain
// concept that lives only in RuleDirection.
func convertDirection(d envelope.Direction) RuleDirection {
	switch d {
	case envelope.Send:
		return DirectionSend
	case envelope.Receive:
		return DirectionReceive
	default:
		// Unknown directions are treated as Send by convention; no current
		// production path produces a non-Send/non-Receive direction.
		return DirectionSend
	}
}
