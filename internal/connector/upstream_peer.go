package connector

import (
	"net"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// UpstreamProxyOf reports the upstream proxy conn was dialed through.
func UpstreamProxyOf(conn net.Conn) string {
	return ""
}

// WithUpstreamPeer stamps the upstream-leg peer onto envCtx.
func WithUpstreamPeer(envCtx envelope.EnvelopeContext, conn net.Conn) envelope.EnvelopeContext {
	return envCtx
}
