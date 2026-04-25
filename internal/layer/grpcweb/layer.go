package grpcweb

import (
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Role identifies whether the wrapped Channel is server-side (local endpoint
// behaves as the gRPC-Web server, sees inbound requests as Send) or
// client-side (local endpoint behaves as the gRPC-Web client, sees inbound
// responses as Receive).
//
// The constant is local to this package (not cross-imported from
// httpaggregator) because gRPC-Web must remain Channel-type-agnostic per
// Friction 4-C — the wrapper does not depend on the inner Channel's
// concrete Role enum.
type Role uint8

const (
	// RoleServer: local endpoint is the gRPC-Web server.
	// Inbound (Next) HTTPMessage envelopes have Direction=Send (request from
	// client) and Direction=Receive (response from upstream we are mediating
	// or that we will reply to via Send).
	// On Send-side (request) Next path, this Layer emits GRPCStartMessage +
	// 0..N GRPCDataMessage envelopes (no embedded trailer; gRPC-Web requests
	// have none). On Receive-side (response) Send path (i.e., Send called by
	// the caller to reply), this Layer assembles HTTPMessage from the
	// caller's GRPCStart + 0..N GRPCData + GRPCEnd events into an outbound
	// HTTPMessage with an embedded trailer LPM frame.
	RoleServer Role = iota

	// RoleClient: local endpoint is the gRPC-Web client.
	// On Send-side (request) Send path, the caller pushes
	// GRPCStartMessage + 0..N GRPCDataMessage + GRPCEndMessage(Send sentinel)
	// and this Layer assembles a single outbound HTTPMessage (no embedded
	// trailer) and forwards via inner.Send.
	// On Receive-side (response) Next path, this Layer emits GRPCStart + 0..N
	// GRPCData + GRPCEnd envelopes from the inbound HTTPMessage (response
	// body LPMs + embedded trailer LPM).
	RoleClient
)

// String returns a human-readable label.
func (r Role) String() string {
	switch r {
	case RoleServer:
		return "server"
	case RoleClient:
		return "client"
	default:
		return "unknown"
	}
}

// Wrap returns a [layer.Channel] that interprets the inner Channel's
// HTTPMessage envelopes as gRPC-Web traffic. The returned Channel emits
// GRPCStartMessage / GRPCDataMessage / GRPCEndMessage envelopes on Next and
// accepts the same envelope types on Send (the caller is responsible for
// terminating each direction with a GRPCEndMessage — see the package doc for
// the D6 Send-side flush convention).
//
// Wrap is Channel-type-agnostic (Friction 4-C): inner may be an HTTP/1.x
// Channel or an httpaggregator-wrapped HTTP/2 Channel. Wrap does not
// type-assert on the concrete Channel implementation.
//
// Close on the returned Channel cascades to inner.Close (per RFC-001 cascade
// discipline).
func Wrap(inner layer.Channel, role Role) layer.Channel {
	return newChannel(inner, role)
}
