package grpc

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// Role identifies whether the wrapped Channel is server-side (the local
// endpoint behaves as the gRPC server) or client-side (the local endpoint
// behaves as the gRPC client). Mirrors the convention used by
// internal/layer/http2 and internal/layer/httpaggregator: in RoleServer,
// request HEADERS arrive on the inner Channel with Direction=Send, and the
// response HEADERS / DATA / TRAILERS travel back with Direction=Receive.
//
// The Layer does not need Role for translation — gRPC events keep the
// inner envelope's Direction unchanged — but the Role is recorded on the
// wrapper for symmetry with sibling Layers and for future extensions
// (e.g., per-direction metadata caches).
type Role uint8

const (
	// RoleServer: the local endpoint is the gRPC server. Request envelopes
	// arrive with Direction=Send; response envelopes are sent back with
	// Direction=Receive.
	RoleServer Role = iota
	// RoleClient: the local endpoint is the gRPC client. Response envelopes
	// arrive with Direction=Receive; request envelopes are sent with
	// Direction=Send.
	RoleClient
)

// Wrap consumes a single event-granular HTTP/2 stream Channel and returns
// a Channel that yields per-RPC-event gRPC envelopes (GRPCStartMessage /
// GRPCDataMessage / GRPCEndMessage).
//
// firstHeaders is the pre-peeked H2HeadersEvent envelope obtained by the
// connector when detecting the application/grpc content-type. Per RFC-001
// §3.3.2 / Friction 4-A, the wrapper queues it as if it had been the next
// envelope read from inner.Next() — i.e., it becomes the source of the
// first emitted GRPCStartMessage envelope.
//
// As a special case (D5), if firstHeaders is nil or has empty Raw bytes
// the wrapper treats it as a synthetic startup signal and discards it;
// the first Next call then reads a real envelope from inner. This shape
// is used by the upstream-side dispatcher in N7 U2 where the upstream
// connection is established before any wire bytes are exchanged.
//
// role records the direction convention of the wrapped channel; see Role.
//
// Close on the returned Channel cascades to inner.Close (per N6.7
// cascade discipline); idempotent via sync.Once.
func Wrap(stream layer.Channel, firstHeaders *envelope.Envelope, role Role) layer.Channel {
	gc := &grpcChannel{
		inner:    stream,
		role:     role,
		streamID: stream.StreamID(),
		recvDone: make(chan struct{}),
	}
	// Apply D5: only replay firstHeaders when it carries real wire bytes.
	if firstHeaders != nil && len(firstHeaders.Raw) > 0 {
		gc.peeked = firstHeaders
	}
	return gc
}
