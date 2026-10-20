package grpc

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// RawWinsSupported reports whether this Layer's Send can write a plugin's
// msg["raw"] on env verbatim (RFC-001 §9.3 D4 "Raw wins"). The Pipeline
// consults it through the route's WireEncoderRegistry before RecordStep,
// so a refused raw write never becomes a recorded modified variant that
// the wire did not carry.
//
//   - GRPCStartMessage / GRPCEndMessage → false. Their Raw is the HPACK
//     header-block fragment observed on the source connection: unframed
//     and encoded against that connection's dynamic table, so it cannot
//     be written to another (pooled) connection. Send always rebuilds the
//     HEADERS from the struct fields. End never reaches a plugin hook
//     today ((grpc, on_end) is lifecycle-only); it is listed as defence
//     in depth. The decision does not depend on End's Raw being set.
//   - GRPCDataMessage → true. Its Raw is the LPM-framed DATA payload,
//     which sendData writes verbatim; the Layer still owns DATA framing,
//     stream ids and flow control.
//
// A nil env (or nil Message) has nothing to refuse and reports true.
func RawWinsSupported(env *envelope.Envelope) bool {
	if env == nil {
		return true
	}
	switch env.Message.(type) {
	case *envelope.GRPCStartMessage, *envelope.GRPCEndMessage:
		return false
	default:
		return true
	}
}

// warnRawWinsIgnored is the Layer backstop for a raw-authoritative
// envelope that reached Send although RawWinsSupported refuses it (a
// WireEncoderRegistry without the gRPC policy). Send takes the Message
// path regardless; the Warn flags that the recorded variant may differ
// from the wire.
func warnRawWinsIgnored(ctx context.Context, env *envelope.Envelope) {
	if !env.RawWins() || RawWinsSupported(env) {
		return
	}
	slog.WarnContext(ctx, "grpc: raw-authoritative envelope cannot be written verbatim; sending the Message instead (recorded variant may differ from the wire)",
		slog.String("stream_id", env.StreamID),
		slog.String("message_type", fmt.Sprintf("%T", env.Message)),
	)
}
