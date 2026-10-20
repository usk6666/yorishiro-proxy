package httpaggregator

import (
	"context"
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// RawWinsSupported reports whether this Layer's Send can write a plugin's
// msg["raw"] on env verbatim (RFC-001 §9.3 D4 "Raw wins"). It is false
// for every HTTPMessage: an h2 HTTPMessage's Raw is the concatenation of
// HPACK header-block fragment(s), DATA payloads and the trailer block —
// no frame headers, HPACK-encoded against the source connection's dynamic
// table. Writing it to another (pooled) connection would desync HPACK
// state, stream ids and flow control, so it is a read-only diagnostic
// view and Send always rebuilds HEADERS/DATA from the Message.
//
// The h2 route's WireEncoderRegistry registers this predicate for
// envelope.ProtocolHTTP; the h1 route does not (HTTP/1.x writes Raw
// verbatim). A nil env has nothing to refuse and reports true.
func RawWinsSupported(env *envelope.Envelope) bool {
	if env == nil {
		return true
	}
	_, isHTTP := env.Message.(*envelope.HTTPMessage)
	return !isHTTP
}

// warnRawWinsIgnored is the Layer backstop for a raw-authoritative
// envelope that reached Send although the h2 policy refuses it (a
// WireEncoderRegistry without the policy). Send takes the Message path
// regardless; the Warn flags that the recorded variant may differ from
// the wire.
func warnRawWinsIgnored(ctx context.Context, env *envelope.Envelope) {
	if !env.RawWins() {
		return
	}
	slog.WarnContext(ctx, "httpaggregator: raw-authoritative envelope cannot be written verbatim on HTTP/2; sending the Message instead (recorded variant may differ from the wire)",
		slog.String("stream_id", env.StreamID),
		slog.String("direction", env.Direction.String()),
	)
}
