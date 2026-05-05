package http2

import (
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// IsPushChannel reports whether ch is a server-pushed stream (i.e., a channel
// created from a PUSH_PROMISE received on an HTTP/2 ClientRole Layer).
//
// The push distinction is a protocol-specific detail and intentionally does
// NOT appear on the generic layer.Channel interface; callers that need to
// treat push streams specially (e.g., the upstream push recorder in
// internal/connector) use this type-asserting helper instead.
//
// Non-*channel inputs return false.
func IsPushChannel(ch layer.Channel) bool {
	c, ok := ch.(*channel)
	if !ok {
		return false
	}
	return c.isPush
}

// PushOriginChannelStreamID returns the UUID StreamID of the channel that
// carried the PUSH_PROMISE that created ch, or ("", false) when ch is not a
// push channel (or is not a channel produced by this package).
//
// The returned identifier is the origin channel's layer.Channel.StreamID(),
// not the HTTP/2 wire stream id. It is stable across the push channel's
// lifetime and is intended to be written to flow.Stream.Tags and
// flow.Flow.Metadata so analysts can correlate pushed content back to its
// originating request.
func PushOriginChannelStreamID(ch layer.Channel) (string, bool) {
	c, ok := ch.(*channel)
	if !ok || !c.isPush {
		return "", false
	}
	return c.originStreamID, true
}
