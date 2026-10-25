package http2

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// TestLayer_MultiplexedStreamsShareConnID pins the premise behind the
// WebUI's "Flows on this connection" navigation: every h2 stream the
// server-role Layer yields for one client connection carries the
// connection's ConnID on its envelopes, so RecordStep stamps the same
// Stream.ConnID on each of them and query filter.conn_id groups them.
func TestLayer_MultiplexedStreamsShareConnID(t *testing.T) {
	const connID = "conn-multiplexed"
	l, peer, cleanup := startServerLayer(t, WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID}))
	defer cleanup()
	peer.consumePeerSettings(t)
	peer.sendInitialSettings(t)

	for _, streamID := range []uint32{1, 3} {
		encoded := peer.encoder.Encode([]hpack.HeaderField{
			{Name: ":method", Value: "GET"},
			{Name: ":scheme", Value: "https"},
			{Name: ":path", Value: "/conn-id"},
			{Name: ":authority", Value: "example.test"},
		})
		if err := peer.wr.WriteHeaders(streamID, true, true, encoded); err != nil {
			t.Fatalf("stream %d: peer.WriteHeaders: %v", streamID, err)
		}

		var ch layer.Channel
		select {
		case ch = <-l.Channels():
		case <-time.After(time.Second):
			t.Fatalf("stream %d: did not receive Channel within 1s", streamID)
		}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		env, err := ch.Next(ctx)
		cancel()
		if err != nil {
			t.Fatalf("stream %d: Channel.Next: %v", streamID, err)
		}
		if env.Context.ConnID != connID {
			t.Errorf("stream %d: Context.ConnID = %q, want %q", streamID, env.Context.ConnID, connID)
		}
	}
}
