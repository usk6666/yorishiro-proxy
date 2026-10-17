package session

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// USK-1164: the ws/sse-over-h2 upgrade must DetachStream on the Layer that
// owns the stream. After a GOAWAY redial the streams of one CONNECT live on
// different upstream connections whose stream ids restart at 1, so the
// owning Layer has to come from the Channel that carries the stream — the
// stack's pooled Layer is the wrong connection for any redialed stream.

// newDrainedClientH2Layer builds a real ClientRole *http2.Layer over a
// net.Pipe whose peer end discards everything the Layer writes (preface,
// SETTINGS, HEADERS). Same construction as proxybuild's dialPeerH2Layer.
func newDrainedClientH2Layer(t *testing.T, name string) *http2.Layer {
	t.Helper()
	cliConn, srvConn := net.Pipe()
	go func() { _, _ = io.Copy(io.Discard, srvConn) }()
	l, err := http2.New(cliConn, name, http2.ClientRole)
	if err != nil {
		t.Fatalf("http2.New(%s): %v", name, err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = srvConn.Close()
	})
	return l
}

// openAggregatedRequestStream opens a stream on l, wraps it the way the
// live h2 path wraps upstream streams (httpaggregator), and sends a GET so
// HEADERS allocates the wire stream id (allocated lazily, USK-740).
func openAggregatedRequestStream(t *testing.T, l *http2.Layer) (raw, agg layer.Channel) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := l.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	agg = httpaggregator.WrapWithDefaults(raw, httpaggregator.RoleClient, nil)
	req := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "https",
			Authority: "example.test",
			Path:      "/events",
		},
	}
	if err := agg.Send(ctx, req); err != nil {
		t.Fatalf("aggregator Send: %v", err)
	}
	return raw, agg
}

func TestH2StreamOwner_ReturnsLayerCarryingTheChannel(t *testing.T) {
	// pooled plays chain[0] (stack.UpstreamH2Layer()), redialed plays
	// chain[1]. Both allocate stream id 1 for their first stream — the
	// exact collision a GOAWAY redial produces inside one CONNECT.
	pooled := newDrainedClientH2Layer(t, "chain0-pooled")
	redialed := newDrainedClientH2Layer(t, "chain1-redialed")

	pooledRaw, pooledAgg := openAggregatedRequestStream(t, pooled)
	redialedRaw, redialedAgg := openAggregatedRequestStream(t, redialed)

	tests := []struct {
		name      string
		ch        layer.Channel
		wantLayer *http2.Layer
	}{
		{"aggregator on redialed layer", redialedAgg, redialed},
		{"raw channel on redialed layer", redialedRaw, redialed},
		{"aggregator on pooled layer", pooledAgg, pooled},
		{"raw channel on pooled layer", pooledRaw, pooled},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, id, err := h2StreamOwner(tt.ch, "upstream")
			if err != nil {
				t.Fatalf("h2StreamOwner: unexpected error: %v", err)
			}
			if got != tt.wantLayer {
				t.Errorf("h2StreamOwner layer = %p, want %p (the Layer that carries the Channel)", got, tt.wantLayer)
			}
			if id != 1 {
				t.Errorf("h2StreamOwner id = %d, want 1", id)
			}
		})
	}
}

// ownerStubChannel is a minimal layer.Channel exposing neither
// H2StreamID nor H2Layer; the variants below embed it.
type ownerStubChannel struct{}

func (ownerStubChannel) StreamID() string                                   { return "owner-stub" }
func (ownerStubChannel) Next(_ context.Context) (*envelope.Envelope, error) { return nil, io.EOF }
func (ownerStubChannel) Send(_ context.Context, _ *envelope.Envelope) error { return nil }
func (ownerStubChannel) Close() error                                       { return nil }
func (ownerStubChannel) Closed() <-chan struct{}                            { return nil }
func (ownerStubChannel) Err() error                                         { return nil }

// idOnlyChannel exposes H2StreamID but no owning Layer.
type idOnlyChannel struct{ ownerStubChannel }

func (idOnlyChannel) H2StreamID() uint32 { return 1 }

// nilLayerChannel exposes both surfaces but reports no owning Layer.
type nilLayerChannel struct{ ownerStubChannel }

func (nilLayerChannel) H2StreamID() uint32    { return 1 }
func (nilLayerChannel) H2Layer() *http2.Layer { return nil }

// layerNoIDChannel reports an owning Layer but no stream id yet.
type layerNoIDChannel struct {
	ownerStubChannel
	l *http2.Layer
}

func (layerNoIDChannel) H2StreamID() uint32      { return 0 }
func (c layerNoIDChannel) H2Layer() *http2.Layer { return c.l }

func TestH2StreamOwner_ErrorsWithoutOwningLayer(t *testing.T) {
	someLayer := &http2.Layer{} // pointer identity only; never invoked
	tests := []struct {
		name    string
		ch      layer.Channel
		wantSub string
	}{
		{"nil channel", nil, "nil"},
		{"channel exposes only H2StreamID", idOnlyChannel{}, "H2Layer"},
		{"channel reports nil H2Layer", nilLayerChannel{}, "H2Layer"},
		{"channel reports stream id 0", layerNoIDChannel{l: someLayer}, "stream id 0"},
		{"channel exposes neither", ownerStubChannel{}, "H2"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, id, err := h2StreamOwner(tt.ch, "upstream")
			if err == nil {
				t.Fatalf("h2StreamOwner = (%p, %d, nil), want an error (no silent fallback to the stack's pooled Layer)", got, id)
			}
			if got != nil || id != 0 {
				t.Errorf("h2StreamOwner returned (%p, %d) alongside error, want (nil, 0)", got, id)
			}
			if !strings.Contains(err.Error(), tt.wantSub) || !strings.Contains(err.Error(), "upstream") {
				t.Errorf("error %q should mention %q and the side", err.Error(), tt.wantSub)
			}
		})
	}
}
