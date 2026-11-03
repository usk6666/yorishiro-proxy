package connector

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// queueChannel is a layer.Channel that yields queued event envelopes, then
// io.EOF.
type queueChannel struct {
	mu     sync.Mutex
	q      []*envelope.Envelope
	closed chan struct{}
	once   sync.Once
}

func newQueueChannel(evs ...*envelope.Envelope) *queueChannel {
	return &queueChannel{q: evs, closed: make(chan struct{})}
}

func (c *queueChannel) StreamID() string { return "queue" }
func (c *queueChannel) Next(context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.q) == 0 {
		return nil, io.EOF
	}
	ev := c.q[0]
	c.q = c.q[1:]
	return ev, nil
}
func (c *queueChannel) Send(context.Context, *envelope.Envelope) error { return nil }
func (c *queueChannel) Close() error {
	c.once.Do(func() { close(c.closed) })
	return nil
}
func (c *queueChannel) Closed() <-chan struct{} { return c.closed }
func (c *queueChannel) Err() error              { return nil }

// TestDispatchH2_GRPCWebBranchesNeverStream (USK-1401 R5 / T11): the
// gRPC-Web Layer reassembles whole bodies, so the aggregator under it must
// never consult the body-mode predicate — on the client-side dispatch and on
// the upstream wrap chosen by the request protocol, whatever the response
// content-type.
func TestDispatchH2_GRPCWebBranchesNeverStream(t *testing.T) {
	var calls atomic.Int32
	lopts := httpaggregator.WrapOptions{BodyMode: func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
		calls.Add(1)
		return layer.Stream()
	}}
	lpm := []byte{0, 0, 0, 0, 0}

	t.Run("client_dispatch", func(t *testing.T) {
		calls.Store(0)
		hdr := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: &http2.H2HeadersEvent{
			Method: "POST", Scheme: "https", Authority: "g.test", Path: "/svc/M",
			Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc-web+proto"}},
		}}
		data := &envelope.Envelope{Direction: envelope.Send, Protocol: envelope.ProtocolHTTP, Message: &http2.H2DataEvent{Payload: lpm, EndStream: true}}
		ch, err := DispatchH2StreamFull(context.Background(), newQueueChannel(hdr, data), httpaggregator.RoleServer,
			lopts, slog.Default(), nil, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = ch.Next(ctx)
		if n := calls.Load(); n != 0 {
			t.Errorf("body-mode predicate consulted %d times under the gRPC-Web Layer, want 0", n)
		}
	})
	t.Run("upstream_wrap", func(t *testing.T) {
		calls.Store(0)
		hdr := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP, Message: &http2.H2HeadersEvent{
			Status: 200, Headers: []envelope.KeyValue{{Name: "content-type", Value: "text/html"}},
		}}
		data := &envelope.Envelope{Direction: envelope.Receive, Protocol: envelope.ProtocolHTTP, Message: &http2.H2DataEvent{Payload: []byte("<html>"), EndStream: true}}
		ch := WrapH2UpstreamForDispatchFull(newQueueChannel(hdr, data), envelope.ProtocolGRPCWeb, lopts, nil, nil, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_, _ = ch.Next(ctx)
		if n := calls.Load(); n != 0 {
			t.Errorf("body-mode predicate consulted %d times under the gRPC-Web Layer, want 0", n)
		}
	})
}
