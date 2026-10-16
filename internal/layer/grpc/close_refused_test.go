package grpc

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// closeRecordingChannel is a minimal inner layer.Channel that records which
// teardown entry point the wrapper invoked (USK-1157).
type closeRecordingChannel struct {
	mu                sync.Mutex
	closeCalls        int
	closeRefusedCalls int
	termOnce          sync.Once
	termDone          chan struct{}
}

func newCloseRecordingChannel() *closeRecordingChannel {
	return &closeRecordingChannel{termDone: make(chan struct{})}
}

func (c *closeRecordingChannel) StreamID() string { return "close-recording" }

func (c *closeRecordingChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	select {
	case <-c.termDone:
		return nil, io.EOF
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (c *closeRecordingChannel) Send(context.Context, *envelope.Envelope) error { return nil }

func (c *closeRecordingChannel) Closed() <-chan struct{} { return c.termDone }

func (c *closeRecordingChannel) Err() error {
	select {
	case <-c.termDone:
		return io.EOF
	default:
		return nil
	}
}

func (c *closeRecordingChannel) Close() error {
	c.mu.Lock()
	c.closeCalls++
	c.mu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
	return nil
}

func (c *closeRecordingChannel) counts() (closeCalls, closeRefusedCalls int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCalls, c.closeRefusedCalls
}

// refusedCapableChannel additionally implements CloseRefused, mirroring the
// HTTP/2 stream channel.
type refusedCapableChannel struct {
	*closeRecordingChannel
}

func (c refusedCapableChannel) CloseRefused() error {
	c.mu.Lock()
	c.closeRefusedCalls++
	c.mu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
	return nil
}

func wrapForCloseRefusedTest(inner layer.Channel) layer.Channel {
	return Wrap(inner, nil, RoleServer)
}

// TestGRPCChannel_CloseRefused_ForwardsToInner pins that the wrapper forwards
// CloseRefused to an inner Channel that supports it (the HTTP/2 stream), so
// the session's REFUSED_STREAM decision reaches the wire, and that the
// wrapper's own teardown still runs (USK-1157).
func TestGRPCChannel_CloseRefused_ForwardsToInner(t *testing.T) {
	rec := newCloseRecordingChannel()
	ch := wrapForCloseRefusedTest(refusedCapableChannel{rec})

	rc, ok := ch.(interface{ CloseRefused() error })
	if !ok {
		t.Fatalf("%T does not implement CloseRefused", ch)
	}
	if err := rc.CloseRefused(); err != nil {
		t.Fatalf("CloseRefused: %v", err)
	}
	// The session may still call Close afterwards; it must be a no-op.
	if err := ch.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	closeCalls, refusedCalls := rec.counts()
	if refusedCalls != 1 || closeCalls != 0 {
		t.Errorf("inner calls: CloseRefused=%d Close=%d, want CloseRefused=1 Close=0", refusedCalls, closeCalls)
	}
	select {
	case <-ch.Closed():
	default:
		t.Error("wrapper Closed() not signalled after CloseRefused")
	}
}

// TestGRPCChannel_CloseRefused_FallsBackToClose pins that an inner Channel
// without CloseRefused is torn down with its plain Close.
func TestGRPCChannel_CloseRefused_FallsBackToClose(t *testing.T) {
	rec := newCloseRecordingChannel()
	ch := wrapForCloseRefusedTest(rec)

	rc, ok := ch.(interface{ CloseRefused() error })
	if !ok {
		t.Fatalf("%T does not implement CloseRefused", ch)
	}
	if err := rc.CloseRefused(); err != nil {
		t.Fatalf("CloseRefused: %v", err)
	}
	closeCalls, refusedCalls := rec.counts()
	if closeCalls != 1 || refusedCalls != 0 {
		t.Errorf("inner calls: Close=%d CloseRefused=%d, want Close=1 CloseRefused=0", closeCalls, refusedCalls)
	}
}
