package grpcweb

import (
	"context"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// closeRecordingChannel is a minimal inner layer.Channel that records which
// teardown entry point the wrapper invoked (USK-1157, USK-1269).
type closeRecordingChannel struct {
	mu         sync.Mutex
	closeCalls int
	codes      []uint32
	termOnce   sync.Once
	termDone   chan struct{}
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

func (c *closeRecordingChannel) calls() (closeCalls int, codes []uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closeCalls, append([]uint32(nil), c.codes...)
}

// codeCapableChannel additionally implements CloseWithCode, mirroring the
// HTTP/2 stream channel.
type codeCapableChannel struct {
	*closeRecordingChannel
}

func (c codeCapableChannel) CloseWithCode(code uint32) error {
	c.mu.Lock()
	c.codes = append(c.codes, code)
	c.mu.Unlock()
	c.termOnce.Do(func() { close(c.termDone) })
	return nil
}

type codeCloser interface {
	CloseWithCode(code uint32) error
}

func wrapForCloseWithCodeTest(inner layer.Channel) layer.Channel {
	return Wrap(inner, RoleServer)
}

// TestGRPCWebChannel_CloseWithCode_ForwardsToInner pins that the wrapper
// forwards CloseWithCode — with the code unchanged — to an inner Channel that
// supports it (the HTTP/2 stream), so the session's relay of the upstream
// RST_STREAM code (or its REFUSED_STREAM decision) reaches the wire, and that
// the wrapper's own teardown still runs (USK-1157, USK-1269).
func TestGRPCWebChannel_CloseWithCode_ForwardsToInner(t *testing.T) {
	for _, code := range []uint32{0x2, 0x7, 0xb, 0xff} {
		rec := newCloseRecordingChannel()
		ch := wrapForCloseWithCodeTest(codeCapableChannel{rec})

		cc, ok := ch.(codeCloser)
		if !ok {
			t.Fatalf("%T does not implement CloseWithCode", ch)
		}
		if err := cc.CloseWithCode(code); err != nil {
			t.Fatalf("CloseWithCode(%#x): %v", code, err)
		}
		// The session may still call Close afterwards; it must be a no-op.
		if err := ch.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}

		closeCalls, codes := rec.calls()
		if len(codes) != 1 || codes[0] != code || closeCalls != 0 {
			t.Errorf("inner calls: CloseWithCode=%v Close=%d, want CloseWithCode=[%#x] Close=0", codes, closeCalls, code)
		}
		select {
		case <-ch.Closed():
		default:
			t.Errorf("wrapper Closed() not signalled after CloseWithCode(%#x)", code)
		}
	}
}

// TestGRPCWebChannel_CloseWithCode_FallsBackToClose pins that an inner Channel
// without CloseWithCode is torn down with its plain Close.
func TestGRPCWebChannel_CloseWithCode_FallsBackToClose(t *testing.T) {
	rec := newCloseRecordingChannel()
	ch := wrapForCloseWithCodeTest(rec)

	cc, ok := ch.(codeCloser)
	if !ok {
		t.Fatalf("%T does not implement CloseWithCode", ch)
	}
	if err := cc.CloseWithCode(0x2); err != nil {
		t.Fatalf("CloseWithCode: %v", err)
	}
	closeCalls, codes := rec.calls()
	if closeCalls != 1 || len(codes) != 0 {
		t.Errorf("inner calls: Close=%d CloseWithCode=%v, want Close=1 CloseWithCode=[]", closeCalls, codes)
	}
}
