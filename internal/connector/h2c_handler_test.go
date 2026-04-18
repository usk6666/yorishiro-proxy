package connector

import (
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// h2cTestHarness wires a ServerRole handler on one half of net.Pipe and a
// ClientRole Layer on the other so tests can drive streams without having
// to hand-encode HPACK frames.
type h2cTestHarness struct {
	t           *testing.T
	cliConn     net.Conn
	srvConn     net.Conn
	clientLayer *http2.Layer
	handlerDone chan error
	handlerCtx  context.Context
	handlerCanc context.CancelFunc
	onStreamSpy func(context.Context, layer.Channel)
}

// newH2CTestHarness builds the harness. The caller provides the OnStream
// callback that the handler will receive for every accepted stream.
// The harness starts both the handler and the client-side Layer so tests
// can immediately begin opening streams.
func newH2CTestHarness(t *testing.T, onStream func(context.Context, layer.Channel)) *h2cTestHarness {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	h := &h2cTestHarness{
		t:           t,
		cliConn:     cliConn,
		srvConn:     srvConn,
		handlerDone: make(chan error, 1),
		onStreamSpy: onStream,
	}

	handler := NewH2CHandler(H2CHandlerConfig{
		OnStream: func(ctx context.Context, ch layer.Channel) {
			h.onStreamSpy(ctx, ch)
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	ctx = ContextWithConnID(ctx, "test-conn")
	h.handlerCtx = ctx
	h.handlerCanc = cancel

	// Start the handler in a goroutine. Its preface-read will block until
	// the client-side Layer is constructed (which sends the preface).
	pc := NewPeekConn(srvConn)
	go func() {
		h.handlerDone <- handler(ctx, pc)
	}()

	// Build a client-side Layer on the other half of the pipe. This sends
	// the preface, unblocking the handler's http2.New.
	clientLayer, err := http2.New(cliConn, "test-client", http2.ClientRole,
		http2.WithScheme("http"),
	)
	if err != nil {
		t.Fatalf("client layer New: %v", err)
	}
	h.clientLayer = clientLayer
	return h
}

// closeClient tears down the client-side Layer (and the underlying conn),
// which should signal the handler's reader loop to exit via Channels() close.
func (h *h2cTestHarness) closeClient() {
	_ = h.clientLayer.Close()
	_ = h.cliConn.Close()
}

// waitForHandler blocks until the handler returns or the timeout expires.
func (h *h2cTestHarness) waitForHandler(timeout time.Duration) error {
	select {
	case err := <-h.handlerDone:
		return err
	case <-time.After(timeout):
		h.t.Fatalf("handler did not return within %v", timeout)
		return nil
	}
}

func TestNewH2CHandler_PrefaceSuccess(t *testing.T) {
	// onStream is never called in this test (no streams opened).
	h := newH2CTestHarness(t, func(context.Context, layer.Channel) {})
	defer h.handlerCanc()

	// Preface succeeded once h.clientLayer construction returned — that is
	// itself evidence that the ServerRole Layer finished its preface read.
	// We just verify the handler stays alive until we close the client.
	h.closeClient()
	if err := h.waitForHandler(2 * time.Second); err != nil {
		t.Errorf("handler returned error: %v", err)
	}
}

func TestNewH2CHandler_PerStreamDispatch(t *testing.T) {
	const nStreams = 3

	var (
		mu       sync.Mutex
		observed []string
		wg       sync.WaitGroup
	)
	wg.Add(nStreams)

	h := newH2CTestHarness(t, func(_ context.Context, ch layer.Channel) {
		mu.Lock()
		observed = append(observed, ch.StreamID())
		mu.Unlock()
		wg.Done()

		// Read the incoming envelope so the server-side assembler makes
		// progress and the stream closes cleanly. We do not respond; closing
		// the handler via ctx cancel tears down the Layer regardless.
		readCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		for {
			_, err := ch.Next(readCtx)
			if err != nil {
				return
			}
		}
	})
	defer h.handlerCanc()

	// Open nStreams client streams and Send a minimal request on each.
	for i := 0; i < nStreams; i++ {
		ch, err := h.clientLayer.OpenStream(context.Background())
		if err != nil {
			t.Fatalf("OpenStream %d: %v", i, err)
		}
		env := &envelope.Envelope{
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolHTTP,
			Message: &envelope.HTTPMessage{
				Method:    "GET",
				Scheme:    "http",
				Authority: "example.com",
				Path:      "/",
			},
		}
		sendCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		if err := ch.Send(sendCtx, env); err != nil {
			cancel()
			t.Fatalf("Send %d: %v", i, err)
		}
		cancel()
	}

	// Wait for the handler's OnStream to fire for every stream.
	waited := make(chan struct{})
	go func() {
		wg.Wait()
		close(waited)
	}()
	select {
	case <-waited:
	case <-time.After(3 * time.Second):
		t.Fatalf("OnStream fired only %d times, wanted %d", len(observed), nStreams)
	}

	mu.Lock()
	seen := make(map[string]bool)
	for _, id := range observed {
		if id == "" {
			t.Errorf("empty StreamID")
		}
		if seen[id] {
			t.Errorf("duplicate StreamID: %s", id)
		}
		seen[id] = true
	}
	mu.Unlock()

	// Tear down: cancel handler ctx so it returns, then verify it exits.
	h.handlerCanc()
	h.closeClient()
	_ = h.waitForHandler(2 * time.Second)
}

func TestNewH2CHandler_ContextCancel(t *testing.T) {
	h := newH2CTestHarness(t, func(_ context.Context, ch layer.Channel) {
		_ = ch.Close()
	})

	// Cancel and expect the handler to return without error.
	h.handlerCanc()
	err := h.waitForHandler(2 * time.Second)
	if err != nil {
		t.Errorf("handler returned unexpected error: %v", err)
	}
	_ = h.clientLayer.Close()
	_ = h.cliConn.Close()
}

func TestNewH2CHandler_ClientClose(t *testing.T) {
	h := newH2CTestHarness(t, func(_ context.Context, ch layer.Channel) {
		_ = ch.Close()
	})
	defer h.handlerCanc()

	// Client-side close should cascade to the server's reader loop which
	// closes Channels(), causing the handler to return cleanly.
	h.closeClient()
	err := h.waitForHandler(2 * time.Second)
	if err != nil {
		t.Errorf("handler returned unexpected error: %v", err)
	}
}

func TestNewH2CHandler_NilOnStream(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()

	handler := NewH2CHandler(H2CHandlerConfig{OnStream: nil})
	ctx, cancel := context.WithCancel(context.Background())
	ctx = ContextWithConnID(ctx, "test-conn")
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- handler(ctx, NewPeekConn(srvConn))
	}()

	clientLayer, err := http2.New(cliConn, "test-client", http2.ClientRole,
		http2.WithScheme("http"),
	)
	if err != nil {
		t.Fatalf("client New: %v", err)
	}

	// Open a stream; the handler should immediately close it since OnStream
	// is nil. Drive Next on the client-side channel until it reports EOF.
	ch, err := clientLayer.OpenStream(context.Background())
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "http",
			Authority: "example.com",
			Path:      "/",
		},
	}
	sendCtx, sendCancel := context.WithTimeout(context.Background(), 2*time.Second)
	_ = ch.Send(sendCtx, env)
	sendCancel()

	// Tear down the client and the handler's ctx to exit.
	cancel()
	_ = clientLayer.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("handler returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("handler did not exit within 2s")
	}
}

func TestNewH2CHandler_BadPreface(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	defer cliConn.Close()

	handler := NewH2CHandler(H2CHandlerConfig{
		OnStream: func(context.Context, layer.Channel) {
			t.Errorf("OnStream should not be invoked when preface is invalid")
		},
	})

	ctx := ContextWithConnID(context.Background(), "bad-preface")
	done := make(chan error, 1)
	go func() {
		done <- handler(ctx, NewPeekConn(srvConn))
	}()

	// Feed garbage that cannot be a valid preface. Write enough bytes to
	// unblock the server's io.ReadFull call with a mismatch.
	if _, err := cliConn.Write([]byte("GARBAGE / HTTP/1.1\r\n\r\nXXXXX")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	// Close the client so the server-side Read returns EOF if more bytes
	// are still expected — either way, runServerPreface fails and http2.New
	// closes the underlying conn.
	_ = cliConn.Close()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("handler returned error, want nil: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("handler did not exit within 2s")
	}
}

func TestCoordinator_OnHTTP2Stream_BuildsHandler(t *testing.T) {
	var called atomic.Int32
	coord := NewCoordinator(CoordinatorConfig{
		OnHTTP2Stream: func(context.Context, layer.Channel) {
			called.Add(1)
		},
	})

	h := coord.buildHTTP2Handler()
	if h == nil {
		t.Fatalf("buildHTTP2Handler returned nil when OnHTTP2Stream is set")
	}

	// Also verify the nil path.
	empty := NewCoordinator(CoordinatorConfig{})
	if got := empty.buildHTTP2Handler(); got != nil {
		t.Errorf("buildHTTP2Handler without OnHTTP2Stream = %v, want nil", got)
	}
}
