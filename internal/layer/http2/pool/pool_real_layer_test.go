package pool

import (
	"context"
	"errors"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	http2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestPool_RealLayer_ShutdownEvict_AfterUpstreamCleanEOF is the USK-796
// regression test wiring a real *http2.Layer into the Pool. It exercises
// the precise failure mode reported in the issue:
//
//  1. A client-role *http2.Layer is dialed against a peer (via net.Pipe).
//  2. The peer end is closed cleanly — the Layer's reader observes io.EOF
//     and runs handleReadError, which closes the shutdown channel without
//     setting lastErr and without exchanging GOAWAY.
//  3. Before USK-796, neither LastReaderError() nor GoAwayClosed() flagged
//     the dead Layer, so selectLocked retained it. The pool fast-path
//     then returned this Layer to the next CONNECT and OpenStream
//     immediately failed with *layer.StreamError{Reason: "layer shutdown"}.
//  4. After USK-796, IsShutdown() returns true; selectLocked evicts the
//     entry; GetOrDial dials a fresh Layer.
//
// This test runs in the fast (untagged) tier because it uses net.Pipe and
// completes in well under a second. Wiring a real upstream + MITM proxy
// would not exercise additional behavior beyond what the pool unit test
// (TestLivenessProbe_Shutdown_GetOrDialDialsFresh) and the layer unit test
// (TestLayer_IsShutdown_TrueAfterUpstreamEOF) already cover; this test is
// the integration glue that proves the two halves compose correctly.
func TestPool_RealLayer_ShutdownEvict_AfterUpstreamCleanEOF(t *testing.T) {
	cliConn, srvConn := net.Pipe()

	// Read the client preface on the peer side concurrently so New() can
	// proceed (matching the layer_test.go startClientLayer harness pattern).
	prefaceDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(http2.ClientPreface))
		if _, err := io.ReadFull(srvConn, buf); err != nil {
			prefaceDone <- err
			return
		}
		if string(buf) != http2.ClientPreface {
			prefaceDone <- errors.New("preface mismatch")
			return
		}
		prefaceDone <- nil
	}()

	deadLayer, err := http2.New(cliConn, "test-shutdown-evict", http2.ClientRole)
	if err != nil {
		t.Fatalf("New(client): %v", err)
	}
	if perr := <-prefaceDone; perr != nil {
		t.Fatalf("preface read: %v", perr)
	}

	// Sanity: before any teardown signal, IsShutdown() is false.
	if deadLayer.IsShutdown() {
		t.Fatalf("IsShutdown() before EOF = true, want false")
	}

	p := New(PoolOptions{})
	defer p.Close()
	key := PoolKey{HostPort: "127.0.0.1:443", TLSConfigHash: "test"}
	p.putLayer(key, deadLayer)

	// Simulate clean upstream FIN: close the peer end of the pipe. The
	// Layer's reader observes io.EOF and runs handleReadError, which
	// closes l.shutdown via shutdownOnce.Do without setting lastErr.
	_ = srvConn.Close()

	// Wait for IsShutdown() to flip — the reader goroutine drives this
	// asynchronously. 2s is generous; net.Pipe surfaces EOF immediately.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !deadLayer.IsShutdown() {
		time.Sleep(5 * time.Millisecond)
	}
	if !deadLayer.IsShutdown() {
		t.Fatalf("IsShutdown() after upstream EOF = false, want true")
	}
	// USK-796 invariants — neither legacy predicate catches this state.
	if got := deadLayer.LastReaderError(); got != nil {
		t.Errorf("LastReaderError() after clean EOF = %v, want nil", got)
	}
	if deadLayer.GoAwayClosed() {
		t.Errorf("GoAwayClosed() after clean EOF = true, want false")
	}

	// GetOrDial must NOT return the dead Layer — it must dial fresh.
	freshCli, freshPeer := net.Pipe()
	defer freshCli.Close()
	defer freshPeer.Close()
	freshPrefaceDone := make(chan error, 1)
	go func() {
		buf := make([]byte, len(http2.ClientPreface))
		if _, rerr := io.ReadFull(freshPeer, buf); rerr != nil {
			freshPrefaceDone <- rerr
			return
		}
		freshPrefaceDone <- nil
	}()

	var dialCount atomic.Int32
	got, err := p.GetOrDial(context.Background(), key, func() (*http2.Layer, error) {
		dialCount.Add(1)
		l, derr := http2.New(freshCli, "test-fresh", http2.ClientRole)
		if derr != nil {
			return nil, derr
		}
		if perr := <-freshPrefaceDone; perr != nil {
			_ = l.Close()
			return nil, perr
		}
		return l, nil
	})
	if err != nil {
		t.Fatalf("GetOrDial: %v", err)
	}
	if got == nil {
		t.Fatalf("GetOrDial returned nil layer")
	}
	if got == deadLayer {
		t.Fatalf("GetOrDial returned the dead (shutdown) layer; pool failed to evict")
	}
	if dialCount.Load() != 1 {
		t.Fatalf("dialFn called %d times, want 1 (fresh dial after shutdown evict)", dialCount.Load())
	}
	// Cleanup the fresh layer so its goroutines exit.
	p.Put(key, got)
}
