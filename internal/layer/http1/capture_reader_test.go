package http1

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// captureReader unit tests. We use real TCP sockets from testConn so the
// behavior matches production net.Conn semantics.

// TestInterruptCaptureReader_PassthroughBeforeStart verifies that Read
// behaves identically to the underlying conn before StartCapture is called.
// No side-buffer is built when capture is not enabled.
func TestInterruptCaptureReader_PassthroughBeforeStart(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	cr := newInterruptCaptureReader(server)

	// Write some bytes from client side; read them through cr.
	if _, err := client.Write([]byte("hello")); err != nil {
		t.Fatalf("client.Write: %v", err)
	}
	buf := make([]byte, 5)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := io.ReadFull(cr, buf)
	if err != nil {
		t.Fatalf("cr.Read: %v", err)
	}
	if n != 5 || string(buf) != "hello" {
		t.Fatalf("got %q (n=%d), want \"hello\" (n=5)", buf, n)
	}

	// Drain returns nil because capture was never started.
	captured := cr.Drain()
	if captured != nil {
		t.Errorf("Drain before StartCapture returned %q, want nil", captured)
	}
}

// TestInterruptCaptureReader_CapturesAfterStart verifies that bytes
// returned by Read after StartCapture are recorded; bytes before are not.
func TestInterruptCaptureReader_CapturesAfterStart(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	cr := newInterruptCaptureReader(server)

	// Phase 1: read "AAAA" before StartCapture.
	if _, err := client.Write([]byte("AAAA")); err != nil {
		t.Fatalf("phase1 write: %v", err)
	}
	buf := make([]byte, 4)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf); err != nil {
		t.Fatalf("phase1 read: %v", err)
	}

	// StartCapture: from here on, bytes are captured.
	cr.StartCapture()

	// Phase 2: write "BBBB"; read through cr; expect captured.
	if _, err := client.Write([]byte("BBBB")); err != nil {
		t.Fatalf("phase2 write: %v", err)
	}
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf); err != nil {
		t.Fatalf("phase2 read: %v", err)
	}

	captured := cr.Drain()
	if !bytes.Equal(captured, []byte("BBBB")) {
		t.Errorf("Drain = %q, want %q", captured, "BBBB")
	}

	// Drain resets capture; subsequent reads must not be captured even
	// without a fresh StartCapture.
	if _, err := client.Write([]byte("CC")); err != nil {
		t.Fatalf("phase3 write: %v", err)
	}
	buf2 := make([]byte, 2)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf2); err != nil {
		t.Fatalf("phase3 read: %v", err)
	}
	if got := cr.Drain(); got != nil {
		t.Errorf("Drain after reset returned %q, want nil", got)
	}
}

// TestInterruptCaptureReader_DrainResetsCapture verifies that Drain
// disables capturing — subsequent Reads do not append to the buffer.
func TestInterruptCaptureReader_DrainResetsCapture(t *testing.T) {
	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	cr := newInterruptCaptureReader(server)
	cr.StartCapture()

	// First batch: captured.
	if _, err := client.Write([]byte("X")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf); err != nil {
		t.Fatal(err)
	}
	if got := cr.Drain(); !bytes.Equal(got, []byte("X")) {
		t.Errorf("first Drain = %q, want \"X\"", got)
	}

	// Second batch: post-Drain, capture is OFF.
	if _, err := client.Write([]byte("Y")); err != nil {
		t.Fatal(err)
	}
	server.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := io.ReadFull(cr, buf); err != nil {
		t.Fatal(err)
	}
	if got := cr.Drain(); got != nil {
		t.Errorf("second Drain = %q, want nil (capture disabled)", got)
	}
}

// TestInterruptCaptureReader_ConcurrentStartAndRead verifies that the mutex
// in interruptCaptureReader serializes StartCapture against an in-flight
// Read so a race-favorable conn.Read whose return value lands AFTER
// StartCapture is still captured. This is the exact race USK-715 fixes:
// the parser's Read returns successfully with WS frame bytes; the
// orchestrator races to set the deadline; whichever order they observe in
// the wrapper, the bytes either are (good — captured) or are not (bad —
// lost) recorded.
func TestInterruptCaptureReader_ConcurrentStartAndRead(t *testing.T) {
	const iterations = 50

	for i := 0; i < iterations; i++ {
		client, server := testConn(t)
		cr := newInterruptCaptureReader(server)

		var wg sync.WaitGroup
		wg.Add(2)

		// Reader goroutine: blocks on Read, gets bytes, returns.
		readBytes := make([]byte, 0, 4)
		go func() {
			defer wg.Done()
			buf := make([]byte, 4)
			server.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, _ := cr.Read(buf)
			readBytes = append(readBytes, buf[:n]...)
		}()

		// Writer + StartCapture: write bytes, then StartCapture, racing
		// the reader's mutex acquisition.
		go func() {
			defer wg.Done()
			// Tiny stagger so the reader is parked first.
			time.Sleep(5 * time.Millisecond)
			_, _ = client.Write([]byte("ZZZZ"))
			cr.StartCapture()
		}()

		wg.Wait()

		// We assert ONLY that no bytes are dropped (reader saw all 4) —
		// the side-buffer may or may not have captured them depending on
		// whose mutex acquisition won the race. The race that USK-715
		// fixes is in the production sequence Mark→SetReadDeadline; this
		// test exercises the wrapper's primitive correctness.
		if !bytes.Equal(readBytes, []byte("ZZZZ")) {
			t.Errorf("iteration %d: reader saw %q, want %q", i, readBytes, "ZZZZ")
		}

		_ = cr.Drain()
		_ = client.Close()
		_ = server.Close()
	}
}
