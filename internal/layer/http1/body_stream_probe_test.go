package http1

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// TestBodyStream_BufferUpToProbe_AllocationBoundedByBody checks that a
// BufferUpTo probe sizes its memory from the body, not from the limit: a
// large plugin_max_body_size must not cost a limit-sized allocation per
// response, and a body above body_spill_threshold (but within the limit)
// must spill rather than be held whole in RAM (USK-1409 review F-1 / S-2).
func TestBodyStream_BufferUpToProbe_AllocationBoundedByBody(t *testing.T) {
	const (
		limit     = 256 << 20 // a valid, large plugin_max_body_size
		threshold = 64 << 10  // body_spill_threshold
		maxAlloc  = 32 << 20  // generous ceiling, far below limit
	)
	cases := []struct {
		name      string
		bodyLen   int
		wantSpill bool
	}{
		{name: "small body", bodyLen: 10},
		{name: "body over spill threshold", bodyLen: 2 << 20, wantSpill: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
				return layer.BufferUpTo(limit)
			}
			l, peer := newStreamingUpstream(t, mode,
				WithBodySpillDir(t.TempDir()),
				WithBodySpillThreshold(threshold),
				WithMaxBodySize(limit))
			ch := sendExchange(t, l, "GET", "/")

			body := bytes.Repeat([]byte("x"), tc.bodyLen)
			// Chunked: no Content-Length hint for the probe to size from.
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)

			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			go func() { _, _ = peer.Write([]byte(resp)) }()
			env := nextWithin(t, ch, 10*time.Second)
			runtime.ReadMemStats(&after)

			if got := after.TotalAlloc - before.TotalAlloc; got > maxAlloc {
				t.Errorf("allocated %d bytes to buffer a %d-byte body (limit %d); want <= %d",
					got, tc.bodyLen, limit, maxAlloc)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.BodyStream != nil {
				t.Fatal("body within the BufferUpTo limit was streamed; want buffered")
			}
			var gotBody []byte
			if msg.BodyBuffer != nil {
				if tc.wantSpill && !msg.BodyBuffer.IsFileBacked() {
					t.Error("body over body_spill_threshold is not file-backed")
				}
				b, err := msg.BodyBuffer.Bytes(context.Background())
				if err != nil {
					t.Fatalf("BodyBuffer.Bytes: %v", err)
				}
				gotBody = b
			} else {
				if tc.wantSpill {
					t.Error("body over body_spill_threshold was held in memory (no BodyBuffer)")
				}
				gotBody = msg.Body
			}
			if !bytes.Equal(gotBody, body) {
				t.Errorf("body = %d bytes, want %d bytes", len(gotBody), len(body))
			}
		})
	}
}

// TestBodyStream_BufferUpToProbe_SpilledPrefixStreams covers a body over
// the BufferUpTo limit whose probe spilled past body_spill_threshold: the
// stream replays the spilled semantic prefix and the raw prefix ahead of
// the rest, and the spill files are released when the body ends — read to
// the end or closed unread.
func TestBodyStream_BufferUpToProbe_SpilledPrefixStreams(t *testing.T) {
	const (
		limit     = 256 << 10
		threshold = 64 << 10
	)
	for _, readIt := range []bool{true, false} {
		t.Run(fmt.Sprintf("read=%v", readIt), func(t *testing.T) {
			mode := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
				return layer.BufferUpTo(limit)
			}
			dir := t.TempDir()
			l, peer := newStreamingUpstream(t, mode,
				WithBodySpillDir(dir),
				WithBodySpillThreshold(threshold))
			ch := sendExchange(t, l, "GET", "/")

			body := make([]byte, 512<<10)
			for i := range body {
				body[i] = byte('a' + i%26)
			}
			wireBody := fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body)
			go func() {
				_, _ = peer.Write([]byte("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + wireBody))
			}()

			env := nextWithin(t, ch, 10*time.Second)
			msg := streamedMsg(t, env)
			var raw bytes.Buffer
			msg.BodyStream.Observe(nil, func(p []byte) { raw.Write(p) })
			if readIt {
				got, err := io.ReadAll(msg.BodyStream)
				if err != nil {
					t.Fatalf("ReadAll: %v", err)
				}
				if !bytes.Equal(got, body) {
					t.Fatalf("semantic body = %d bytes, want %d (prefix replay broken)", len(got), len(body))
				}
				if raw.String() != wireBody {
					t.Fatalf("raw body = %d bytes, want the %d wire bytes", raw.Len(), len(wireBody))
				}
			} else {
				_ = msg.BodyStream.Close()
			}
			<-msg.BodyStream.Done()
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("ReadDir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("spill dir holds %d file(s) after the body ended; want the probe spill released", len(entries))
			}
		})
	}
}

// TestBodyStream_BufferUpToProbe_ErrorAfterSpillReleasesFile covers a
// BufferUpTo probe that spilled past body_spill_threshold and then hit a
// non-EOF read error — a malformed chunk size, or the upstream resetting
// the connection. The probe's spill file must be released with the error,
// not leaked (USK-1409 review round 2, F-5).
func TestBodyStream_BufferUpToProbe_ErrorAfterSpillReleasesFile(t *testing.T) {
	const (
		limit     = 256 << 10
		threshold = 64 << 10
	)
	chunk := bytes.Repeat([]byte("y"), 100<<10)
	cases := []struct {
		name string
		// fail drives the upstream peer into the error once the probe
		// spilled. It runs on its own goroutine: report with t.Error only.
		fail func(t *testing.T, peer net.Conn, dir string)
	}{
		{
			name: "bad chunk size after threshold",
			fail: func(t *testing.T, peer net.Conn, _ string) {
				if _, err := fmt.Fprintf(peer, "%x\r\n%s\r\nZZZZ\r\n", len(chunk), chunk); err != nil {
					t.Errorf("upstream write: %v", err)
				}
			},
		},
		{
			name: "connection reset after threshold",
			fail: func(t *testing.T, peer net.Conn, dir string) {
				// Declare a chunk the probe is still reading when the reset lands.
				if _, err := fmt.Fprintf(peer, "%x\r\n%s", 300<<10, chunk); err != nil {
					t.Errorf("upstream write: %v", err)
					return
				}
				waitForProbeSpill(t, dir)
				tc, ok := peer.(*net.TCPConn)
				if !ok {
					t.Errorf("peer = %T, want *net.TCPConn", peer)
					return
				}
				_ = tc.SetLinger(0)
				_ = tc.Close()
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
				return layer.BufferUpTo(limit)
			}
			dir := t.TempDir()
			l, peer := newStreamingUpstream(t, mode,
				WithBodySpillDir(dir),
				WithBodySpillThreshold(threshold))
			ch := sendExchange(t, l, "GET", "/")

			peerWrite(t, peer, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
			go tc.fail(t, peer, dir)

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if _, err := ch.Next(ctx); err == nil {
				t.Fatal("Next succeeded; want the body read error")
			}
			if n := probeSpillFiles(t, dir); n != 0 {
				t.Errorf("spill dir holds %d probe spill file(s) after the probe failed; want 0 (leaked temp file / fd)", n)
			}
		})
	}
}

// probeSpillFiles counts the semantic body spill files in dir.
func probeSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Errorf("ReadDir: %v", err)
		return 0
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), config.BodySpillPrefix) {
			n++
		}
	}
	return n
}

// waitForProbeSpill waits until the probe created its spill file in dir.
func waitForProbeSpill(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for probeSpillFiles(t, dir) == 0 {
		if time.Now().After(deadline) {
			t.Error("probe never spilled past body_spill_threshold")
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestBodyStream_BufferUpToProbe_LimitOverMaxBodyStreams covers a
// BufferUpTo limit (plugin_max_body_size) above max_body_size: the probe
// can buffer at most max_body_size, so a body larger than max_body_size is
// streamed past the plugin — byte-identical on the wire — rather than
// failing with "body exceeds max size" (USK-1409 review round 2, F-6).
func TestBodyStream_BufferUpToProbe_LimitOverMaxBodyStreams(t *testing.T) {
	const (
		limit     = 256 << 10 // plugin_max_body_size
		maxBody   = 128 << 10 // max_body_size, below the plugin limit
		threshold = 64 << 10
	)
	body := make([]byte, 200<<10) // over max_body_size, within the plugin limit
	for i := range body {
		body[i] = byte('a' + i%26)
	}
	cases := []struct {
		name    string
		head    string
		rawBody string
	}{
		{
			name:    "content-length",
			head:    fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n", len(body)),
			rawBody: string(body),
		},
		{
			name:    "chunked",
			head:    "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
			rawBody: fmt.Sprintf("%x\r\n%s\r\n0\r\n\r\n", len(body), body),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
				return layer.BufferUpTo(limit)
			}
			dir := t.TempDir()
			l, peer := newStreamingUpstream(t, mode,
				WithBodySpillDir(dir),
				WithBodySpillThreshold(threshold),
				WithMaxBodySize(maxBody))
			ch := sendExchange(t, l, "GET", "/")
			go func() { _, _ = peer.Write([]byte(tc.head + tc.rawBody)) }()

			env := nextWithin(t, ch, 10*time.Second)
			msg := streamedMsg(t, env)
			var raw bytes.Buffer
			msg.BodyStream.Observe(nil, func(p []byte) { raw.Write(p) })
			got, err := io.ReadAll(msg.BodyStream)
			if err != nil {
				t.Fatalf("ReadAll: %v", err)
			}
			if !bytes.Equal(got, body) {
				t.Errorf("semantic body = %d bytes, want %d", len(got), len(body))
			}
			if raw.String() != tc.rawBody {
				t.Errorf("raw body = %d bytes, want the %d wire bytes", raw.Len(), len(tc.rawBody))
			}
		})
	}
}
