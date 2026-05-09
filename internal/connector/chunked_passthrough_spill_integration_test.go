//go:build e2e && !e2e_smoke

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"testing"
	"time"
)

// USK-772: end-to-end test proving that chunked Transfer-Encoding responses
// LARGER than BodySpillThreshold round-trip through the proxy with byte-level
// wire fidelity via the parser disk-spill path.
//
// USK-769 closed the small-body case (memory-only RawBody preserves chunk
// framing). USK-772 closes the large-body case: the parser's bodyCaptureSink
// promotes to a disk-backed bodybuf above threshold, and the opaque
// passthrough send streams from the buffer via io.Copy.
//
// This test lives in the full e2e tier (//go:build e2e && !e2e_smoke) because
// the body is multi-MiB and too slow for the per-PR smoke gate. The matching
// memory-path tests in chunked_passthrough_integration_test.go run on every
// PR.

// largeChunkedResponseBytes returns a chunked-TE response whose body exceeds
// the spill threshold so the test exercises the bodybuf path. Three chunks
// of varying sizes plus a trailer ensure chunk framing fidelity (not just
// body byte fidelity) is verified.
func largeChunkedResponseBytes(spillThreshold int64) []byte {
	// Chunk sizes chosen so total > spillThreshold * 4 (well above
	// threshold so the spill is unambiguous).
	const chunk1 = 1 << 20 // 1 MiB
	chunk2 := int(spillThreshold) + (1 << 20)
	const chunk3 = 1 << 21 // 2 MiB

	c1 := bytes.Repeat([]byte("A"), chunk1)
	c2 := bytes.Repeat([]byte("B"), chunk2)
	c3 := bytes.Repeat([]byte("C"), chunk3)

	var body bytes.Buffer
	body.WriteString(fmt.Sprintf("%x\r\n", chunk1))
	body.Write(c1)
	body.WriteString("\r\n")
	body.WriteString(fmt.Sprintf("%x;ext=v\r\n", chunk2))
	body.Write(c2)
	body.WriteString("\r\n")
	body.WriteString(fmt.Sprintf("%x\r\n", chunk3))
	body.Write(c3)
	body.WriteString("\r\n")
	body.WriteString("0\r\nX-Trailer: yes\r\n\r\n")

	header := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: application/octet-stream\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	return append([]byte(header), body.Bytes()...)
}

// startUpstreamFixedLargeChunkedResponse is the multi-MiB twin of
// startUpstreamFixedChunkedResponse. The wire bytes are deterministic so the
// test can assert byte-level equality.
func startUpstreamFixedLargeChunkedResponse(t *testing.T, wireBytes []byte) (net.Listener, func() []byte) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	captured := make(chan []byte, 1)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			captured <- nil
			return
		}
		defer conn.Close()

		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		br := bufio.NewReader(conn)
		reqBytes, err := readHTTPRequest(br)
		if err != nil {
			captured <- nil
			return
		}
		reqCopy := make([]byte, len(reqBytes))
		copy(reqCopy, reqBytes)

		conn.SetWriteDeadline(time.Now().Add(60 * time.Second))
		if _, err := conn.Write(wireBytes); err != nil {
			captured <- reqCopy
			return
		}
		captured <- reqCopy
	}()

	return ln, func() []byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(60 * time.Second):
			t.Fatal("timeout waiting for upstream captured request")
			return nil
		}
	}
}

// readUntilEOFLong drains conn fully with a longer deadline suitable for
// multi-MiB bodies.
func readUntilEOFLong(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 64*1024)
	for {
		n, err := conn.Read(tmp)
		if n > 0 {
			buf.Write(tmp[:n])
		}
		if err != nil {
			break
		}
	}
	return buf.Bytes()
}

// dialThroughCONNECTPlainHTTPLong is a longer-deadline twin of
// dialThroughCONNECTPlainHTTP.
func dialThroughCONNECTPlainHTTPLong(t *testing.T, proxyAddr, target, path string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(connectReq)); err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}
	buf := make([]byte, 256)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("unexpected CONNECT response: %q", got)
	}
	conn.SetReadDeadline(time.Time{})

	rawReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, target,
	)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write plain HTTP request through CONNECT tunnel: %v", err)
	}
	return readUntilEOFLong(t, conn)
}

// TestFullListener_ChunkedResponse_LargeBody_Spilled_Passthrough exercises
// the USK-772 disk-spill path end-to-end. With a low BodySpillThreshold
// (256 KiB), the multi-MiB chunked response triggers the parser's
// disk-spill bodybuf during capture. The proxy's opaque passthrough send
// path must still emit the full wire bytes byte-for-byte to the client.
//
// Verifies:
//   - Client receives a byte-identical wire snapshot of the upstream response
//     (chunk framing, extension, trailer all preserved).
//   - SHA-256 of the relayed bytes matches the upstream wire's SHA-256.
//   - Transfer-Encoding header is preserved (no TE→CL rewrite).
//   - Stream/Flow recording captured the response (basic existence check).
//   - Spill files are removed from BodySpillDir after the session completes.
func TestFullListener_ChunkedResponse_LargeBody_Spilled_Passthrough(t *testing.T) {
	const spillThreshold = 256 << 10 // 256 KiB
	wire := largeChunkedResponseBytes(spillThreshold)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	upstreamLn, getReq := startUpstreamFixedLargeChunkedResponse(t, wire)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	spillDir := t.TempDir()
	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThreshold,
		bodyMaxSize:        64 << 20, // 64 MiB; comfortably > total body
	})

	wg.Add(1)
	resp := dialThroughCONNECTPlainHTTPLong(t, proxyAddr, target, "/large-chunked")

	gotReq := getReq()
	waitSessionDone(t, wg)

	// --- Communication success ---
	if gotReq == nil {
		t.Fatal("upstream received no request")
	}
	if !bytes.Contains(resp, []byte("200 OK")) {
		t.Fatal("response missing 200 OK")
	}

	// --- Byte-level wire fidelity ---
	if len(resp) != len(wire) {
		t.Fatalf("relayed wire length mismatch: got=%d want=%d", len(resp), len(wire))
	}
	if !bytes.Equal(resp, wire) {
		gotSum := sha256Sum(resp)
		wantSum := sha256Sum(wire)
		t.Errorf("relayed wire bytes do not match upstream wire: got SHA-256=%s want SHA-256=%s",
			gotSum, wantSum)
	}

	// --- TE header preservation (no TE→CL rewrite on passthrough) ---
	hdr := extractResponseHeader(resp)
	if !bytes.Contains(bytes.ToLower(hdr), []byte("transfer-encoding: chunked")) {
		t.Errorf("Transfer-Encoding: chunked missing on wire (TE→CL rewrite leaked):\n%s", hdr)
	}

	// --- Stream / Flow recording ---
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}
	recvFlows := store.flowsByDirection("receive")
	if len(recvFlows) < 1 {
		t.Fatal("expected at least 1 receive flow, got 0")
	}

	// --- Spill file cleanup ---
	// After the session ends, the body-spill temp files must have been
	// cleaned by bodybuf.Release. The exact names depend on
	// bodybuf.NewFile's tempfile naming, but they all share the
	// "yorishiro-body-" prefix. Wait briefly for async cleanup.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir(spillDir)
		if err != nil {
			t.Fatalf("read spill dir: %v", err)
		}
		anyLeft := false
		for _, e := range entries {
			if !e.IsDir() {
				anyLeft = true
				break
			}
		}
		if !anyLeft {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	entries, _ := os.ReadDir(spillDir)
	for _, e := range entries {
		if !e.IsDir() {
			t.Errorf("spill file not cleaned up after session: %q", e.Name())
		}
	}
}

func sha256Sum(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
