//go:build e2e

package connector_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"
)

// USK-769: end-to-end smoke tests proving that chunked Transfer-Encoding
// responses round-trip through the proxy with byte-level wire fidelity.
//
// Failure mode the fix closes: prior to USK-769, parser.dechunkedReader
// stripped chunk framing during read; only the dechunked semantic body
// reached msg.Body. The opaque pass-through send branch wrote
// rawResp.RawBytes (header section only, with Transfer-Encoding: chunked
// still in headers) followed by msg.Body (flat dechunked bytes). The wire
// became "TE: chunked" header + flat body — a curl client parsing the
// chunked body bailed with "Illegal or missing hexadecimal sequence in
// chunked-encoding".
//
// These tests use a hand-coded net.Listener that returns a fixed wire byte
// sequence (we cannot use httptest.Server because httptest controls chunk
// encoding internally and would defeat byte-level assertions).

// chunkedResponseBytes returns a complete HTTP/1.1 response with a
// hand-crafted chunked body — multiple chunks, mixed-case hex sizes, a
// chunk extension, and a trailer. The exact bytes returned are also the
// expected wire bytes after the proxy round-trip.
func chunkedResponseBytes() []byte {
	// Body section:
	//   "5\r\nhello\r\n"                -> chunk 1 (lower hex)
	//   "6;name=val\r\n world\r\n"      -> chunk 2 (with extension)
	//   "A\r\n0123456789\r\n"           -> chunk 3 (upper hex)
	//   "0\r\nX-Trailer: yes\r\n\r\n"   -> terminal + trailer
	body := "5\r\nhello\r\n" +
		"6;name=val\r\n world\r\n" +
		"A\r\n0123456789\r\n" +
		"0\r\nX-Trailer: yes\r\n\r\n"
	header := "HTTP/1.1 200 OK\r\n" +
		"Transfer-Encoding: chunked\r\n" +
		"Content-Type: text/plain\r\n" +
		"Connection: close\r\n" +
		"\r\n"
	return []byte(header + body)
}

// readUntilEOFChunked reads from conn until io.EOF (or another error). Used
// by the chunked passthrough tests since chunked responses carry no
// Content-Length and the upstream ends with Connection: close.
func readUntilEOFChunked(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	var buf bytes.Buffer
	tmp := make([]byte, 4096)
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

// dialThroughCONNECTPlainHTTP performs CONNECT to target then sends a plain
// HTTP/1.x request (no TLS) over the tunnel. Mirrors connectAndSendPlainHTTP
// but reads until EOF so chunked responses with Connection: close terminate
// cleanly without a Content-Length cue.
func dialThroughCONNECTPlainHTTP(t *testing.T, proxyAddr, target, path string) []byte {
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
	return readUntilEOFChunked(t, conn)
}

// dialThroughSOCKS5PlainHTTPChunked performs the SOCKS5 handshake to target,
// sends a plain HTTP/1.1 request (no TLS), and returns the raw bytes the
// proxy emitted back to the client. Reads until EOF for chunked-friendly
// termination.
func dialThroughSOCKS5PlainHTTPChunked(t *testing.T, proxyAddr, targetHost string, targetPort int, path string) []byte {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("write SOCKS5 greeting: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	method := make([]byte, 2)
	if _, err := io.ReadFull(conn, method); err != nil {
		t.Fatalf("read SOCKS5 method: %v", err)
	}
	if method[0] != 0x05 || method[1] != 0x00 {
		t.Fatalf("SOCKS5 method selection unexpected: %x", method)
	}

	// CONNECT request (DOMAIN ATYP).
	req := []byte{0x05, 0x01, 0x00, 0x03, byte(len(targetHost))}
	req = append(req, []byte(targetHost)...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	req = append(req, portBuf...)
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("write SOCKS5 CONNECT: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read SOCKS5 reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 reply unexpected: %x", reply)
	}
	conn.SetReadDeadline(time.Time{})

	// Now plain HTTP — no TLS handshake. The proxy must peek the inner byte
	// (USK-762 inner-peek dispatch) and route to the plain-HTTP stack.
	target := net.JoinHostPort(targetHost, strconv.Itoa(targetPort))
	rawReq := fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, target,
	)
	conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write SOCKS5 plain HTTP request: %v", err)
	}
	return readUntilEOFChunked(t, conn)
}

// startUpstreamFixedChunkedResponse starts a TCP server that, on a single
// connection, reads one HTTP/1.x request and returns the fixed wire bytes
// produced by chunkedResponseBytes(). The request bytes are captured for
// assertion.
func startUpstreamFixedChunkedResponse(t *testing.T) (net.Listener, func() []byte) {
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

		conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		br := bufio.NewReader(conn)
		reqBytes, err := readHTTPRequest(br)
		if err != nil {
			captured <- nil
			return
		}
		reqCopy := make([]byte, len(reqBytes))
		copy(reqCopy, reqBytes)

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := conn.Write(chunkedResponseBytes()); err != nil {
			captured <- reqCopy
			return
		}
		// Connection: close on the response — close the conn now.
		captured <- reqCopy
	}()

	return ln, func() []byte {
		select {
		case b := <-captured:
			return b
		case <-time.After(15 * time.Second):
			t.Fatal("timeout waiting for upstream captured request")
			return nil
		}
	}
}

// extractResponseBody returns everything after the first CRLFCRLF in resp.
func extractResponseBody(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return nil
	}
	return resp[idx+4:]
}

// extractResponseHeader returns the header section (up to and including the
// terminator CRLF CRLF) of resp.
func extractResponseHeader(resp []byte) []byte {
	idx := bytes.Index(resp, []byte("\r\n\r\n"))
	if idx < 0 {
		return resp
	}
	return resp[:idx+4]
}

// TestFullListener_ChunkedResponse_Passthrough_HTTP1Forward is the merge-gate
// smoke test for USK-769. It exercises the CONNECT + plain HTTP/1.x inner
// stream path (the typical `curl --proxytunnel` shape) — equivalent to the
// downstream plumbing used by `curl -x http://127.0.0.1:port http://...`
// once the proxy frontend has dispatched. This is the path that actually
// ran the broken sendResponseOpaque code in the bug report.
//
// Verifies:
//   - The body the client receives is byte-for-byte identical to the chunked
//     body the upstream produced (chunk size hex preserved, extension
//     preserved, trailer preserved, terminal "0\r\n...\r\n" preserved).
//   - The Transfer-Encoding: chunked header is preserved on the wire — no
//     TE→CL rewrite when the body was not modified by any pipeline step.
func TestFullListener_ChunkedResponse_Passthrough_HTTP1Forward(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getReq := startUpstreamFixedChunkedResponse(t)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	wg.Add(1)
	resp := dialThroughCONNECTPlainHTTP(t, proxyAddr, target, "/chunked")

	gotReq := getReq()
	waitSessionDone(t, wg)

	// --- Communication success ---
	if !bytes.Contains(resp, []byte("200 OK")) {
		t.Errorf("response missing 200 OK:\n%s", hex.Dump(resp))
	}
	if gotReq == nil {
		t.Fatal("upstream received no request")
	}

	// --- Wire-level chunked framing fidelity ---
	wantBody := extractResponseBody(chunkedResponseBytes())
	gotBody := extractResponseBody(resp)
	if !bytes.Equal(gotBody, wantBody) {
		t.Errorf("chunked body wire mismatch:\n got=\n%swant=\n%s",
			hex.Dump(gotBody), hex.Dump(wantBody))
	}

	// Transfer-Encoding header must be preserved (no TE→CL rewrite).
	hdr := extractResponseHeader(resp)
	if !bytes.Contains(bytes.ToLower(hdr), []byte("transfer-encoding: chunked")) {
		t.Errorf("Transfer-Encoding: chunked missing on wire — TE→CL rewrite leaked into unmodified passthrough:\n%s", hdr)
	}
	if bytes.Contains(bytes.ToLower(hdr), []byte("content-length:")) {
		t.Errorf("Content-Length unexpectedly stamped on chunked passthrough:\n%s", hdr)
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
}

// TestFullListener_ChunkedResponse_Passthrough_SOCKS5Plain is the merge-gate
// smoke test for USK-769 via SOCKS5 + plain HTTP — the path discovered in
// the original 2026-05-08 SOCKS5 listener investigation that surfaced the
// bug.
func TestFullListener_ChunkedResponse_Passthrough_SOCKS5Plain(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamLn, getReq := startUpstreamFixedChunkedResponse(t)
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}

	proxyAddr, store, wg := startFullListenerProxy(t, ctx, fullListenerOpts{})

	wg.Add(1)
	resp := dialThroughSOCKS5PlainHTTPChunked(t, proxyAddr, host, port, "/chunked")

	gotReq := getReq()
	waitSessionDone(t, wg)

	if !bytes.Contains(resp, []byte("200 OK")) {
		t.Errorf("response missing 200 OK:\n%s", hex.Dump(resp))
	}
	if gotReq == nil {
		t.Fatal("upstream received no request")
	}

	wantBody := extractResponseBody(chunkedResponseBytes())
	gotBody := extractResponseBody(resp)
	if !bytes.Equal(gotBody, wantBody) {
		t.Errorf("chunked body wire mismatch (SOCKS5 plain):\n got=\n%swant=\n%s",
			hex.Dump(gotBody), hex.Dump(wantBody))
	}

	hdr := extractResponseHeader(resp)
	if !bytes.Contains(bytes.ToLower(hdr), []byte("transfer-encoding: chunked")) {
		t.Errorf("Transfer-Encoding: chunked missing on wire (SOCKS5 plain):\n%s", hdr)
	}

	// Stream recording — Scheme should be "http" since the inner is plain.
	streams := store.getStreams()
	if len(streams) < 1 {
		t.Fatal("expected at least 1 stream, got 0")
	}
	if streams[0].Protocol != "http" {
		t.Errorf("stream protocol = %q, want %q", streams[0].Protocol, "http")
	}
	if streams[0].Scheme != "" && !strings.EqualFold(streams[0].Scheme, "http") {
		t.Errorf("stream scheme = %q, want %q", streams[0].Scheme, "http")
	}
}
