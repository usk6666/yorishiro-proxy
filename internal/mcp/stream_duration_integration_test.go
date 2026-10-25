//go:build e2e && !e2e_smoke

package mcp

// stream_duration_integration_test.go — USK-1347 coverage: every Stream
// created by resend_* / fuzz_* must record a real Stream.Duration
// (elapsed since RecordStep stamped Stream.Timestamp) instead of the
// SaveStream-time 0. fuzz_grpc / fuzz_raw variant Streams must also be
// finalised out of State="active".
//
// Each test drives the real MCP tool against an upstream that delays its
// reply by streamDurationDelay, then asserts duration_ms is at least that
// delay and no larger than a generous ceiling (never equality).

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer/ws"
)

// streamDurationDelay is the injected upstream delay. Small to keep the
// exhaustive tier fast, large enough to dwarf loopback round-trip noise.
const streamDurationDelay = 300 * time.Millisecond

// assertStreamDuration fetches streamID and checks min <= Duration <= max.
// Returns the Stream for further assertions.
func assertStreamDuration(t *testing.T, store flow.Store, streamID string, min, max time.Duration) *flow.Stream {
	t.Helper()
	st, err := store.GetStream(context.Background(), streamID)
	if err != nil || st == nil {
		t.Fatalf("GetStream(%s): stream=%v err=%v", streamID, st, err)
	}
	if st.Duration < min || st.Duration > max {
		t.Errorf("Stream %s Duration = %v, want in [%v, %v] (USK-1347: resend/fuzz Stream must record real elapsed time)",
			streamID, st.Duration, min, max)
	}
	return st
}

// findOriginStream returns the single Stream stamped with origin, failing
// the test when there is not exactly one.
func findOriginStream(t *testing.T, store flow.Store, origin flow.Origin) *flow.Stream {
	t.Helper()
	streams, err := store.ListStreams(context.Background(), flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	var found []*flow.Stream
	for _, s := range streams {
		if s.Origin == origin {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("found %d Origin=%s Streams, want 1 (total %d)", len(found), origin, len(streams))
	}
	return found[0]
}

// startDelayedHTTPServer is an HTTP upstream that sleeps delay before
// answering 200 "ok".
func startDelayedHTTPServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(delay)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// startHangingTCPServer accepts connections, drains whatever the client
// sends, and never replies; connections are closed at test cleanup.
func startHangingTCPServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	var (
		mu    sync.Mutex
		conns []net.Conn
	)
	t.Cleanup(func() {
		_ = ln.Close()
		mu.Lock()
		defer mu.Unlock()
		for _, c := range conns {
			_ = c.Close()
		}
	})
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startDelayedRawServer reads one chunk per connection, sleeps delay,
// writes a canned reply and closes the connection (EOF ends the raw
// receive loop).
func startDelayedRawServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				buf := make([]byte, 8192)
				if _, err := c.Read(buf); err != nil {
					return
				}
				time.Sleep(delay)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
			}(c)
		}
	}()
	return ln.Addr().String()
}

// startDelayedWSEchoServer is newWebSocketEchoServer with a delay before
// every echoed frame.
func startDelayedWSEchoServer(t *testing.T, delay time.Duration) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleDelayedWSEchoConn(c, delay)
		}
	}()
	return ln.Addr().String()
}

func handleDelayedWSEchoConn(conn net.Conn, delay time.Duration) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	r := bufio.NewReader(conn)
	if _, err := http.ReadRequest(r); err != nil {
		return
	}
	resp := "HTTP/1.1 101 Switching Protocols\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Accept: dummy-accept-key\r\n" +
		"\r\n"
	if _, err := conn.Write([]byte(resp)); err != nil {
		return
	}
	for {
		frame, err := ws.ReadFrame(r)
		if err != nil {
			return
		}
		time.Sleep(delay)
		if err := ws.WriteFrame(conn, &ws.Frame{Fin: true, Opcode: frame.Opcode, Payload: frame.Payload}); err != nil {
			return
		}
		if frame.Opcode == ws.OpcodeClose {
			return
		}
	}
}

// TestResendHTTP_StreamDurationRecorded reproduces the report: the
// resend_http Stream must carry the elapsed time, comparable to the
// tool's duration_ms.
func TestResendHTTP_StreamDurationRecorded(t *testing.T) {
	cs, store, _, _ := setupResendHTTPSession(t)
	authority := startDelayedHTTPServer(t, streamDurationDelay)

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/slow",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.DurationMs < streamDurationDelay.Milliseconds() {
		t.Fatalf("tool duration_ms = %d, want >= %d (fixture delay not observed)", out.DurationMs, streamDurationDelay.Milliseconds())
	}

	st := assertStreamDuration(t, store, out.StreamID, streamDurationDelay,
		time.Duration(out.DurationMs)*time.Millisecond+50*time.Millisecond)
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
}

// TestResendHTTP_TimeoutError_StreamDurationRecorded covers AC3: a
// resend that ends in error (upstream accepts and never answers, so the
// timeout fires) still records its real elapsed time.
func TestResendHTTP_TimeoutError_StreamDurationRecorded(t *testing.T) {
	cs, store, _, _ := setupResendHTTPSession(t)
	addr := startHangingTCPServer(t)

	const timeout = 300 * time.Millisecond
	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": addr,
		"path":      "/",
		"headers": []map[string]any{
			{"name": "Host", "value": addr},
		},
		"timeout_ms": int(timeout.Milliseconds()),
	})
	if !res.IsError {
		t.Fatalf("expected timeout to surface as IsError, got success")
	}

	// The lower bound is deliberately below the timeout. Duration is
	// measured from Stream.Timestamp, which RecordStep stamps, whereas the
	// per-request deadline (rtCtx in handleResendHTTP) starts earlier —
	// before pipeline build, rate-limit wait and the pre-Record steps. So
	// Duration = timeout + unwind - pre-Record overhead, which can land
	// just under the timeout on a loaded runner. timeout-100ms still
	// proves the regression: before USK-1347 the recorded value was 0.
	resendStream := findOriginStream(t, store, flow.OriginResend)
	st := assertStreamDuration(t, store, resendStream.ID, timeout-100*time.Millisecond, timeout+2*time.Second)
	if st.State != "error" {
		t.Errorf("Stream.State = %q, want error", st.State)
	}
}

// TestResendWS_StreamDurationRecorded covers resend_ws.
func TestResendWS_StreamDurationRecorded(t *testing.T) {
	cs, store, _, _ := setupResendWSSession(t)
	addr := startDelayedWSEchoServer(t, streamDurationDelay)
	seedID := seedResendWSFlow(t, store, addr, false)

	res := callResendWS(t, cs, map[string]any{
		"flow_id":    seedID,
		"opcode":     "text",
		"payload":    "slow",
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("tool returned error: %s", extractTextContent(res))
	}
	var out resendWSResult
	decodeStructuredResult(t, res, &out)

	st := assertStreamDuration(t, store, out.StreamID, streamDurationDelay,
		time.Duration(out.DurationMs)*time.Millisecond+50*time.Millisecond)
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
}

// TestResendGRPC_StreamDurationRecorded covers resend_grpc.
func TestResendGRPC_StreamDurationRecorded(t *testing.T) {
	cs, store, _, _ := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{delay: streamDurationDelay}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "slow"},
		},
		"timeout_ms": 10000,
	})
	var out resendGRPCResult
	decodeResendGRPCResult(t, res, &out)

	st := assertStreamDuration(t, store, out.StreamID, streamDurationDelay,
		time.Duration(out.DurationMs)*time.Millisecond+50*time.Millisecond)
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
}

// TestResendRaw_StreamDurationRecorded covers resend_raw.
func TestResendRaw_StreamDurationRecorded(t *testing.T) {
	cs, store, _ := setupResendRawSession(t)
	addr := startDelayedRawServer(t, streamDurationDelay)
	seedID := seedRawStream(t, store, []byte("ping"))

	out := callResendRaw(t, cs, map[string]any{
		"flow_id":     seedID,
		"target_addr": addr,
		"timeout_ms":  5000,
	})

	st := assertStreamDuration(t, store, out.StreamID, streamDurationDelay,
		time.Duration(out.DurationMs)*time.Millisecond+50*time.Millisecond)
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
}

// TestFuzzHTTP_VariantStreamsRecordDuration covers fuzz_http variants.
func TestFuzzHTTP_VariantStreamsRecordDuration(t *testing.T) {
	cs, store, _, _ := setupFuzzHTTPSession(t)
	authority := startDelayedHTTPServer(t, streamDurationDelay)

	result := callFuzzHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "http",
		"authority": authority,
		"path":      "/seed",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/v1", "/v2"}},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}
	for _, row := range result.Variants {
		assertStreamDuration(t, store, row.StreamID, streamDurationDelay,
			time.Duration(row.DurationMs)*time.Millisecond+time.Second)
	}
}

// TestFuzzWS_VariantStreamsRecordDuration covers fuzz_ws variants.
func TestFuzzWS_VariantStreamsRecordDuration(t *testing.T) {
	cs, store, _, _ := setupFuzzWSSession(t)
	addr := startDelayedWSEchoServer(t, streamDurationDelay)

	result := callFuzzWS(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "ws",
		"path":        "/echo",
		"opcode":      "text",
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v1", "v2"}},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}
	for _, row := range result.Variants {
		assertStreamDuration(t, store, row.StreamID, streamDurationDelay,
			time.Duration(row.DurationMs)*time.Millisecond+time.Second)
	}
}

// TestFuzzGRPC_VariantStreamsFinalizedWithDuration covers fuzz_grpc
// variants, which before USK-1347 were never finalised at all (stuck in
// State="active" with Duration 0).
func TestFuzzGRPC_VariantStreamsFinalizedWithDuration(t *testing.T) {
	cs, store, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{
		respond: func(req []byte) ([]byte, *status.Status) {
			time.Sleep(streamDurationDelay)
			return append(append([]byte(nil), req...), "|echo"...), nil
		},
	}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
		},
		"timeout_ms": 10000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}
	for i, row := range result.Variants {
		st := assertStreamDuration(t, store, row.StreamID, streamDurationDelay,
			time.Duration(row.DurationMs)*time.Millisecond+time.Second)
		if st.State != "complete" {
			t.Errorf("variants[%d] Stream.State = %q, want complete", i, st.State)
		}
	}
}

// TestFuzzRaw_VariantStreamsFinalizedWithDuration covers fuzz_raw
// variants, which before USK-1347 were never finalised at all.
func TestFuzzRaw_VariantStreamsFinalizedWithDuration(t *testing.T) {
	cs, store, _, _ := setupFuzzRawSession(t)
	addr := startDelayedRawServer(t, streamDurationDelay)

	result := callFuzzRaw(t, cs, map[string]any{
		"target_addr": addr,
		"positions": []map[string]any{
			{"path": "payload", "payloads": []string{"v1", "v2"}},
		},
		"timeout_ms": 5000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}
	for i, row := range result.Variants {
		st := assertStreamDuration(t, store, row.StreamID, streamDurationDelay,
			time.Duration(row.DurationMs)*time.Millisecond+time.Second)
		if st.State != "complete" {
			t.Errorf("variants[%d] Stream.State = %q, want complete", i, st.State)
		}
	}
}
