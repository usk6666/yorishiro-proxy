//go:build e2e && !e2e_smoke

// USK-1189 exhaustive coverage: phases, the raw-capture cap, the
// tcp_forwards TLS handshake site, over-long CONNECT heads, and the
// not-recorded guards (zero-byte connections, client closes).
package proxybuild_test

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// TestProxybuild_PlainForward_PeekTimeout_RequestLinePhase (T4a): a request
// line that never completed is recorded verbatim with phase=request_line
// and no request-line overlay.
func TestProxybuild_PlainForward_PeekTimeout_RequestLinePhase(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)

	payload := "GET http://x/pa"
	got := usk1189SendAndAwaitClose(t, fix.proxyAddr, payload, 3*time.Second)
	if !strings.HasPrefix(string(got), "HTTP/1.1 400 ") {
		t.Fatalf("client read %q, want the 400", got)
	}
	st, flows := awaitErrorStream(t, fix.store, "request_head_timeout", 2, 5*time.Second)
	if st.Tags["phase"] != "request_line" {
		t.Errorf("Tags[phase] = %q, want request_line", st.Tags["phase"])
	}
	for _, f := range flows {
		if f.Direction != "send" {
			continue
		}
		if string(f.RawBytes) != payload {
			t.Errorf("send RawBytes = %q, want %q", f.RawBytes, payload)
		}
		if f.Method != "" {
			t.Errorf("send Method = %q, want empty (request line incomplete)", f.Method)
		}
	}
}

// TestProxybuild_PlainForward_PeekTimeout_RawCapped (T4b): the recorded
// bytes honour max_raw_capture_size.
func TestProxybuild_PlainForward_PeekTimeout_RawCapped(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, func(bc *connector.BuildConfig) { bc.MaxRawCaptureSize = 16 }, 300*time.Millisecond)

	payload := "GET http://127.0.0.1:9/" + strings.Repeat("a", 60) + " HTTP/1.1\r\nHost: 127.0.0.1:9\r\nX-P"
	_ = usk1189SendAndAwaitClose(t, fix.proxyAddr, payload, 3*time.Second)
	st, flows := awaitErrorStream(t, fix.store, "request_head_timeout", 1, 5*time.Second)
	for _, f := range flows {
		if f.Direction != "send" {
			continue
		}
		if string(f.RawBytes) != payload[:16] {
			t.Errorf("send RawBytes = %q, want %q", f.RawBytes, payload[:16])
		}
		if f.Metadata["raw_truncated"] != "true" {
			t.Errorf("Metadata[raw_truncated] = %q, want true", f.Metadata["raw_truncated"])
		}
		return
	}
	t.Fatalf("no send flow on stream %s", st.ID)
}

// TestProxybuild_TCPForwardTLS_HandshakeTimeoutTagged (T8): the third TLS
// handshake site (tcp_forwards tls:true) tags the timeout too.
func TestProxybuild_TCPForwardTLS_HandshakeTimeoutTagged(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)
	if err := fix.mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: "127.0.0.1:1", Protocol: "http", TLS: true},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	addr := fix.mgr.TCPForwardAddrs()["0"]
	if addr == "" {
		t.Fatal("TCPForwardAddrs missing port 0")
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	defer conn.Close()
	usk1189StallTLSHandshake(t, conn)

	st, _ := awaitErrorStream(t, fix.store, "client_tls_error", 0, 5*time.Second)
	for k, v := range map[string]string{
		"phase":              "tls_handshake",
		"closed_by":          "proxy",
		"timeout":            "request_timeout",
		"request_timeout_ms": "300",
	} {
		if st.Tags[k] != v {
			t.Errorf("Tags[%q] = %q, want %q", k, st.Tags[k], v)
		}
	}
}

// usk1189ErrorStreamCount returns the number of State=error streams.
func usk1189ErrorStreamCount(s *usk1181Store) int {
	n := 0
	for _, st := range s.allStreams() {
		if st.State == "error" {
			n++
		}
	}
	return n
}

// TestProxybuild_ZeroByteConnections_NotRecorded (T9): connections that
// never send a byte leave no record; a positive control on the same
// listener proves the recorder is live.
func TestProxybuild_ZeroByteConnections_NotRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)
	fix.mgr.SetPeekTimeout(200 * time.Millisecond)

	for i := 0; i < 2; i++ {
		if got := usk1189SendAndAwaitClose(t, fix.proxyAddr, "", 3*time.Second); len(got) != 0 {
			t.Errorf("silent connection %d got a reply: %q", i, got)
		}
	}
	_ = usk1189SendAndAwaitClose(t, fix.proxyAddr, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nX-Pa", 3*time.Second)
	awaitErrorStream(t, fix.store, "connect_request_timeout", 1, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if n := usk1189ErrorStreamCount(fix.store); n != 1 {
		t.Errorf("error streams = %d, want exactly 1 (the positive control)", n)
	}
}

// TestProxybuild_PlainForward_ClientClose_NotRecorded (T10): a client that
// half-closes mid-head still gets the 400 but leaves no record.
func TestProxybuild_PlainForward_ClientClose_NotRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	fix := startUSK1189Proxy(t, ctx, nil, nil, 300*time.Millisecond)

	conn, err := net.DialTimeout("tcp", fix.proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := conn.Write([]byte("GET http://127.0.0.1:9/x HTTP/1.1\r\nHo")); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = conn.(*net.TCPConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	_ = conn.Close()
	if !strings.HasPrefix(string(buf[:n]), "HTTP/1.1 400 ") {
		t.Errorf("client read %q, want the 400", buf[:n])
	}

	_ = usk1189SendAndAwaitClose(t, fix.proxyAddr, "GET http://127.0.0.1:9/y HTTP/1.1\r\nHo", 3*time.Second)
	awaitErrorStream(t, fix.store, "request_head_timeout", 2, 5*time.Second)
	time.Sleep(200 * time.Millisecond)
	if n := usk1189ErrorStreamCount(fix.store); n != 1 {
		t.Errorf("error streams = %d, want exactly 1 (the positive control)", n)
	}
}

// TestProxybuild_CONNECT_OverLimitHead_Recorded (T12, U1): an over-long
// CONNECT request line or header section is recorded under the existing
// parser-limit reasons with phase=connect_request; no response is sent.
func TestProxybuild_CONNECT_OverLimitHead_Recorded(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		reason  string
	}{
		{
			name:    "request line",
			payload: "CONNECT " + strings.Repeat("a", 4<<20+16) + " HTTP/1.1\r\n\r\n",
			reason:  "request_line_too_long",
		},
		{
			name:    "header section",
			payload: "CONNECT 127.0.0.1:1 HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 10050) + "\r\n",
			reason:  "request_header_too_large",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			// A generous request timeout so a loaded machine reaches the
			// parser limit before the header deadline (USK-1181 lesson).
			fix := startUSK1189Proxy(t, ctx, nil, nil, 30*time.Second)

			conn, err := net.DialTimeout("tcp", fix.proxyAddr, 5*time.Second)
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()
			go func() { _, _ = conn.Write([]byte(tc.payload)) }()
			_ = conn.SetReadDeadline(time.Now().Add(20 * time.Second))
			buf := make([]byte, 512)
			if n, _ := conn.Read(buf); n != 0 {
				t.Errorf("proxy replied to an over-limit CONNECT: %q", buf[:n])
			}

			st, _ := awaitErrorStream(t, fix.store, tc.reason, 1, 10*time.Second)
			if st.Tags["phase"] != "connect_request" {
				t.Errorf("Tags[phase] = %q, want connect_request", st.Tags["phase"])
			}
			if st.Tags["closed_by"] != "proxy" {
				t.Errorf("Tags[closed_by] = %q, want proxy", st.Tags["closed_by"])
			}
			if _, ok := st.Tags["wrote_response"]; ok {
				t.Errorf("Tags[wrote_response] present, want absent")
			}
			send := assertOnlySendFlow(t, fix.store, st)
			if len(send.RawBytes) == 0 || !strings.HasPrefix(tc.payload, string(send.RawBytes)) {
				t.Errorf("send RawBytes (%d bytes) is not a non-empty prefix of the payload", len(send.RawBytes))
			}
		})
	}
}
