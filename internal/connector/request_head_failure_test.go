package connector

import (
	"bytes"
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// USK-1189: the CONNECT request and the plain-forward target peek are read
// by connector handlers before any Layer exists. When the proxy itself ends
// such a read after bytes arrived, the handler hands what the wire showed
// to OnRequestHeadFailure.

type headFailureCapture struct {
	mu     sync.Mutex
	calls  int
	target string
	head   *http1.RequestHeadError
}

func (c *headFailureCapture) fn(_ context.Context, target string, head *http1.RequestHeadError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls++
	c.target = target
	c.head = head
}

func (c *headFailureCapture) get() (int, string, *http1.RequestHeadError) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls, c.target, c.head
}

// runCONNECTPartial runs the CONNECT handler over a net.Pipe, sends payload
// and, when closeAfter is set, closes the client side; otherwise the client
// stalls until the handler gives up. Returns once the handler returned.
func runCONNECTPartial(t *testing.T, bc *BuildConfig, cb OnRequestHeadFailureFunc, payload string, closeAfter bool) {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		_, _ = client.Write([]byte(payload))
		if closeAfter {
			_ = client.Close()
			return
		}
		// Drain so a (never expected) reply cannot block the handler.
		buf := make([]byte, 512)
		for {
			if _, err := client.Read(buf); err != nil {
				return
			}
		}
	}()
	h := NewCONNECTHandler(CONNECTHandlerConfig{
		Negotiator:           NewCONNECTNegotiator(nil),
		BuildCfg:             bc,
		OnRequestHeadFailure: cb,
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h(ContextWithConnID(context.Background(), "conn-1189"), NewPeekConn(server))
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("CONNECT handler did not return")
	}
}

func usk1189BuildCfg(timeout time.Duration) *BuildConfig {
	bc := &BuildConfig{}
	bc.SetRequestHeaderTimeout(timeout)
	return bc
}

func TestCONNECTHandler_PartialRequestTimeout_ReportsHead(t *testing.T) {
	cases := []struct {
		name       string
		payload    string
		wantTarget string
		wantMethod string
		wantAuth   string
	}{
		{
			name:       "headers incomplete, valid authority",
			payload:    "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Pa",
			wantTarget: "127.0.0.1:1",
			wantMethod: "CONNECT",
			wantAuth:   "127.0.0.1:1",
		},
		{
			name:       "headers incomplete, authority without port",
			payload:    "CONNECT nohost HTTP/1.1\r\n",
			wantTarget: "",
			wantMethod: "CONNECT",
			wantAuth:   "nohost",
		},
		{
			name:       "request line incomplete",
			payload:    "CONNECT 127.0.0.1:1 HT",
			wantTarget: "",
			wantMethod: "",
			wantAuth:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capt := &headFailureCapture{}
			runCONNECTPartial(t, usk1189BuildCfg(50*time.Millisecond), capt.fn, tc.payload, false)
			calls, target, head := capt.get()
			if calls != 1 || head == nil {
				t.Fatalf("OnRequestHeadFailure calls = %d, want 1", calls)
			}
			if head.Reason != "connect_request_timeout" {
				t.Errorf("Reason = %q, want connect_request_timeout", head.Reason)
			}
			if head.Phase != "connect_request" {
				t.Errorf("Phase = %q, want connect_request", head.Phase)
			}
			if head.Timeout != 50*time.Millisecond {
				t.Errorf("Timeout = %v, want 50ms", head.Timeout)
			}
			if string(head.Raw) != tc.payload {
				t.Errorf("Raw = %q, want %q", head.Raw, tc.payload)
			}
			if head.RawTruncated {
				t.Error("RawTruncated = true, want false")
			}
			if head.Method != tc.wantMethod {
				t.Errorf("Method = %q, want %q", head.Method, tc.wantMethod)
			}
			if head.Authority != tc.wantAuth {
				t.Errorf("Authority = %q, want %q", head.Authority, tc.wantAuth)
			}
			if target != tc.wantTarget {
				t.Errorf("target = %q, want %q", target, tc.wantTarget)
			}
			if head.Status != 0 || head.ResponseWritten || len(head.Response) != 0 {
				t.Errorf("Status/ResponseWritten/Response = %d/%v/%q, want none", head.Status, head.ResponseWritten, head.Response)
			}
			if head.Scheme != "" {
				t.Errorf("Scheme = %q, want empty", head.Scheme)
			}
			if head.Err == nil || head.Started.IsZero() {
				t.Errorf("Err = %v, Started = %v; want both set", head.Err, head.Started)
			}
		})
	}
}

func TestCONNECTHandler_PartialRequestTimeout_RawCapped(t *testing.T) {
	bc := usk1189BuildCfg(50 * time.Millisecond)
	bc.MaxRawCaptureSize = 16
	payload := "CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\nX-Pad: aaaaaaaa"
	capt := &headFailureCapture{}
	runCONNECTPartial(t, bc, capt.fn, payload, false)
	calls, _, head := capt.get()
	if calls != 1 || head == nil {
		t.Fatalf("OnRequestHeadFailure calls = %d, want 1", calls)
	}
	if string(head.Raw) != payload[:16] || !head.RawTruncated {
		t.Errorf("Raw = %q (truncated=%v), want %q truncated", head.Raw, head.RawTruncated, payload[:16])
	}
}

func TestCONNECTHandler_PartialRequestClientClose_NotReported(t *testing.T) {
	capt := &headFailureCapture{}
	runCONNECTPartial(t, usk1189BuildCfg(2*time.Second), capt.fn, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nX-Pa", true)
	if calls, _, _ := capt.get(); calls != 0 {
		t.Errorf("OnRequestHeadFailure calls = %d, want 0 for a client close", calls)
	}
}

func TestCONNECTHandler_PartialRequestTimeout_NilCallback(t *testing.T) {
	runCONNECTPartial(t, usk1189BuildCfg(50*time.Millisecond), nil, "CONNECT 127.0.0.1:1 HTTP/1.1\r\nX-Pa", false)
}

// runForwardPartial runs the plain-forward handler over a net.Pipe, sends
// payload and returns every byte the client read back.
func runForwardPartial(t *testing.T, timeout time.Duration, cb OnRequestHeadFailureFunc, payload string, closeWrite bool) []byte {
	t.Helper()
	client, server := net.Pipe()
	defer client.Close()
	got := make(chan []byte, 1)
	go func() {
		_, _ = client.Write([]byte(payload))
		if closeWrite {
			_ = client.Close()
			got <- nil
			return
		}
		got <- drainAndCapture(t, client)
	}()
	h := NewHTTP1ForwardHandler(HTTP1ForwardHandlerConfig{
		RequestTimeout:       timeout,
		OnRequestHeadFailure: cb,
	})
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h(ContextWithConnID(context.Background(), "conn-1189"), NewPeekConn(server))
		_ = server.Close()
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("forward handler did not return")
	}
	return <-got
}

func TestHTTP1ForwardHandler_PeekTimeout_ReportsHeadAndResponse(t *testing.T) {
	cases := []struct {
		name       string
		payload    string
		wantPhase  string
		wantMethod string
	}{
		{name: "headers", payload: "GET http://example.com/x HTTP/1.1\r\nHo", wantPhase: "headers", wantMethod: "GET"},
		{name: "request line", payload: "GET http://x/pa", wantPhase: "request_line", wantMethod: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capt := &headFailureCapture{}
			got := runForwardPartial(t, 50*time.Millisecond, capt.fn, tc.payload, false)
			if !bytes.HasPrefix(got, []byte("HTTP/1.1 400 Bad Request\r\n")) {
				t.Fatalf("client read %q, want a 400", got)
			}
			calls, target, head := capt.get()
			if calls != 1 || head == nil {
				t.Fatalf("OnRequestHeadFailure calls = %d, want 1", calls)
			}
			if head.Reason != http1.RequestHeadTimeout {
				t.Errorf("Reason = %q, want request_head_timeout", head.Reason)
			}
			if head.Phase != tc.wantPhase {
				t.Errorf("Phase = %q, want %q", head.Phase, tc.wantPhase)
			}
			if head.Scheme != "http" {
				t.Errorf("Scheme = %q, want http", head.Scheme)
			}
			if head.Timeout != 50*time.Millisecond {
				t.Errorf("Timeout = %v, want 50ms", head.Timeout)
			}
			if string(head.Raw) != tc.payload {
				t.Errorf("Raw = %q, want %q", head.Raw, tc.payload)
			}
			if head.Method != tc.wantMethod {
				t.Errorf("Method = %q, want %q", head.Method, tc.wantMethod)
			}
			if head.Status != 400 || !head.ResponseWritten {
				t.Errorf("Status/ResponseWritten = %d/%v, want 400/true", head.Status, head.ResponseWritten)
			}
			if !bytes.Equal(head.Response, got) {
				t.Errorf("Response = %q, want the bytes the client read %q", head.Response, got)
			}
			if target != "" {
				t.Errorf("target = %q, want empty", target)
			}
		})
	}
}

func TestHTTP1ForwardHandler_PeekClientClose_NotReported(t *testing.T) {
	capt := &headFailureCapture{}
	_ = runForwardPartial(t, 2*time.Second, capt.fn, "GET http://example.com/x HTTP/1.1\r\nHo", true)
	if calls, _, _ := capt.get(); calls != 0 {
		t.Errorf("OnRequestHeadFailure calls = %d, want 0 for a client close", calls)
	}
}

func TestHTTP1ForwardHandler_PeekTimeout_NilCallback(t *testing.T) {
	got := runForwardPartial(t, 50*time.Millisecond, nil, "GET http://example.com/x HTTP/1.1\r\nHo", false)
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 400 Bad Request\r\n")) {
		t.Errorf("client read %q, want a 400", got)
	}
}
