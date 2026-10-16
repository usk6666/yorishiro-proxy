//go:build e2e && !e2e_smoke

package http2_test

import (
	"context"
	"io"
	nethttp "net/http"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1137 (defect A) end-to-end: a header block larger than the 16 KiB
// default SETTINGS_MAX_FRAME_SIZE is written by Go's x/net http2 client and
// server as HEADERS(END_STREAM, !END_HEADERS) + CONTINUATION(END_HEADERS)
// when the message has no body. Before the fix the proxy lost END_STREAM on
// that shape and the exchange hung until the client gave up.

// e2eBigHeaderValue mirrors the reporter's 10 KiB reproducer; 4 of them make
// a ~36 KiB HPACK block that needs at least two CONTINUATION frames. Kept
// below the pre-USK-1137 16 KiB per-string HPACK cap so these tests isolate defect A.
var e2eBigHeaderValue = strings.Repeat("x", 10*1024)

var e2eBigHeaderNames = []string{"X-A", "X-B", "X-C", "X-D"}

// flowHeaderValue looks a header up case-insensitively in a recorded flow.
func flowHeaderValue(f *flow.Flow, name string) (string, bool) {
	for k, v := range f.Headers {
		if strings.EqualFold(k, name) && len(v) > 0 {
			return v[0], true
		}
	}
	return "", false
}

func splitSendRecv(flows []*flow.Flow) (sendF, recvF *flow.Flow) {
	for _, f := range flows {
		switch f.Direction {
		case "send":
			sendF = f
		case "receive":
			recvF = f
		}
	}
	return sendF, recvF
}

// TestH2MITM_BodylessRequest_LargeHeaders_SplitAcrossContinuation covers Test
// Plan #4: a body-less GET with 4×10 KiB headers reaches upstream with every
// header intact, the client gets 200, and the stream is recorded complete
// with the headers on the Send flow.
func TestH2MITM_BodylessRequest_LargeHeaders_SplitAcrossContinuation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	type seen struct {
		values map[string]string
	}
	seenCh := make(chan seen, 1)
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "usk-1137-req", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		s := seen{values: map[string]string{}}
		for _, n := range e2eBigHeaderNames {
			s.values[n] = r.Header.Get(n)
		}
		select {
		case seenCh <- s:
		default:
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upShutdown()

	proxyAddr, store := startH2MITMProxy(t, ctx, makeBuildCfg(t, nil), pipelineOpts{})
	cli := newMITMH2Client(proxyAddr, upAddr)

	reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reqCancel()
	req, err := nethttp.NewRequestWithContext(reqCtx, "GET", "https://"+upAddr+"/usk-1137", nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range e2eBigHeaderNames {
		req.Header.Set(n, e2eBigHeaderValue)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do (body-less GET with 4x10KiB headers): %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want ok", body)
	}

	select {
	case s := <-seenCh:
		for _, n := range e2eBigHeaderNames {
			if s.values[n] != e2eBigHeaderValue {
				t.Errorf("upstream %s length = %d, want %d", n, len(s.values[n]), len(e2eBigHeaderValue))
			}
		}
	default:
		t.Error("upstream handler never saw the request")
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
	sendF, _ := splitSendRecv(flows)
	if sendF == nil {
		t.Fatal("no send flow recorded")
	}
	if sendF.Method != "GET" {
		t.Errorf("send Method = %q, want GET", sendF.Method)
	}
	for _, n := range e2eBigHeaderNames {
		v, ok := flowHeaderValue(sendF, n)
		if !ok || v != e2eBigHeaderValue {
			t.Errorf("send flow header %s present=%v length=%d, want length %d", n, ok, len(v), len(e2eBigHeaderValue))
		}
	}
	if len(sendF.RawBytes) == 0 {
		t.Error("send flow RawBytes empty - wire bytes not captured")
	}
}

// TestH2MITM_BodylessResponse_LargeHeaders_SplitAcrossContinuation covers
// Test Plan #5: upstream answers 204 with 4×10 KiB response headers (Go's
// server emits HEADERS(END_STREAM) + CONTINUATION); the client receives 204
// with every header and the stream is recorded complete.
func TestH2MITM_BodylessResponse_LargeHeaders_SplitAcrossContinuation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "usk-1137-resp", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		for _, n := range e2eBigHeaderNames {
			w.Header().Set(n, e2eBigHeaderValue)
		}
		w.WriteHeader(nethttp.StatusNoContent)
	}))
	defer upShutdown()

	proxyAddr, store := startH2MITMProxy(t, ctx, makeBuildCfg(t, nil), pipelineOpts{})
	cli := newMITMH2Client(proxyAddr, upAddr)

	reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reqCancel()
	req, err := nethttp.NewRequestWithContext(reqCtx, "GET", "https://"+upAddr+"/usk-1137-204", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do (204 with 4x10KiB response headers): %v", err)
	}
	_, _ = io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != nethttp.StatusNoContent {
		t.Errorf("status = %d, want 204", resp.StatusCode)
	}
	for _, n := range e2eBigHeaderNames {
		if got := resp.Header.Get(n); got != e2eBigHeaderValue {
			t.Errorf("client response header %s length = %d, want %d", n, len(got), len(e2eBigHeaderValue))
		}
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
	_, recvF := splitSendRecv(flows)
	if recvF == nil {
		t.Fatal("no receive flow recorded")
	}
	if recvF.StatusCode != nethttp.StatusNoContent {
		t.Errorf("recv StatusCode = %d, want 204", recvF.StatusCode)
	}
	for _, n := range e2eBigHeaderNames {
		v, ok := flowHeaderValue(recvF, n)
		if !ok || v != e2eBigHeaderValue {
			t.Errorf("recv flow header %s present=%v length=%d, want length %d", n, ok, len(v), len(e2eBigHeaderValue))
		}
	}
	if len(recvF.RawBytes) == 0 {
		t.Error("recv flow RawBytes empty - wire bytes not captured")
	}
}
