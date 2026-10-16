//go:build e2e && !e2e_smoke

package http2_test

import (
	"context"
	"io"
	nethttp "net/http"
	"strings"
	"testing"
	"time"
)

// USK-1137 (defect C) end-to-end: Google Ad Manager requests carry a 21–26
// KiB :path. Before the fix the proxy's 16 KiB HPACK string cap rejected the
// header block, the client saw a connection error, and nothing was recorded.

// TestH2MITM_LargePath_21KiB covers Test Plan #10: GET /?q=<21000 x> through
// the MITM proxy reaches upstream with the exact path, the client gets the
// upstream response, and the stream is recorded complete with the full URL.
func TestH2MITM_LargePath_21KiB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	query := "q=" + strings.Repeat("x", 21000)
	seenCh := make(chan string, 1)
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "usk-1137-path", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		select {
		case seenCh <- r.URL.RequestURI():
		default:
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer upShutdown()

	proxyAddr, store := startH2MITMProxy(t, ctx, makeBuildCfg(t, nil), pipelineOpts{})
	cli := newMITMH2Client(proxyAddr, upAddr)

	reqCtx, reqCancel := context.WithTimeout(ctx, 15*time.Second)
	defer reqCancel()
	req, err := nethttp.NewRequestWithContext(reqCtx, "GET", "https://"+upAddr+"/?"+query, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client Do (GET with 21 KiB :path): %s", strings.ReplaceAll(err.Error(), query, "q=<21000 x>"))
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
	case got := <-seenCh:
		if got != "/?"+query {
			t.Errorf("upstream RequestURI is %d bytes, want %d", len(got), len(query)+2)
		}
	default:
		t.Error("upstream handler never saw the request")
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
	sendF, recvF := splitSendRecv(flows)
	if sendF == nil {
		t.Fatal("no send flow recorded")
	}
	if sendF.Method != "GET" {
		t.Errorf("send Method = %q, want GET", sendF.Method)
	}
	if sendF.URL == nil {
		t.Fatal("send flow URL is nil")
	}
	if sendF.URL.RawQuery != query {
		t.Errorf("send flow URL RawQuery is %d bytes, want %d", len(sendF.URL.RawQuery), len(query))
	}
	if len(sendF.RawBytes) == 0 {
		t.Error("send flow RawBytes empty - wire bytes not captured")
	}
	switch {
	case recvF == nil:
		t.Error("no receive flow recorded")
	case recvF.StatusCode != 200:
		t.Errorf("receive flow StatusCode = %d, want 200", recvF.StatusCode)
	}
}
