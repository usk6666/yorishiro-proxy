//go:build e2e && !e2e_smoke

// USK-1157 exhaustive-tier coverage. Reuses the frame-level origin and raw
// client defined in h2_upstream_refused_integration_test.go (smoke tier,
// which is a subset of this tier's build).
package proxybuild_test

import (
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH2UpstreamRSTRefused_ClientSeesRefusedStream: the origin answers three
// streams and resets the fourth with RST_STREAM(REFUSED_STREAM). The raw
// client must see REFUSED_STREAM on exactly that stream.
func TestH2UpstreamRSTRefused_ClientSeesRefusedStream(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originRSTLast, 4)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	ids := []uint32{1, 3, 5, 7}
	cli.sendGETs(t, origin.addr, ids...)
	res := cli.collect(t, 10*time.Second, ids...)

	var ok, refused int
	for _, id := range ids {
		r := res[id]
		switch {
		case r.ended && len(r.statuses) == 1 && r.statuses[0] == "200":
			ok++
		case r.rst && r.rstCode == http2.ErrCodeRefusedStream && len(r.statuses) == 0:
			refused++
		default:
			t.Errorf("stream %d: statuses=%v ended=%v rst=%v code=%v; want 200 or RST_STREAM(REFUSED_STREAM)",
				id, r.statuses, r.ended, r.rst, r.rstCode)
		}
	}
	if ok != 3 || refused != 1 {
		t.Errorf("client outcomes: %d x 200, %d x REFUSED_STREAM; want 3 and 1", ok, refused)
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 3, "error/refused": 1}, 5*time.Second)
}

// TestH2UpstreamRSTRefused_RetryingClientSucceeds: same origin, retrying
// client — 4/4 succeed; the retry reuses the (still healthy) upstream
// connection.
func TestH2UpstreamRSTRefused_RetryingClientSucceeds(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originRSTLast, 4)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	client := newH2ClientThroughProxyForPoolTest(proxyAddr, origin.addr)
	defer client.CloseIdleConnections()

	errs := make([]error, 4)
	var wg sync.WaitGroup
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			req, _ := gohttp.NewRequestWithContext(ctx, gohttp.MethodGet,
				fmt.Sprintf("https://%s/req-%d", origin.addr, i), nil)
			resp, err := client.Do(req)
			if err != nil {
				errs[i] = err
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if resp.StatusCode != gohttp.StatusOK {
				errs[i] = fmt.Errorf("status %d", resp.StatusCode)
			}
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("request %d: %v; want 200", i, err)
		}
	}
	waitStreamOutcomes(t, store, map[string]int{"complete/": 4, "error/refused": 1}, 5*time.Second)
}

// TestH2UpstreamRefused_AfterEarlyHints_ClientSeesCancel is the guard for
// the "response already started" rule: once a 103 Early Hints HEADERS has
// been forwarded, the stream is no longer unprocessed from the client's
// point of view, so the proxy must keep resetting it with CANCEL even though
// the upstream refused it afterwards.
func TestH2UpstreamRefused_AfterEarlyHints_ClientSeesCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originEarlyHintsThenRST, 1)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	cli.sendGETs(t, origin.addr, 1)
	r := cli.collect(t, 10*time.Second, 1)[1]

	if len(r.statuses) != 1 || r.statuses[0] != "103" {
		t.Fatalf("response HEADERS statuses = %v, want [103] forwarded before the reset", r.statuses)
	}
	if !r.rst || r.rstCode != http2.ErrCodeCancel {
		t.Errorf("stream 1: rst=%v code=%v, want RST_STREAM(CANCEL)", r.rst, r.rstCode)
	}
	waitStreamOutcomes(t, store, map[string]int{"error/refused": 1}, 5*time.Second)
}

// TestH2UpstreamGoAway_NoRSTSentUpstreamOnRefusedStreams pins the upstream
// leg: after GOAWAY(last_stream_id=N), the proxy must not send RST_STREAM
// on the streams above N while tearing the sessions down — the origin
// already declared them closed and unprocessed (RFC 9113 §6.8), and
// answering a refusal with a reset is what RFC 9113 §5.4.2 forbids for
// RST_STREAM.
func TestH2UpstreamGoAway_NoRSTSentUpstreamOnRefusedStreams(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2Origin(t, originGoAwayAfterFirst, 4)
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	ids := []uint32{1, 3, 5, 7}
	cli.sendGETs(t, origin.addr, ids...)
	_ = cli.collect(t, 10*time.Second, ids...)

	select {
	case <-origin.firstConnDone:
	case <-time.After(10 * time.Second):
		t.Fatal("origin's first connection did not finish its post-GOAWAY hold")
	}
	refused := origin.refusedIDs()
	if len(refused) != 3 {
		t.Fatalf("origin refused %d streams, want 3", len(refused))
	}
	for _, f := range origin.framesAfterRefusal() {
		if f.typ == http2.FrameRSTStream && refused[f.streamID] {
			t.Errorf("proxy sent RST_STREAM(%v) upstream on GOAWAY-refused stream %d", f.rstCode, f.streamID)
		}
	}
}
