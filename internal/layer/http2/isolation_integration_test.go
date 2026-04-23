//go:build e2e

package http2_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// TestConnectionLevelWindowDecoupledByEventLayer (USK-637 U4 acceptance
// guard): a long-held Pipeline Intercept on one stream must NOT prevent
// other streams on the same h2 connection from completing.
//
// Pre-split behavior: Intercept holding a stream's HTTPMessage stalls the
// Layer's reader because DATA frames pile up in the Layer's BodyBuffer
// without WINDOW_UPDATE being emitted — the per-connection WINDOW fills
// once enough streams are held, and unrelated streams can no longer send
// DATA.
//
// Post-split behavior: WINDOW_UPDATE fires at DATA-frame-arrival time
// (Layer-level) regardless of whether the aggregator/Pipeline has
// consumed the event. A held Pipeline therefore cannot backpressure the
// connection-level WINDOW; Stream B's request-response completes
// independently of the held streams.
//
// The test runs:
//   - Stream A: POST /hold with a body. Intercept matches on path; the
//     request is held indefinitely.
//   - Streams C, D, E: same as A.
//   - Stream B: GET /fast (no Intercept match). Must complete within a
//     short deadline.
//
// The proxy is configured to multiplex all five streams over the same
// h2 connection (same upstream target).
func TestConnectionLevelWindowDecoupledByEventLayer(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes the request body back to avoid any server-side
	// hangs. Intercept rule is applied proxy-side; upstream is oblivious.
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "isolation-up",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			body, _ := io.ReadAll(r.Body)
			_, _ = w.Write(body)
		}))
	defer upShutdown()

	// Intercept engine: hold any request whose path starts with "/hold".
	engine := httprules.NewInterceptEngine()
	engine.SetRules([]httprules.InterceptRule{{
		ID:          "hold-path",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/hold`),
	}})
	queue := common.NewHoldQueue()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		interceptEngine: engine,
		holdQueue:       queue,
	})

	// Shared MITM client → all streams pool to the same h2 connection for
	// the same target.
	cli := newMITMH2Client(proxyAddr, upAddr)

	// Launch 4 held streams. They MUST NOT complete during the test;
	// interceptors hold them indefinitely.
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		name := fmt.Sprintf("hold-%c", 'A'+i)
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			// Use a reasonable body so per-stream WINDOW consumes a
			// visible fraction of the connection-level WINDOW if the
			// pre-split behavior were still in effect.
			body := bytes.Repeat([]byte{'x'}, 64*1024)
			req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost,
				"https://"+upAddr+"/hold?name="+name, bytes.NewReader(body))
			resp, err := cli.Do(req)
			if resp != nil {
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
			_ = err
		}(name)
	}

	// Give the held streams time to reach the Intercept step. Their
	// HEADERS and DATA frames must fully transit upstream before the
	// Intercept queue holds them.
	time.Sleep(200 * time.Millisecond)

	// Launch the "fast" stream on the same pooled h2 connection. If
	// connection-level WINDOW has been stalled by the held streams
	// (pre-split failure), this request's request body or response never
	// completes.
	fastDone := make(chan error, 1)
	go func() {
		fastCtx, fastCancel := context.WithTimeout(ctx, 10*time.Second)
		defer fastCancel()
		req, _ := nethttp.NewRequestWithContext(fastCtx, nethttp.MethodGet,
			"https://"+upAddr+"/fast", nil)
		resp, err := cli.Do(req)
		if err != nil {
			fastDone <- err
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
		fastDone <- nil
	}()

	select {
	case err := <-fastDone:
		if err != nil {
			// An error on /fast when /hold is holding indicates the
			// pre-split failure mode (connection-level WINDOW stalled).
			if strings.Contains(err.Error(), "context deadline exceeded") {
				t.Fatalf("USK-637 regression: /fast stream did not complete while /hold streams held. "+
					"Pre-split behavior: Pipeline hold blocks connection-level WINDOW. "+
					"Post-split: WINDOW_UPDATE should fire at frame-arrival, decoupling. err=%v", err)
			}
			t.Fatalf("/fast returned error: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("USK-637 regression: /fast did not complete within 10s; connection-level WINDOW is stalled by held streams")
	}

	// Release held streams so the goroutines exit cleanly. HoldQueue.Clear
	// drops pending holds (they return ctx.Canceled from Hold on ctx
	// cancellation above — this is best-effort cleanup to avoid leaking
	// goroutines past the test.
	queue.Clear()
	cancel()
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		// Non-fatal: best effort cleanup.
	}
}
