//go:build e2e && !e2e_smoke && linux

package mcptest_test

import (
	"bytes"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// --- Test Plan #13 ---------------------------------------------------------

// TestE2E_FlowSink_StalledConsumerDoesNotDelayProxy: the sink's active
// file is a FIFO whose reader never reads, so once the pipe buffer is
// full every sink write blocks — a consumer that stopped. Proxied
// requests must still complete promptly, and query(status) must report
// the events the sink had to drop.
func TestE2E_FlowSink_StalledConsumerDoesNotDelayProxy(t *testing.T) {
	sinkDir := filepath.Join(t.TempDir(), "sink")
	if err := os.MkdirAll(sinkDir, 0o700); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(sinkDir, "flows.jsonl")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	// Hold the read end open without reading. Registered before the
	// harness so it closes after the server shut down, which unblocks the
	// stuck sink writer (EPIPE).
	reader, err := os.OpenFile(fifo, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open fifo reader: %v", err)
	}
	t.Cleanup(func() { _ = reader.Close() })

	cfg := `{"flow_sink":{"dir":"` + sinkDir + `","queue_max_events":4}}`
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{ConfigJSON: cfg})
	proxyAddr := startProxyWithPassthrough(t, h)
	upstream, _ := startObservedUpstream(t)
	client := proxyHTTPClient(t, proxyAddr)

	// 16 KiB bodies: a few lines fill the 64 KiB pipe buffer.
	body := bytes.Repeat([]byte("s"), 16<<10)
	const requests = 30
	for i := 0; i < requests; i++ {
		start := time.Now()
		r := <-requestThroughProxy(t, client, "POST", "http://"+upstream+"/sink-stall", nil, body)
		if r.err != nil || r.statusCode != 200 {
			t.Fatalf("request %d: status %d err %v", i, r.statusCode, r.err)
		}
		if d := time.Since(start); d > 2*time.Second {
			t.Fatalf("request %d took %v while the sink consumer was stalled", i, d)
		}
	}

	deadline := time.Now().Add(10 * time.Second)
	for {
		st := h.MustOK(t, "query", map[string]any{"resource": "status"}).Decoded
		sink, _ := st["flow_sink"].(map[string]any)
		if sink != nil && numFromAny(sink["dropped_events"]) > 0 {
			if numFromAny(sink["dropped_bytes"]) <= 0 {
				t.Errorf("flow_sink.dropped_bytes = %v, want > 0", sink["dropped_bytes"])
			}
			if d, _ := sink["dir"].(string); d != sinkDir {
				t.Errorf("flow_sink.dir = %q, want %q", d, sinkDir)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(status).flow_sink = %v, want dropped_events > 0", sink)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
