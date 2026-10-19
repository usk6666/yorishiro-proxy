//go:build e2e

package http2_test

// USK-635 / USK-1213 smoke tier: the HTTP/2 SafetyFilter must match a
// destructive pattern inside a request body that spilled to disk. This file
// owns the spill harness (thresholds, body builders, h2BufferInspector,
// assertH2Spilled); the exhaustive-tier siblings in
// large_body_integration_test.go (Transform, variant recording, cleanup,
// MaxBodySize, fast path, trailers, concurrent streams, the 11 MiB
// production-threshold round trip) reuse it. See that file's header for the
// full scenario list.

import (
	"bytes"
	"context"
	"io"
	nethttp "net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

const (
	// h2SpillThresholdTest is the BodySpillThreshold used by these tests.
	h2SpillThresholdTest = 256 << 10
	// h2LargeBodySize is above h2SpillThresholdTest, so it spills to disk.
	h2LargeBodySize = 1 << 20

	h2DestructiveSQLMarker = "DROP TABLE users;"
	h2SecretMarker         = "SECRET"
)

// makeH2LargeBody returns size bytes with a deterministic repeating pattern.
// Matches the precedent in TestLargeResponseBody_SpillRoundtrip_11MiB so
// variant recording with hash comparison is reliable.
func makeH2LargeBody(size int) []byte {
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	b := bytes.Repeat(pattern, size/256)
	if len(b) < size {
		b = append(b, make([]byte, size-len(b))...)
	}
	return b
}

// embedH2Marker overwrites marker into body at offset (or end-aligned if
// offset is beyond the body length minus marker length).
func embedH2Marker(body []byte, marker string, offset int) []byte {
	if offset+len(marker) > len(body) {
		offset = len(body) - len(marker)
	}
	copy(body[offset:], []byte(marker))
	return body
}

// countH2SpillFiles counts files in dir whose name starts with
// config.BodySpillPrefix. Returns 0 if dir does not exist.
func countH2SpillFiles(t *testing.T, dir string) int {
	t.Helper()
	if dir == "" {
		t.Fatal("countH2SpillFiles: empty dir")
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatalf("ReadDir %s: %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasPrefix(e.Name(), config.BodySpillPrefix) {
			n++
		}
	}
	return n
}

// h2BufferInspector is a Pipeline Step that records whether the HTTP
// envelopes it sees carry a file-backed BodyBuffer, and how many spill files
// were on disk at that moment. Prepended to the pipeline (before Safety /
// Transform release or replace the BodyBuffer) to prove the disk-spill path
// was really exercised. Safe for concurrent streams.
type h2BufferInspector struct {
	spillDir        string
	fileBackedCount atomic.Int32
	maxBodyLen      atomic.Int64
	maxFilesOnDisk  atomic.Int32
}

func (b *h2BufferInspector) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	m, ok := env.Message.(*envelope.HTTPMessage)
	if !ok || m == nil || m.BodyBuffer == nil || !m.BodyBuffer.IsFileBacked() {
		return pipeline.Result{}
	}
	b.fileBackedCount.Add(1)
	storeMax64(&b.maxBodyLen, m.BodyBuffer.Len())
	if entries, err := os.ReadDir(b.spillDir); err == nil {
		var n int32
		for _, e := range entries {
			if !e.IsDir() && strings.HasPrefix(e.Name(), config.BodySpillPrefix) {
				n++
			}
		}
		storeMax32(&b.maxFilesOnDisk, n)
	}
	return pipeline.Result{}
}

func storeMax64(a *atomic.Int64, v int64) {
	for {
		cur := a.Load()
		if v <= cur || a.CompareAndSwap(cur, v) {
			return
		}
	}
}

func storeMax32(a *atomic.Int32, v int32) {
	for {
		cur := a.Load()
		if v <= cur || a.CompareAndSwap(cur, v) {
			return
		}
	}
}

// assertH2Spilled fails t unless inspector saw at least wantCount file-backed
// BodyBuffers, the largest wantLen bytes long, with a spill file on disk.
func assertH2Spilled(t *testing.T, inspector *h2BufferInspector, wantCount int, wantLen int) {
	t.Helper()
	if got := inspector.fileBackedCount.Load(); got < int32(wantCount) {
		t.Errorf("inspector saw %d file-backed BodyBuffers, want >= %d; a %d-byte body must spill above the %d-byte threshold",
			got, wantCount, wantLen, h2SpillThresholdTest)
	}
	if got := inspector.maxBodyLen.Load(); got != int64(wantLen) {
		t.Errorf("inspector saw file-backed BodyBuffer length = %d, want %d", got, wantLen)
	}
	if got := inspector.maxFilesOnDisk.Load(); got < 1 {
		t.Errorf("inspector saw %d spill files mid-flight, want >= 1", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 1: SafetyFilter matches a disk-backed REQUEST body (H2)
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_SafetyFilterMatchesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	body := embedH2Marker(makeH2LargeBody(h2LargeBodySize), h2DestructiveSQLMarker, h2LargeBodySize/2)

	var upstreamHits atomic.Int32
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "safety-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			upstreamHits.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(nethttp.StatusOK)
		}))
	defer upShutdown()

	safetyEngine := httprules.NewSafetyEngine()
	if err := safetyEngine.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}

	spillDir := t.TempDir()
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		safetyEngine:       safetyEngine,
		prependCustomSteps: []pipeline.Step{inspector},
	})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, "https://"+upAddr+"/sql", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/sql")
	req.ContentLength = int64(len(body))
	resp, doErr := cli.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// doErr may be nil (upstream-free 0-length response if pipeline drops
	// before headers) or non-nil (stream reset). Either is consistent with
	// "no response from a dropped envelope" in the current pipeline — the
	// definitive assertion is that upstream never saw the request.
	_ = doErr

	// Give pipeline time to drain the drop.
	time.Sleep(500 * time.Millisecond)

	assertH2Spilled(t, inspector, 1, h2LargeBodySize)
	if h := upstreamHits.Load(); h != 0 {
		t.Errorf("upstream handler fired %d times, want 0 (safety filter must block before stream open)", h)
	}
	if n := countH2SpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files after safety-drop, want 0", n)
	}
	// No Stream record is guaranteed because SafetyStep drops before
	// RecordStep.createStream. No flow assertions needed; _ store elides the
	// unused variable.
	_ = store
}
