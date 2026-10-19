//go:build e2e

package http1_test

// USK-635 / USK-1213 smoke tier: the HTTP/1.x SafetyFilter must match a
// destructive pattern inside a body that spilled to disk. This file owns the
// spill harness (thresholds, body builders, bufferInspector, assertSpilled);
// the exhaustive-tier siblings in large_body_integration_test.go (Transform,
// variant recording, temp-file cleanup, fast path, large-body round trips)
// reuse it. See that file's header for the full scenario list.

import (
	"context"
	"fmt"
	"io"
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
	// spillThresholdTest is the BodySpillThreshold used by these tests.
	spillThresholdTest = 256 << 10
	// largeBodySize is above spillThresholdTest, so it spills to disk.
	largeBodySize = 1 << 20

	// destructiveSQLMarker is any SQL fragment that matches the
	// destructive-sql:drop rule pattern ((?i)DROP\s+TABLE\s+...). Embedded
	// in a large POST body to prove safety filtering materializes a
	// disk-backed body and matches against it.
	destructiveSQLMarker = "DROP TABLE users;"
)

// makeLargeBody returns size bytes of deterministic content. Values cycle
// through 0..250 (prime modulus keeps the pattern non-trivial), matching the
// precedent in TestHTTPSMITM_LargeBodyRoundtrip.
func makeLargeBody(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// embedMarker overwrites bytes at offset with marker and returns body
// unchanged. Caller supplies an offset large enough to ensure the marker
// lands inside the disk-backed portion (> spill threshold) — typically the
// middle of the body.
func embedMarker(body []byte, marker string, offset int) []byte {
	if offset+len(marker) > len(body) {
		offset = len(body) - len(marker)
	}
	copy(body[offset:], []byte(marker))
	return body
}

// countSpillFiles returns the number of files in dir whose name starts with
// config.BodySpillPrefix. Subdirectories and non-spill files are ignored.
// Returns 0 if dir does not exist.
func countSpillFiles(t *testing.T, dir string) int {
	t.Helper()
	if dir == "" {
		t.Fatal("countSpillFiles: empty dir")
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

// bufferInspector is a Pipeline Step that records whether the envelope it sees
// carries a file-backed BodyBuffer. Used by the cleanup test to prove the
// mid-flight disk-spill path was exercised without introducing extra Clone
// Retains via HoldQueue.
type bufferInspector struct {
	sawFileBacked atomic.Bool
	bodyLen       atomic.Int64
	filesOnDisk   atomic.Int32
	spillDir      string
}

func (b *bufferInspector) Process(_ context.Context, env *envelope.Envelope) pipeline.Result {
	if m, ok := env.Message.(*envelope.HTTPMessage); ok && m != nil && m.BodyBuffer != nil {
		if m.BodyBuffer.IsFileBacked() {
			b.sawFileBacked.Store(true)
		}
		b.bodyLen.Store(m.BodyBuffer.Len())
		if entries, err := os.ReadDir(b.spillDir); err == nil {
			var n int32
			for _, e := range entries {
				if !e.IsDir() && strings.HasPrefix(e.Name(), config.BodySpillPrefix) {
					n++
				}
			}
			b.filesOnDisk.Store(n)
		}
	}
	return pipeline.Result{}
}

// assertSpilled fails t unless inspector saw a file-backed BodyBuffer of
// wantLen bytes with at least one spill file on disk at that moment. It is
// what keeps these tests from passing vacuously on the in-memory path when
// the spill threshold does not apply.
func assertSpilled(t *testing.T, inspector *bufferInspector, wantLen int) {
	t.Helper()
	if !inspector.sawFileBacked.Load() {
		t.Errorf("bufferInspector did not observe a file-backed BodyBuffer; a %d-byte body must spill above the %d-byte threshold", wantLen, spillThresholdTest)
	}
	if got := inspector.bodyLen.Load(); got != int64(wantLen) {
		t.Errorf("bufferInspector observed BodyBuffer length = %d, want %d", got, wantLen)
	}
	if got := inspector.filesOnDisk.Load(); got < 1 {
		t.Errorf("bufferInspector observed %d spill files mid-flight, want >= 1", got)
	}
}

// ---------------------------------------------------------------------------
// Scenario 1: SafetyFilter matches a disk-backed REQUEST body
// ---------------------------------------------------------------------------
//
// The SafetyEngine.CheckInput path reads msg.BodyBuffer.Bytes(ctx) via
// materializeBody when targeting TargetBody. This test proves the pipeline
// (a) drains the body into a file-backed BodyBuffer, (b) materializes it for
// pattern matching, (c) drops the envelope so upstream never receives the
// request, and (d) releases the temp file before session end.
//
// Response-side (Output Filter) safety on disk-backed bodies is deferred to
// USK-636; this test is the request-side half of that coverage.

func TestLargeBody_HTTP1_SafetyFilterMatchesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	body := embedMarker(makeLargeBody(largeBodySize), destructiveSQLMarker, largeBodySize/2)

	// Upstream should never be contacted. Return a canned response if it is,
	// so we can distinguish "safety blocked" (upstream got 0 requests) from
	// "upstream got the request and replied".
	upstreamLn, getUpstreamReqs := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	safetyEngine := httprules.NewSafetyEngine()
	if err := safetyEngine.LoadPreset(common.PresetDestructiveSQL); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}

	spillDir := t.TempDir()
	inspector := &bufferInspector{spillDir: spillDir}
	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		safetyEngine:       safetyEngine,
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThresholdTest,
		prependCustomSteps: []pipeline.Step{inspector},
	})

	// Send the large POST. We expect no HTTP response (safety drop closes
	// the client side without replying in the RFC-001 pipeline).
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	reqHeader := fmt.Sprintf(
		"POST /sql HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nContent-Type: application/sql\r\nConnection: close\r\n\r\n",
		target, len(body),
	)
	if _, err := tlsConn.Write([]byte(reqHeader)); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if _, err := tlsConn.Write(body); err != nil {
		t.Fatalf("write body: %v", err)
	}

	// Read until EOF or timeout; either means the proxy didn't respond.
	tlsConn.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, _ = io.ReadAll(tlsConn)

	// Close upstream listener so the Accept goroutine unblocks its Accept
	// call and flushes its "captured" channel. Without this, the safety-drop
	// path never triggers Accept and getUpstreamReqs would wait 15 s.
	upstreamLn.Close()
	upstreamReqs := getUpstreamReqs()

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertSpilled(t, inspector, largeBodySize)
	if got := len(upstreamReqs); got != 0 {
		t.Errorf("upstream received %d requests, want 0 (safety filter must block before dial)", got)
	}

	// Cleanup invariant: BodyBuffer for the dropped envelope must be
	// released before session end. USK-634 session backstop owns this.
	if n := countSpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files after safety-drop, want 0 (temp file leak)", n)
	}
}
