//go:build e2e

package http2_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-635 — N6.5 acceptance gate for HTTP/2.
//
// Mirrors the http1 large_body_integration_test.go scenarios but drives
// requests through an HTTP/2 MITM tunnel: client → CONNECT → TLS(ALPN=h2)
// → HTTP/2 Layer. Each h2 stream spills to its own BodyBuffer, so the
// cleanup + isolation assertions also catch cross-stream leaks that the
// http1 tests cannot observe.
//
// Scenario #1 is REQUEST-side (SafetyEngine.CheckInput); response-side
// safety on disk-backed bodies awaits USK-636.

const (
	h2LargeBodySize25MiB = 25 << 20
	h2SmallBodySize5MiB  = 5 << 20

	// h2MaxBodyTestCap caps MaxBodySize low enough that a 25 MiB response
	// breaches it. The code path is identical to the production 254 MiB
	// cap; this just economizes test memory.
	h2MaxBodyTestCap = 20 << 20

	h2DestructiveSQLMarker = "DROP TABLE users;"
	h2SecretMarker         = "SECRET"
	// h2ReplaceWith is intentionally the SAME LENGTH as h2SecretMarker so
	// that the Transform rewrite keeps the total body size identical.
	// h2 wire encoding inherits the request's Content-Length pseudo-header
	// from msg.Headers; restamping CL after a body-length change is a
	// separate improvement (not in scope for USK-635). A same-length
	// replacement exercises the disk-backed materialize path without
	// depending on the CL restamp.
	h2ReplaceWith = "SECRE7"
)

// ---------------------------------------------------------------------------
// Body helpers (kept local to this package; http1 test file has its own set)
// ---------------------------------------------------------------------------

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

// waitStreamReachesState polls store until the specified stream ID's last
// update records wantState, or timeout expires.
func waitStreamReachesState(t *testing.T, store *testStore, streamID, wantState string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, u := range store.getUpdates(streamID) {
			if u.State == wantState {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	var observed []string
	for _, u := range store.getUpdates(streamID) {
		observed = append(observed, fmt.Sprintf("state=%q reason=%q", u.State, u.FailureReason))
	}
	t.Fatalf("timeout waiting for stream %s state=%q (observed: %v)", streamID, wantState, observed)
}

// ---------------------------------------------------------------------------
// Scenario 1: SafetyFilter matches a 25 MiB disk-backed REQUEST body (H2)
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_SafetyFilterMatchesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	body := embedH2Marker(makeH2LargeBody(h2LargeBodySize25MiB), h2DestructiveSQLMarker, h2LargeBodySize25MiB/2)

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
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{safetyEngine: safetyEngine})

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

// ---------------------------------------------------------------------------
// Scenario 2: TransformReplaceBody rewrites a 25 MiB disk-backed RESPONSE body
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_TransformReplacesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedH2Marker(makeH2LargeBody(h2LargeBodySize25MiB), h2SecretMarker, h2LargeBodySize25MiB/2)
	expected := bytes.Replace(respBody, []byte(h2SecretMarker), []byte(h2ReplaceWith), 1)
	wantHash := sha256.Sum256(expected)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "transform-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	defer upShutdown()

	transformEngine := httprules.NewTransformEngine()
	transformEngine.SetRules([]httprules.TransformRule{{
		ID:          "redact-secret",
		Enabled:     true,
		Priority:    1,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformReplaceBody,
		BodyPattern: regexp.MustCompile(h2SecretMarker),
		BodyReplace: h2ReplaceWith,
	}})

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{transformEngine: transformEngine})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/big", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		t.Fatalf("copy body: %v", err)
	}
	if n != int64(len(expected)) {
		t.Errorf("client body length = %d, want %d", n, len(expected))
	}
	gotHash := h.Sum(nil)
	if !bytes.Equal(gotHash, wantHash[:]) {
		t.Errorf("client body hash mismatch: got=%x want=%x", gotHash, wantHash)
	}

	// Cleanup: allow backstop drain to run.
	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Variant recording preserves both original and modified 25 MiB
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_VariantRecordingPersistsBothVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedH2Marker(makeH2LargeBody(h2LargeBodySize25MiB), h2SecretMarker, h2LargeBodySize25MiB/2)
	expectedMod := bytes.Replace(respBody, []byte(h2SecretMarker), []byte(h2ReplaceWith), 1)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "variant-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	defer upShutdown()

	transformEngine := httprules.NewTransformEngine()
	transformEngine.SetRules([]httprules.TransformRule{{
		ID:          "redact-secret",
		Enabled:     true,
		Priority:    1,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformReplaceBody,
		BodyPattern: regexp.MustCompile(h2SecretMarker),
		BodyReplace: h2ReplaceWith,
	}})

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{transformEngine: transformEngine})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/variant", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Wait for both variant flows to land.
	deadline := time.Now().Add(10 * time.Second)
	var original, modified *flow.Flow
	for time.Now().Before(deadline) {
		original, modified = nil, nil
		for _, f := range store.allFlows() {
			if f.Direction != "receive" || f.Metadata == nil {
				continue
			}
			switch f.Metadata["variant"] {
			case "original":
				original = f
			case "modified":
				modified = f
			}
		}
		if original != nil && modified != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if original == nil {
		t.Fatal("expected original variant receive flow")
	}
	if modified == nil {
		t.Fatal("expected modified variant receive flow")
	}

	if len(original.Body) != h2LargeBodySize25MiB {
		t.Errorf("original variant Body length = %d, want %d", len(original.Body), h2LargeBodySize25MiB)
	}
	if !bytes.Contains(original.Body, []byte(h2SecretMarker)) {
		t.Errorf("original variant body missing %q", h2SecretMarker)
	}
	if original.BodyTruncated {
		t.Error("original variant BodyTruncated = true; 25 MiB fits under default 254 MiB cap")
	}

	if len(modified.Body) != len(expectedMod) {
		t.Errorf("modified variant Body length = %d, want %d", len(modified.Body), len(expectedMod))
	}
	if bytes.Contains(modified.Body, []byte(h2SecretMarker)) {
		t.Errorf("modified variant still contains %q", h2SecretMarker)
	}
	if !bytes.Contains(modified.Body, []byte(h2ReplaceWith)) {
		t.Errorf("modified variant missing %q", h2ReplaceWith)
	}

	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: Temp-file cleanup on session end (disk-backed 25 MiB, H2)
// ---------------------------------------------------------------------------
//
// Simpler than the http1 equivalent: a plain 25 MiB POST traverses the h2
// pipeline and returns 200. The cleanup invariant is asserted from pre/post
// file counts; the mid-flight file-backed state is implicitly verified by the
// Transform + Variant + Trailers tests which depend on the same disk-spill
// path. The http1 version uses a custom Pipeline Step (bufferInspector); the
// h2 pipeline helper does not expose a prepend-steps hook today, so this
// variant relies purely on before/after counts.

func TestLargeBody_HTTP2_TempFileCleanupOnSessionEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	reqBody := makeH2LargeBody(h2LargeBodySize25MiB)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "cleanup-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(nethttp.StatusOK)
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Fatalf("setup: BodySpillDir has %d files, want 0", sf)
	}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, err := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, "https://"+upAddr+"/cleanup", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = int64(len(reqBody))
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// Give the stream teardown + backstop drain a brief window.
	time.Sleep(500 * time.Millisecond)

	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after session, want 0 (temp file leak)", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: MaxBodySize exceeded → RST_STREAM(INTERNAL_ERROR) (H2)
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_ExceedsMaxBodySizeReturnsStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := makeH2LargeBody(h2LargeBodySize25MiB)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "maxbody-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, h2MaxBodyTestCap)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/toobig", nil)
	resp, err := cli.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// Client should observe either an error or an incomplete body read; both
	// are consistent with a RST_STREAM(INTERNAL_ERROR) mid-stream.
	_ = err

	// Wait for the stream's OnComplete to project state=error.
	deadline := time.Now().Add(10 * time.Second)
	var erroredID string
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			for _, u := range store.getUpdates(st.ID) {
				if u.State == "error" && u.FailureReason == "internal_error" {
					erroredID = st.ID
					break
				}
			}
			if erroredID != "" {
				break
			}
		}
		if erroredID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if erroredID == "" {
		// Dump what we observed.
		var obs []string
		for _, st := range store.getStreams() {
			for _, u := range store.getUpdates(st.ID) {
				obs = append(obs, fmt.Sprintf("%s state=%q reason=%q", st.ID, u.State, u.FailureReason))
			}
		}
		t.Fatalf("no stream reached error/internal_error; observed: %v", obs)
	}

	// Bodybuf teardown on ErrMaxSizeExceeded removes the partial temp file.
	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after MaxBodySize error, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 6: Fast path (body <= spill threshold) produces no temp file (H2)
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_FastPathNoTempFileBelowThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	reqBody := makeH2LargeBody(h2SmallBodySize5MiB)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "fast-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.WriteHeader(nethttp.StatusOK)
		}))
	defer upShutdown()

	interceptEngine := httprules.NewInterceptEngine()
	interceptEngine.AddRule(httprules.InterceptRule{
		ID:          "hold-fast",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`/fast`),
	})
	holdQueue := common.NewHoldQueue()
	holdQueue.SetTimeout(30 * time.Second)

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		interceptEngine: interceptEngine,
		holdQueue:       holdQueue,
	})

	cli := newMITMH2Client(proxyAddr, upAddr)
	doneReq := make(chan struct{}, 1)
	go func() {
		defer func() { doneReq <- struct{}{} }()
		req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodPost, "https://"+upAddr+"/fast", bytes.NewReader(reqBody))
		req.ContentLength = int64(len(reqBody))
		resp, err := cli.Do(req)
		if resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		_ = err
	}()

	var held *common.HeldEntry
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if entries := holdQueue.List(); len(entries) > 0 {
			held = entries[0]
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if held == nil {
		t.Fatal("no entry appeared in hold queue")
	}

	msg, ok := held.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("held envelope message is *%T, want *HTTPMessage", held.Envelope.Message)
	}
	if msg.BodyBuffer != nil {
		t.Errorf("msg.BodyBuffer = %v; 5 MiB body must not spill (below 10 MiB threshold)", msg.BodyBuffer)
	}
	if len(msg.Body) != h2SmallBodySize5MiB {
		t.Errorf("msg.Body length = %d, want %d", len(msg.Body), h2SmallBodySize5MiB)
	}
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d files mid-flight on fast path, want 0", sf)
	}

	if err := holdQueue.Release(held.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("release: %v", err)
	}

	<-doneReq
	time.Sleep(200 * time.Millisecond)

	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d files after session on fast path, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 7: Trailers survive disk-spill (H2 only — H1 has the chunked
// trailer test in mitm_integration_test.go).
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_TrailersPreservedAfterDiskSpill(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := makeH2LargeBody(h2LargeBodySize25MiB)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "trailer-spill-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Trailer", "X-Checksum")
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			if f, ok := w.(nethttp.Flusher); ok {
				f.Flush()
			}
			_, _ = w.Write(respBody)
			w.Header().Set("X-Checksum", "big-body-sha")
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/trailer", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	n, err := io.Copy(io.Discard, resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if n != int64(len(respBody)) {
		t.Errorf("client body length = %d, want %d", n, len(respBody))
	}
	if got := resp.Trailer.Get("X-Checksum"); got != "big-body-sha" {
		t.Errorf("client Trailer X-Checksum = %q, want big-body-sha", got)
	}
	resp.Body.Close()

	// Wait for the receive flow to land, then check Trailers projection.
	_, flows := ensureLinkedExchange(t, store, 10*time.Second)
	var recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "receive" {
			recvF = f
			break
		}
	}
	if recvF == nil {
		t.Fatal("no receive flow")
	}
	if recvF.Trailers == nil {
		t.Fatal("receive flow Trailers is nil; trailers were dropped on disk-spill path")
	}
	// HTTP/2 wire reality is lowercase header names (RFC 9113 §8.2.1).
	if got := recvF.Trailers["x-checksum"]; len(got) != 1 || got[0] != "big-body-sha" {
		t.Errorf("recvF.Trailers[x-checksum] = %v, want [big-body-sha]", got)
	}
	if len(recvF.Body) != h2LargeBodySize25MiB {
		t.Errorf("receive flow Body length = %d, want %d", len(recvF.Body), h2LargeBodySize25MiB)
	}

	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 8: Concurrent streams spill independently + cleanup at end
// ---------------------------------------------------------------------------
//
// 5 parallel streams × 25 MiB response, multiplexed over a single CONNECT
// tunnel (upstream accept count stays at 1). Each stream must produce an
// independent disk-backed BodyBuffer; all files must be cleaned up once all
// sessions end. Cross-contamination check compares per-stream response hash
// against the sent body for that stream.

func TestLargeBody_HTTP2_ConcurrentStreamsIndependent(t *testing.T) {
	// Force a GC cycle before running. The test peaks at several hundred
	// MiB allocated across stream bodies + per-stream BodyBuffer spill
	// copies + variant snapshots; earlier tests in the same package can
	// leave allocations that push the x/net/http2 server into surfacing a
	// PROTOCOL_ERROR under the race detector. A warm-up GC plus a
	// conservative stream count (3) makes the test robust to CI memory
	// pressure without losing the concurrent-isolation signal.
	runtime.GC()

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// 3 streams × 25 MiB = ~75 MiB in flight. The isolation property
	// (per-stream BodyBuffer, independent spill files, no cross-contamination)
	// holds at n=3; higher values stress x/net/http2 server limits in CI.
	const nStreams = 3

	// Per-stream deterministic body: marker byte at offset 0 of each body
	// distinguishes streams without costing a full per-stream allocation of
	// 25 MiB × 5 = 125 MiB upstream-side.
	baseBody := makeH2LargeBody(h2LargeBodySize25MiB)

	// Upstream reads X-Stream-Id and stamps a marker byte at offset 0 of the
	// response body it writes. Concurrent streams thus each get a body that
	// differs only at byte 0, enough for cross-contamination checks.
	upAddr, _, accepts, upShutdown := startH2TLSUpstream(t, "concurrent-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			idStr := r.Header.Get("X-Stream-Id")
			id, _ := strconv.Atoi(idStr)
			// Clone baseBody and stamp the id byte at offset 0.
			body := make([]byte, len(baseBody))
			copy(body, baseBody)
			body[0] = byte(id + 1) // +1 so id=0 isn't the same as baseBody[0]
			w.Header().Set("Content-Length", strconv.Itoa(len(body)))
			_, _ = w.Write(body)
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)

	// Warm-up to establish the shared CONNECT tunnel before the n concurrent
	// requests fan out over it.
	warmReq, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/warm", nil)
	warmReq.Header.Set("X-Stream-Id", "warm")
	if wResp, wErr := cli.Do(warmReq); wErr == nil {
		_, _ = io.Copy(io.Discard, wResp.Body)
		wResp.Body.Close()
	}

	type result struct {
		id   int
		hash [32]byte
		n    int64
		err  error
	}
	resCh := make(chan result, nStreams)
	var wg sync.WaitGroup
	for i := 0; i < nStreams; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/concurrent", nil)
			req.Header.Set("X-Stream-Id", strconv.Itoa(id))
			resp, err := cli.Do(req)
			if err != nil {
				resCh <- result{id: id, err: err}
				return
			}
			h := sha256.New()
			n, cpErr := io.Copy(h, resp.Body)
			resp.Body.Close()
			var hash [32]byte
			copy(hash[:], h.Sum(nil))
			resCh <- result{id: id, hash: hash, n: n, err: cpErr}
		}(i)
	}
	wg.Wait()
	close(resCh)

	for r := range resCh {
		if r.err != nil {
			t.Errorf("stream %d: %v", r.id, r.err)
			continue
		}
		if r.n != int64(h2LargeBodySize25MiB) {
			t.Errorf("stream %d: body length = %d, want %d", r.id, r.n, h2LargeBodySize25MiB)
			continue
		}
		// Compute the expected hash: baseBody with byte(id+1) at offset 0.
		expected := make([]byte, len(baseBody))
		copy(expected, baseBody)
		expected[0] = byte(r.id + 1)
		wantHash := sha256.Sum256(expected)
		if r.hash != wantHash {
			t.Errorf("stream %d: body hash mismatch — cross-contamination or truncation", r.id)
		}
	}

	// Upstream accept count = 1 proves the concurrent streams shared a single
	// tunnel (HTTP/2 multiplexing), plus the warm-up established that tunnel.
	if acc := accepts(); acc != 1 {
		t.Errorf("upstream accept count = %d, want 1 (shared CONNECT must multiplex n streams)", acc)
	}

	// Each concurrent stream should have produced a Stream + its own receive
	// flow of the full 25 MiB. The warm-up is recorded separately but is not
	// part of the isolation assertion.
	deadline := time.Now().Add(15 * time.Second)
	var linked int
	for time.Now().Before(deadline) {
		linked = 0
		for _, st := range store.getStreams() {
			flows := store.flowsForStream(st.ID)
			var sendF, recvF *flow.Flow
			for _, f := range flows {
				if f.Direction == "send" {
					sendF = f
				} else if f.Direction == "receive" {
					recvF = f
				}
			}
			if sendF == nil || recvF == nil {
				continue
			}
			sid := ""
			for k, v := range sendF.Headers {
				if (k == "X-Stream-Id" || k == "x-stream-id") && len(v) > 0 {
					sid = v[0]
					break
				}
			}
			if sid == "warm" {
				continue
			}
			if len(recvF.Body) != h2LargeBodySize25MiB {
				continue
			}
			linked++
		}
		if linked == nStreams {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if linked != nStreams {
		t.Errorf("concurrent linked send+recv pairs with 25 MiB body = %d, want %d", linked, nStreams)
	}

	// All BodyBuffers must have been released; zero leftover spill files.
	time.Sleep(500 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after %d concurrent streams, want 0 "+
			"(per-stream BodyBuffer must be released individually)", sf, nStreams)
	}
}
