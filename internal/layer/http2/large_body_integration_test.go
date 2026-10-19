//go:build e2e && !e2e_smoke

package http2_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	nethttp "net/http"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
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
//
// The spill threshold is lowered to h2SpillThresholdTest (256 KiB) so 1 MiB
// bodies cross it; the code path is the same as with the 10 MiB production
// default (USK-1205). Every spill-dependent test prepends an
// h2BufferInspector and asserts that a file-backed BodyBuffer was actually
// seen mid-flight, so a threshold that silently stops applying fails the
// test instead of letting it pass on the in-memory path.
//
// Tiering (USK-1213): Scenario #1 and the shared spill harness live in the
// smoke-tier large_body_smoke_integration_test.go; everything in this file
// is exhaustive (nightly), including the 11 MiB production-threshold round
// trip (Scenario 9) moved here from http2_integration_test.go.

// ---------------------------------------------------------------------------
// Body helpers (kept local to this package; http1 test file has its own set)
// ---------------------------------------------------------------------------

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
// Scenario 2: TransformReplaceBody rewrites a disk-backed RESPONSE body
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_TransformReplacesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedH2Marker(makeH2LargeBody(h2LargeBodySize), h2SecretMarker, h2LargeBodySize/2)
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
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		transformEngine:    transformEngine,
		prependCustomSteps: []pipeline.Step{inspector},
	})

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
	assertH2Spilled(t, inspector, 1, h2LargeBodySize)

	// Cleanup: allow backstop drain to run.
	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Variant recording preserves both original and modified bodies
// ---------------------------------------------------------------------------

func TestLargeBody_HTTP2_VariantRecordingPersistsBothVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedH2Marker(makeH2LargeBody(h2LargeBodySize), h2SecretMarker, h2LargeBodySize/2)
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
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		transformEngine:    transformEngine,
		prependCustomSteps: []pipeline.Step{inspector},
	})

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
	assertH2Spilled(t, inspector, 1, h2LargeBodySize)

	if len(original.Body) != h2LargeBodySize {
		t.Errorf("original variant Body length = %d, want %d", len(original.Body), h2LargeBodySize)
	}
	if !bytes.Contains(original.Body, []byte(h2SecretMarker)) {
		t.Errorf("original variant body missing %q", h2SecretMarker)
	}
	if original.BodyTruncated {
		t.Error("original variant BodyTruncated = true; body fits under default 254 MiB cap")
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
// Scenario 4: Temp-file cleanup on session end (disk-backed body, H2)
// ---------------------------------------------------------------------------
//
// A plain large POST traverses the h2 pipeline and returns 200. The
// h2BufferInspector proves the request body was file-backed mid-flight with a
// spill file on disk; the cleanup invariant is then asserted from the
// post-session file count.

func TestLargeBody_HTTP2_TempFileCleanupOnSessionEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	reqBody := makeH2LargeBody(h2LargeBodySize)

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
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, _ := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		prependCustomSteps: []pipeline.Step{inspector},
	})

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

	assertH2Spilled(t, inspector, 1, h2LargeBodySize)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after session, want 0 (temp file leak)", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: MaxBodySize exceeded → RST_STREAM(INTERNAL_ERROR) (H2)
// ---------------------------------------------------------------------------
//
// Threshold (256 KiB) < cap (512 KiB) < body (1 MiB): the body spills to a
// temp file first and then breaches the cap on the disk-backed path, so the
// partial temp file must be removed. The error surfaces inside the Layer
// before the envelope reaches the Pipeline, so no inspector Step can observe
// the spill; the threshold ordering above is what guarantees it. (The h2
// smoke sibling uses threshold 0, so only this test covers the cap on the
// spill path.)

func TestLargeBody_HTTP2_ExceedsMaxBodySizeReturnsStreamError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// The test only exercises the spill-to-disk path if the body spills
	// before the cap is hit: threshold < cap < body. The error is raised
	// inside the Layer, so no inspector Step can observe the spill; guard
	// the ordering here so a later constant edit cannot silently move this
	// test onto the in-memory path.
	spillThreshold, maxBodySize, bodySize := int64(h2SpillThresholdTest), int64(h2MaxBodyTestCap), int64(h2LargeBodySize)
	if !(spillThreshold < maxBodySize && maxBodySize < bodySize) {
		t.Fatalf("precondition: need spill threshold (%d) < max body size (%d) < body size (%d)",
			spillThreshold, maxBodySize, bodySize)
	}

	respBody := makeH2LargeBody(int(bodySize))

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "maxbody-marker",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, spillThreshold, maxBodySize)
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

	reqBody := makeH2LargeBody(h2SmallBodySize)

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
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
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
		t.Errorf("msg.BodyBuffer = %v; a %d-byte body must not spill (below the %d-byte threshold)", msg.BodyBuffer, h2SmallBodySize, h2SpillThresholdTest)
	}
	if len(msg.Body) != h2SmallBodySize {
		t.Errorf("msg.Body length = %d, want %d", len(msg.Body), h2SmallBodySize)
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

	respBody := makeH2LargeBody(h2LargeBodySize)

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
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		prependCustomSteps: []pipeline.Step{inspector},
	})

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
	if len(recvF.Body) != h2LargeBodySize {
		t.Errorf("receive flow Body length = %d, want %d", len(recvF.Body), h2LargeBodySize)
	}
	assertH2Spilled(t, inspector, 1, h2LargeBodySize)

	time.Sleep(200 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// ---------------------------------------------------------------------------
// Scenario 8: Concurrent streams spill independently + cleanup at end
// ---------------------------------------------------------------------------
//
// 3 parallel streams × 1 MiB response, multiplexed over a single CONNECT
// tunnel (upstream accept count stays at 1). Each stream must produce an
// independent disk-backed BodyBuffer; all files must be cleaned up once all
// sessions end. Cross-contamination check compares per-stream response hash
// against the sent body for that stream.

func TestLargeBody_HTTP2_ConcurrentStreamsIndependent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Second)
	defer cancel()

	// 3 streams × 1 MiB, each above the 256 KiB test spill threshold, so
	// the disk-spill code path is exercised per stream — the isolation
	// property the test verifies is disk-spill-aware. (USK-715 had already
	// lowered this from 25 MiB to 12 MiB to stay under x/net/http2's
	// per-connection memory ceiling with -race; USK-1205 lowered the
	// threshold instead of relying on the 10 MiB default.)
	const nStreams = 3
	const concurrentBodySize = h2LargeBodySize

	// Per-stream deterministic body: marker byte at offset 0 of each body
	// distinguishes streams without a full per-stream allocation
	// upstream-side.
	baseBody := makeH2LargeBody(concurrentBodySize)

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
	inspector := &h2BufferInspector{spillDir: spillDir}
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, h2SpillThresholdTest, 0)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{
		prependCustomSteps: []pipeline.Step{inspector},
	})

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
		if r.n != int64(concurrentBodySize) {
			t.Errorf("stream %d: body length = %d, want %d", r.id, r.n, concurrentBodySize)
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

	// Every concurrent response spilled to its own file-backed BodyBuffer
	// (the warm-up response has no body, so it does not count).
	assertH2Spilled(t, inspector, nStreams, concurrentBodySize)

	// Each concurrent stream should have produced a Stream + its own receive
	// flow of the full body. The warm-up is recorded separately but is not
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
			if len(recvF.Body) != concurrentBodySize {
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
		t.Errorf("concurrent linked send+recv pairs with full body = %d, want %d", linked, nStreams)
	}

	// All BodyBuffers must have been released; zero leftover spill files.
	time.Sleep(500 * time.Millisecond)
	if sf := countH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after %d concurrent streams, want 0 "+
			"(per-stream BodyBuffer must be released individually)", sf, nStreams)
	}
}

// ---------------------------------------------------------------------------
// Scenario 9: 11 MiB response round-trips at the production spill threshold
// (moved from http2_integration_test.go by USK-1213)
// ---------------------------------------------------------------------------

// TestLargeResponseBody_SpillRoundtrip_11MiB verifies that an 11 MiB body
// round-trips through the MITM proxy end-to-end under the USK-632 model:
// the assembler aggregates all DATA frames into a BodyBuffer (memory →
// file-backed past the configured spill threshold) and emits the envelope
// only after END_STREAM. After USK-633, RecordStep materializes the
// BodyBuffer into flow.Flow.Body via projectHTTPBody (capped at
// config.MaxBodySize = 254 MiB), so recvF.Body carries the full 11 MiB —
// the wire-observed bytes also remain on RawBytes (L7/L4 duality).
func TestLargeResponseBody_SpillRoundtrip_11MiB(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	const size = 11 << 20
	// Deterministic pattern: 256-byte repeating counter.
	pattern := make([]byte, 256)
	for i := range pattern {
		pattern[i] = byte(i)
	}
	expected := bytes.Repeat(pattern, size/256)
	if len(expected) != size {
		expected = append(expected, make([]byte, size-len(expected))...)
	}
	expectedHash := sha256.Sum256(expected)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "large-marker", nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(expected)
	}))
	defer upShutdown()

	bcfg := makeBuildCfg(t, nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, "GET", "https://"+upAddr+"/big", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer resp.Body.Close()

	h := sha256.New()
	n, err := io.Copy(h, resp.Body)
	if err != nil {
		// An analyst driving a large download MUST get the full body through
		// the proxy. A FLOW_CONTROL_ERROR is a proxy bug, not a client bug.
		t.Fatalf("copy: %v", err)
	}
	if n != size {
		t.Errorf("got %d bytes, want %d", n, size)
	}
	gotHash := h.Sum(nil)
	if !bytes.Equal(gotHash, expectedHash[:]) {
		t.Errorf("body hash mismatch: got=%x want=%x", gotHash, expectedHash)
	}

	st, flows := ensureLinkedExchange(t, store, 5*time.Second)
	var recvF *flow.Flow
	for _, f := range flows {
		if f.Direction == "receive" {
			recvF = f
			break
		}
	}
	if recvF == nil {
		t.Fatal("no receive flow under linked stream")
	}
	// RecordStep materializes the BodyBuffer into flow.Flow.Body after USK-633
	// (projectHTTPBody with MaxBodySize=254 MiB). 11 MiB fits under the cap
	// and must be recorded faithfully for analyst review.
	if len(recvF.Body) != size {
		t.Errorf("receive flow Body length = %d, want %d", len(recvF.Body), size)
	} else {
		gotBodyHash := sha256.Sum256(recvF.Body)
		if !bytes.Equal(gotBodyHash[:], expectedHash[:]) {
			t.Errorf("receive flow Body hash mismatch: got=%x want=%x", gotBodyHash, expectedHash)
		}
	}
	if len(recvF.Headers) == 0 {
		t.Error("receive flow headers missing")
	}
	if len(recvF.RawBytes) == 0 {
		t.Error("receive flow RawBytes empty")
	}

	waitForStreamState(t, store, st.ID, "complete", 5*time.Second)
}
