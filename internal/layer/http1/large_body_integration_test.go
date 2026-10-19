//go:build e2e && !e2e_smoke

package http1_test

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-635 — N6.5 acceptance gate for HTTP/1.x.
//
// These tests verify that SafetyFilter, TransformEngine, variant recording,
// and temp-file cleanup all work end-to-end on bodies that exceed the spill
// threshold and thus exercise the disk-backed BodyBuffer code path.
//
// The spill threshold is lowered to spillThresholdTest (256 KiB) so a 1 MiB
// body crosses it; the code path is the same as with the 10 MiB production
// default (USK-1205). Every spill-dependent test prepends a bufferInspector
// and asserts (assertSpilled) that a file-backed BodyBuffer was actually seen
// mid-flight, so a threshold that silently stops applying fails the test
// instead of letting it pass on the in-memory path.
//
// MaxBodySize enforcement on the spill path is covered by the smoke test
// TestSmoke_HTTP1_MaxBodySize_StreamErrorOnExceed.
//
// Per USK-613 MITM-diagnostic test philosophy: assertions target recording
// outcomes (flow content, state transitions, spill-dir file counts), not
// "bytes flowed".
//
// Scenario #1 covers the REQUEST-side safety path because SafetyEngine only
// exposes CheckInput today — response-side (Output Filter) is deferred to
// USK-636 and will get a companion test when CheckOutput lands.

const (
	// spillThresholdTest is the BodySpillThreshold used by these tests.
	spillThresholdTest = 256 << 10
	// largeBodySize is above spillThresholdTest, so it spills to disk.
	largeBodySize = 1 << 20
	// smallBodySize is below spillThresholdTest, so it stays in memory.
	smallBodySize = 128 << 10

	// destructiveSQLMarker is any SQL fragment that matches the
	// destructive-sql:drop rule pattern ((?i)DROP\s+TABLE\s+...). Embedded
	// in a large POST body to prove safety filtering materializes a
	// disk-backed body and matches against it.
	destructiveSQLMarker = "DROP TABLE users;"

	// secretMarker is the plaintext replaced by TransformReplaceBody rules
	// in the tests that exercise Transform on disk-backed bodies.
	secretMarker = "SECRET"
	replaceWith  = "REDACTED"
)

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

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

// writeLargeResponse builds a complete HTTP/1.1 response with Content-Length
// framing around body and a "Connection: close" header.
func writeLargeResponse(body []byte) []byte {
	header := fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		len(body),
	)
	out := make([]byte, 0, len(header)+len(body))
	out = append(out, []byte(header)...)
	out = append(out, body...)
	return out
}

// readFullHTTPResponse reads one complete HTTP/1.1 response (status + headers
// + Content-Length-framed body) from tlsConn. Returns headers (up to and
// including \r\n\r\n) and body as separate slices. readErr is the underlying
// read error if the connection closed unexpectedly.
func readFullHTTPResponse(t *testing.T, tlsConn net.Conn) (header, body []byte, readErr error) {
	t.Helper()
	br := bufio.NewReader(tlsConn)

	var hdrBuf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			return hdrBuf.Bytes(), nil, err
		}
		hdrBuf.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}
	header = hdrBuf.Bytes()

	cl := 0
	for _, line := range strings.Split(string(header), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			cl, _ = strconv.Atoi(val)
		}
	}
	if cl <= 0 {
		return header, nil, nil
	}
	body = make([]byte, cl)
	_, err := io.ReadFull(br, body)
	return header, body, err
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

// ---------------------------------------------------------------------------
// Scenario 2: TransformReplaceBody rewrites a disk-backed RESPONSE body
// ---------------------------------------------------------------------------
//
// TransformEngine.TransformResponse materializes msg.BodyBuffer, regex-
// replaces, and commits msg.Body. USK-631 guarantees the committed bytes
// round-trip to the client via the http1 channel's Send path (synthetic send
// because BodyBuffer was released on Transform commit).

func TestLargeBody_HTTP1_TransformReplacesDiskBackedBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedMarker(makeLargeBody(largeBodySize), secretMarker, largeBodySize/2)
	expectedBytes := bytes.Replace(respBody, []byte(secretMarker), []byte(replaceWith), 1)

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return writeLargeResponse(respBody)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	transformEngine := httprules.NewTransformEngine()
	transformEngine.SetRules([]httprules.TransformRule{{
		ID:          "redact-secret",
		Enabled:     true,
		Priority:    1,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformReplaceBody,
		BodyPattern: regexp.MustCompile(secretMarker),
		BodyReplace: replaceWith,
	}})

	spillDir := t.TempDir()
	inspector := &bufferInspector{spillDir: spillDir}
	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		transformEngine:    transformEngine,
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThresholdTest,
		prependCustomSteps: []pipeline.Step{inspector},
	})

	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()
	rawReq := fmt.Sprintf("GET /big HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))

	_, got, readErr := readFullHTTPResponse(t, tlsConn)
	if readErr != nil && readErr != io.EOF {
		t.Fatalf("read response: %v", readErr)
	}
	if len(got) != len(expectedBytes) {
		t.Fatalf("client body length = %d, want %d", len(got), len(expectedBytes))
	}
	gotHash := sha256.Sum256(got)
	wantHash := sha256.Sum256(expectedBytes)
	if gotHash != wantHash {
		t.Errorf("client body hash mismatch: got=%x want=%x", gotHash, wantHash)
	}

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertSpilled(t, inspector, largeBodySize)
	if bytes.Contains(got, []byte(secretMarker)) {
		t.Errorf("client body still contains %q — Transform did not replace", secretMarker)
	}
	if !bytes.Contains(got, []byte(replaceWith)) {
		t.Errorf("client body missing replacement %q", replaceWith)
	}

	if n := countSpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Scenario 3: Variant recording preserves both original and modified disk-backed bodies
// ---------------------------------------------------------------------------
//
// RecordStep's variant path takes a snapshot before Pipeline Run. For
// disk-backed bodies, USK-631 Retains the BodyBuffer on CloneMessage so the
// snapshot can materialize the original bytes even after Transform commits
// a new msg.Body. Both variants must land in the flow store with
// Metadata["variant"] = "original"/"modified".

func TestLargeBody_HTTP1_VariantRecordingPersistsBothVersions(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	respBody := embedMarker(makeLargeBody(largeBodySize), secretMarker, largeBodySize/2)

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return writeLargeResponse(respBody)
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	transformEngine := httprules.NewTransformEngine()
	transformEngine.SetRules([]httprules.TransformRule{{
		ID:          "redact-secret",
		Enabled:     true,
		Priority:    1,
		Direction:   httprules.DirectionResponse,
		ActionType:  httprules.TransformReplaceBody,
		BodyPattern: regexp.MustCompile(secretMarker),
		BodyReplace: replaceWith,
	}})

	spillDir := t.TempDir()
	inspector := &bufferInspector{spillDir: spillDir}
	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		transformEngine:    transformEngine,
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThresholdTest,
		prependCustomSteps: []pipeline.Step{inspector},
	})

	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()
	rawReq := fmt.Sprintf("GET /variant HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, _, _ = readFullHTTPResponse(t, tlsConn)

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	assertSpilled(t, inspector, largeBodySize)

	// Locate the original + modified receive flows.
	var original, modified *flow.Flow
	for _, f := range store.allFlows() {
		if f.Direction != "receive" {
			continue
		}
		if f.Metadata == nil {
			continue
		}
		switch f.Metadata["variant"] {
		case "original":
			original = f
		case "modified":
			modified = f
		}
	}
	if original == nil {
		t.Fatal("expected original variant receive flow")
	}
	if modified == nil {
		t.Fatal("expected modified variant receive flow")
	}

	// Original must carry the untouched bytes. Modified must reflect the
	// post-transform bytes. RecordStep maxBodySize cap defaults to
	// config.MaxBodySize (254 MiB) so the body round-trips uncut.
	if len(original.Body) != largeBodySize {
		t.Errorf("original variant Body length = %d, want %d", len(original.Body), largeBodySize)
	}
	if !bytes.Contains(original.Body, []byte(secretMarker)) {
		t.Errorf("original variant must still contain %q", secretMarker)
	}
	if original.BodyTruncated {
		t.Error("original variant BodyTruncated = true; body fits under default 254 MiB cap")
	}

	expectedMod := bytes.Replace(respBody, []byte(secretMarker), []byte(replaceWith), 1)
	if len(modified.Body) != len(expectedMod) {
		t.Errorf("modified variant Body length = %d, want %d", len(modified.Body), len(expectedMod))
	}
	if bytes.Contains(modified.Body, []byte(secretMarker)) {
		t.Errorf("modified variant still contains %q — Transform did not commit", secretMarker)
	}
	if !bytes.Contains(modified.Body, []byte(replaceWith)) {
		t.Errorf("modified variant missing %q", replaceWith)
	}

	if n := countSpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", n)
	}
}

// ---------------------------------------------------------------------------
// Scenario 4: Temp-file cleanup on session end (disk-backed body)
// ---------------------------------------------------------------------------
//
// Asserts the core N6.5 invariant: a disk-backed body that traverses the
// full session lifecycle leaves zero temp files behind. Uses a custom
// Pipeline Step (bufferInspector) to snapshot the mid-flight BodyBuffer state
// — a lightweight alternative to intercept Hold that avoids the extra Clone
// Retains the HoldQueue introduces (see follow-up note in the PR).

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

func TestLargeBody_HTTP1_TempFileCleanupOnSessionEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	reqBody := makeLargeBody(largeBodySize)

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	spillDir := t.TempDir()
	inspector := &bufferInspector{spillDir: spillDir}

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThresholdTest,
		prependCustomSteps: []pipeline.Step{inspector},
	})

	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()
	reqHeader := fmt.Sprintf(
		"POST /cleanup HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		target, len(reqBody),
	)
	if _, err := tlsConn.Write([]byte(reqHeader)); err != nil {
		t.Fatalf("write headers: %v", err)
	}
	if _, err := tlsConn.Write(reqBody); err != nil {
		t.Fatalf("write body: %v", err)
	}
	tlsConn.SetReadDeadline(time.Now().Add(60 * time.Second))
	_, _ = io.ReadAll(tlsConn)

	select {
	case <-sessionDone:
	case <-time.After(60 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// Mid-flight invariant: inspector saw a file-backed BodyBuffer with the
	// full body, and at that point at least one spill file existed on disk.
	assertSpilled(t, inspector, largeBodySize)

	// Cleanup invariant: zero temp files after session.
	if n := countSpillFiles(t, spillDir); n != 0 {
		entries, _ := os.ReadDir(spillDir)
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("BodySpillDir has %d leftover files after session, want 0 (temp file leak); files: %v", n, names)
	}
}

// ---------------------------------------------------------------------------
// Scenario 5: Fast path (body <= spill threshold) produces no temp file
// ---------------------------------------------------------------------------
//
// smallBodySize (128 KiB) < spillThresholdTest (256 KiB). msg.BodyBuffer must
// be nil and msg.Body must carry the full bytes. Assert via intercept Hold
// (mid-flight) that the fast path is taken, then release normally and verify
// 0 files after.
//
// (The former Scenario 5, MaxBodySize exceeded on the spill path, is covered
// by the smoke test TestSmoke_HTTP1_MaxBodySize_StreamErrorOnExceed; smoke is
// a subset of the full tier, so it was a duplicate here.)

func TestLargeBody_HTTP1_FastPathNoTempFileBelowThreshold(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	reqBody := makeLargeBody(smallBodySize)

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

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
	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		interceptEngine:    interceptEngine,
		holdQueue:          holdQueue,
		bodySpillDir:       spillDir,
		bodySpillThreshold: spillThresholdTest,
	})

	respCh := make(chan struct{}, 1)
	go func() {
		defer func() { respCh <- struct{}{} }()
		tlsConn := connectThroughProxy(t, proxyAddr, target)
		defer tlsConn.Close()
		reqHeader := fmt.Sprintf(
			"POST /fast HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			target, len(reqBody),
		)
		_, _ = tlsConn.Write([]byte(reqHeader))
		_, _ = tlsConn.Write(reqBody)
		tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		_, _ = io.ReadAll(tlsConn)
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
	// Fast path: BodyBuffer must be nil, Body populated.
	if msg.BodyBuffer != nil {
		t.Errorf("msg.BodyBuffer = %v; a %d-byte body must not spill (below the %d-byte threshold)", msg.BodyBuffer, smallBodySize, spillThresholdTest)
	}
	if len(msg.Body) != smallBodySize {
		t.Errorf("msg.Body length = %d, want %d", len(msg.Body), smallBodySize)
	}
	if n := countSpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d files mid-flight on fast path, want 0", n)
	}

	if err := holdQueue.Release(held.ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("release: %v", err)
	}

	<-respCh
	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	if n := countSpillFiles(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d files after session on fast path, want 0", n)
	}
}
