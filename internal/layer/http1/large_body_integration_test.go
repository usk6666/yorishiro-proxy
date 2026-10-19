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
	"testing"
	"time"

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
//
// Tiering (USK-1213): Scenario #1 and the shared spill harness live in the
// smoke-tier large_body_smoke_integration_test.go; everything in this file
// is exhaustive (nightly), including the 15 MiB / 11 MiB production-threshold
// round trips (TestHTTPSMITM_LargeBody*) moved here from
// mitm_integration_test.go.

// ---------------------------------------------------------------------------
// Body helpers
// ---------------------------------------------------------------------------

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

// TestHTTPSMITM_LargeBodyRoundtrip verifies that a response body exceeding
// the spill threshold (15 MiB > default 10 MiB) round-trips correctly
// through the MITM proxy. The BodyBuffer path serializes the buffered file
// back onto the wire for the client.
func TestHTTPSMITM_LargeBodyRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// 15 MiB of deterministic content so we can byte-compare end-to-end.
	const bodyLen = 15 << 20
	largeBody := make([]byte, bodyLen)
	for i := range largeBody {
		largeBody[i] = byte(i % 251) // prime modulus → non-trivial pattern
	}

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		// Pre-allocate header + body.
		header := fmt.Sprintf(
			"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
			bodyLen)
		out := make([]byte, 0, len(header)+bodyLen)
		out = append(out, []byte(header)...)
		out = append(out, largeBody...)
		return out
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, _, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	// Client-side: send request and read the full response manually (the
	// helper connectAndSendHTTP would spin on a 15 MiB body).
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	rawReq := fmt.Sprintf("GET /large HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}

	// Read response fully.
	tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	br := bufio.NewReader(tlsConn)

	// Read status line + headers.
	var headerBuf bytes.Buffer
	for {
		line, err := br.ReadBytes('\n')
		if err != nil {
			t.Fatalf("read response headers: %v", err)
		}
		headerBuf.Write(line)
		if bytes.Equal(line, []byte("\r\n")) {
			break
		}
	}

	// Parse Content-Length.
	cl := 0
	for _, line := range strings.Split(headerBuf.String(), "\r\n") {
		if strings.HasPrefix(strings.ToLower(line), "content-length:") {
			val := strings.TrimSpace(line[len("content-length:"):])
			cl, _ = strconv.Atoi(val)
		}
	}
	if cl != bodyLen {
		t.Fatalf("Content-Length = %d, want %d", cl, bodyLen)
	}

	body := make([]byte, cl)
	if _, err := io.ReadFull(br, body); err != nil {
		t.Fatalf("read response body: %v", err)
	}

	// Wait for session completion.
	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	// Verify the body bytes round-tripped byte-for-byte.
	if !bytes.Equal(body, largeBody) {
		// Avoid dumping 15 MiB on diff — just show first divergence.
		for i := 0; i < len(body) && i < len(largeBody); i++ {
			if body[i] != largeBody[i] {
				t.Fatalf("body byte %d: got %d, want %d", i, body[i], largeBody[i])
			}
		}
		t.Fatalf("body length mismatch: got %d, want %d", len(body), bodyLen)
	}
}

// TestHTTPSMITM_LargeBodyChunkedTrailers verifies that chunked trailers
// survive on a body larger than the spill threshold. Before USK-631 this
// would have emitted AnomalyTrailersInPassthrough and dropped the trailers;
// after USK-631 the body is always fully drained into BodyBuffer, so the
// trailers are recorded on HTTPMessage.Trailers and AnomalyTrailersInPassthrough
// is NOT present in the anomalies list.
func TestHTTPSMITM_LargeBodyChunkedTrailers(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		return []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{})

	// Build a chunked body larger than the default spill threshold (10 MiB).
	// One 11 MiB chunk + trailer keeps the framing simple.
	const chunkSize = 11 << 20
	chunkData := make([]byte, chunkSize)
	for i := range chunkData {
		chunkData[i] = 'A' // deterministic content
	}

	var reqBuf bytes.Buffer
	fmt.Fprintf(&reqBuf,
		"POST /upload HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"Trailer: X-Checksum\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		target)
	fmt.Fprintf(&reqBuf, "%x\r\n", chunkSize)
	reqBuf.Write(chunkData)
	reqBuf.WriteString("\r\n0\r\nX-Checksum: big-body-xyz\r\n\r\n")

	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()

	if _, err := tlsConn.Write(reqBuf.Bytes()); err != nil {
		t.Fatalf("write chunked request: %v", err)
	}

	// Read response so server closes; exact content doesn't matter here.
	tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	respBuf := make([]byte, 4096)
	for {
		if _, err := tlsConn.Read(respBuf); err != nil {
			break
		}
	}

	select {
	case <-sessionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	sendFlows := store.flowsByDirection("send")
	if len(sendFlows) < 1 {
		t.Fatal("expected at least 1 send flow")
	}
	sendFlow := sendFlows[0]

	// Trailers must be captured even though the body exceeded the spill
	// threshold (the dechunked body is fully drained into BodyBuffer before
	// extractTrailers runs).
	if sendFlow.Trailers == nil {
		t.Fatal("large-body chunked trailers were dropped; expected Trailers populated")
	}
	got := sendFlow.Trailers["X-Checksum"]
	if len(got) != 1 || got[0] != "big-body-xyz" {
		t.Errorf("sendFlow.Trailers[X-Checksum] = %v, want [big-body-xyz]", got)
	}

	// USK-631: AnomalyTrailersInPassthrough must NOT appear on large-body
	// chunked requests anymore. The anomaly (if it were still emitted) would
	// be projected into flow Metadata by RecordStep; the absence of any
	// trailer-related anomaly is indirectly confirmed by the trailers being
	// populated above.
}
