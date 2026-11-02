//go:build e2e

package http1_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-799 / USK-1409 — smoke-tier verification of max_body_size on the
// HTTP/1.x response path, with a 1 MiB cap and a 2 MiB body so the merge
// gate re-validates it quickly on every PR. It is also the only coverage of
// MaxBodySize on the HTTP/1.x spill path (the exhaustive duplicate in
// large_body_integration_test.go was removed by USK-1205).
//
// USK-1409 inverted the default outcome on purpose: a response no rule
// needs whole is streamed, so max_body_size (the buffering cap) no longer
// applies to it and the client gets the whole body; only the record is cut
// at max_record_body_size. The buffered outcome (stream error) still holds
// for a response that a rule forces into the buffer — see
// TestSmoke_HTTP1_MaxBodySize_BufferedStreamErrorOnExceed, which keeps the
// pre-USK-1409 assertions.
const (
	// MaxBodySize is enforced by the HTTP/1 channel only when the body
	// triggers the disk-spill path (bodies smaller than the spill
	// threshold are returned in-memory without bodybuf, so the cap is
	// not consulted). Set a small spill threshold so a 2 MiB body
	// crosses it cheaply.
	smokeMaxBodyCap     = 1 << 20       // 1 MiB
	smokeSpillThreshold = 512 * 1 << 10 // 512 KiB
	smokeBodySize       = 2 << 20       // 2 MiB
)

// startMaxBodySizeUpstream serves one 2 MiB Content-Length response.
func startMaxBodySizeUpstream(t *testing.T, respBody []byte) (target, respHead string) {
	t.Helper()
	respHead = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(respBody))
	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		out := make([]byte, 0, len(respHead)+len(respBody))
		out = append(out, []byte(respHead)...)
		out = append(out, respBody...)
		return out
	})
	t.Cleanup(func() { _ = upstreamLn.Close() })
	return upstreamLn.Addr().String(), respHead
}

// fetchToobig sends GET /toobig through the proxy and returns everything
// the client received.
func fetchToobig(t *testing.T, proxyAddr, target string) []byte {
	t.Helper()
	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()
	rawReq := fmt.Sprintf("GET /toobig HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	got, _ := io.ReadAll(tlsConn)
	return got
}

// TestSmoke_HTTP1_MaxBodySize_RecordTruncatedOnExceed: a streamed response
// over max_body_size reaches the client whole; the recorded copy is cut at
// max_record_body_size and marked.
func TestSmoke_HTTP1_MaxBodySize_RecordTruncatedOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	respBody := makeSmokeBody(smokeBodySize)
	target, respHead := startMaxBodySizeUpstream(t, respBody)

	spillDir := t.TempDir()
	opts := proxyOpts{
		bodySpillDir:       spillDir,
		bodySpillThreshold: smokeSpillThreshold,
		maxBodySize:        smokeMaxBodyCap,
		recordMaxBodySize:  smokeMaxBodyCap,
	}
	opts.responseBodyMode = bodyModeFor(opts)
	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, opts)

	got := fetchToobig(t, proxyAddr, target)
	i := bytes.Index(got, []byte("\r\n\r\n"))
	if i < 0 {
		t.Fatalf("client received no response head (%d bytes)", len(got))
	}
	clientBody := got[i+4:]
	if len(clientBody) != smokeBodySize {
		t.Fatalf("client body = %d bytes, want the whole %d", len(clientBody), smokeBodySize)
	}
	if sha256.Sum256(clientBody) != sha256.Sum256(respBody) {
		t.Fatal("client body sha256 differs from the upstream body")
	}

	select {
	case <-sessionDone:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}
	waitStreamState(t, store, "complete")

	recv := waitFlowsByDirection(t, store, "receive", 1)
	if len(recv) != 1 {
		t.Fatalf("receive flows = %d, want 1", len(recv))
	}
	fl := recv[0]
	if !fl.BodyTruncated {
		t.Error("receive flow BodyTruncated = false, want true")
	}
	if len(fl.Body) != smokeMaxBodyCap {
		t.Errorf("recorded body = %d bytes, want %d (max_record_body_size)", len(fl.Body), smokeMaxBodyCap)
	}
	if !bytes.Equal(fl.Body, respBody[:len(fl.Body)]) {
		t.Error("recorded body is not the leading bytes of the upstream body")
	}
	if fl.Metadata["http_anomaly_raw_body_truncated"] == "" {
		t.Errorf("receive flow metadata lacks http_anomaly_raw_body_truncated: %v", fl.Metadata)
	}
	if max := len(respHead) + smokeMaxBodyCap; len(fl.RawBytes) > max {
		t.Errorf("recorded raw bytes = %d, want <= head + record cap = %d", len(fl.RawBytes), max)
	}
	if n := countSpillFilesSmoke(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", n)
	}
}

// TestSmoke_HTTP1_MaxBodySize_BufferedStreamErrorOnExceed keeps the
// pre-USK-1409 assertions for a response that is still buffered: a
// replace_body rule matching the response forces the buffer, and the
// operator-configured max_body_size then ends the stream with an error.
func TestSmoke_HTTP1_MaxBodySize_BufferedStreamErrorOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	target, _ := startMaxBodySizeUpstream(t, makeSmokeBody(smokeBodySize))

	tf := httprules.NewTransformEngine()
	rule, err := httprules.CompileTransformRule("force-buffer", 0, httprules.DirectionResponse,
		"", "^/toobig$", nil, httprules.TransformReplaceBody, "", "", "never-present-marker", "x")
	if err != nil {
		t.Fatalf("CompileTransformRule: %v", err)
	}
	tf.AddRule(*rule)

	spillDir := t.TempDir()
	opts := proxyOpts{
		transformEngine:    tf,
		bodySpillDir:       spillDir,
		bodySpillThreshold: smokeSpillThreshold,
		maxBodySize:        smokeMaxBodyCap,
	}
	opts.responseBodyMode = bodyModeFor(opts)
	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, opts)

	_ = fetchToobig(t, proxyAddr, target)

	select {
	case <-sessionDone:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	st := waitStreamState(t, store, "error")
	if st.FailureReason != "internal_error" {
		t.Errorf("Stream.FailureReason = %q, want %q", st.FailureReason, "internal_error")
	}

	if n := countSpillFilesSmoke(t, spillDir); n != 0 {
		t.Errorf("BodySpillDir has %d leftover files after MaxBodySize error, want 0", n)
	}
}

// makeSmokeBody returns size bytes of deterministic content. Local helper to
// avoid depending on the e2e-only-not-smoke `makeLargeBody` from
// large_body_integration_test.go.
func makeSmokeBody(size int) []byte {
	b := make([]byte, size)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// countSpillFilesSmoke counts files in dir whose name starts with
// config.BodySpillPrefix. Local sibling of countSpillFiles (exhaustive tier).
func countSpillFilesSmoke(t *testing.T, dir string) int {
	t.Helper()
	if dir == "" {
		t.Fatal("countSpillFilesSmoke: empty dir")
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
