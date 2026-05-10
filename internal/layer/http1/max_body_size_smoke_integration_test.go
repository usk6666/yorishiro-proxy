//go:build e2e

package http1_test

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// USK-799 — smoke-tier verification that the HTTP/1.x channel honours an
// operator-configured MaxBodySize override. The exhaustive 25 MiB / 254 MiB
// scenarios live in large_body_integration_test.go (full tier); this smoke
// test economises with a 1 MiB cap + 2 MiB body so the merge gate can
// re-validate the wire-cap path quickly on every PR.
func TestSmoke_HTTP1_MaxBodySize_StreamErrorOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

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
	respBody := makeSmokeBody(smokeBodySize)

	upstreamLn, _ := startUpstreamHTTPS(t, func(_ []byte) []byte {
		hdr := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(respBody))
		out := make([]byte, 0, len(hdr)+len(respBody))
		out = append(out, []byte(hdr)...)
		out = append(out, respBody...)
		return out
	})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	spillDir := t.TempDir()
	proxyAddr, store, sessionDone := startHTTPMITMProxy(t, ctx, target, proxyOpts{
		bodySpillDir:       spillDir,
		bodySpillThreshold: smokeSpillThreshold,
		maxBodySize:        smokeMaxBodyCap,
	})

	tlsConn := connectThroughProxy(t, proxyAddr, target)
	defer tlsConn.Close()
	rawReq := fmt.Sprintf("GET /toobig HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", target)
	if _, err := tlsConn.Write([]byte(rawReq)); err != nil {
		t.Fatalf("write request: %v", err)
	}
	tlsConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	_, _ = io.ReadAll(tlsConn)

	select {
	case <-sessionDone:
	case <-time.After(20 * time.Second):
		t.Fatal("timeout waiting for session to complete")
	}

	deadline := time.Now().Add(5 * time.Second)
	var stStream string
	var stReason string
	for time.Now().Before(deadline) {
		for _, st := range store.getStreams() {
			if st.State == "error" {
				stStream = st.ID
				stReason = st.FailureReason
				break
			}
		}
		if stStream != "" {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stStream == "" {
		t.Fatalf("no stream reached state=error after MaxBodySize cap exceeded")
	}
	if stReason != "internal_error" {
		t.Errorf("Stream.FailureReason = %q, want %q", stReason, "internal_error")
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
