//go:build e2e

package http2_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	nethttp "net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// USK-799 — smoke-tier verification that the HTTP/2 channel honours an
// operator-configured MaxBodySize override. The exhaustive 25 MiB / 254 MiB
// scenarios live in large_body_integration_test.go (full tier); this smoke
// test economises with a 1 MiB cap + 2 MiB body so the merge gate can
// re-validate the wire-cap path quickly on every PR.
func TestSmoke_HTTP2_MaxBodySize_StreamErrorOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	const (
		smokeMaxBodyCap = 1 << 20 // 1 MiB
		smokeBodySize   = 2 << 20 // 2 MiB
	)
	respBody := makeSmokeH2Body(smokeBodySize)

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "maxbody-smoke",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, smokeMaxBodyCap)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/toobig", nil)
	resp, err := cli.Do(req)
	if resp != nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	// Either a non-nil err or an incomplete-body read is consistent with
	// RST_STREAM(INTERNAL_ERROR) on the wire; the definitive assertion is
	// the Stream state below.
	_ = err

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
		var obs []string
		for _, st := range store.getStreams() {
			for _, u := range store.getUpdates(st.ID) {
				obs = append(obs, fmt.Sprintf("%s state=%q reason=%q", st.ID, u.State, u.FailureReason))
			}
		}
		t.Fatalf("no stream reached error/internal_error; observed: %v", obs)
	}

	time.Sleep(200 * time.Millisecond)
	if sf := countSmokeH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files after MaxBodySize error, want 0", sf)
	}
}

// makeSmokeH2Body returns size bytes of deterministic content. Local helper
// to avoid depending on the e2e-only-not-smoke `makeH2LargeBody` from
// large_body_integration_test.go.
func makeSmokeH2Body(size int) []byte {
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

// countSmokeH2SpillFiles counts files in dir whose name starts with
// config.BodySpillPrefix. Local sibling of countH2SpillFiles (exhaustive tier).
func countSmokeH2SpillFiles(t *testing.T, dir string) int {
	t.Helper()
	if dir == "" {
		t.Fatal("countSmokeH2SpillFiles: empty dir")
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
