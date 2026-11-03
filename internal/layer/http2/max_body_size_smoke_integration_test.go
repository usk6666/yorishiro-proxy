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
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

// USK-799 / USK-1401 — smoke-tier verification of max_body_size on the
// HTTP/2 response path, with a 1 MiB cap and a 2 MiB body so the merge gate
// re-validates it quickly on every PR. The exhaustive 25 MiB / 254 MiB
// scenarios live in large_body_integration_test.go (full tier).
//
// USK-1401 inverted the default outcome on purpose (as USK-1409 did for
// HTTP/1.x): a response no rule needs whole is streamed, so max_body_size
// (the buffering cap) no longer applies to it and the client gets the whole
// body; only the record is cut at max_record_body_size. The buffered outcome
// (stream error) still holds for a response a rule forces into the buffer —
// see TestSmoke_HTTP2_MaxBodySize_BufferedStreamErrorOnExceed, which keeps
// the pre-USK-1401 assertions unchanged.

const (
	smokeMaxBodyCap = 1 << 20 // 1 MiB
	smokeBodySize   = 2 << 20 // 2 MiB
)

// startMaxBodySmokeUpstream serves the 2 MiB Content-Length response.
func startMaxBodySmokeUpstream(t *testing.T, respBody []byte) (addr string, shutdown func()) {
	t.Helper()
	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "maxbody-smoke",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
			_, _ = w.Write(respBody)
		}))
	return upAddr, upShutdown
}

// smokeH2BodyMode is the production body-mode predicate over the given
// transform engine (nil: no rule needs a body whole).
func smokeH2BodyMode(tf *httprules.TransformEngine) layer.BodyModeFunc {
	return proxybuild.NewHTTPBodyModeFunc(proxybuild.HTTPBodyModeEngines{Transform: tf})
}

// TestSmoke_HTTP2_MaxBodySize_RecordTruncatedOnExceed: a streamed h2
// response over max_body_size reaches the client whole; the recorded copy is
// cut at max_record_body_size and marked, and the Stream completes.
func TestSmoke_HTTP2_MaxBodySize_RecordTruncatedOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	respBody := makeSmokeH2Body(smokeBodySize)
	upAddr, upShutdown := startMaxBodySmokeUpstream(t, respBody)
	defer upShutdown()

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, smokeMaxBodyCap)
	bcfg.ResponseBodyMode = smokeH2BodyMode(nil)
	bcfg.RequestBodyMode = smokeH2BodyMode(nil)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{recordMaxBodySize: smokeMaxBodyCap})

	cli := newMITMH2Client(proxyAddr, upAddr)
	req, _ := nethttp.NewRequestWithContext(ctx, nethttp.MethodGet, "https://"+upAddr+"/toobig", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	clientBody, rerr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if rerr != nil {
		t.Fatalf("client body read failed after %d bytes: %v (a streamed body must not hit max_body_size)", len(clientBody), rerr)
	}
	if len(clientBody) != smokeBodySize {
		t.Fatalf("client body = %d bytes, want the whole %d", len(clientBody), smokeBodySize)
	}
	if sha256.Sum256(clientBody) != sha256.Sum256(respBody) {
		t.Fatal("client body sha256 differs from the upstream body")
	}

	var recv *flow.Flow
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && recv == nil {
		for _, f := range store.allFlows() {
			if f.Direction == "receive" && (f.WireLevel == "" || f.WireLevel == flow.WireLevelSemantic) {
				recv = f
			}
		}
		if recv == nil {
			time.Sleep(20 * time.Millisecond)
		}
	}
	if recv == nil {
		t.Fatal("no receive flow recorded")
	}
	if !recv.BodyTruncated {
		t.Error("receive flow BodyTruncated = false, want true")
	}
	if len(recv.Body) != smokeMaxBodyCap {
		t.Errorf("recorded body = %d bytes, want %d (max_record_body_size)", len(recv.Body), smokeMaxBodyCap)
	}
	if !bytes.Equal(recv.Body, respBody[:len(recv.Body)]) {
		t.Error("recorded body is not the leading bytes of the upstream body")
	}
	if recv.Metadata["http_anomaly_raw_body_truncated"] == "" {
		t.Errorf("receive flow metadata lacks http_anomaly_raw_body_truncated: %v", recv.Metadata)
	}
	if len(recv.RawBytes) > smokeMaxBodyCap {
		t.Errorf("recorded raw bytes = %d, want <= record cap %d", len(recv.RawBytes), smokeMaxBodyCap)
	}

	waitH2StreamState(t, store, recv.StreamID, "complete")
	if sf := countSmokeH2SpillFiles(t, spillDir); sf != 0 {
		t.Errorf("BodySpillDir has %d leftover files, want 0", sf)
	}
}

// waitH2StreamState polls until streamID reached state (10s).
func waitH2StreamState(t *testing.T, store *testStore, streamID, state string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last []string
	for time.Now().Before(deadline) {
		last = last[:0]
		for _, u := range store.getUpdates(streamID) {
			if u.State == state {
				return
			}
			last = append(last, fmt.Sprintf("state=%q reason=%q", u.State, u.FailureReason))
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("stream %s never reached state %q; updates: %v", streamID, state, last)
}

// TestSmoke_HTTP2_MaxBodySize_BufferedStreamErrorOnExceed keeps the
// pre-USK-1401 assertions (TestSmoke_HTTP2_MaxBodySize_StreamErrorOnExceed,
// unchanged) for a response that is still buffered: a replace_body rule
// matching the response forces the buffer, and the operator-configured
// max_body_size then ends the stream with RST_STREAM(INTERNAL_ERROR).
func TestSmoke_HTTP2_MaxBodySize_BufferedStreamErrorOnExceed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	respBody := makeSmokeH2Body(smokeBodySize)

	upAddr, upShutdown := startMaxBodySmokeUpstream(t, respBody)
	defer upShutdown()

	tf := httprules.NewTransformEngine()
	rule, rerr := httprules.CompileTransformRule("force-buffer", 0, httprules.DirectionResponse,
		"", "^/toobig$", nil, httprules.TransformReplaceBody, "", "", "never-present-marker", "x")
	if rerr != nil {
		t.Fatalf("CompileTransformRule: %v", rerr)
	}
	tf.AddRule(*rule)

	spillDir := t.TempDir()
	bcfg := makeBuildCfgWithBody(t, nil, spillDir, 0, smokeMaxBodyCap)
	bcfg.ResponseBodyMode = smokeH2BodyMode(tf)
	bcfg.RequestBodyMode = smokeH2BodyMode(tf)
	proxyAddr, store := startH2MITMProxy(t, ctx, bcfg, pipelineOpts{transformEngine: tf})

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
