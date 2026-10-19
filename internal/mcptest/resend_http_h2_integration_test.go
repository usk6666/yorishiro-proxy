//go:build e2e

package mcptest_test

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	gohttp "net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// USK-1198 production-wiring e2e: a flow recorded over HTTP/2 by the live
// proxy is re-sent by resend_http / fuzz_http over HTTP/2. Before the fix
// the resend dial pinned ALPN to http/1.1 and drove an HTTP/1 Layer, so the
// origin below — which offers both h2 and http/1.1, like the origin in the
// GitHub issue 137 verification — saw the resend as HTTP/1.1.

// protoUpstream is an HTTPS origin offering ALPN ["h2","http/1.1"] that
// records r.Proto and r.Host per request (server-side observation).
type protoUpstream struct {
	srv *httptest.Server

	mu     sync.Mutex
	protos []string
	hosts  []string
	paths  []string
	got    chan struct{}
}

func startProtoUpstream(t *testing.T) *protoUpstream {
	t.Helper()
	u := &protoUpstream{got: make(chan struct{}, 16)}
	u.srv = httptest.NewUnstartedServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		u.mu.Lock()
		u.protos = append(u.protos, r.Proto)
		u.hosts = append(u.hosts, r.Host)
		u.paths = append(u.paths, r.URL.Path)
		u.mu.Unlock()
		select {
		case u.got <- struct{}{}:
		default:
		}
		w.WriteHeader(gohttp.StatusOK)
		_, _ = io.WriteString(w, "proto-ok")
	}))
	u.srv.EnableHTTP2 = true
	u.srv.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12}
	u.srv.StartTLS()
	t.Cleanup(u.srv.Close)
	return u
}

// waitN blocks until the upstream has seen n requests and returns the
// n-th (1-based) proto, host and path.
func (u *protoUpstream) waitN(t *testing.T, n int, timeout time.Duration) (proto, host, path string) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		u.mu.Lock()
		if len(u.protos) >= n {
			proto, host, path = u.protos[n-1], u.hosts[n-1], u.paths[n-1]
			u.mu.Unlock()
			return proto, host, path
		}
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("upstream saw fewer than %d requests within %v", n, timeout)
		}
	}
}

// recordH2Flow starts the proxy, sends one HTTP/2 GET through it to the
// upstream and returns the recorded flow id plus the target authority.
func recordH2Flow(t *testing.T, h *mcptest.Harness, u *protoUpstream, path string) (flowID, target string) {
	t.Helper()
	startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
	proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
	if proxyAddr == "" {
		t.Fatalf("proxy_start: missing listen_addr: %s", startRes.Text)
	}
	_, port, _ := net.SplitHostPort(u.srv.Listener.Addr().String())
	target = net.JoinHostPort("localhost", port)

	if status := h2RawGET(t, proxyAddr, target, path); status != "200" {
		t.Fatalf("h2 :status = %q, want 200", status)
	}
	if proto, _, _ := u.waitN(t, 1, 5*time.Second); proto != "HTTP/2.0" {
		t.Fatalf("live leg reached upstream as %q, want HTTP/2.0 (precondition)", proto)
	}
	fl := waitForWirePathFlow(t, h, path, nil, 5*time.Second)
	if v := flowHTTPVersion(t, h, fl.ID); v != "h2" {
		t.Fatalf("live recorded http_version = %q, want h2 (precondition)", v)
	}
	return fl.ID, target
}

// flowHTTPVersion reads query{resource:"flow"}.http_version.
func flowHTTPVersion(t *testing.T, h *mcptest.Harness, id string) string {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id})
	var parsed struct {
		HTTPVersion string `json:"http_version"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode query(flow): %v (text=%q)", err, res.Text)
	}
	return parsed.HTTPVersion
}

// streamIDsWithVersion returns the ids of origin-filtered streams that have
// at least one Flow recorded with http_version == version.
func streamIDsWithVersion(t *testing.T, h *mcptest.Harness, origin, version string) map[string]bool {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{
		"resource": "flows",
		"filter":   map[string]any{"origin": origin, "http_version": version},
	})
	var parsed struct {
		Flows []struct {
			ID string `json:"id"`
		} `json:"flows"`
	}
	if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
		t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
	}
	out := map[string]bool{}
	for _, f := range parsed.Flows {
		out[f.ID] = true
	}
	return out
}

// TestE2E_ResendHTTP_H2RecordedFlow_SentOverHTTP2 covers the Issue's
// headline acceptance criteria end to end through the production binary
// wiring: the resend of a live-recorded h2 flow reaches the origin as
// HTTP/2.0 with :authority equal to the recorded authority, and the new
// Stream's Flows record http_version "h2" — none "http/1.1".
func TestE2E_ResendHTTP_H2RecordedFlow_SentOverHTTP2(t *testing.T) {
	u := startProtoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{TLSFingerprint: "none"})
	flowID, target := recordH2Flow(t, h, u, "/usk1198/resend")

	res := h.MustOK(t, "resend_http", map[string]any{"flow_id": flowID})
	streamID, _ := res.Decoded["stream_id"].(string)
	if streamID == "" {
		t.Fatalf("resend_http: missing stream_id: %s", res.Text)
	}

	proto, host, path := u.waitN(t, 2, 10*time.Second)
	if proto != "HTTP/2.0" {
		t.Errorf("resend reached upstream as %q, want HTTP/2.0", proto)
	}
	if host != target {
		t.Errorf("resend :authority (r.Host) = %q, want recorded authority %q", host, target)
	}
	if path != "/usk1198/resend" {
		t.Errorf("resend path = %q, want /usk1198/resend", path)
	}

	if v := flowHTTPVersion(t, h, streamID); v != "h2" {
		t.Errorf("resend stream http_version = %q, want h2", v)
	}
	if streamIDsWithVersion(t, h, "resend", "http/1.1")[streamID] {
		t.Errorf("resend stream %s has a Flow recorded as http/1.1; want every Flow h2", streamID)
	}
	if !streamIDsWithVersion(t, h, "resend", "h2")[streamID] {
		t.Errorf("resend stream %s not found under filter http_version=h2", streamID)
	}
}

// TestE2E_FuzzHTTP_H2RecordedFlow_VariantsSentOverHTTP2 is the fuzz_http
// sibling: every variant of a live-recorded h2 flow reaches the origin as
// HTTP/2.0 and records http_version "h2".
func TestE2E_FuzzHTTP_H2RecordedFlow_VariantsSentOverHTTP2(t *testing.T) {
	u := startProtoUpstream(t)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{TLSFingerprint: "none"})
	flowID, _ := recordH2Flow(t, h, u, "/usk1198/fuzz")

	res := h.MustOK(t, "fuzz_http", map[string]any{
		"flow_id": flowID,
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/usk1198/v0", "/usk1198/v1"}},
		},
	})
	var out struct {
		CompletedVariants int `json:"completed_variants"`
		Variants          []struct {
			StreamID   string `json:"stream_id"`
			StatusCode int    `json:"status_code"`
			Error      string `json:"error"`
		} `json:"variants"`
	}
	raw, _ := json.Marshal(res.Decoded)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode fuzz_http result: %v (%s)", err, res.Text)
	}
	if out.CompletedVariants != 2 || len(out.Variants) != 2 {
		t.Fatalf("fuzz_http completed %d variants (%+v), want 2", out.CompletedVariants, out.Variants)
	}
	for i := range out.Variants {
		proto, _, _ := u.waitN(t, i+2, 10*time.Second)
		if proto != "HTTP/2.0" {
			t.Errorf("variant %d reached upstream as %q, want HTTP/2.0", i, proto)
		}
		v := out.Variants[i]
		if v.Error != "" || v.StatusCode != 200 {
			t.Errorf("variant %d: status=%d error=%q, want 200 and no error", i, v.StatusCode, v.Error)
		}
		if got := flowHTTPVersion(t, h, v.StreamID); got != "h2" {
			t.Errorf("variant %d stream http_version = %q, want h2", i, got)
		}
	}
}
