//go:build e2e && !e2e_smoke

// USK-1199 exhaustive coverage: the capture_scope decision for a
// body-bearing HTTP/2 stream on the remaining aggregator entry points
// (CONNECT + h2c, TCP forward h2c) and when the body trips MaxBodySize
// so no semantic envelope is ever produced. The merge-gate cases live in
// capture_scope_overlay_smoke_integration_test.go.
package mcptest_test

import (
	"crypto/tls"
	"fmt"
	"net"
	gohttp "net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// TestE2E_CaptureScopeOverlay_H2C_IncludeMethod: CONNECT + h2c POST with
// a body is recorded under include method=POST; a GET is not.
func TestE2E_CaptureScopeOverlay_H2C_IncludeMethod(t *testing.T) {
	upstreamAddr, shutdown := startSmokeH2CUpstream(t)
	defer shutdown()

	h, proxyAddr := startCaptureScopeHarness(t, mcptest.HarnessOptions{},
		map[string]any{"includes": []any{map[string]any{"method": "POST"}}})
	client := newH2CClientThroughProxy(proxyAddr, upstreamAddr)

	doCaptureScopeRequest(t, client, gohttp.MethodGet, "http://"+upstreamAddr+"/usk1199-h2c?case=get", 2)
	doCaptureScopeRequest(t, client, gohttp.MethodPost, "http://"+upstreamAddr+"/usk1199-h2c?case=post", 2)

	flows := waitForCaptureScopeFlows(t, h, "the h2c POST flow", 5*time.Second, func(fs []captureScopeFlow) bool {
		_, ok := findCompleteFlow(fs, "case=post")
		return ok
	})
	post, _ := findCompleteFlow(flows, "case=post")
	assertH2FrameRows(t, h, post.ID)
	for _, f := range listCaptureScopeFlows(t, h, map[string]any{"wire_level": "all"}) {
		if strings.Contains(f.URL, "case=get") {
			t.Errorf("h2c GET flow %s recorded under include method=POST", f.ID)
		}
	}
}

// TestE2E_CaptureScopeOverlay_TCPForwardH2_IncludeMethod: a plaintext TCP
// forward with protocol=http2 to an h2c upstream (prior knowledge) records
// a body-bearing POST under include method=POST and not a GET.
func TestE2E_CaptureScopeOverlay_TCPForwardH2_IncludeMethod(t *testing.T) {
	upstreamAddr, shutdown := startSmokeH2CUpstream(t)
	defer shutdown()

	h := mcptest.StartHarness(t, mcptest.HarnessOptions{})
	forwardPort := pickFreePort(t)
	h.MustOK(t, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
		"capture_scope": map[string]any{
			"includes": []any{map[string]any{"method": "POST"}},
		},
		"tcp_forwards": map[string]any{
			strconv.Itoa(forwardPort): map[string]any{
				"target":   upstreamAddr,
				"protocol": "http2",
			},
		},
	})

	forwardAddr := net.JoinHostPort("127.0.0.1", strconv.Itoa(forwardPort))
	tr := &http2.Transport{
		AllowHTTP: true,
		DialTLS: func(_, _ string, _ *tls.Config) (net.Conn, error) {
			return net.DialTimeout("tcp", forwardAddr, 5*time.Second)
		},
	}
	t.Cleanup(tr.CloseIdleConnections)
	client := &gohttp.Client{Transport: tr, Timeout: 15 * time.Second}

	doCaptureScopeRequest(t, client, gohttp.MethodGet, "http://"+forwardAddr+"/usk1199-fwd?case=get", 2)
	doCaptureScopeRequest(t, client, gohttp.MethodPost, "http://"+forwardAddr+"/usk1199-fwd?case=post", 2)

	flows := waitForCaptureScopeFlows(t, h, "the TCP-forward h2 POST flow", 5*time.Second, func(fs []captureScopeFlow) bool {
		_, ok := findCompleteFlow(fs, "case=post")
		return ok
	})
	post, _ := findCompleteFlow(flows, "case=post")
	assertH2FrameRows(t, h, post.ID)
	for _, f := range listCaptureScopeFlows(t, h, map[string]any{"wire_level": "all"}) {
		if strings.Contains(f.URL, "case=get") {
			t.Errorf("TCP-forward h2 GET flow %s recorded under include method=POST", f.ID)
		}
	}
}

// TestE2E_CaptureScopeOverlay_H2BodyOverMaxBodySize: a request body
// above max_body_size trips the aggregator's gate (RST_STREAM) before any
// semantic envelope exists, so only h2-frame overlay rows are recorded.
// Under an include rule matching the request those rows (and their
// Stream) are kept; under a non-matching include nothing is recorded.
func TestE2E_CaptureScopeOverlay_H2BodyOverMaxBodySize(t *testing.T) {
	// The smallest max_body_size the server accepts without a
	// body_spill_threshold override (which has no CLI/ConfigJSON seam in
	// the harness): the default 10 MiB spill threshold must not exceed it.
	const maxBody = 10 << 20
	cases := []struct {
		name       string
		rule       map[string]any
		wantStream bool
	}{
		{name: "matching_include_keeps_overlay_rows", rule: map[string]any{"url_prefix": "/big/"}, wantStream: true},
		{name: "non_matching_include_records_nothing", rule: map[string]any{"url_prefix": "/other/"}, wantStream: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			upstreamAddr := startH2TLSUpstream(t)
			h, proxyAddr := startCaptureScopeHarness(t,
				mcptest.HarnessOptions{ConfigJSON: fmt.Sprintf(`{"max_body_size":%d}`, maxBody)},
				map[string]any{"includes": []any{tc.rule}})
			client := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)

			body := strings.Repeat("x", maxBody+(256<<10))
			req, err := gohttp.NewRequest(gohttp.MethodPost, "https://"+upstreamAddr+"/big/usk1199", strings.NewReader(body))
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			if resp, err := client.Do(req); err == nil {
				resp.Body.Close()
			}
			// The client's outcome (RST / error) is not the subject; the
			// recording is. A follow-up in-scope request settles the
			// asynchronous record path for the matching case.
			if tc.wantStream {
				waitForCaptureScopeFlows(t, h, "an overlay-only stream for the oversized POST", 5*time.Second, func(fs []captureScopeFlow) bool {
					return len(fs) > 0
				})
				return
			}
			// Settle: drive a request through a fresh connection and
			// wait for its response; RecordStep runs before forwarding,
			// so every earlier Send decision has been taken by then.
			client2 := newH2TLSClientThroughProxy(t, proxyAddr, upstreamAddr)
			doCaptureScopeRequest(t, client2, gohttp.MethodGet, "https://"+upstreamAddr+"/settle", 2)
			if flows := listCaptureScopeFlows(t, h, map[string]any{"wire_level": "all"}); len(flows) != 0 {
				t.Errorf("%d flows recorded under non-matching include, want 0: %+v", len(flows), flows)
			}
		})
	}
}
