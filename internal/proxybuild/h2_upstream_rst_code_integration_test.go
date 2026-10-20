//go:build e2e && !e2e_smoke

// USK-1269 exhaustive-tier coverage: the RST_STREAM error code an upstream
// h2 origin resets a stream with must reach the h2 client verbatim — as it
// would on a direct connection — instead of being rewritten to CANCEL.
// Reuses the frame-level origin and raw client defined in
// h2_upstream_refused_integration_test.go.
package proxybuild_test

import (
	"context"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

// TestH2UpstreamRST_ClientSeesUpstreamCode: the origin answers one of two
// streams with 200 and resets the other with RST_STREAM(code). The raw
// client must see that exact code on the reset stream — including codes outside
// the five recorded classifications and an unknown extension code (RFC 9113
// §7: unknown codes MUST NOT trigger special behavior). Recording keeps
// classifying the reset (codes without a dedicated category record as
// "aborted").
func TestH2UpstreamRST_ClientSeesUpstreamCode(t *testing.T) {
	tests := []struct {
		code       http2.ErrCode
		wantReason string
	}{
		{code: http2.ErrCodeInternal, wantReason: "internal_error"},
		{code: http2.ErrCodeEnhanceYourCalm, wantReason: "aborted"},
		{code: http2.ErrCodeHTTP11Required, wantReason: "aborted"},
		{code: http2.ErrCode(0xff), wantReason: "aborted"},
	}
	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()

			origin := startRefusingH2OriginOpts(t, refusingOriginOpts{mode: originRSTLast, batch: 2, rstCode: tt.code})
			store := &flowStoreForH2Pool{}
			proxyAddr := startProxyForRefusedTest(t, ctx, store)

			cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
			ids := []uint32{1, 3}
			cli.sendGETs(t, origin.addr, ids...)
			res := cli.collect(t, 10*time.Second, ids...)

			// The proxy opens the upstream streams concurrently, so which
			// client stream the origin resets is not fixed.
			var ok, reset int
			for _, id := range ids {
				r := res[id]
				switch {
				case r.ended && len(r.statuses) == 1 && r.statuses[0] == "200":
					ok++
				case r.rst && r.rstCode == tt.code && len(r.statuses) == 0:
					reset++
				default:
					t.Errorf("stream %d: statuses=%v ended=%v rst=%v code=%v; want 200 or RST_STREAM(%v)",
						id, r.statuses, r.ended, r.rst, r.rstCode, tt.code)
				}
			}
			if ok != 1 || reset != 1 {
				t.Errorf("client outcomes: %d x 200, %d x RST_STREAM(%v); want 1 and 1", ok, reset, tt.code)
			}
			waitStreamOutcomes(t, store, map[string]int{"complete/": 1, "error/" + tt.wantReason: 1}, 5*time.Second)
		})
	}
}

// TestH2UpstreamRST_AfterEarlyHints_ClientSeesUpstreamCode: the "response
// already started" downgrade is specific to REFUSED_STREAM (RFC 9113 §8.7,
// see TestH2UpstreamRefused_AfterEarlyHints_ClientSeesCancel). Any other
// upstream code is relayed even after a 103 Early Hints reached the client.
func TestH2UpstreamRST_AfterEarlyHints_ClientSeesUpstreamCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{mode: originEarlyHintsThenRST, batch: 1, rstCode: http2.ErrCodeInternal})
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	cli.sendGETs(t, origin.addr, 1)
	r := cli.collect(t, 10*time.Second, 1)[1]

	if len(r.statuses) != 1 || r.statuses[0] != "103" {
		t.Fatalf("response HEADERS statuses = %v, want [103] forwarded before the reset", r.statuses)
	}
	if !r.rst || r.rstCode != http2.ErrCodeInternal {
		t.Errorf("stream 1: rst=%v code=%v, want RST_STREAM(INTERNAL_ERROR)", r.rst, r.rstCode)
	}
	waitStreamOutcomes(t, store, map[string]int{"error/internal_error": 1}, 5*time.Second)
}

// TestH2UpstreamRST_GRPCWeb_ClientSeesUpstreamCode: the same relay for a
// gRPC-Web request over h2 through CONNECT (the client stream is wrapped by
// the gRPC-Web Channel). sendGRPCWebUnary lives in
// tcp_forward_h2_rst_code_integration_test.go.
func TestH2UpstreamRST_GRPCWeb_ClientSeesUpstreamCode(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	origin := startRefusingH2OriginOpts(t, refusingOriginOpts{mode: originRSTLast, batch: 1, rstCode: http2.ErrCodeInternal})
	store := &flowStoreForH2Pool{}
	proxyAddr := startProxyForRefusedTest(t, ctx, store)

	cli := dialRawH2ThroughProxy(t, proxyAddr, origin.addr)
	sendGRPCWebUnary(t, cli, origin.addr, 1)
	r := cli.collect(t, 10*time.Second, 1)[1]

	if !r.rst || r.rstCode != http2.ErrCodeInternal || len(r.statuses) != 0 {
		t.Errorf("stream 1: statuses=%v ended=%v rst=%v code=%v; want RST_STREAM(INTERNAL_ERROR)",
			r.statuses, r.ended, r.rst, r.rstCode)
	}
	waitStreamOutcomes(t, store, map[string]int{"error/internal_error": 1}, 5*time.Second)
}
