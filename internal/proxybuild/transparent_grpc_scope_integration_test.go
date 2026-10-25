//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"crypto/tls"
	"encoding/binary"
	"io"
	gohttp "net/http"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// USK-1376 (E6): on a transparent TLS MITM connection admitted by its
// SNI, a native gRPC call's :authority is judged per request — a denied
// name, or an allowed name not bound to the original destination by DNS,
// is refused with grpc-status 7 and never reaches the upstream. Before,
// the SNI admission (meant for raw bytes) let every gRPC call through.

// grpcCountingH2Upstream serves h2 on each MITM'd upstream connection,
// counting requests and answering each with an empty grpc-status 0.
func grpcCountingH2Upstream(hits *atomic.Int64) func(*tls.Conn) {
	return func(tc *tls.Conn) {
		(&http2.Server{}).ServeConn(tc, &http2.ServeConnOpts{Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			hits.Add(1)
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Trailer", "Grpc-Status")
			w.WriteHeader(200)
			w.Header().Set("Grpc-Status", "0")
		})})
	}
}

// grpcCallVia runs one native gRPC unary request with the given
// :authority over a fresh transparent TLS MITM connection (SNI sni) and
// returns its grpc-status.
func grpcCallVia(t *testing.T, p *transparentProxy, sni, authority string) string {
	t.Helper()
	tc := mitmTLS(t, p, sni, []string{"h2"})
	defer tc.Close()
	cc, err := (&http2.Transport{}).NewClientConn(tc)
	if err != nil {
		t.Fatalf("h2 client conn: %v", err)
	}
	payload := []byte("usk-1376")
	frame := make([]byte, 5+len(payload))
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload)))
	copy(frame[5:], payload)
	req, _ := gohttp.NewRequest("POST", "https://"+sni+"/pkg.Echo/Say", strings.NewReader(string(frame)))
	req.Host = authority
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	resp, err := cc.RoundTrip(req)
	if err != nil {
		t.Fatalf("h2 round trip (:authority %q): %v", authority, err)
	}
	_, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if s := resp.Trailer.Get("Grpc-Status"); s != "" {
		return s
	}
	return resp.Header.Get("Grpc-Status")
}

func TestTransparent_TLS_GRPCAuthorityCheckedPerRequest(t *testing.T) {
	ctx := transparentCtx(t)
	var hits atomic.Int64
	up := newCapturingTLSUpstream(t, []string{"h2"}, grpcCountingH2Upstream(&hits))
	loop := netip.MustParseAddr("127.0.0.1")
	p := startTransparentProxy(t, ctx, up.addr(), func(d *proxybuild.Deps) {
		d.Scope = policyScope(
			[]connector.TargetRule{{Hostname: "allowed.example"}, {Hostname: "unbound.example"}},
			[]connector.TargetRule{{Hostname: "denied.example"}},
		)
		d.NameResolver = newFakeNameResolver(map[string][]netip.Addr{
			"allowed.example": {loop},
			"unbound.example": {netip.MustParseAddr("192.0.2.77")},
			"denied.example":  {loop},
		})
	})

	if got := grpcCallVia(t, p, "allowed.example", "allowed.example"); got != "0" {
		t.Fatalf("allowed bound :authority: grpc-status %q, want 0", got)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits after the allowed call = %d, want 1", got)
	}

	for _, authority := range []string{"denied.example", "unbound.example"} {
		t.Run(authority, func(t *testing.T) {
			before := hits.Load()
			got := grpcCallVia(t, p, "allowed.example", authority)
			if n := hits.Load() - before; n != 0 {
				t.Errorf(":authority %s reached the upstream (%d hits)", authority, n)
			}
			if got != "7" {
				t.Errorf(":authority %s: grpc-status %q, want 7 (PERMISSION_DENIED)", authority, got)
			}
		})
	}
	waitStream(t, p.store, 0, func(st *flow.Stream) bool {
		return st.Protocol == "grpc" && st.BlockedBy == "target_scope" && st.State == "error"
	})
}
