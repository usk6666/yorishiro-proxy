package connector

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
)

// newTestBuildConfig constructs a minimal *BuildConfig for the target-override
// builder tests. Mirrors the shape used by plain_http_stack_test.go.
func newTestBuildConfig(t *testing.T) *BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	return &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
}

// pipePair returns a (local, peer) pair from net.Pipe whose lifecycle is
// hooked into t.Cleanup. The peer end is what callers pass to the stack
// builder; the local end stays alive for the test duration so the bytechunk
// Layer's reader has a peer to read from.
func pipePair(t *testing.T) (local, peer net.Conn) {
	t.Helper()
	local, peer = net.Pipe()
	t.Cleanup(func() {
		_ = local.Close()
		_ = peer.Close()
	})
	return local, peer
}

// TestBuildConnectionStackWithTarget_RawSuccess verifies the only fully-wired
// protocol branch of USK-912: ForwardProtocolRaw assembles a
// [bytechunk → bytechunk] stack with both Layers as *bytechunk.Layer.
func TestBuildConnectionStackWithTarget_RawSuccess(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)

	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:   "api.example.com:50051",
		Protocol: ForwardProtocolRaw,
	}

	stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err != nil {
		t.Fatalf("BuildConnectionStackWithTarget(raw): %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	if stack.ConnID == "" {
		t.Error("stack.ConnID is empty")
	}

	if _, ok := stack.ClientTopmost().(*bytechunk.Layer); !ok {
		t.Errorf("client topmost = %T, want *bytechunk.Layer", stack.ClientTopmost())
	}
	if _, ok := stack.UpstreamTopmost().(*bytechunk.Layer); !ok {
		t.Errorf("upstream topmost = %T, want *bytechunk.Layer", stack.UpstreamTopmost())
	}
	if stack.UpstreamH2Layer() != nil {
		t.Error("upstreamH2 should be nil for raw target-override stack")
	}
}

// TestBuildConnectionStackWithTarget_RawEmptyProtocol verifies that an
// empty Protocol string is NOT treated as ForwardProtocolRaw at this point
// — empty collapses to auto, which is the deferred branch. This is a
// guardrail: forward callers that forget to populate the field should not
// silently get a bytechunk stack; they should see the explicit
// "auto not yet wired" error.
func TestBuildConnectionStackWithTarget_EmptyProtocolDeferred(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)

	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target: "api.example.com:50051",
		// Protocol unset — exercises the empty → auto collapse.
	}

	_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err == nil {
		t.Fatal("expected non-nil error for empty Protocol (deferred to auto), got nil")
	}
	if !strings.Contains(err.Error(), "USK-913") {
		t.Errorf("expected error to cite USK-913, got %q", err.Error())
	}
}

// TestBuildConnectionStackWithTarget_DeferredProtocols enumerates every
// non-raw protocol selector and confirms each returns a "not yet wired"
// error mentioning the responsible follow-up Issue. This is the
// signature-locking test: downstream Issues (USK-913+) will replace each
// case body with the real implementation, but the validation +
// dispatch surface is already in place today.
func TestBuildConnectionStackWithTarget_DeferredProtocols(t *testing.T) {
	cases := []struct {
		name      string
		protocol  ForwardProtocol
		wantIssue string
	}{
		{name: "auto", protocol: ForwardProtocolAuto, wantIssue: "USK-913"},
		{name: "http", protocol: ForwardProtocolHTTP, wantIssue: "USK-913"},
		{name: "http2", protocol: ForwardProtocolHTTP2, wantIssue: "USK-913"},
		{name: "grpc", protocol: ForwardProtocolGRPC, wantIssue: "USK-914"},
		{name: "websocket", protocol: ForwardProtocolWebSocket, wantIssue: "USK-914"},
		{name: "sse", protocol: ForwardProtocolSSE, wantIssue: "USK-914"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, clientPeer := pipePair(t)
			_, upstreamPeer := pipePair(t)
			cfg := newTestBuildConfig(t)
			params := TargetOverrideParams{
				Target:   "api.example.com:50051",
				Protocol: tc.protocol,
			}
			_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
			if err == nil {
				t.Fatalf("protocol %q: expected non-nil deferred error, got nil", tc.protocol)
			}
			if !strings.Contains(err.Error(), tc.wantIssue) {
				t.Errorf("protocol %q: error %q does not cite %q", tc.protocol, err.Error(), tc.wantIssue)
			}
		})
	}
}

// TestBuildConnectionStackWithTarget_TLSTerminateDeferred confirms
// TLSTerminate=true short-circuits with a USK-915 reference rather than
// silently doing nothing.
func TestBuildConnectionStackWithTarget_TLSTerminateDeferred(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:       "api.example.com:443",
		Protocol:     ForwardProtocolRaw,
		TLSTerminate: true,
	}
	_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err == nil {
		t.Fatal("expected non-nil error for TLSTerminate=true, got nil")
	}
	if !strings.Contains(err.Error(), "USK-915") {
		t.Errorf("expected error to cite USK-915, got %q", err.Error())
	}
}

// TestBuildConnectionStackWithTarget_UpstreamTLSDeferred confirms
// UpstreamTLS=true short-circuits with a USK-916 reference.
func TestBuildConnectionStackWithTarget_UpstreamTLSDeferred(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:      "api.example.com:443",
		Protocol:    ForwardProtocolRaw,
		UpstreamTLS: true,
	}
	_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err == nil {
		t.Fatal("expected non-nil error for UpstreamTLS=true, got nil")
	}
	if !strings.Contains(err.Error(), "USK-916") {
		t.Errorf("expected error to cite USK-916, got %q", err.Error())
	}
}

// TestBuildConnectionStackWithTarget_ALPNOffersAccepted verifies that
// the ALPNOffers field is accepted in raw mode (no error from validation
// or dispatch) even though raw does not actually use ALPN. This locks in
// the "ALPN is caller-supplied, empty means no extension" semantic for
// downstream Issues.
func TestBuildConnectionStackWithTarget_ALPNOffersAccepted(t *testing.T) {
	cases := []struct {
		name   string
		offers []string
	}{
		{name: "nil", offers: nil},
		{name: "empty", offers: []string{}},
		{name: "single", offers: []string{"http/1.1"}},
		{name: "multi", offers: []string{"h2", "http/1.1"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, clientPeer := pipePair(t)
			_, upstreamPeer := pipePair(t)
			cfg := newTestBuildConfig(t)
			params := TargetOverrideParams{
				Target:     "api.example.com:50051",
				Protocol:   ForwardProtocolRaw,
				ALPNOffers: tc.offers,
			}
			stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
			if err != nil {
				t.Fatalf("ALPNOffers=%v: unexpected error: %v", tc.offers, err)
			}
			t.Cleanup(func() { _ = stack.Close() })
		})
	}
}

// TestBuildConnectionStackWithTarget_Validation covers input-validation
// failure modes: nil config, nil conn, empty / malformed target, unknown
// protocol. Each must surface a clear error rather than panic.
func TestBuildConnectionStackWithTarget_Validation(t *testing.T) {
	t.Run("nil_config", func(t *testing.T) {
		_, clientPeer := pipePair(t)
		_, upstreamPeer := pipePair(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer,
			TargetOverrideParams{Target: "api.example.com:80", Protocol: ForwardProtocolRaw}, nil)
		if err == nil {
			t.Fatal("expected error for nil config")
		}
	})

	t.Run("nil_client_conn", func(t *testing.T) {
		_, upstreamPeer := pipePair(t)
		cfg := newTestBuildConfig(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), nil, upstreamPeer,
			TargetOverrideParams{Target: "api.example.com:80", Protocol: ForwardProtocolRaw}, cfg)
		if err == nil {
			t.Fatal("expected error for nil clientConn")
		}
	})

	t.Run("nil_upstream_conn", func(t *testing.T) {
		_, clientPeer := pipePair(t)
		cfg := newTestBuildConfig(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, nil,
			TargetOverrideParams{Target: "api.example.com:80", Protocol: ForwardProtocolRaw}, cfg)
		if err == nil {
			t.Fatal("expected error for nil upstreamConn")
		}
	})

	t.Run("empty_target", func(t *testing.T) {
		_, clientPeer := pipePair(t)
		_, upstreamPeer := pipePair(t)
		cfg := newTestBuildConfig(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer,
			TargetOverrideParams{Target: "", Protocol: ForwardProtocolRaw}, cfg)
		if err == nil {
			t.Fatal("expected error for empty target")
		}
	})

	t.Run("malformed_target", func(t *testing.T) {
		_, clientPeer := pipePair(t)
		_, upstreamPeer := pipePair(t)
		cfg := newTestBuildConfig(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer,
			TargetOverrideParams{Target: "no-port-here", Protocol: ForwardProtocolRaw}, cfg)
		if err == nil {
			t.Fatal("expected error for malformed target (no port)")
		}
	})

	t.Run("unknown_protocol", func(t *testing.T) {
		_, clientPeer := pipePair(t)
		_, upstreamPeer := pipePair(t)
		cfg := newTestBuildConfig(t)
		_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer,
			TargetOverrideParams{Target: "api.example.com:80", Protocol: ForwardProtocol("quic")}, cfg)
		if err == nil {
			t.Fatal("expected error for unknown protocol")
		}
		if !strings.Contains(err.Error(), "invalid protocol") {
			t.Errorf("expected 'invalid protocol' substring, got %q", err.Error())
		}
	})
}

// TestPerformClientMITM_Validation confirms the exported wrapper rejects
// nil arguments before invoking the package-private helper. The wire-level
// MITM behaviour itself is exercised end-to-end by existing
// stack_builder_test.go and the MITM integration suite; this test only
// guards the new exported surface.
func TestPerformClientMITM_Validation(t *testing.T) {
	cfg := newTestBuildConfig(t)
	_, clientPeer := pipePair(t)

	t.Run("nil_cfg", func(t *testing.T) {
		_, _, err := PerformClientMITM(context.Background(), clientPeer, "example.com", nil, nil)
		if err == nil {
			t.Fatal("expected error for nil cfg")
		}
	})
	t.Run("nil_issuer", func(t *testing.T) {
		emptyCfg := &BuildConfig{ProxyConfig: &config.ProxyConfig{}}
		_, _, err := PerformClientMITM(context.Background(), clientPeer, "example.com", nil, emptyCfg)
		if err == nil {
			t.Fatal("expected error for nil issuer")
		}
	})
	t.Run("nil_conn", func(t *testing.T) {
		_, _, err := PerformClientMITM(context.Background(), nil, "example.com", nil, cfg)
		if err == nil {
			t.Fatal("expected error for nil clientConn")
		}
	})
	t.Run("empty_host", func(t *testing.T) {
		_, _, err := PerformClientMITM(context.Background(), clientPeer, "", nil, cfg)
		if err == nil {
			t.Fatal("expected error for empty host")
		}
	})
}

// TestDialUpstreamWithALPN_Validation confirms the exported wrapper
// rejects nil arguments before invoking the dial. End-to-end TLS
// behaviour is exercised by the existing MITM integration suite.
func TestDialUpstreamWithALPN_Validation(t *testing.T) {
	cfg := newTestBuildConfig(t)

	t.Run("nil_cfg", func(t *testing.T) {
		_, _, err := DialUpstreamWithALPN(context.Background(), "api.example.com:443", "api.example.com", nil, true, nil, nil, nil)
		if err == nil {
			t.Fatal("expected error for nil cfg")
		}
	})
	t.Run("empty_target", func(t *testing.T) {
		_, _, err := DialUpstreamWithALPN(context.Background(), "", "api.example.com", nil, true, nil, nil, cfg)
		if err == nil {
			t.Fatal("expected error for empty target")
		}
	})
	t.Run("empty_host", func(t *testing.T) {
		_, _, err := DialUpstreamWithALPN(context.Background(), "api.example.com:443", "", nil, true, nil, nil, cfg)
		if err == nil {
			t.Fatal("expected error for empty host")
		}
	})
}

// TestBuildConnectionStackWithTarget_PreservesConnIDUniqueness verifies
// that two calls produce distinct ConnIDs — important because the live
// path keys per-connection state on this ID.
func TestBuildConnectionStackWithTarget_PreservesConnIDUniqueness(t *testing.T) {
	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{Target: "api.example.com:50051", Protocol: ForwardProtocolRaw}

	_, c1 := pipePair(t)
	_, u1 := pipePair(t)
	s1, err := BuildConnectionStackWithTarget(context.Background(), c1, u1, params, cfg)
	if err != nil {
		t.Fatalf("first build: %v", err)
	}
	t.Cleanup(func() { _ = s1.Close() })

	_, c2 := pipePair(t)
	_, u2 := pipePair(t)
	s2, err := BuildConnectionStackWithTarget(context.Background(), c2, u2, params, cfg)
	if err != nil {
		t.Fatalf("second build: %v", err)
	}
	t.Cleanup(func() { _ = s2.Close() })

	if s1.ConnID == s2.ConnID {
		t.Errorf("expected distinct ConnIDs, both got %q", s1.ConnID)
	}
}
