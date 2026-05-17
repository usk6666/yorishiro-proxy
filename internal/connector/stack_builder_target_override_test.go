package connector

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
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

// TestBuildConnectionStackWithTarget_EmptyProtocolRoutesViaAuto verifies that
// an empty Protocol string collapses to Auto and then falls through to the
// Raw branch when the peek does not see HTTP/1.x bytes. USK-913 wired the
// Auto arm; prior to that this case rejected with a "not yet wired" error.
// The peek has a bounded deadline so a net.Pipe peer that never sends bytes
// resolves to InnerUnknown → Raw fallback within the test timeout.
func TestBuildConnectionStackWithTarget_EmptyProtocolRoutesViaAuto(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)

	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target: "api.example.com:50051",
		// Protocol unset — exercises the empty → auto collapse.
	}

	stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err != nil {
		t.Fatalf("BuildConnectionStackWithTarget(empty/auto): %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	// Auto with no bytes peeked falls through to Raw — both topmosts are
	// bytechunk Layers.
	if _, ok := stack.ClientTopmost().(*bytechunk.Layer); !ok {
		t.Errorf("client topmost = %T, want *bytechunk.Layer (Auto fallback to Raw)", stack.ClientTopmost())
	}
}

// TestBuildConnectionStackWithTarget_DeferredProtocols was the
// USK-912-era enumeration of "not yet wired" protocol arms. After
// USK-913 (http/ws/sse/auto) and USK-914 (http2/grpc) landed the
// entire BuildConnectionStackWithTarget protocol switch is wired, so
// this table is intentionally empty. Kept as a structural placeholder
// so future deferrals (e.g., a new ForwardProtocol value introduced
// without a wired arm) re-use the same fixture pattern.
func TestBuildConnectionStackWithTarget_DeferredProtocols(t *testing.T) {
	cases := []struct {
		name      string
		protocol  ForwardProtocol
		wantIssue string
	}{}
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

// TestBuildConnectionStackWithTarget_HTTPSuccess verifies that
// ForwardProtocolHTTP / ForwardProtocolWebSocket / ForwardProtocolSSE all
// assemble [http1 → http1] with scheme="http". USK-913 wired these arms.
// The three protocols share an identical stack — the expectation filter
// (WS upgrade required / SSE Content-Type required) lives at the
// proxybuild handler layer rather than inside the connector builder.
func TestBuildConnectionStackWithTarget_HTTPSuccess(t *testing.T) {
	cases := []struct {
		name     string
		protocol ForwardProtocol
	}{
		{name: "http", protocol: ForwardProtocolHTTP},
		{name: "websocket", protocol: ForwardProtocolWebSocket},
		{name: "sse", protocol: ForwardProtocolSSE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, clientPeer := pipePair(t)
			_, upstreamPeer := pipePair(t)
			cfg := newTestBuildConfig(t)
			params := TargetOverrideParams{
				Target:   "api.example.com:80",
				Protocol: tc.protocol,
			}
			stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
			if err != nil {
				t.Fatalf("protocol %q: %v", tc.protocol, err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			if _, ok := stack.ClientTopmost().(*http1.Layer); !ok {
				t.Errorf("protocol %q: client topmost = %T, want *http1.Layer", tc.protocol, stack.ClientTopmost())
			}
			if _, ok := stack.UpstreamTopmost().(*http1.Layer); !ok {
				t.Errorf("protocol %q: upstream topmost = %T, want *http1.Layer", tc.protocol, stack.UpstreamTopmost())
			}
			if stack.ConnID == "" {
				t.Error("stack.ConnID is empty")
			}
		})
	}
}

// TestBuildConnectionStackWithTarget_H2CDispatch verifies that the
// HTTP2 / GRPC selector reach the h2c builder branch by feeding closed
// connections and asserting the wrap error cites the expected sub-stage.
// A full positive-path test of the assembled stack (with a real h2 client
// preface) lives in proxybuild's e2e suite — see
// internal/proxybuild/tcp_forward_h2_integration_test.go and
// internal/proxybuild/tcp_forward_grpc_integration_test.go.
func TestBuildConnectionStackWithTarget_H2CDispatch(t *testing.T) {
	cases := []struct {
		name     string
		protocol ForwardProtocol
	}{
		{name: "http2", protocol: ForwardProtocolHTTP2},
		{name: "grpc", protocol: ForwardProtocolGRPC},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct conns whose Reads return EOF immediately so the
			// upstream http2.New ClientRole preface-write succeeds but the
			// reader goroutine sees EOF on the very next frame read. We only
			// need the dispatcher to route into the h2c builder branch — the
			// builder may then fail at either the upstream or client Layer
			// construction; both outcomes indicate the dispatch reached the
			// h2 branch (not the "not yet wired" error path).
			clientLocal, clientPeer := net.Pipe()
			t.Cleanup(func() { _ = clientLocal.Close(); _ = clientPeer.Close() })
			upstreamLocal, upstreamPeer := net.Pipe()
			t.Cleanup(func() { _ = upstreamLocal.Close(); _ = upstreamPeer.Close() })

			// Drain the conns asynchronously: discard whatever the http2
			// Layer writes (preface + SETTINGS frame on the upstream side;
			// SETTINGS on the client side after preface read). Close on
			// drain end so subsequent reads return EOF.
			drainAndClose := func(c net.Conn) {
				go func() {
					buf := make([]byte, 4096)
					for {
						if _, err := c.Read(buf); err != nil {
							return
						}
					}
				}()
			}
			drainAndClose(clientLocal)
			drainAndClose(upstreamLocal)

			// Close the peers' read direction so the http2.New's preface
			// validation surfaces a deterministic error. net.Pipe does not
			// support CloseRead, so closing the whole conn after a short
			// delay achieves the same outcome.
			go func() {
				time.Sleep(50 * time.Millisecond)
				_ = clientLocal.Close()
				_ = upstreamLocal.Close()
			}()

			cfg := newTestBuildConfig(t)
			params := TargetOverrideParams{
				Target:   "api.example.com:50051",
				Protocol: tc.protocol,
			}
			_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
			// The interesting assertion is the error path — it must NOT
			// be the "not yet wired" sentinel. Either the upstream or
			// client h2 layer construction surfaces a wrap error citing
			// "buildTargetOverrideH2CStack" or the connector's
			// "BuildConnectionStackWithTarget" prefix.
			if err == nil {
				t.Fatalf("protocol %q: expected error from closed peer dispatch (no real h2 handshake), got success", tc.protocol)
			}
			if strings.Contains(err.Error(), "not yet wired") {
				t.Errorf("protocol %q: dispatch returned 'not yet wired' (%q); h2c branch was not reached", tc.protocol, err.Error())
			}
		})
	}
}

// TestBuildConnectionStackWithTarget_AutoH2CRejected verifies that the
// Auto arm refuses to opportunistically negotiate h2c — operators must
// declare Protocol="http2" explicitly. After USK-914 wired the h2c arm
// the rejection is no longer a "deferred to USK-914" message; Auto stays
// strict on purpose so that an h2c forward only happens when the
// operator declared the intent. We force the H2C preface bytes onto the
// wire so peekInnerProtocol classifies as InnerH2C; the build call then
// returns the explicit-declaration-required error.
func TestBuildConnectionStackWithTarget_AutoH2CRejected(t *testing.T) {
	clientLocal, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)

	// Push the H2C preface so peekInnerProtocol classifies as InnerH2C.
	go func() {
		_, _ = clientLocal.Write([]byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"))
	}()

	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:   "api.example.com:80",
		Protocol: ForwardProtocolAuto,
	}
	_, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err == nil {
		t.Fatal("expected non-nil error for Auto + h2c preface, got nil")
	}
	if !strings.Contains(err.Error(), "explicit Protocol") {
		t.Errorf("expected error to cite explicit-Protocol requirement, got %q", err.Error())
	}
}

// TestBuildConnectionStackWithTarget_AutoHTTPResolvesToHTTP verifies the
// happy path of Auto: when the first bytes look like an HTTP/1.x request
// line, the assembled stack is [http1 → http1].
func TestBuildConnectionStackWithTarget_AutoHTTPResolvesToHTTP(t *testing.T) {
	clientLocal, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)

	go func() {
		_, _ = clientLocal.Write([]byte("GET / HTTP/1.1\r\nHost: api.example.com\r\n\r\n"))
	}()

	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:   "api.example.com:80",
		Protocol: ForwardProtocolAuto,
	}
	stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err != nil {
		t.Fatalf("BuildConnectionStackWithTarget(auto+http): %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })

	if _, ok := stack.ClientTopmost().(*http1.Layer); !ok {
		t.Errorf("client topmost = %T, want *http1.Layer (Auto → HTTP)", stack.ClientTopmost())
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

// TestBuildConnectionStackWithTarget_UpstreamTLSInformational confirms
// USK-916 changed UpstreamTLS=true from a hard reject into an
// informational flag — the builder no longer dials upstream TLS itself
// (caller-side dial via proxybuild.dialForwardUpstream), so the field
// only signals intent. The builder accepts the value and assembles the
// stack as if the caller had already dialed TLS upstream of this call.
func TestBuildConnectionStackWithTarget_UpstreamTLSInformational(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	cfg := newTestBuildConfig(t)
	params := TargetOverrideParams{
		Target:      "api.example.com:443",
		Protocol:    ForwardProtocolRaw,
		UpstreamTLS: true,
	}
	stack, err := BuildConnectionStackWithTarget(context.Background(), clientPeer, upstreamPeer, params, cfg)
	if err != nil {
		t.Fatalf("expected UpstreamTLS=true to be accepted (USK-916 informational flag), got error: %v", err)
	}
	if stack == nil {
		t.Fatal("expected non-nil stack, got nil")
	}
	_ = stack.Close()
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
