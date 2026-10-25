package connector

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// USK-1378: an h1 redial reproduces the first upstream dial's TLS shape —
// the transparent no-ALPN stack is redialed with Go standard TLS and no
// ALPN, every other TLS stack with [http/1.1] under the uTLS profile.

// hasFFDHEGroup reports whether curves carry the ffdhe groups (256, 257)
// the uTLS Firefox profile offers and Go's standard crypto/tls never does.
func hasFFDHEGroup(curves []tls.CurveID) bool {
	return slices.Contains(curves, tls.CurveID(256)) || slices.Contains(curves, tls.CurveID(257))
}

// buildNoALPNThroughClient runs buildTransparentNoALPNStack on the server
// side of a local TCP connection while a TLS client offering no ALPN
// handshakes on the other side and sends an HTTP/1.1 request head, so the
// stack takes the http1 route.
func buildNoALPNThroughClient(t *testing.T, ut UpstreamTarget, cfg *BuildConfig) *ConnectionStack {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	type result struct {
		stack *ConnectionStack
		err   error
	}
	resCh := make(chan result, 1)
	go func() {
		sc, aerr := ln.Accept()
		if aerr != nil {
			resCh <- result{err: aerr}
			return
		}
		stack, _, _, berr := buildTransparentNoALPNStack(context.Background(), sc, ut, cfg, ClientHelloPeek{SNI: extractHost(ut.TLS)}, 5*time.Second)
		if berr != nil {
			_ = sc.Close()
		}
		resCh <- result{stack: stack, err: berr}
	}()

	cc, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	clientTLS := tls.Client(cc, &tls.Config{
		ServerName:         extractHost(ut.TLS),
		InsecureSkipVerify: true, //nolint:gosec // test: the MITM cert is not under test
	})
	go func() {
		if clientTLS.Handshake() == nil {
			_, _ = io.WriteString(clientTLS, "GET / HTTP/1.1\r\nHost: "+extractHost(ut.TLS)+"\r\n\r\n")
		}
	}()

	var res result
	select {
	case res = <-resCh:
	case <-time.After(10 * time.Second):
		t.Fatal("buildTransparentNoALPNStack timed out")
	}
	if res.err != nil {
		t.Fatalf("buildTransparentNoALPNStack: %v", res.err)
	}
	t.Cleanup(func() { _ = res.stack.Close() })
	return res.stack
}

func TestRedialUpstreamH1_KeepsFirstDialTLSShape(t *testing.T) {
	newCfg := func(t *testing.T) *BuildConfig {
		return &BuildConfig{
			ProxyConfig:        &config.ProxyConfig{},
			Issuer:             newUpstreamTargetTestIssuer(t),
			InsecureSkipVerify: true,
			TLSFingerprint:     "firefox",
		}
	}
	redial := func(t *testing.T, stack *ConnectionStack, ut UpstreamTarget, cfg *BuildConfig) {
		t.Helper()
		stale, ok := stack.UpstreamTopmost().(*http1.Layer)
		if !ok {
			t.Fatalf("UpstreamTopmost = %T, want *http1.Layer", stack.UpstreamTopmost())
		}
		fresh, err := RedialUpstreamH1(context.Background(), UpstreamTargetOf(stack, ut.Dial), UpstreamTLSShapeOf(stack), stale, cfg, 1)
		if err != nil {
			t.Fatalf("RedialUpstreamH1: %v", err)
		}
		t.Cleanup(func() { _ = fresh.Close() })
	}

	t.Run("transparent no-ALPN stack: standard TLS, no ALPN", func(t *testing.T) {
		up := startSNIRecordingUpstream(t, []string{"http/1.1"})
		cfg := newCfg(t)
		ut := up.splitTarget("a.example")
		stack := buildNoALPNThroughClient(t, ut, cfg)
		if got := UpstreamTLSShapeOf(stack); got != UpstreamTLSStandardNoALPN {
			t.Fatalf("UpstreamTLSShapeOf = %v, want UpstreamTLSStandardNoALPN", got)
		}
		redial(t, stack, ut, cfg)
		hellos := up.recordedHellos()
		if len(hellos) != 2 {
			t.Fatalf("upstream saw %d ClientHellos, want 2", len(hellos))
		}
		for i, h := range hellos {
			if len(h.protos) != 0 || hasFFDHEGroup(h.curves) {
				t.Errorf("ClientHello %d: ALPN %v, groups %v; want no ALPN and Go standard TLS", i, h.protos, h.curves)
			}
		}
		if snis := up.recordedSNIs(); !slices.Equal(snis, []string{"a.example", "a.example"}) {
			t.Errorf("upstream SNIs = %q, want a.example twice", snis)
		}
	})

	t.Run("BuildConnectionStack stack: http/1.1 under the profile", func(t *testing.T) {
		up := startSNIRecordingUpstream(t, []string{"http/1.1"})
		cfg := newCfg(t)
		ut := up.splitTarget("a.example")
		got := buildThroughClient(t, ut, cfg, []string{"http/1.1"}, ClientHelloPeek{})
		if got.err != nil {
			t.Fatalf("BuildConnectionStack: %v", got.err)
		}
		if shape := UpstreamTLSShapeOf(got.stack); shape != UpstreamTLSProfiled {
			t.Fatalf("UpstreamTLSShapeOf = %v, want UpstreamTLSProfiled", shape)
		}
		redial(t, got.stack, ut, cfg)
		hellos := up.recordedHellos()
		if len(hellos) != 2 {
			t.Fatalf("upstream saw %d ClientHellos, want 2", len(hellos))
		}
		if h := hellos[1]; !slices.Equal(h.protos, []string{"http/1.1"}) || !hasFFDHEGroup(h.curves) {
			t.Errorf("redial ClientHello: ALPN %v, groups %v; want [http/1.1] under the firefox profile", h.protos, h.curves)
		}
	})
}

func TestUpstreamTLSShapeOf_NilStack(t *testing.T) {
	if got := UpstreamTLSShapeOf(nil); got != UpstreamTLSProfiled {
		t.Errorf("UpstreamTLSShapeOf(nil) = %v, want UpstreamTLSProfiled", got)
	}
}
