package connector

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// testFixedConnID is the connection ID the conn-ID adoption tests put on
// ctx, standing in for the one FullListener.handleConn / the tcp_forward
// admission mints and logs as conn_id.
const testFixedConnID = "fixed-conn"

// fixedConnIDCtx returns a ctx carrying testFixedConnID.
func fixedConnIDCtx() context.Context {
	return ContextWithConnID(context.Background(), testFixedConnID)
}

// layerConnID reports the ConnID a Layer stamps on its envelopes, and
// false for Layers that stamp no EnvelopeContext (e.g. the TLS layer).
func layerConnID(l layer.Layer) (string, bool) {
	switch v := l.(type) {
	case interface {
		EnvelopeContextTemplate() envelope.EnvelopeContext
	}:
		return v.EnvelopeContextTemplate().ConnID, true
	case interface {
		EnvelopeContext() envelope.EnvelopeContext
	}:
		return v.EnvelopeContext().ConnID, true
	}
	return "", false
}

// assertStackAdoptsConnID asserts stack.ConnID and the ConnID every
// envelope-stamping Layer on both sides carries equal want, and that each
// side has at least one such Layer.
func assertStackAdoptsConnID(t *testing.T, stack *ConnectionStack, want string) {
	t.Helper()
	if stack.ConnID != want {
		t.Errorf("stack.ConnID = %q, want %q (the ctx conn ID)", stack.ConnID, want)
	}
	for _, side := range []struct {
		name   string
		layers []layer.Layer
	}{
		{"client", stack.client.layers},
		{"upstream", stack.upstream.layers},
	} {
		stamped := 0
		for _, l := range side.layers {
			id, ok := layerConnID(l)
			if !ok {
				continue
			}
			stamped++
			if id != want {
				t.Errorf("%s Layer %T EnvelopeContext.ConnID = %q, want %q", side.name, l, id, want)
			}
		}
		if stamped == 0 {
			t.Errorf("%s side has no envelope-stamping Layer (layers=%d)", side.name, len(side.layers))
		}
	}
}

func TestGenerateConnID_UUIDFormat(t *testing.T) {
	id := GenerateConnID()
	if _, err := uuid.Parse(id); err != nil {
		t.Fatalf("GenerateConnID() = %q, not a uuid: %v", id, err)
	}
	if len(id) != 36 {
		t.Errorf("GenerateConnID() = %q, len %d, want the 36-char canonical uuid form", id, len(id))
	}
}

func TestGenerateConnID_Distinct(t *testing.T) {
	const n = 10000
	seen := make(map[string]struct{}, n)
	for i := 0; i < n; i++ {
		id := GenerateConnID()
		if _, dup := seen[id]; dup {
			t.Fatalf("GenerateConnID collided after %d draws: %q", i, id)
		}
		seen[id] = struct{}{}
	}
}

func TestConnIDOrGenerate(t *testing.T) {
	if got := ConnIDOrGenerate(fixedConnIDCtx()); got != testFixedConnID {
		t.Errorf("ConnIDOrGenerate(ctx with ID) = %q, want %q", got, testFixedConnID)
	}
	got := ConnIDOrGenerate(context.Background())
	if _, err := uuid.Parse(got); err != nil {
		t.Errorf("ConnIDOrGenerate(empty ctx) = %q, want a fresh uuid: %v", got, err)
	}
}

func TestBuildPlainHTTPStack_AdoptsCtxConnID(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	stack, err := BuildPlainHTTPStack(fixedConnIDCtx(), clientPeer, upstreamPeer, "example.com:80", &BuildConfig{})
	if err != nil {
		t.Fatalf("BuildPlainHTTPStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	assertStackAdoptsConnID(t, stack, testFixedConnID)
}

func TestBuildPlainHTTPStack_MintsWithoutCtxConnID(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	stack, err := BuildPlainHTTPStack(context.Background(), clientPeer, upstreamPeer, "example.com:80", &BuildConfig{})
	if err != nil {
		t.Fatalf("BuildPlainHTTPStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	if _, err := uuid.Parse(stack.ConnID); err != nil {
		t.Fatalf("stack.ConnID = %q, want a minted uuid: %v", stack.ConnID, err)
	}
	assertStackAdoptsConnID(t, stack, stack.ConnID)
}

func TestBuildBytechunkStack_AdoptsCtxConnID(t *testing.T) {
	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	stack, err := BuildBytechunkStack(fixedConnIDCtx(), clientPeer, upstreamPeer, "example.com:443", &BuildConfig{})
	if err != nil {
		t.Fatalf("BuildBytechunkStack: %v", err)
	}
	t.Cleanup(func() { _ = stack.Close() })
	assertStackAdoptsConnID(t, stack, testFixedConnID)
}

func TestBuildConnectionStackWithTarget_AdoptsCtxConnID(t *testing.T) {
	for _, protocol := range []ForwardProtocol{ForwardProtocolRaw, ForwardProtocolHTTP} {
		t.Run(string(protocol), func(t *testing.T) {
			_, clientPeer := pipePair(t)
			_, upstreamPeer := pipePair(t)
			params := TargetOverrideParams{Target: "api.example.com:50051", Protocol: protocol}
			stack, err := BuildConnectionStackWithTarget(fixedConnIDCtx(), clientPeer, upstreamPeer, params, newTestBuildConfig(t))
			if err != nil {
				t.Fatalf("BuildConnectionStackWithTarget(%s): %v", protocol, err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			assertStackAdoptsConnID(t, stack, testFixedConnID)
		})
	}
}

// tcpConnPair returns the two ends of a loopback TCP connection. Kernel
// buffering lets both h2 prefaces cross without the lock-step a
// net.Pipe would impose.
func tcpConnPair(t *testing.T) (a, b net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	acc := make(chan net.Conn, 1)
	go func() {
		c, aerr := ln.Accept()
		if aerr != nil {
			acc <- nil
			return
		}
		acc <- c
	}()
	a, err = net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	b = <-acc
	if b == nil {
		_ = a.Close()
		t.Fatal("accept failed")
	}
	t.Cleanup(func() { _ = a.Close(); _ = b.Close() })
	return a, b
}

// startH2CPeers runs the two HTTP/2 peers an h2c stack builder talks to:
// a ClientRole Layer standing in for the client on clientLocal and a
// ServerRole Layer standing in for the upstream on upstreamLocal.
func startH2CPeers(t *testing.T, clientLocal, upstreamLocal net.Conn) {
	t.Helper()
	for _, p := range []struct {
		conn net.Conn
		role http2.Role
	}{
		{clientLocal, http2.ClientRole},
		{upstreamLocal, http2.ServerRole},
	} {
		go func(c net.Conn, role http2.Role) {
			l, err := http2.New(c, "peer", role, http2.WithScheme("http"))
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = l.Close() })
		}(p.conn, p.role)
	}
}

func TestBuildH2CStacks_AdoptCtxConnID(t *testing.T) {
	builders := map[string]func(ctx context.Context, clientConn, upstreamConn net.Conn) (*ConnectionStack, error){
		"BuildPlainH2CStack": func(ctx context.Context, c, u net.Conn) (*ConnectionStack, error) {
			return BuildPlainH2CStack(ctx, c, u, "api.example.com:80", &BuildConfig{})
		},
		"target_override_http2": func(ctx context.Context, c, u net.Conn) (*ConnectionStack, error) {
			params := TargetOverrideParams{Target: "api.example.com:50051", Protocol: ForwardProtocolHTTP2}
			return BuildConnectionStackWithTarget(ctx, c, u, params, newTestBuildConfig(t))
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			clientLocal, clientPeer := tcpConnPair(t)
			upstreamLocal, upstreamPeer := tcpConnPair(t)
			startH2CPeers(t, clientLocal, upstreamLocal)

			ctx, cancel := context.WithTimeout(fixedConnIDCtx(), 10*time.Second)
			defer cancel()
			stack, err := build(ctx, clientPeer, upstreamPeer)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			t.Cleanup(func() { _ = stack.Close() })
			assertStackAdoptsConnID(t, stack, testFixedConnID)
		})
	}
}

// TestConnectionStackClose_ReleasesPerConnectionRotation pins that the
// per_connection upstream-proxy rotation entry cached under the ctx conn
// ID (the resolver reads ConnIDFromContext at dial time) is the one the
// stack releases on Close — i.e. the stack keys on the same ID.
func TestConnectionStackClose_ReleasesPerConnectionRotation(t *testing.T) {
	cfg := &BuildConfig{}
	r := helperResolver(t, "http://session-§__nonce§:pass@proxy.example:8080", RotationPerConnection)
	cfg.SetRotationForListener("L1", r)

	ctx := ContextWithListenerName(fixedConnIDCtx(), "L1")
	if _, err := cfg.EffectiveUpstreamProxyForCtxErr(ctx); err != nil {
		t.Fatalf("EffectiveUpstreamProxyForCtxErr: %v", err)
	}
	if _, ok := r.perConn.Load(testFixedConnID); !ok {
		t.Fatalf("precondition: per_connection entry for %q not cached", testFixedConnID)
	}

	_, clientPeer := pipePair(t)
	_, upstreamPeer := pipePair(t)
	stack, err := BuildPlainHTTPStack(ctx, clientPeer, upstreamPeer, "example.com:80", cfg)
	if err != nil {
		t.Fatalf("BuildPlainHTTPStack: %v", err)
	}
	stack.SetBuildConfig(cfg)
	_ = stack.Close()

	var left []any
	r.perConn.Range(func(k, _ any) bool {
		left = append(left, k)
		return true
	})
	if len(left) != 0 {
		t.Errorf("per_connection rotation entries left after stack.Close: %v (stack.ConnID=%q)", left, stack.ConnID)
	}
}
