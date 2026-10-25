//go:build e2e && !e2e_smoke

package proxybuild_test

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1376 / USK-1236 (E8): the tcp_forwards `grpc` arm judges each RPC's
// :authority and path. A denied :authority is refused with
// PERMISSION_DENIED; a path-scoped allow admits the arm (it used to be
// refused at the gate because no gRPC path was ever checked) and then
// applies per method.

func startGRPCScopeForward(t *testing.T) (*scopeForwardFixture, *atomic.Int64) {
	t.Helper()
	var hits atomic.Int64
	upAddr, stop := startH2CGRPCUpstream(t, &echoServer{unary: func(_ context.Context, req []byte) ([]byte, error) {
		hits.Add(1)
		return req, nil
	}})
	t.Cleanup(stop)
	return startScopeForward(t, &config.ForwardConfig{Target: upAddr, Protocol: "grpc"}), &hits
}

func invokeViaForward(t *testing.T, fwdAddr, authority, fullMethod string) error {
	t.Helper()
	opts := []grpc.DialOption{
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	}
	if authority != "" {
		opts = append(opts, grpc.WithAuthority(authority))
	}
	cc, err := grpc.NewClient(fwdAddr, opts...)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer cc.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req := []byte("usk-1376")
	var resp []byte
	return cc.Invoke(ctx, fullMethod, &req, &resp)
}

func wantPermissionDenied(t *testing.T, err error, what string) {
	t.Helper()
	if st, _ := status.FromError(err); err == nil || st.Code() != codes.PermissionDenied {
		t.Errorf("%s: err = %v, want PermissionDenied", what, err)
	}
}

func waitForwardBlockedGRPC(t *testing.T, f *scopeForwardFixture) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, st := range f.store.Streams() {
			if st.Protocol == "grpc" && st.BlockedBy == "target_scope" {
				return
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Errorf("no grpc Stream with blocked_by=target_scope recorded")
}

func TestProxybuild_TCPForward_GRPC_DeniedAuthority(t *testing.T) {
	f, hits := startGRPCScopeForward(t)
	f.scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, []connector.TargetRule{{Hostname: "denied.example"}})
	method := fwdEchoFullMethod(fwdEchoMethodUnary)

	if err := invokeViaForward(t, f.fwdAddr, "vhost.example", method); err != nil {
		t.Fatalf("non-denied :authority: %v", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	wantPermissionDenied(t, invokeViaForward(t, f.fwdAddr, "denied.example", method), ":authority denied.example")
	if got := hits.Load(); got != 1 {
		t.Errorf("upstream hits = %d, want 1 — the denied :authority reached the upstream", got)
	}
	waitForwardBlockedGRPC(t, f)
}

func TestProxybuild_TCPForward_GRPC_PathScopedAllow(t *testing.T) {
	f, hits := startGRPCScopeForward(t)
	f.scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/" + fwdEchoServiceName + "/"}}, nil)

	if err := invokeViaForward(t, f.fwdAddr, "", fwdEchoFullMethod(fwdEchoMethodUnary)); err != nil {
		t.Fatalf("method under the allowed prefix: %v, want success", err)
	}
	if got := hits.Load(); got != 1 {
		t.Fatalf("upstream hits = %d, want 1", got)
	}
	wantPermissionDenied(t, invokeViaForward(t, f.fwdAddr, "", "/other.Service/Do"), "method outside the allowed prefix")
	waitForwardBlockedGRPC(t, f)
}
