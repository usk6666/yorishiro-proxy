package mcpserver

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1160: a successful reload reconciles the live-connection registry,
// so a connection the new policy no longer admits is closed, and the
// reload's audit line says how many were closed.
func TestPolicyReload_ReconcilesLiveConns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, `{"allows":[{"hostname":"a.test"},{"hostname":"b.test"}]}`)
	e := bootEngines(t, "", path)
	h := &recordingHandler{}
	r := e.reloader(PolicySource{PolicyFile: path}, slog.New(h))
	reg := connector.NewLiveConns(discardLogger())
	r.liveConns = reg

	register := func(host string) context.Context {
		t.Helper()
		ctx, release, err := reg.Register(context.Background(), connector.LiveConn{
			ConnID: host, Via: "connect", Target: host + ":443",
			Admit: func() (bool, string) { return e.scope.CheckTarget("https", host, 443, "") },
		})
		if err != nil {
			t.Fatalf("Register %s: %v", host, err)
		}
		t.Cleanup(release)
		return ctx
	}
	ctxA := register("a.test")
	ctxB := register("b.test")

	// Unchanged reload: nothing is closed, and no Warn.
	if err := r.Reload("SIGHUP"); err != nil {
		t.Fatalf("Reload (unchanged): %v", err)
	}
	info, ok := h.find(slog.LevelInfo, "target scope policy reloaded")
	if !ok {
		t.Fatalf("missing reload Info; got:\n%s", h.dump())
	}
	if got := info["live_conns_closed"]; got.String() != "0" {
		t.Errorf("unchanged reload live_conns_closed = %v, want 0", got)
	}
	if ctxA.Err() != nil || ctxB.Err() != nil {
		t.Fatalf("unchanged reload cancelled a live connection")
	}

	// Narrowing reload: b.test is closed, a.test survives.
	h.records = nil
	writeFileAtomic(t, path, `{"allows":[{"hostname":"a.test"}]}`)
	if err := r.Reload("SIGHUP"); err != nil {
		t.Fatalf("Reload (narrow): %v", err)
	}
	if ctxA.Err() != nil {
		t.Errorf("a.test is still admitted but was cancelled: %v", context.Cause(ctxA))
	}
	if !errors.Is(context.Cause(ctxB), connector.ErrTargetScopeRevoked) {
		t.Errorf("b.test cause = %v, want ErrTargetScopeRevoked", context.Cause(ctxB))
	}
	info, ok = h.find(slog.LevelInfo, "target scope policy reloaded")
	if !ok {
		t.Fatalf("missing reload Info; got:\n%s", h.dump())
	}
	if got := info["live_conns_closed"]; got.String() != "1" {
		t.Errorf("narrowing reload live_conns_closed = %v, want 1", got)
	}
	warn, ok := h.find(slog.LevelWarn, "target scope policy reload closed live connections")
	if !ok {
		t.Fatalf("missing Warn for closed live connections; got:\n%s", h.dump())
	}
	if got := warn["live_conns_closed"]; got.String() != "1" {
		t.Errorf("Warn live_conns_closed = %v, want 1", got)
	}
}

// A rejected reload leaves the policy, and therefore every live
// connection, untouched.
func TestPolicyReload_RejectedReloadKeepsLiveConns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, `{"allows":[{"hostname":"a.test"}]}`)
	e := bootEngines(t, "", path)
	r := e.reloader(PolicySource{PolicyFile: path}, discardLogger())
	reg := connector.NewLiveConns(discardLogger())
	r.liveConns = reg
	ctx, release, err := reg.Register(context.Background(), connector.LiveConn{
		ConnID: "a", Via: "connect", Target: "a.test:443",
		Admit: func() (bool, string) { return e.scope.CheckTarget("https", "a.test", 443, "") },
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	defer release()

	writeFileAtomic(t, path, `{"allows":[{"hostname":"*"}]}`)
	if err := r.Reload("SIGHUP"); err == nil {
		t.Fatal("Reload accepted an invalid policy")
	}
	if ctx.Err() != nil {
		t.Errorf("rejected reload cancelled a live connection: %v", context.Cause(ctx))
	}
}
