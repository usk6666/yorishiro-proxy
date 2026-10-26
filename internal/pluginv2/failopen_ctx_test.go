package pluginv2

import (
	"context"
	"testing"
	"time"
)

// failOpenKindHookTimeout is spelled as a literal so these tests compile
// independently of the constant they pin.
const failOpenKindHookTimeout = FailOpenKind("hook_timeout")

// spinningHookBody loops far longer than any test deadline; paired with a
// huge MaxSteps budget, only ctx expiry can stop it.
const spinningHookBody = `
    n = 0
    for _ in range(1000000000):
        n = n + 1
    return None
`

// loadFailOpenPluginSteps is loadFailOpenPlugin with an explicit step
// budget.
func loadFailOpenPluginSteps(t *testing.T, script string, maxSteps uint64, protocol, event string, phase Phase) (*Engine, Hook) {
	t.Helper()
	path := writeScript(t, script)
	eng := NewEngine(nil)
	cfg := PluginConfig{Path: path, OnError: string(OnErrorAbort), MaxSteps: maxSteps}
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{cfg}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	hooks := eng.Registry().Lookup(protocol, event, phase)
	if len(hooks) != 1 {
		t.Fatalf("registered hooks for (%s, %s, %s) = %d, want 1", protocol, event, phase, len(hooks))
	}
	return eng, hooks[0]
}

// A lifecycle hook on a DROP-capable event that outlives its deadline is
// cancelled and FireLifecycle returns CONTINUE — the connection is
// accepted although the hook might have dropped it. That is a fail-open
// and must be counted.
func TestFailOpen_LifecycleDeadlineExceeded_Counted(t *testing.T) {
	eng, _ := loadFailOpenPluginSteps(t, `
def hook(msg, ctx):`+spinningHookBody+`
register_hook("connection", "on_connect", hook)
`, 1_000_000_000_000, ProtoConnection, EventOnConnect, PhaseNone)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	act, err := eng.FireLifecycle(ctx, ProtoConnection, EventOnConnect, nil,
		BuildConnectionConnectDict("c1", "127.0.0.1:1", "default"))
	if err != nil || act != ActionContinue {
		t.Fatalf("FireLifecycle = (%v, %v), want (CONTINUE, nil)", act, err)
	}
	got := onlyFailOpen(t, eng)
	if got.Total != 1 || got.ByKind[failOpenKindHookTimeout] != 1 {
		t.Fatalf("FailOpen = {Total: %d, ByKind: %v}, want 1 %s", got.Total, got.ByKind, failOpenKindHookTimeout)
	}
	if got.Last == nil || got.Last.Protocol != ProtoConnection || got.Last.Event != EventOnConnect {
		t.Errorf("FailOpen.Last = %+v, want (connection, on_connect)", got.Last)
	}
}

// Dispatch under an expired deadline forwards the message unchanged, so
// it is counted the same way.
func TestFailOpen_DispatchDeadlineExceeded_Counted(t *testing.T) {
	eng, hook := loadFailOpenPluginSteps(t, `
def hook(msg, ctx):`+spinningHookBody+`
register_hook("http", "on_request", hook)
`, 1_000_000_000_000, ProtoHTTP, EventOnRequest, PhasePrePipeline)

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	out, err := eng.Dispatch(ctx, hook, httpEnv(t))
	if err != nil || out == nil || out.Action != ActionContinue {
		t.Fatalf("Dispatch = (%+v, %v), want CONTINUE", out, err)
	}
	got := onlyFailOpen(t, eng)
	if got.Total != 1 || got.ByKind[failOpenKindHookTimeout] != 1 {
		t.Fatalf("FailOpen = {Total: %d, ByKind: %v}, want 1 %s", got.Total, got.ByKind, failOpenKindHookTimeout)
	}
}

// A cancelled (not timed-out) ctx is teardown: the hook error it causes
// is not a fail-open.
func TestFailOpen_CancelledCtx_NotCounted(t *testing.T) {
	t.Run("Dispatch", func(t *testing.T) {
		eng, hook := loadFailOpenPlugin(t, `
def hook(msg, ctx):
    fail("boom")

register_hook("http", "on_request", hook)
`, ProtoHTTP, EventOnRequest, PhasePrePipeline)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = eng.Dispatch(ctx, hook, httpEnv(t))
		if got := onlyFailOpen(t, eng); got.Total != 0 {
			t.Errorf("FailOpen = %+v, want 0 under a cancelled ctx", got)
		}
	})
	t.Run("FireLifecycle", func(t *testing.T) {
		eng, _ := loadFailOpenPlugin(t, `
def hook(msg, ctx):
    fail("boom")

register_hook("connection", "on_connect", hook)
`, ProtoConnection, EventOnConnect, PhaseNone)
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, _ = eng.FireLifecycle(ctx, ProtoConnection, EventOnConnect, nil,
			BuildConnectionConnectDict("c1", "127.0.0.1:1", "default"))
		if got := onlyFailOpen(t, eng); got.Total != 0 {
			t.Errorf("FailOpen = %+v, want 0 under a cancelled ctx", got)
		}
	})
}

// Exhausting the step budget under a live ctx is a hook error.
func TestFailOpen_StepBudgetExhausted_CountedAsHookError(t *testing.T) {
	eng, hook := loadFailOpenPluginSteps(t, `
def hook(msg, ctx):`+spinningHookBody+`
register_hook("http", "on_request", hook)
`, 10_000, ProtoHTTP, EventOnRequest, PhasePrePipeline)

	_, _ = eng.Dispatch(context.Background(), hook, httpEnv(t))
	got := onlyFailOpen(t, eng)
	if got.Total != 1 || got.ByKind[FailOpenHookError] != 1 {
		t.Fatalf("FailOpen = {Total: %d, ByKind: %v}, want 1 %s", got.Total, got.ByKind, FailOpenHookError)
	}
}
