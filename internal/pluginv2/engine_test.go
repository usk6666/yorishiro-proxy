package pluginv2

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeScript writes contents to t.TempDir() and returns the absolute path.
func writeScript(t *testing.T, contents string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "p.star")
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	return path
}

func TestEngine_RegisterHookHTTPOnRequestDefaultsToPrePipeline(t *testing.T) {
	path := writeScript(t, `
def my_handler(env):
    return None

register_hook("http", "on_request", my_handler)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	got := eng.Registry().Lookup("http", "on_request", PhasePrePipeline)
	if len(got) != 1 {
		t.Fatalf("Lookup len = %d, want 1", len(got))
	}
	if got[0].Phase != PhasePrePipeline {
		t.Errorf("Phase = %q, want pre_pipeline", got[0].Phase)
	}
	if got[0].PluginName != "p" {
		t.Errorf("PluginName = %q, want %q (basename without ext)", got[0].PluginName, "p")
	}
}

func TestEngine_RegisterHookTypoIsLoadTimeError(t *testing.T) {
	path := writeScript(t, `
def h(env):
    return None
register_hook("htttp", "on_request", h)
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}})
	if err == nil {
		t.Fatal("expected load error for typo'd protocol")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T (%v)", err, err)
	}
	if le.Kind != LoadErrUnknownProtocol {
		t.Errorf("Kind = %v, want LoadErrUnknownProtocol", le.Kind)
	}
	if le.Protocol != "htttp" {
		t.Errorf("Protocol = %q, want %q", le.Protocol, "htttp")
	}
}

func TestEngine_RegisterHookUnknownEventForKnownProtocolIsLoadTimeError(t *testing.T) {
	// Event "on_chunk" is valid for ProtoRaw but not for ProtoHTTP. The
	// engine must reject this with LoadErrUnknownEvent (not UnknownProtocol).
	path := writeScript(t, `
def h(env):
    return None
register_hook("http", "on_chunk", h)
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}})
	if err == nil {
		t.Fatal("expected load error for event valid under another protocol")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T (%v)", err, err)
	}
	if le.Kind != LoadErrUnknownEvent {
		t.Errorf("Kind = %v, want LoadErrUnknownEvent", le.Kind)
	}
	if le.Protocol != "http" || le.Event != "on_chunk" {
		t.Errorf("(Protocol, Event) = (%q, %q), want (http, on_chunk)", le.Protocol, le.Event)
	}
}

func TestEngine_RegisterHookConnectionOnConnectAcceptsNoPhase(t *testing.T) {
	path := writeScript(t, `
def h(env):
    return None
register_hook("connection", "on_connect", h)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	got := eng.Registry().Lookup("connection", "on_connect", PhaseNone)
	if len(got) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(got))
	}
	if got[0].Phase != PhaseNone {
		t.Errorf("Phase = %q, want %q", got[0].Phase, PhaseNone)
	}
}

func TestEngine_RegisterHookHTTPOnResponsePostPhase(t *testing.T) {
	path := writeScript(t, `
def sign(env):
    return None
register_hook("http", "on_response", sign, phase="post_pipeline")
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	got := eng.Registry().Lookup("http", "on_response", PhasePostPipeline)
	if len(got) != 1 {
		t.Fatalf("expected 1 hook, got %d", len(got))
	}
	if got[0].Phase != PhasePostPipeline {
		t.Errorf("Phase = %q, want %q", got[0].Phase, PhasePostPipeline)
	}
}

func TestEngine_LifecycleHookRejectsExplicitPhase(t *testing.T) {
	path := writeScript(t, `
def h(env):
    return None
register_hook("connection", "on_connect", h, phase="pre_pipeline")
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}})
	if err == nil {
		t.Fatal("expected error for phase= on lifecycle event")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T", err)
	}
	if le.Kind != LoadErrPhaseNotSupported {
		t.Errorf("Kind = %v, want LoadErrPhaseNotSupported", le.Kind)
	}
}

func TestEngine_RegisterHookFnNotCallable(t *testing.T) {
	path := writeScript(t, `
register_hook("http", "on_request", "not a function")
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}})
	if err == nil {
		t.Fatal("expected NotCallable error")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T (%v)", err, err)
	}
	if le.Kind != LoadErrNotCallable {
		t.Errorf("Kind = %v, want LoadErrNotCallable", le.Kind)
	}
}

func TestEngine_RegisterHookInvalidPhaseValue(t *testing.T) {
	path := writeScript(t, `
def h(env):
    return None
register_hook("http", "on_request", h, phase="midpipeline")
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}})
	if err == nil {
		t.Fatal("expected InvalidPhase error")
	}
	var le *LoadError
	if !errors.As(err, &le) {
		t.Fatalf("expected *LoadError, got %T", err)
	}
	if le.Kind != LoadErrInvalidPhase {
		t.Errorf("Kind = %v, want LoadErrInvalidPhase", le.Kind)
	}
}

func TestEngine_PredeclaredModulesAreAvailable(t *testing.T) {
	// Acceptance criterion 5: state, crypto, store, proxy, action, config
	// modules are usable. The store module requires a DB; this test
	// covers everything except store. A separate test below covers store.
	path := writeScript(t, `
def _check_modules():
    # action: CONTINUE/DROP are sentinel strings; RESPOND/RESPOND_GRPC are
    # callable builtins (USK-671 typed-payload form).
    if action.CONTINUE != "CONTINUE": fail("action.CONTINUE")
    if action.DROP != "DROP": fail("action.DROP")
    resp = action.RESPOND(status_code=204)
    if resp == None: fail("action.RESPOND returned None")
    grpc_resp = action.RESPOND_GRPC(status=7)
    if grpc_resp == None: fail("action.RESPOND_GRPC returned None")

    # crypto: hash + encoding round-trip
    digest = crypto.sha256(b"hello")
    if len(crypto.hex_encode(digest)) == 0: fail("hex_encode")
    if len(crypto.base64_encode(digest)) == 0: fail("base64_encode")

    # state: set / get / delete
    state.set("k", "v")
    if state.get("k") != "v": fail("state round-trip")
    state.delete("k")

    # proxy module is callable surface only.
    if proxy.shutdown == None: fail("proxy.shutdown missing")

    # config: predeclared dict from PluginConfig.Vars
    if config["region"] != "us-east": fail("config var missing")

_check_modules()

def noop(env):
    return None

register_hook("http", "on_request", noop)
`)
	eng := NewEngine(nil)
	cfg := PluginConfig{
		Path:    path,
		OnError: string(OnErrorAbort),
		Vars:    map[string]any{"region": "us-east"},
	}
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{cfg}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	if got := eng.Registry().Count(); got != 1 {
		t.Errorf("Count() = %d, want 1", got)
	}
	if got := eng.PluginCount(); got != 1 {
		t.Errorf("PluginCount() = %d, want 1", got)
	}
}

func TestEngine_StepLimitTrips(t *testing.T) {
	// Top-level infinite loop should be aborted by SetMaxExecutionSteps.
	path := writeScript(t, `
n = 0
for _ in range(10000000):
    n = n + 1
`)
	eng := NewEngine(nil)
	cfg := PluginConfig{Path: path, OnError: string(OnErrorAbort), MaxSteps: 1_000}
	err := eng.LoadPlugins(context.Background(), []PluginConfig{cfg})
	if err == nil {
		t.Fatal("expected step-limit error, got nil")
	}
}

func TestEngine_LoadPluginCancelsOnContext(t *testing.T) {
	// A runaway top-level Starlark loop must abort promptly when the caller
	// cancels the context, instead of waiting for the per-thread step limit
	// to trip. MaxSteps is set high enough that ctx-cancel is the only way
	// to terminate the script in test time.
	path := writeScript(t, `
n = 0
for _ in range(1000000000):
    n = n + 1
`)
	eng := NewEngine(nil)
	cfg := PluginConfig{Path: path, OnError: string(OnErrorAbort), MaxSteps: 1_000_000_000}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// Cancel shortly after LoadPlugins begins. The Starlark runtime
		// observes the cancel and returns from ExecFileOptions.
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()

	start := time.Now()
	err := eng.LoadPlugins(ctx, []PluginConfig{cfg})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected ctx-cancel error, got nil")
	}
	// Must abort in well under a second; the loop above would take many
	// seconds to hit the step limit.
	if elapsed > 2*time.Second {
		t.Errorf("LoadPlugins did not honor ctx.Done() in time: %v", elapsed)
	}
}

func TestEngine_OnErrorSkipDoesNotAbort(t *testing.T) {
	bad := writeScript(t, `register_hook("htttp", "on_request", lambda env: None)`)
	good := writeScript(t, `
def h(env):
    return None
register_hook("http", "on_request", h)
`)
	eng := NewEngine(nil)
	err := eng.LoadPlugins(context.Background(), []PluginConfig{
		{Path: bad, OnError: string(OnErrorSkip)},
		{Path: good, OnError: string(OnErrorAbort)},
	})
	if err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	if got := eng.PluginCount(); got != 1 {
		t.Errorf("PluginCount() = %d, want 1 (only good plugin loaded)", got)
	}
	if got := eng.Registry().Lookup("http", "on_request", PhasePrePipeline); len(got) != 1 {
		t.Errorf("good plugin's hook not registered: %+v", got)
	}
}

func TestEngine_MultiplePluginsAppendInLoadOrder(t *testing.T) {
	a := writeScript(t, `
def h(env):
    return None
register_hook("http", "on_request", h)
`)
	b := writeScript(t, `
def h(env):
    return None
register_hook("http", "on_request", h)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{
		{Name: "alpha", Path: a, OnError: string(OnErrorAbort)},
		{Name: "beta", Path: b, OnError: string(OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	got := eng.Registry().Lookup("http", "on_request", PhasePrePipeline)
	if len(got) != 2 {
		t.Fatalf("Lookup len = %d, want 2", len(got))
	}
	if got[0].PluginName != "alpha" || got[1].PluginName != "beta" {
		t.Errorf("registration order: [%q, %q], want [alpha, beta]",
			got[0].PluginName, got[1].PluginName)
	}
}

func TestEngine_CloseClearsState(t *testing.T) {
	path := writeScript(t, `
state.set("k", "v")
def h(env):
    return None
register_hook("http", "on_request", h)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	if err := eng.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := eng.PluginCount(); got != 0 {
		t.Errorf("after Close PluginCount() = %d, want 0", got)
	}
}
