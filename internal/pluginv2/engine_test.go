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

// TestIntrospect_EmptyEngine verifies an engine with no plugins loaded
// returns a zero-length slice (not nil sentinel) so the MCP handler can
// always return a well-formed array.
func TestIntrospect_EmptyEngine(t *testing.T) {
	eng := NewEngine(nil)
	got := eng.Introspect()
	if got == nil {
		t.Fatal("Introspect() returned nil; want empty slice")
	}
	if len(got) != 0 {
		t.Errorf("Introspect() returned %d entries, want 0", len(got))
	}
}

// TestIntrospect_OneRegistration confirms a single register_hook call is
// surfaced with the resolved phase, protocol, and event tuple plus the
// plugin name (basename without extension when Name is unset).
func TestIntrospect_OneRegistration(t *testing.T) {
	path := writeScript(t, `
def my_handler(ctx, m):
    return None

register_hook("http", "on_request", my_handler, phase="pre_pipeline")
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{{Path: path, OnError: string(OnErrorAbort)}}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	infos := eng.Introspect()
	if len(infos) != 1 {
		t.Fatalf("Introspect() len = %d, want 1", len(infos))
	}
	info := infos[0]
	if info.Name != "p" {
		t.Errorf("Name = %q, want %q", info.Name, "p")
	}
	if info.Path != path {
		t.Errorf("Path = %q, want %q", info.Path, path)
	}
	if !info.Enabled {
		t.Error("Enabled = false, want true")
	}
	if len(info.Registrations) != 1 {
		t.Fatalf("Registrations len = %d, want 1", len(info.Registrations))
	}
	r := info.Registrations[0]
	if r.Protocol != "http" || r.Event != "on_request" || r.Phase != "pre_pipeline" {
		t.Errorf("Registration = %+v, want {http, on_request, pre_pipeline}", r)
	}
}

// TestIntrospect_MultiplePlugins_MultipleRegistrations verifies multiple
// plugins each carrying multiple register_hook calls all surface, in load
// order. Specifically: registrations on each plugin appear in script
// order, and plugins themselves appear in load order.
func TestIntrospect_MultiplePlugins_MultipleRegistrations(t *testing.T) {
	a := writeScript(t, `
def h1(ctx, m):
    return None
def h2(ctx, m):
    return None
register_hook("http", "on_request", h1, phase="pre_pipeline")
register_hook("http", "on_response", h2, phase="post_pipeline")
`)
	b := writeScript(t, `
def h(ctx, m):
    return None
register_hook("ws", "on_message", h, phase="pre_pipeline")
register_hook("connection", "on_connect", h)
`)
	eng := NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{
		{Name: "alpha", Path: a, OnError: string(OnErrorAbort)},
		{Name: "beta", Path: b, OnError: string(OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	infos := eng.Introspect()
	if len(infos) != 2 {
		t.Fatalf("Introspect() len = %d, want 2", len(infos))
	}
	if infos[0].Name != "alpha" || infos[1].Name != "beta" {
		t.Errorf("plugin order = [%q, %q], want [alpha, beta]", infos[0].Name, infos[1].Name)
	}
	if len(infos[0].Registrations) != 2 {
		t.Errorf("alpha Registrations len = %d, want 2", len(infos[0].Registrations))
	}
	if len(infos[1].Registrations) != 2 {
		t.Errorf("beta Registrations len = %d, want 2", len(infos[1].Registrations))
	}
	a0 := infos[0].Registrations[0]
	if a0.Protocol != "http" || a0.Event != "on_request" || a0.Phase != "pre_pipeline" {
		t.Errorf("alpha[0] = %+v, want {http, on_request, pre_pipeline}", a0)
	}
	a1 := infos[0].Registrations[1]
	if a1.Protocol != "http" || a1.Event != "on_response" || a1.Phase != "post_pipeline" {
		t.Errorf("alpha[1] = %+v, want {http, on_response, post_pipeline}", a1)
	}
	b0 := infos[1].Registrations[0]
	if b0.Protocol != "ws" || b0.Event != "on_message" || b0.Phase != "pre_pipeline" {
		t.Errorf("beta[0] = %+v, want {ws, on_message, pre_pipeline}", b0)
	}
	b1 := infos[1].Registrations[1]
	if b1.Protocol != "connection" || b1.Event != "on_connect" || b1.Phase != "none" {
		t.Errorf("beta[1] = %+v, want {connection, on_connect, none}", b1)
	}
}

// TestIntrospect_RedactKeys verifies that PluginConfig.RedactKeys hides
// the corresponding Vars values behind the "<redacted>" sentinel, while
// other keys pass through verbatim.
func TestIntrospect_RedactKeys(t *testing.T) {
	path := writeScript(t, `
def h(ctx, m):
    return None
register_hook("http", "on_request", h)
`)
	eng := NewEngine(nil)
	cfg := PluginConfig{
		Path:       path,
		OnError:    string(OnErrorAbort),
		Vars:       map[string]any{"hmac_key": "secret123", "log_level": "debug", "feature_flag": true},
		RedactKeys: []string{"hmac_key"},
	}
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{cfg}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	infos := eng.Introspect()
	if len(infos) != 1 {
		t.Fatalf("Introspect len = %d, want 1", len(infos))
	}
	v := infos[0].Vars
	if got := v["hmac_key"]; got != "<redacted>" {
		t.Errorf("hmac_key = %v, want \"<redacted>\"", got)
	}
	if got := v["log_level"]; got != "debug" {
		t.Errorf("log_level = %v, want \"debug\"", got)
	}
	if got := v["feature_flag"]; got != true {
		t.Errorf("feature_flag = %v, want true", got)
	}
}

// TestIntrospect_VarsTruncation verifies a string Vars value over the
// 8 KiB cap is truncated and tagged. Values under the cap pass through
// unchanged.
func TestIntrospect_VarsTruncation(t *testing.T) {
	path := writeScript(t, `
def h(ctx, m):
    return None
register_hook("http", "on_request", h)
`)
	eng := NewEngine(nil)
	huge := make([]byte, 16*1024)
	for i := range huge {
		huge[i] = 'A'
	}
	cfg := PluginConfig{
		Path:    path,
		OnError: string(OnErrorAbort),
		Vars: map[string]any{
			"big":   string(huge),
			"small": "stable",
		},
	}
	if err := eng.LoadPlugins(context.Background(), []PluginConfig{cfg}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	infos := eng.Introspect()
	v := infos[0].Vars
	bigRet, ok := v["big"].(string)
	if !ok {
		t.Fatalf("big: type = %T, want string", v["big"])
	}
	if len(bigRet) != redactValueCap+len(redactTruncationMarker) {
		t.Errorf("big len = %d, want %d", len(bigRet), redactValueCap+len(redactTruncationMarker))
	}
	if !endsWithMarker(bigRet) {
		t.Errorf("big does not end with truncation marker: tail=%q", bigRet[len(bigRet)-32:])
	}
	if v["small"] != "stable" {
		t.Errorf("small = %v, want \"stable\"", v["small"])
	}
}

func endsWithMarker(s string) bool {
	if len(s) < len(redactTruncationMarker) {
		return false
	}
	return s[len(s)-len(redactTruncationMarker):] == redactTruncationMarker
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
