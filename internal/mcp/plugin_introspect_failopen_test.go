package mcp

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// loadFailOpenEngine loads script from a fresh temp file and dispatches
// its single (http, on_request) hook once against a plain GET.
func loadFailOpenEngine(t *testing.T, script string) *pluginv2.Engine {
	t.Helper()
	path := filepath.Join(t.TempDir(), "failopen.star")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatalf("write script: %v", err)
	}
	eng := pluginv2.NewEngine(nil)
	if err := eng.LoadPlugins(context.Background(), []pluginv2.PluginConfig{
		{Path: path, OnError: string(pluginv2.OnErrorAbort)},
	}); err != nil {
		t.Fatalf("LoadPlugins: %v", err)
	}
	hooks := eng.Registry().Lookup(pluginv2.ProtoHTTP, pluginv2.EventOnRequest, pluginv2.PhasePrePipeline)
	if len(hooks) != 1 {
		t.Fatalf("registered hooks = %d, want 1", len(hooks))
	}
	env := &envelope.Envelope{
		StreamID: "s", FlowID: "f", Direction: envelope.Send, Protocol: envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/", Authority: "example.com",
			Headers: []envelope.KeyValue{{Name: "Host", Value: "example.com"}}},
	}
	_, _ = eng.Dispatch(context.Background(), hooks[0], env)
	return eng
}

// introspectOnly calls the plugin_introspect handler and returns its single
// plugin entry.
func introspectOnly(t *testing.T, s *Server) pluginIntrospectPlugin {
	t.Helper()
	_, out, err := s.handlePluginIntrospect(context.Background(), nil, pluginIntrospectInput{})
	if err != nil {
		t.Fatalf("handlePluginIntrospect: %v", err)
	}
	if len(out.Plugins) != 1 {
		t.Fatalf("plugins = %d, want 1", len(out.Plugins))
	}
	return out.Plugins[0]
}

// T8: a hook_error reason is plugin-controlled text (fail(msg) can carry
// values read from traffic), so plugin_introspect runs it through the
// Output Filter before handing it to the agent, and bounds its length.
func TestPluginIntrospect_HookErrorReason_OutputFiltered(t *testing.T) {
	eng := loadFailOpenEngine(t, `
def hook(msg, ctx):
    fail("card " + "`+usk1276CardNumber+`" + " seen")

register_hook("http", "on_request", hook)
`)
	s := newServer(context.Background(), nil, nil, nil,
		WithPluginv2Engine(eng), WithSafetyEngine(newUSK1276CardEngine(t)))

	p := introspectOnly(t, s)
	if p.FailOpenCount != 1 || p.LastFailOpen == nil {
		t.Fatalf("fail_open_count = %d, last_fail_open = %v; want 1 and a record", p.FailOpenCount, p.LastFailOpen)
	}
	if p.LastFailOpen.Kind != string(pluginv2.FailOpenHookError) {
		t.Errorf("last_fail_open.kind = %q, want hook_error", p.LastFailOpen.Kind)
	}
	if strings.Contains(p.LastFailOpen.Reason, usk1276CardNumber) {
		t.Errorf("last_fail_open.reason = %q leaks the card number past the Output Filter", p.LastFailOpen.Reason)
	}
	if !strings.Contains(p.LastFailOpen.Reason, usk1276CardReplacement) {
		t.Errorf("last_fail_open.reason = %q, want the Output Filter replacement %q", p.LastFailOpen.Reason, usk1276CardReplacement)
	}
}

// The reason surfaced by plugin_introspect is capped at
// failOpenReasonOutputCap bytes, after masking.
func TestPluginIntrospect_FailOpenReason_Truncated(t *testing.T) {
	eng := loadFailOpenEngine(t, `
def hook(msg, ctx):
    fail("x" * 900)

register_hook("http", "on_request", hook)
`)
	s := newServer(context.Background(), nil, nil, nil, WithPluginv2Engine(eng))
	p := introspectOnly(t, s)
	if p.LastFailOpen == nil {
		t.Fatal("last_fail_open = nil, want a record")
	}
	if n := len(p.LastFailOpen.Reason); n == 0 || n > failOpenReasonOutputCap {
		t.Errorf("len(last_fail_open.reason) = %d, want 1..%d", n, failOpenReasonOutputCap)
	}
}

// The count is always present and the record carries the hook identity
// and an RFC3339 timestamp.
func TestPluginIntrospect_FailOpenFields(t *testing.T) {
	eng := loadFailOpenEngine(t, `
def hook(msg, ctx):
    return action.RESPOND_GRPC(status=16, message="denied")

register_hook("http", "on_request", hook)
`)
	s := newServer(context.Background(), nil, nil, nil, WithPluginv2Engine(eng))
	p := introspectOnly(t, s)
	if p.FailOpenCount != 1 {
		t.Fatalf("fail_open_count = %d, want 1", p.FailOpenCount)
	}
	if p.FailOpenByKind["respond_shape_mismatch"] != 1 {
		t.Errorf("fail_open_by_kind = %v, want respond_shape_mismatch=1", p.FailOpenByKind)
	}
	r := p.LastFailOpen
	if r == nil {
		t.Fatal("last_fail_open = nil")
	}
	if r.Kind != "respond_shape_mismatch" || r.Action != "RESPOND" || r.Protocol != "http" ||
		r.Event != "on_request" || r.Phase != "pre_pipeline" || !strings.Contains(r.Reason, "RESPOND_GRPC") {
		t.Errorf("last_fail_open = %+v", *r)
	}
	if _, err := time.Parse(time.RFC3339, r.At); err != nil {
		t.Errorf("last_fail_open.at = %q is not RFC3339: %v", r.At, err)
	}
}

// The stored reason is cut at pluginv2.FailOpenReasonCap before the Output
// Filter runs, so a sensitive value straddling that cut survives as an
// unmatched fragment at the end. When earlier matches shrink the text
// (a ~780-byte e-mail becomes "[MASKED:email]"), that fragment would land
// inside the 256-byte output cap and reach the agent unmasked.
func TestPluginIntrospect_TruncatedReason_StraddlingFragmentNotLeaked(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{Preset: "credit-card", Action: "mask"},
			{Preset: "email", Action: "mask"},
		},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}
	// "fail: " (6) + 783 + "@x.co" (5) + 220 spaces puts the card number at
	// byte 1014, so the 1 KiB cut keeps only "4111 1111 ".
	eng := loadFailOpenEngine(t, `
def hook(msg, ctx):
    fail("a" * 783 + "@x.co" + " " * 220 + "4111 1111 1111 1111 tail")

register_hook("http", "on_request", hook)
`)
	s := newServer(context.Background(), nil, nil, nil,
		WithPluginv2Engine(eng), WithSafetyEngine(engine))
	p := introspectOnly(t, s)
	if p.LastFailOpen == nil {
		t.Fatal("last_fail_open = nil, want a record")
	}
	if strings.Contains(p.LastFailOpen.Reason, "4111") {
		t.Errorf("last_fail_open.reason = %q leaks a fragment of the card number cut at the 1 KiB reason cap", p.LastFailOpen.Reason)
	}
	if !strings.Contains(p.LastFailOpen.Reason, "[MASKED:email]") {
		t.Errorf("last_fail_open.reason = %q, want the masked e-mail kept", p.LastFailOpen.Reason)
	}
}
