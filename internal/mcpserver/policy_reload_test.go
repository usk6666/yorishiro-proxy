package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1115: Policy Layer reload. The reloader is driven directly here; the
// SIGHUP wiring is covered by cmd/yorishiro-proxy's binary smoke test and
// the end-to-end reload by internal/mcptest.

// recordingHandler is a slog.Handler that keeps every record so tests can
// assert level, message and attributes.
type recordingHandler struct {
	mu      sync.Mutex
	records []slog.Record
}

func (h *recordingHandler) Enabled(context.Context, slog.Level) bool { return true }
func (h *recordingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.records = append(h.records, r.Clone())
	return nil
}
func (h *recordingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *recordingHandler) WithGroup(string) slog.Handler      { return h }

// find returns the attributes of the first record with the given level and
// message, and whether one was found.
func (h *recordingHandler) find(level slog.Level, msg string) (map[string]slog.Value, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, r := range h.records {
		if r.Level != level || r.Message != msg {
			continue
		}
		attrs := map[string]slog.Value{}
		r.Attrs(func(a slog.Attr) bool {
			attrs[a.Key] = a.Value.Resolve()
			return true
		})
		return attrs, true
	}
	return nil, false
}

func (h *recordingHandler) dump() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var b strings.Builder
	for _, r := range h.records {
		fmt.Fprintf(&b, "%s %q", r.Level, r.Message)
		r.Attrs(func(a slog.Attr) bool {
			fmt.Fprintf(&b, " %s=%v", a.Key, a.Value)
			return true
		})
		b.WriteByte('\n')
	}
	return b.String()
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// writeFileAtomic writes content to path atomically (temp file + rename), the way
// an operator's distributor should, so concurrent readers never observe a
// half-written file.
func writeFileAtomic(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", tmp, err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatalf("rename %s: %v", tmp, err)
	}
}

// policyEngines is the boot-equivalent trio of Policy Layer consumers.
type policyEngines struct {
	scope *connector.TargetScope
	rl    *connector.RateLimiter
	bm    *connector.BudgetManager
}

// bootEngines builds the three engines exactly as Run does at boot, from
// the same LoadConfigs result.
func bootEngines(t *testing.T, configFile, policyFile string) policyEngines {
	t.Helper()
	res, err := LoadConfigs(configFile, policyFile)
	if err != nil {
		t.Fatalf("LoadConfigs: %v", err)
	}
	e := policyEngines{
		scope: InitTargetScope(res.TargetScopePolicy),
		rl:    InitRateLimiter(res.TargetScopePolicy, discardLogger()),
		bm:    InitBudgetManager(res.TargetScopePolicy, discardLogger()),
	}
	e.bm.Start(func(string) {})
	t.Cleanup(e.bm.Stop)
	return e
}

func (e policyEngines) reloader(source PolicySource, logger *slog.Logger) *policyReloader {
	return newPolicyReloader(source, e.scope, e.rl, e.bm, logger)
}

// snapshot captures every Policy Layer value the reload may change.
type policyState struct {
	allows, denies []connector.TargetRule
	rate           connector.RateLimitConfig
	budget         connector.BudgetConfig
	origin         connector.PolicyOrigin
}

func (e policyEngines) state() policyState {
	a, d := e.scope.PolicyRules()
	return policyState{allows: a, denies: d, rate: e.rl.PolicyLimits(), budget: e.bm.PolicyBudget(), origin: e.scope.PolicyOrigin()}
}

const bootPolicy = `{
  "allows": [{"hostname": "old.test"}],
  "rate_limits": {"max_requests_per_second": 100},
  "budget": {"max_total_requests": 1000}
}`

// TestPolicyReload_AppliesNewPolicyFile is acceptance criterion 1 at the
// reload seam: a newly denied host is blocked, a newly allowed host passes,
// and sections omitted from the new file are cleared (R4: reloading equals
// booting with that file). request_count survives (R6).
func TestPolicyReload_AppliesNewPolicyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, bootPolicy)
	e := bootEngines(t, "", path)
	e.bm.RecordRequest()
	e.bm.RecordRequest()

	if ok, _ := e.scope.CheckTarget("https", "old.test", 443, "/"); !ok {
		t.Fatal("precondition: old.test blocked at boot")
	}

	writeFileAtomic(t, path, `{"allows":[{"hostname":"new.test"}],"denies":[{"hostname":"old.test"}]}`)
	before := time.Now()
	if err := e.reloader(PolicySource{PolicyFile: path}, discardLogger()).Reload("test"); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	if ok, reason := e.scope.CheckTarget("https", "old.test", 443, "/"); ok || reason != "blocked by policy deny rule" {
		t.Errorf("CheckTarget(old.test) = (%v, %q), want blocked by the new policy deny", ok, reason)
	}
	if ok, reason := e.scope.CheckTarget("https", "new.test", 443, "/"); !ok {
		t.Errorf("CheckTarget(new.test) blocked (%s), want allowed by the new policy", reason)
	}
	if got := e.rl.PolicyLimits(); !got.IsZero() {
		t.Errorf("PolicyLimits after reload without rate_limits = %+v, want zero (full replacement)", got)
	}
	if got := e.bm.PolicyBudget(); !got.IsZero() {
		t.Errorf("PolicyBudget after reload without budget = %+v, want zero (full replacement)", got)
	}
	if got := e.bm.RequestCount(); got != 2 {
		t.Errorf("RequestCount after reload = %d, want 2 (reload must not reset counters)", got)
	}
	origin := e.scope.PolicyOrigin()
	if origin.Source != "policy file" || origin.LoadedAt.Before(before) {
		t.Errorf("PolicyOrigin = %+v, want source \"policy file\" loaded at/after %v", origin, before)
	}
}

// TestPolicyReload_RejectsInvalidPolicyKeepsOld is acceptance criterion 2
// (T3) and atomicity (T9): any invalid input is rejected as a whole and
// all three engines keep the previous policy.
func TestPolicyReload_RejectsInvalidPolicyKeepsOld(t *testing.T) {
	cases := []struct {
		name    string
		content string // "" means: delete the file
		wantErr string
	}{
		{"out-of-vocabulary scheme", `{"allows":[{"hostname":"x.test","schemes":["wss"]}]}`, `scheme "wss"`},
		{"malformed JSON", `{"allows":[`, "invalid JSON"},
		{"HAR document", `{"log":{"version":"1.2","entries":[]}}`, `unknown field "log"`},
		{"valid rules but negative rate limit", `{"allows":[{"hostname":"new.test"}],"rate_limits":{"max_requests_per_second":-1}}`, "rate_limits"},
		{"valid rules but negative budget", `{"denies":[{"hostname":"old.test"}],"budget":{"max_total_requests":-5}}`, "budget"},
		{"missing file", "", "read policy file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "policy.json")
			writeFileAtomic(t, path, bootPolicy)
			e := bootEngines(t, "", path)
			e.scope.SetPolicyOrigin(connector.PolicyOrigin{Source: "policy file", LoadedAt: time.Unix(1, 0)})
			want := e.state()

			if tc.content == "" {
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			} else {
				writeFileAtomic(t, path, tc.content)
			}

			err := e.reloader(PolicySource{PolicyFile: path}, discardLogger()).Reload("test")
			if err == nil {
				t.Fatal("Reload accepted an invalid policy, want an error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("Reload error = %q, want substring %q", err, tc.wantErr)
			}
			if got := e.state(); !reflect.DeepEqual(got, want) {
				t.Errorf("Policy Layer changed by a rejected reload:\n got  %+v\n want %+v", got, want)
			}
			if ok, _ := e.scope.CheckTarget("https", "old.test", 443, "/"); !ok {
				t.Error("old.test blocked after a rejected reload; the previous policy must keep working")
			}
		})
	}
}

// TestPolicyReload_ConfigFileSource covers R5: without -target-policy-file
// the reload re-reads the config file's target_scope_policy, validating the
// whole config exactly as boot does.
func TestPolicyReload_ConfigFileSource(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	writeFileAtomic(t, path, `{"target_scope_policy":{"allows":[{"hostname":"old.test"}]}}`)
	e := bootEngines(t, path, "")
	r := e.reloader(PolicySource{ConfigFile: path}, discardLogger())

	writeFileAtomic(t, path, `{"target_scope_policy":{"allows":[{"hostname":"new.test"}]}}`)
	if err := r.Reload("test"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if ok, _ := e.scope.CheckTarget("https", "new.test", 443, "/"); !ok {
		t.Error("new.test blocked after reloading the config file")
	}
	if got := e.scope.PolicyOrigin().Source; got != "config file" {
		t.Errorf("PolicyOrigin.Source = %q, want \"config file\"", got)
	}

	// A config that boot would refuse (invalid protocol limits) is refused
	// on reload too, even though its policy section is valid.
	want := e.state()
	writeFileAtomic(t, path, `{"target_scope_policy":{"allows":[{"hostname":"other.test"}]},"web_socket":{"max_frame_size":-1}}`)
	if err := r.Reload("test"); err == nil {
		t.Error("Reload accepted a config file that boot would reject")
	}
	if got := e.state(); !reflect.DeepEqual(got, want) {
		t.Errorf("Policy Layer changed by a rejected config reload:\n got  %+v\n want %+v", got, want)
	}

	// Removing the section is a full replacement: no policy at all.
	writeFileAtomic(t, path, `{}`)
	if err := r.Reload("test"); err != nil {
		t.Fatalf("Reload of a config without target_scope_policy: %v", err)
	}
	if e.scope.HasPolicyRules() {
		t.Error("policy rules remain after reloading a config without target_scope_policy")
	}
}

// TestPolicyReload_PolicyFileShadowsConfigFile: with both sources the
// policy file wins on reload exactly as at boot.
func TestPolicyReload_PolicyFileShadowsConfigFile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.json")
	polPath := filepath.Join(dir, "policy.json")
	writeFileAtomic(t, cfgPath, `{"target_scope_policy":{"allows":[{"hostname":"from-config.test"}]}}`)
	writeFileAtomic(t, polPath, `{"allows":[{"hostname":"from-policy.test"}]}`)
	e := bootEngines(t, cfgPath, polPath)

	writeFileAtomic(t, cfgPath, `{"target_scope_policy":{"allows":[{"hostname":"config-v2.test"}]}}`)
	writeFileAtomic(t, polPath, `{"allows":[{"hostname":"policy-v2.test"}]}`)
	if err := e.reloader(PolicySource{ConfigFile: cfgPath, PolicyFile: polPath}, discardLogger()).Reload("test"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	allows, _ := e.scope.PolicyRules()
	if len(allows) != 1 || allows[0].Hostname != "policy-v2.test" {
		t.Errorf("policy allows = %+v, want [policy-v2.test] from the policy file", allows)
	}
}

// TestPolicyReload_NoSourceWarnsAndDoesNothing covers R5's no-source case.
func TestPolicyReload_NoSourceWarnsAndDoesNothing(t *testing.T) {
	e := bootEngines(t, "", "")
	h := &recordingHandler{}
	err := e.reloader(PolicySource{}, slog.New(h)).Reload("test")
	if err == nil || !strings.Contains(err.Error(), "no policy source") {
		t.Errorf("Reload with no source error = %v, want \"no policy source\"", err)
	}
	if _, ok := h.find(slog.LevelWarn, "target scope policy reload skipped: no policy source configured"); !ok {
		t.Errorf("missing Warn record; got:\n%s", h.dump())
	}
}

// TestPolicyReload_Logs is T11: Info with trigger / source / path / sha256
// / counts on success, Error with the reason on reject, Warn naming the
// agent allows that the narrowed policy no longer covers (R2, T6).
func TestPolicyReload_Logs(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, `{"allows":[{"hostname":"*.a.test"},{"hostname":"*.b.test"}],"denies":[{"hostname":"bad.test"}]}`)
	e := bootEngines(t, "", path)
	if err := e.scope.SetAgentRules([]connector.TargetRule{{Hostname: "x.a.test"}, {Hostname: "y.b.test"}}, nil); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	h := &recordingHandler{}
	r := e.reloader(PolicySource{PolicyFile: path}, slog.New(h))

	newPolicy := `{"allows":[{"hostname":"*.a.test"}],"rate_limits":{"max_requests_per_second":5},"budget":{"max_duration":"1h"}}`
	writeFileAtomic(t, path, newPolicy)
	if err := r.Reload("SIGHUP"); err != nil {
		t.Fatalf("Reload: %v", err)
	}

	info, ok := h.find(slog.LevelInfo, "target scope policy reloaded")
	if !ok {
		t.Fatalf("missing Info \"target scope policy reloaded\"; got:\n%s", h.dump())
	}
	sum := sha256.Sum256([]byte(newPolicy))
	wantAttrs := map[string]string{
		"trigger":        "SIGHUP",
		"source":         "policy file",
		"path":           path,
		"sha256":         hex.EncodeToString(sum[:]),
		"allows_before":  "2",
		"allows_after":   "1",
		"denies_before":  "1",
		"denies_after":   "0",
		"policy_max_rps": "5",
	}
	for k, want := range wantAttrs {
		if got, ok := info[k]; !ok || got.String() != want {
			t.Errorf("Info attr %s = %v (present=%v), want %s", k, got, ok, want)
		}
	}
	if _, ok := info["mtime"]; !ok {
		t.Error("Info record lacks mtime")
	}

	warn, ok := h.find(slog.LevelWarn, "agent allow rules are outside the reloaded policy allow list and no longer match")
	if !ok {
		t.Fatalf("missing Warn about agent allows outside the policy; got:\n%s", h.dump())
	}
	if got := warn["agent_allows"].String(); !strings.Contains(got, "y.b.test") || strings.Contains(got, "x.a.test") {
		t.Errorf("Warn agent_allows = %q, want only y.b.test", got)
	}

	writeFileAtomic(t, path, `{"allows":[{"hostname":"*"}]}`)
	if err := r.Reload("SIGHUP"); err == nil {
		t.Fatal("Reload accepted hostname \"*\"")
	}
	errAttrs, ok := h.find(slog.LevelError, "target scope policy reload rejected; previous policy retained")
	if !ok {
		t.Fatalf("missing Error record for the rejected reload; got:\n%s", h.dump())
	}
	if got := errAttrs["error"].String(); !strings.Contains(got, `hostname "*"`) {
		t.Errorf("Error attr error = %q, want the validation reason", got)
	}
	if got := errAttrs["trigger"].String(); got != "SIGHUP" {
		t.Errorf("Error attr trigger = %q, want SIGHUP", got)
	}
}

// TestPolicyReload_WarnsWhenBudgetAlreadyExhausted (R6): narrowing the
// budget below current usage is logged so the operator knows the proxy is
// about to stop.
func TestPolicyReload_WarnsWhenBudgetAlreadyExhausted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, `{}`)
	e := bootEngines(t, "", path)
	for i := 0; i < 3; i++ {
		e.bm.RecordRequest()
	}
	h := &recordingHandler{}
	writeFileAtomic(t, path, `{"budget":{"max_total_requests":2}}`)
	if err := e.reloader(PolicySource{PolicyFile: path}, slog.New(h)).Reload("test"); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if _, ok := h.find(slog.LevelWarn, "reloaded policy budget is already exhausted; the proxy stops"); !ok {
		t.Errorf("missing budget-exhausted Warn; got:\n%s", h.dump())
	}
}

// policyRulesRemovedWarn is the Warn a reload logs when it drops every
// policy allow and deny rule.
const policyRulesRemovedWarn = "reloaded policy has no allow or deny rules; the previous target scope policy rules were removed"

// TestPolicyReload_WarnsWhenPolicyRulesRemoved (security review S-1): the
// -config source is decoded leniently, as at boot, so a misspelled key or
// an emptied file reloads as "no policy" and silently drops every allow
// and deny. The reload cannot refuse it without diverging from boot, but
// it must say so loudly: a Warn naming the source path and the rule counts
// that were dropped.
func TestPolicyReload_WarnsWhenPolicyRulesRemoved(t *testing.T) {
	const bootConfig = `{"target_scope_policy":{"allows":[{"hostname":"old.test"},{"hostname":"*.old.test"}],"denies":[{"hostname":"bad.old.test"}]}}`
	const bootPolicyFile = `{"allows":[{"hostname":"old.test"},{"hostname":"*.old.test"}],"denies":[{"hostname":"bad.old.test"}]}`
	cases := []struct {
		name           string
		policyFile     bool // source is -target-policy-file instead of -config
		content        string
		sectionPresent bool
	}{
		{"config: misspelled top-level key", false, `{"target_scope_polcy":{"allows":[{"hostname":"new.test"}]}}`, false},
		{"config: misspelled keys inside the section", false, `{"target_scope_policy":{"allow":[{"hostname":"new.test"}],"deny":[{"hostname":"bad.test"}]}}`, true},
		{"config: empty object", false, `{}`, false},
		{"config: null", false, `null`, false},
		{"policy file: empty object", true, `{}`, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "source.json")
			var e policyEngines
			var source PolicySource
			if tc.policyFile {
				writeFileAtomic(t, path, bootPolicyFile)
				e = bootEngines(t, "", path)
				source = PolicySource{PolicyFile: path}
			} else {
				writeFileAtomic(t, path, bootConfig)
				e = bootEngines(t, path, "")
				source = PolicySource{ConfigFile: path}
			}
			h := &recordingHandler{}
			writeFileAtomic(t, path, tc.content)
			if err := e.reloader(source, slog.New(h)).Reload("SIGHUP"); err != nil {
				t.Fatalf("Reload: %v (boot accepts this file, so reload must too)", err)
			}
			if e.scope.HasPolicyRules() {
				t.Fatal("precondition: the reload was expected to clear the policy rules")
			}
			warn, ok := h.find(slog.LevelWarn, policyRulesRemovedWarn)
			if !ok {
				t.Fatalf("missing Warn %q; got:\n%s", policyRulesRemovedWarn, h.dump())
			}
			wantSource := "config file"
			if tc.policyFile {
				wantSource = "policy file"
			}
			want := map[string]string{
				"trigger":                "SIGHUP",
				"source":                 wantSource,
				"path":                   path,
				"allows_before":          "2",
				"denies_before":          "1",
				"policy_section_present": fmt.Sprint(tc.sectionPresent),
			}
			for k, w := range want {
				if got, ok := warn[k]; !ok || got.String() != w {
					t.Errorf("Warn attr %s = %v (present=%v), want %s", k, got, ok, w)
				}
			}
		})
	}

	// Negative controls: the Warn is about losing rules, not about every
	// reload or every rule-less policy.
	t.Run("narrowing that keeps rules does not warn", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeFileAtomic(t, path, bootConfig)
		e := bootEngines(t, path, "")
		h := &recordingHandler{}
		writeFileAtomic(t, path, `{"target_scope_policy":{"denies":[{"hostname":"bad.old.test"}]}}`)
		if err := e.reloader(PolicySource{ConfigFile: path}, slog.New(h)).Reload("SIGHUP"); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if _, ok := h.find(slog.LevelWarn, policyRulesRemovedWarn); ok {
			t.Errorf("unexpected Warn %q for a reload that keeps a deny rule; got:\n%s", policyRulesRemovedWarn, h.dump())
		}
	})
	t.Run("no rules before and after does not warn", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.json")
		writeFileAtomic(t, path, `{}`)
		e := bootEngines(t, path, "")
		h := &recordingHandler{}
		writeFileAtomic(t, path, `{"target_scope_policy":{"rate_limits":{"max_requests_per_second":5}}}`)
		if err := e.reloader(PolicySource{ConfigFile: path}, slog.New(h)).Reload("SIGHUP"); err != nil {
			t.Fatalf("Reload: %v", err)
		}
		if _, ok := h.find(slog.LevelWarn, policyRulesRemovedWarn); ok {
			t.Errorf("unexpected Warn %q when there were no rules to remove; got:\n%s", policyRulesRemovedWarn, h.dump())
		}
	})
}

// TestPolicyReload_ConcurrentWithReaders is T10 (run under -race): reloads,
// concurrent reloads, and the data-path readers of all three engines.
func TestPolicyReload_ConcurrentWithReaders(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	writeFileAtomic(t, path, bootPolicy)
	e := bootEngines(t, "", path)
	r := e.reloader(PolicySource{PolicyFile: path}, discardLogger())

	variants := []string{
		bootPolicy,
		`{"allows":[{"hostname":"new.test"}],"rate_limits":{"max_requests_per_host_per_second":50},"budget":{"max_duration":"1h"}}`,
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var reloads atomic.Int64
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if r.Reload("race") == nil {
					reloads.Add(1)
				}
			}
		}()
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				e.scope.CheckTarget("https", "old.test", 443, "/")
				e.scope.PolicyOrigin()
				e.rl.Check("old.test")
				e.bm.RecordRequest()
				e.bm.EffectiveBudget()
			}
		}()
	}
	for i := 0; i < 50; i++ {
		writeFileAtomic(t, path, variants[i%2])
		time.Sleep(time.Millisecond)
	}
	close(stop)
	wg.Wait()
	if reloads.Load() == 0 {
		t.Error("no reload succeeded during the race run")
	}
}

// TestPolicyReloader_RunConsumesTriggers: each trigger event runs one
// reload and reports its result; cancelling ctx ends the loop.
func TestPolicyReloader_RunConsumesTriggers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	writeFileAtomic(t, path, bootPolicy)
	e := bootEngines(t, "", path)
	r := e.reloader(PolicySource{PolicyFile: path}, discardLogger())

	ctx, cancel := context.WithCancel(context.Background())
	trig := make(chan struct{}, 1)
	results := make(chan error, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.run(ctx, trig, "test", func(err error) { results <- err })
	}()

	writeFileAtomic(t, path, `{"denies":[{"hostname":"old.test"}]}`)
	trig <- struct{}{}
	select {
	case err := <-results:
		if err != nil {
			t.Fatalf("reload result = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("trigger did not produce a reload result within 5s")
	}
	if ok, _ := e.scope.CheckTarget("https", "old.test", 443, "/"); ok {
		t.Error("old.test still allowed after a triggered reload")
	}

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("run did not return after ctx cancel")
	}
}

// TestRun_PolicyReloadHookOnlyWithPolicySource is T4b (decision U2): Run
// installs the reload trigger only when -target-policy-file or -config is
// given, and releases it when Run returns. Without a source the hook is
// never called, so the binary leaves SIGHUP at Go's default.
//
// -no-http-mcp without -stdio-mcp makes Run return on its own after the
// whole assembly (the "no MCP transport enabled" error), so these runs end
// without a listener.
func TestRun_PolicyReloadHookOnlyWithPolicySource(t *testing.T) {
	dir := t.TempDir()
	policyPath := filepath.Join(dir, "policy.json")
	writeFileAtomic(t, policyPath, `{"allows":[{"hostname":"x.test"}]}`)
	configPath := filepath.Join(dir, "config.json")
	writeFileAtomic(t, configPath, `{}`)

	cases := []struct {
		name          string
		extra         []string
		wantInstalled bool
	}{
		{"no source", nil, false},
		{"policy file", []string{"-target-policy-file", policyPath}, true},
		{"config file", []string{"-config", configPath}, true},
	}
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			fs := flag.NewFlagSet("reload-hook", flag.ContinueOnError)
			fs.SetOutput(discardWriter{})
			args := append([]string{
				"-db", filepath.Join(dir, fmt.Sprintf("hook-%d.db", i)),
				"-ca-ephemeral",
				"-no-http-mcp",
				"-log-level", "error",
			}, tc.extra...)

			var installed, stopped atomic.Int32
			err := Run(ctx, fs, args, RunOptions{
				Version: "test",
				PolicyReload: func() PolicyReloadTrigger {
					installed.Add(1)
					return PolicyReloadTrigger{Name: "test", C: make(chan struct{}), Stop: func() { stopped.Add(1) }}
				},
			})
			if err == nil || !strings.Contains(err.Error(), "no MCP transport enabled") {
				t.Fatalf("Run error = %v, want \"no MCP transport enabled\"", err)
			}
			want := int32(0)
			if tc.wantInstalled {
				want = 1
			}
			if got := installed.Load(); got != want {
				t.Errorf("PolicyReload hook called %d times, want %d", got, want)
			}
			if got := stopped.Load(); got != want {
				t.Errorf("trigger Stop called %d times, want %d", got, want)
			}
		})
	}
}

// TestLoadConfigFileSource_IgnoresRemovedCodecPlugins pins the handling of
// the removed `codec_plugins` key (USK-1210). It has had no effect since
// v0.15.0 (USK-706); a config file that still carries it — in the
// pre-removal documented shape, an array of {path} entries — must keep
// loading through the boot / SIGHUP entry point, with its real sections
// applied and validation passing. The config loader is lenient about
// unknown keys by design (see config's TestLoadFile_UnknownFieldsIgnored).
func TestLoadConfigFileSource_IgnoresRemovedCodecPlugins(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	content := `{
		"codec_plugins": [{"path": "x.star"}, {"path": "dir/"}],
		"target_scope_policy": {
			"allows": [{"hostname": "*.target.example"}]
		}
	}`
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	proxyCfg, loaded, err := loadConfigFileSource(path)
	if err != nil {
		t.Fatalf("loadConfigFileSource: %v", err)
	}
	if proxyCfg == nil || loaded == nil {
		t.Fatalf("loadConfigFileSource returned nil result: cfg=%v loaded=%v", proxyCfg, loaded)
	}
	pol := proxyCfg.TargetScopePolicy
	if pol == nil || len(pol.Allows) != 1 || pol.Allows[0].Hostname != "*.target.example" {
		t.Fatalf("TargetScopePolicy = %+v, want one allow rule for *.target.example", pol)
	}
	if loaded.Policy != pol {
		t.Errorf("LoadedPolicy.Policy = %p, want the config's TargetScopePolicy %p", loaded.Policy, pol)
	}
	if loaded.Source != "config file" {
		t.Errorf("LoadedPolicy.Source = %q, want %q", loaded.Source, "config file")
	}
}
