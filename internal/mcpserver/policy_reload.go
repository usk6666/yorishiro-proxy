package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// Policy Layer reload (USK-1115).
//
// The Policy Layer — target scope allows/denies, rate_limits and budget —
// is the operator's ceiling over what the AI agent may reach. It is loaded
// at boot and can be replaced at runtime only through a path the agent
// cannot reach: cmd/yorishiro-proxy turns SIGHUP into a reload request
// (RunOptions.PolicyReload). The agent-facing MCP server (stdio and HTTP)
// has no tool or action for it; internal/mcp never calls a Policy Layer
// writer (pinned by internal/mcp's TestPolicyLayer_NotWritableFromMCP).
//
// A reload re-reads the same source boot used, validates it completely,
// and only then swaps the three engines. Any failure leaves the running
// policy untouched. New connections and new envelopes see the new policy,
// and every live connection admitted by the CONNECT / SOCKS5 / plain-forward
// gates is re-evaluated with the check that admitted it: one that would not
// be admitted now is closed (connector.LiveConns, USK-1160) — including
// TLS passthrough relays and bytechunk tunnels, which no per-envelope step
// ever re-checks. A path_prefix-only deny closes no connection; the
// per-request HTTPScopeStep enforces it.

// PolicySource names where the Policy Layer is read from. The precedence is
// the one LoadConfigs applies at boot: PolicyFile (-target-policy-file) when
// set, else the target_scope_policy section of ConfigFile (-config).
type PolicySource struct {
	ConfigFile string
	PolicyFile string
}

// configured reports whether any policy source is set. Without one, Run
// installs no reload trigger (decision U2), so SIGHUP keeps its default.
func (s PolicySource) configured() bool {
	return s.ConfigFile != "" || s.PolicyFile != ""
}

// LoadedPolicy is one read of a policy source.
type LoadedPolicy struct {
	// Policy is the parsed, validated policy; nil when the source defines
	// none (a config file without target_scope_policy) or no source is set.
	Policy *config.TargetScopePolicyConfig
	// Source is "policy file", "config file", or "" (no source).
	Source string
	// Path, SHA256 and ModTime identify the exact file content that was
	// validated, for the audit log. SIGHUP cannot name its sender, so the
	// content fingerprint is what ties a reload to a distribution.
	Path    string
	SHA256  string
	ModTime time.Time
}

// errNoPolicySource is returned by a reload when no source is configured.
var errNoPolicySource = errors.New("no policy source configured (-target-policy-file or -config)")

// LoadPolicySource reads and validates the Policy Layer from source exactly
// as boot does. For the config-file source the whole config is validated
// the way boot validates it (parse, protocol limits, ProxyConfig.Validate)
// and then only its target_scope_policy section is used; the config's other
// sections are not re-applied. With no source it returns an empty result.
func LoadPolicySource(source PolicySource) (*LoadedPolicy, error) {
	switch {
	case source.PolicyFile != "":
		return loadPolicyFileSource(source.PolicyFile)
	case source.ConfigFile != "":
		_, lp, err := loadConfigFileSource(source.ConfigFile)
		return lp, err
	default:
		return &LoadedPolicy{}, nil
	}
}

// loadPolicyFileSource loads -target-policy-file (strict decoding +
// TargetScopePolicyConfig.Validate, USK-1084).
func loadPolicyFileSource(path string) (*LoadedPolicy, error) {
	data, sum, mtime, err := readSourceFile("policy", path)
	if err != nil {
		return nil, fmt.Errorf("load target policy file: %w", err)
	}
	policy, err := config.ParsePolicyFile(path, data)
	if err != nil {
		return nil, fmt.Errorf("load target policy file: %w", err)
	}
	return &LoadedPolicy{Policy: policy, Source: "policy file", Path: path, SHA256: sum, ModTime: mtime}, nil
}

// loadConfigFileSource loads -config and validates it as boot does,
// returning both the ProxyConfig (boot uses it) and its policy section.
func loadConfigFileSource(path string) (*config.ProxyConfig, *LoadedPolicy, error) {
	data, sum, mtime, err := readSourceFile("config", path)
	if err != nil {
		return nil, nil, fmt.Errorf("load config file: %w", err)
	}
	proxyCfg, err := config.ParseFile(path, data)
	if err != nil {
		return nil, nil, fmt.Errorf("load config file: %w", err)
	}
	if err := config.ValidateProtocolLimits(proxyCfg); err != nil {
		return nil, nil, fmt.Errorf("invalid protocol limits: %w", err)
	}
	if err := proxyCfg.Validate(); err != nil {
		return nil, nil, fmt.Errorf("invalid proxy config: %w", err)
	}
	return proxyCfg, &LoadedPolicy{
		Policy:  proxyCfg.TargetScopePolicy,
		Source:  "config file",
		Path:    path,
		SHA256:  sum,
		ModTime: mtime,
	}, nil
}

// readSourceFile reads path once and fingerprints exactly those bytes, so
// the logged sha256 is the content that was validated. kind ("config" /
// "policy") keeps the read error wording of config.LoadFile /
// config.LoadPolicyFile.
func readSourceFile(kind, path string) (data []byte, sum string, mtime time.Time, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("read %s file %s: %w", kind, path, err)
	}
	defer f.Close()
	if fi, statErr := f.Stat(); statErr == nil {
		mtime = fi.ModTime()
	}
	data, err = io.ReadAll(f)
	if err != nil {
		return nil, "", time.Time{}, fmt.Errorf("read %s file %s: %w", kind, path, err)
	}
	h := sha256.Sum256(data)
	return data, hex.EncodeToString(h[:]), mtime, nil
}

// policyRateLimits converts the policy's rate_limits section; an omitted
// section means no policy limit.
func policyRateLimits(p *config.TargetScopePolicyConfig) connector.RateLimitConfig {
	if p == nil || p.RateLimits == nil {
		return connector.RateLimitConfig{}
	}
	return connector.RateLimitConfig{
		MaxRequestsPerSecond:        p.RateLimits.MaxRequestsPerSecond,
		MaxRequestsPerHostPerSecond: p.RateLimits.MaxRequestsPerHostPerSecond,
	}
}

// policyBudget converts the policy's budget section; an omitted section
// means no policy budget.
func policyBudget(p *config.TargetScopePolicyConfig) connector.BudgetConfig {
	if p == nil || p.Budget == nil {
		return connector.BudgetConfig{}
	}
	return connector.BudgetConfig{
		MaxTotalRequests: p.Budget.MaxTotalRequests,
		MaxDuration:      time.Duration(p.Budget.MaxDuration),
	}
}

// policySnapshot is the fully built, immutable form of one Policy Layer,
// ready to hand to the three engines. Building it cannot fail, so once a
// snapshot exists every remaining step of the reload is infallible.
type policySnapshot struct {
	allows, denies []connector.TargetRule
	rate           connector.RateLimitConfig
	budget         connector.BudgetConfig
}

func newPolicySnapshot(p *config.TargetScopePolicyConfig) policySnapshot {
	var s policySnapshot
	if p != nil {
		s.allows = ConvertTargetRules(p.Allows)
		s.denies = ConvertTargetRules(p.Denies)
	}
	s.rate = policyRateLimits(p)
	s.budget = policyBudget(p)
	return s
}

// policyReloader replaces the Policy Layer of the three process-singleton
// engines from the configured source. Reloads are serialized.
type policyReloader struct {
	mu     sync.Mutex
	source PolicySource
	scope  *connector.TargetScope
	rl     *connector.RateLimiter
	bm     *connector.BudgetManager
	// liveConns, when non-nil, is reconciled after every successful
	// reload (USK-1160).
	liveConns *connector.LiveConns
	logger    *slog.Logger
	now       func() time.Time
}

func newPolicyReloader(source PolicySource, scope *connector.TargetScope, rl *connector.RateLimiter, bm *connector.BudgetManager, logger *slog.Logger) *policyReloader {
	return &policyReloader{source: source, scope: scope, rl: rl, bm: bm, logger: logger, now: time.Now}
}

// Reload re-reads the policy source and, if it is valid, installs it as
// the new Policy Layer — a full replacement: a section omitted from the new
// source is cleared, exactly as booting with that source would leave it.
// trigger labels the request in the log (e.g. "SIGHUP").
//
// Every check runs before any engine is touched; on error the running
// policy is retained and the error is logged and returned. The three
// engines are then updated one after another, so a concurrent request may
// briefly see the new scope with the old rate limit — acceptable, because
// each engine on its own is always fully old or fully new.
func (r *policyReloader) Reload(trigger string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.source.configured() {
		r.logger.Warn("target scope policy reload skipped: no policy source configured", "trigger", trigger)
		return errNoPolicySource
	}
	loaded, err := LoadPolicySource(r.source)
	if err != nil {
		r.logger.Error("target scope policy reload rejected; previous policy retained",
			"trigger", trigger, "error", err)
		return err
	}
	snap := newPolicySnapshot(loaded.Policy)

	beforeAllows, beforeDenies := r.scope.PolicyRules()
	outside := r.scope.ReplacePolicyRules(snap.allows, snap.denies,
		connector.PolicyOrigin{Source: loaded.Source, LoadedAt: r.now()})
	// USK-1160: close the live connections the new scope no longer admits.
	// Inside r.mu, right after the scope swap, so reconciles of
	// concurrent reloads cannot interleave out of order.
	liveClosed := r.liveConns.Reconcile(trigger)
	r.rl.SetPolicyLimits(snap.rate)
	exhausted := r.bm.ReplacePolicyBudget(snap.budget)

	effRate := r.rl.EffectiveLimits()
	effBudget := r.bm.EffectiveBudget()
	r.logger.Info("target scope policy reloaded",
		"trigger", trigger,
		"source", loaded.Source,
		"path", loaded.Path,
		"sha256", loaded.SHA256,
		"mtime", loaded.ModTime,
		"allows_before", len(beforeAllows),
		"allows_after", len(snap.allows),
		"denies_before", len(beforeDenies),
		"denies_after", len(snap.denies),
		"policy_max_rps", snap.rate.MaxRequestsPerSecond,
		"policy_max_rps_per_host", snap.rate.MaxRequestsPerHostPerSecond,
		"effective_max_rps", effRate.MaxRequestsPerSecond,
		"effective_max_rps_per_host", effRate.MaxRequestsPerHostPerSecond,
		"policy_max_total_requests", snap.budget.MaxTotalRequests,
		"policy_max_duration", snap.budget.MaxDuration.String(),
		"effective_max_total_requests", effBudget.MaxTotalRequests,
		"effective_max_duration", effBudget.MaxDuration.String(),
		"live_conns_closed", liveClosed,
	)
	if liveClosed > 0 {
		r.logger.Warn("target scope policy reload closed live connections",
			"trigger", trigger,
			"live_conns_closed", liveClosed)
	}
	// The -config source is decoded leniently, as at boot, so a misspelled
	// key ("target_scope_polcy", "deny") or an emptied file reloads as "no
	// policy". Refusing it would diverge from boot; say it loudly instead
	// (security review S-1). Reload-only: boot behavior is unchanged.
	if (len(beforeAllows) > 0 || len(beforeDenies) > 0) && len(snap.allows) == 0 && len(snap.denies) == 0 {
		r.logger.Warn("reloaded policy has no allow or deny rules; the previous target scope policy rules were removed",
			"trigger", trigger,
			"source", loaded.Source,
			"path", loaded.Path,
			"allows_before", len(beforeAllows),
			"denies_before", len(beforeDenies),
			"policy_section_present", loaded.Policy != nil,
		)
	}
	if len(outside) > 0 {
		hosts := make([]string, len(outside))
		for i, rule := range outside {
			hosts[i] = rule.Hostname
		}
		r.logger.Warn("agent allow rules are outside the reloaded policy allow list and no longer match",
			"agent_allows", hosts)
	}
	if exhausted != "" {
		r.logger.Warn("reloaded policy budget is already exhausted; the proxy stops",
			"budget", exhausted)
	}
	return nil
}

// run performs one Reload per value received on c until ctx is cancelled
// or c is closed, reporting each result to onReload (may be nil).
func (r *policyReloader) run(ctx context.Context, c <-chan struct{}, trigger string, onReload func(error)) {
	for {
		select {
		case <-ctx.Done():
			return
		case _, ok := <-c:
			if !ok {
				return
			}
			err := r.Reload(trigger)
			if onReload != nil {
				onReload(err)
			}
		}
	}
}

// policyReloadWiring carries the reload plumbing from Run into
// assembleAndRunMCPServer.
type policyReloadWiring struct {
	source   PolicySource
	boot     *LoadedPolicy
	trigger  PolicyReloadTrigger
	onReload func(error)
}

// installPolicyReload obtains the reload trigger from opts — only when a
// policy source is configured (decision U2). It is called right after the
// boot policy loaded, so a SIGHUP arriving during the rest of startup is
// buffered (and handled once the reloader runs) instead of killing the
// process. The returned Stop is never nil.
func installPolicyReload(opts RunOptions, source PolicySource) PolicyReloadTrigger {
	var trig PolicyReloadTrigger
	if opts.PolicyReload != nil && source.configured() {
		trig = opts.PolicyReload()
	}
	if trig.Stop == nil {
		trig.Stop = func() {}
	}
	return trig
}

// startPolicyReloader records the boot policy's origin and, when a trigger
// is installed, starts the goroutine that serves reload requests. The
// returned stop function cancels it and waits for an in-flight reload to
// finish. Call it only once the engines are fully started (BudgetManager
// armed), so a reload never races boot.
//
// liveConns (may be nil) is reconciled after every successful reload.
func startPolicyReloader(ctx context.Context, w policyReloadWiring, scope *connector.TargetScope, liveConns *connector.LiveConns, rl *connector.RateLimiter, bm *connector.BudgetManager, logger *slog.Logger) (stop func()) {
	if w.boot != nil && w.boot.Source != "" {
		scope.SetPolicyOrigin(connector.PolicyOrigin{Source: w.boot.Source, LoadedAt: time.Now()})
	}
	if w.trigger.C == nil {
		return func() {}
	}
	reloader := newPolicyReloader(w.source, scope, rl, bm, logger)
	reloader.liveConns = liveConns
	rctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		reloader.run(rctx, w.trigger.C, w.trigger.Name, w.onReload)
	}()
	var bootSum string
	if w.boot != nil {
		bootSum = w.boot.SHA256
	}
	logger.Info("target scope policy reload enabled",
		"trigger", w.trigger.Name,
		"policy_file", w.source.PolicyFile,
		"config_file", w.source.ConfigFile,
		"boot_sha256", bootSum)
	return func() {
		cancel()
		<-done
	}
}
