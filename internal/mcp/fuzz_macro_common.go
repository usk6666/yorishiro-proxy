// Package mcp fuzz_macro_common.go holds the shared infrastructure for
// pre/post macro hooks across the typed fuzz tools: fuzz_http (live
// today) and fuzz_ws / fuzz_grpc / fuzz_raw (in-progress per USK-984 /
// USK-985 / USK-986). The exported symbols here are the contract those
// per-protocol fuzz tools call into so the macro hook config struct
// (MacroConfig), its validator, the iteration / job hookExecutor
// builders, and the per-iteration kvStore prep are written once and
// reused across protocols.
//
// USK-983: Pure-refactor extraction from fuzz_http_helpers.go and
// fuzz_http.go — fuzz_http's behaviour is unchanged. The exported
// names mark the seam that the sibling fuzz_ws / fuzz_grpc / fuzz_raw
// implementations will plug into.
package mcp

import (
	"fmt"
	"regexp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
)

// MacroConfig is the pre/post macro hook configuration shared by the
// typed fuzz tools (fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw).
// USK-960 introduced per-iteration hooks; USK-961 added per-job +
// mix-scope; USK-983 extracted the per-protocol-neutral parts here so
// fuzz_ws / fuzz_grpc / fuzz_raw can reuse the same struct shape and
// validators without duplicating the schema tags.
//
// scope="iteration" (default) fires once per variant; the per-iteration
// KV Store is allocated fresh in the variant loop with reserved keys
// §__iteration§ / §__nonce§ seeded and (for post) reserved __response_*
// keys injected before the macro runs.
//
// scope="job" fires exactly once outside the variant loop against a
// separate job-scoped KV Store that is merged into each iteration's
// store before per-iteration reserved keys are seeded — so pre=job
// extracts flow into every variant's request templating, and post=job
// summarises after the loop completes. Reserved keys (§__iteration§,
// §__nonce§, __response_*) are NOT visible to job-scope macros (the
// loop has not started for pre-job, and is over with discarded per-
// iteration kvStores for post-job). run_interval is rejected when
// scope="job" (single-fire by construction).
type MacroConfig struct {
	// Name is the stored macro name (defined via macro.define).
	Name string `json:"name" jsonschema:"REQUIRED stored macro name"`

	// Scope: "iteration" (default) or "job". Mix-scope is supported —
	// pre and post may independently select their scope. Empty defaults
	// to "iteration".
	Scope string `json:"scope,omitempty" jsonschema:"iteration (default; fires once per variant) | job (fires once outside the variant loop; KV Store is shared across the whole job and merged into each iteration's per-variant store)"`

	// OnError selects the iteration's behaviour when the hook errors.
	//   "skip"     (default) — record the iteration as skipped, do not send
	//                          the fuzz request, do not run the post hook,
	//                          continue to the next variant.
	//   "abort"    — abort the fuzz run with an error.
	//   "continue" — log the error, persist a fuzz_macro_results row, and
	//                continue to the variant's send (templates may carry
	//                unresolved §var§ literals — recorded in
	//                fuzz_results.error).
	OnError string `json:"on_error,omitempty" jsonschema:"skip (default) | abort | continue"`

	// Vars is a static map of kvStore overrides injected before the macro
	// runs. Keys with the reserved prefix ("__") are silently dropped at
	// injection time (matches internal/job/job.go:mergeKVStore precedent)
	// so a Vars entry cannot shadow runtime-populated reserved keys such
	// as __iteration / __nonce / __response_* (USK-981 Q2).
	//
	// scope="iteration": Vars is injected into every variant's per-
	// iteration kvStore after the job-store copy and before
	// SeedIterationKV — so the operator's static overrides are visible to
	// §var§ template expansion on the variant request but cannot shadow
	// per-iteration reserved keys.
	//
	// scope="job": Vars is injected once into the job kvStore at job
	// start. The job-store is then naturally merged into every per-
	// iteration kvStore via the existing copy at iteration setup.
	Vars map[string]string `json:"vars,omitempty" jsonschema:"static kvStore overrides injected before the macro runs. Keys with the '__' reserved prefix are silently dropped (USK-981)"`

	// RunInterval gates when the hook fires across iterations. Only valid
	// for scope="iteration" — scope="job" hooks fire exactly once by
	// construction and the validator rejects scope="job" + non-empty
	// RunInterval (USK-961 Q10).
	//
	// pre_macro legal values: "always" (default) | "once" | "every_n" |
	// "on_error". post_macro legal values: "always" (default) |
	// "on_status" | "on_match". Pre and post have disjoint legal sets;
	// validation runs per-direction via the underlying hooks.go
	// validators (USK-981 Q7).
	RunInterval string `json:"run_interval,omitempty" jsonschema:"hook firing cadence (scope=iteration only). pre_macro: always (default) | once | every_n | on_error. post_macro: always (default) | on_status | on_match. Rejected when scope='job'"`

	// N is the interval count for RunInterval="every_n". Required when
	// RunInterval="every_n"; ignored otherwise.
	N int `json:"n,omitempty" jsonschema:"iteration cadence for RunInterval='every_n' (>= 1)"`

	// StatusCodes is the list of response status codes that gate
	// post_macro firing for RunInterval="on_status". Required when
	// RunInterval="on_status"; ignored otherwise. post_macro only.
	StatusCodes []int `json:"status_codes,omitempty" jsonschema:"response status codes for post_macro RunInterval='on_status'"`

	// MatchPattern is the regex pattern matched against the response body
	// for post_macro RunInterval="on_match". Required when
	// RunInterval="on_match"; ignored otherwise. post_macro only.
	MatchPattern string `json:"match_pattern,omitempty" jsonschema:"response body regex pattern for post_macro RunInterval='on_match'"`

	// compiledPattern is the pre-compiled MatchPattern, set during
	// validation so the hook executor reuses it across iterations rather
	// than recompiling. Not serialised — internal to the validator/
	// executor handoff. Matches the precedent on hookConfig.compiledPattern.
	compiledPattern *regexp.Regexp `json:"-"`
}

// ValidateMacroConfig validates one pre/post macro hook config.
// scope="iteration" (default) and scope="job" are both accepted (USK-961).
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
//
// macro-name lookup is intentionally deferred to runtime — checking the
// stored macros table here would require an extra DB roundtrip for every
// fuzz_* call. Runtime invocation surfaces the missing-macro error via
// loadAndBuildMacroDeps and short-circuits the iteration per the OnError
// policy.
//
// USK-981: when RunInterval is non-empty, the pre/post legal set is
// enforced via validatePreMacroHook / validatePostMacroHook so the
// directional asymmetry (e.g. on_status is post-only) is surfaced at
// MCP-tool input parse rather than at hook dispatch. scope="job" +
// non-empty RunInterval is rejected verbatim per Q10 — scope="job"
// hooks fire exactly once by construction (the call site, not the
// RunInterval engine knob, owns the single-fire guarantee).
func ValidateMacroConfig(label string, cfg *MacroConfig, isPre bool) error {
	if cfg == nil {
		return nil
	}
	if cfg.Name == "" {
		return fmt.Errorf("%s: name is required", label)
	}
	scope := cfg.Scope
	if scope == "" {
		scope = "iteration"
	}
	switch scope {
	case "iteration", "job":
	default:
		return fmt.Errorf("%s: invalid scope %q (must be iteration or job)", label, scope)
	}
	switch cfg.OnError {
	case "", "skip", "abort", "continue":
	default:
		return fmt.Errorf("%s: invalid on_error %q (must be skip, abort, or continue)", label, cfg.OnError)
	}
	// USK-981 Q10: scope="job" + non-empty RunInterval is structurally
	// meaningless — scope="job" hooks fire exactly once via the call
	// site, not via the RunInterval engine knob. Reject at MCP-tool
	// input parse with the documented verbatim message.
	if scope == "job" && cfg.RunInterval != "" {
		return fmt.Errorf("%s: run_interval is only valid for scope=iteration; for scope=job the hook fires exactly once", label)
	}
	// USK-981 Q7 + Q12: when RunInterval is non-empty AND scope is
	// "iteration", delegate to the polarity-specific hooks.go validator
	// so the disjoint pre/post legal sets are enforced. We construct a
	// transient hookConfig because validatePreMacroHook /
	// validatePostMacroHook already implement the disjoint-set + N /
	// StatusCodes / MatchPattern cross-field rules.
	if cfg.RunInterval != "" || cfg.N != 0 || len(cfg.StatusCodes) > 0 || cfg.MatchPattern != "" {
		h := &hookConfig{
			Macro:        cfg.Name,
			RunInterval:  cfg.RunInterval,
			N:            cfg.N,
			StatusCodes:  cfg.StatusCodes,
			MatchPattern: cfg.MatchPattern,
		}
		var herr error
		if isPre {
			herr = validatePreMacroHook(h)
		} else {
			herr = validatePostMacroHook(h)
		}
		if herr != nil {
			return fmt.Errorf("%s: %w", label, herr)
		}
		// Carry the compiled regex back so the hook executor reuses it
		// rather than recompiling on every iteration (matches the
		// validatePostMacroHook precedent for hooksInput callers).
		cfg.compiledPattern = h.compiledPattern
	}
	return nil
}

// BuildIterationHookExecutor returns the hookExecutor used by the
// per-iteration call sites. It is always non-nil so the gating logic in
// the per-protocol fuzz runOne can dispatch via the executor; when no
// hook is configured, the executor is a no-op shell.
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
//
// USK-981: iteration-scope hooks thread the user-supplied RunInterval /
// N / StatusCodes / MatchPattern / compiledPattern into the underlying
// hookConfig so the engine's shouldRunPreMacro / shouldRunPostMacro
// gates (always / once / every_n / on_status / on_match) become
// user-configurable. Empty RunInterval defaults to "always" — the same
// as the no-knob path. Vars is intentionally NOT mirrored onto the
// hookConfig.Vars field because fuzz_*'s injection contract is
// "Vars seeds the per-iteration kvStore at iteration start" (see
// PrepareIteration), which fires unconditionally on every iteration —
// independent of the hook-fire gate. The hookConfig.Vars merge in
// executePreMacro / executePostMacro is downstream of that gate and
// would only fire when the hook itself fires.
func BuildIterationHookExecutor(s *Server, preMacro, postMacro *MacroConfig) *hookExecutor {
	if preMacro == nil && postMacro == nil {
		return newHookExecutor(s, nil, &hookState{})
	}
	hooks := &hooksInput{}
	if preMacro != nil {
		hooks.PreMacro = &hookConfig{
			Macro:           preMacro.Name,
			RunInterval:     resolveRunInterval(preMacro.RunInterval),
			N:               preMacro.N,
			StatusCodes:     preMacro.StatusCodes,
			MatchPattern:    preMacro.MatchPattern,
			compiledPattern: preMacro.compiledPattern,
		}
	}
	if postMacro != nil {
		hooks.PostMacro = &hookConfig{
			Macro:           postMacro.Name,
			RunInterval:     resolveRunInterval(postMacro.RunInterval),
			N:               postMacro.N,
			StatusCodes:     postMacro.StatusCodes,
			MatchPattern:    postMacro.MatchPattern,
			compiledPattern: postMacro.compiledPattern,
			PassResponse:    true,
		}
	}
	return newHookExecutor(s, hooks, &hookState{})
}

// resolveRunInterval returns the engine-facing RunInterval string,
// defaulting empty to "always" so the underlying hooks.go gate matches
// the pre-USK-981 behaviour when the caller does not opt in.
func resolveRunInterval(s string) string {
	if s == "" {
		return "always"
	}
	return s
}

// BuildJobHookExecutor returns (jobHookExec, jobKVStore) for the
// scope="job" call sites, or (nil, nil) when neither hook is job-scoped.
// Distinct from BuildIterationHookExecutor so the hookState.preMacroExecuted
// state is not flipped by the job-side single-fire call. Post-job leaves
// PassResponse off (no per-iteration response is available — Q21).
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
//
// USK-981: scope="job" forces RunInterval="always" (the validator
// already rejected non-empty RunInterval for scope="job", so this is
// belt-and-braces). Vars from job-scope hooks is injected into the
// returned jobKVStore with reserved-key silent-drop — matches the
// internal/job/job.go mergeKVStore precedent.
func BuildJobHookExecutor(s *Server, preMacro, postMacro *MacroConfig) (*hookExecutor, map[string]string) {
	if !IsJobScope(preMacro) && !IsJobScope(postMacro) {
		return nil, nil
	}
	jobHooks := &hooksInput{}
	if IsJobScope(preMacro) {
		jobHooks.PreMacro = &hookConfig{Macro: preMacro.Name, RunInterval: "always"}
	}
	if IsJobScope(postMacro) {
		jobHooks.PostMacro = &hookConfig{Macro: postMacro.Name, RunInterval: "always"}
	}
	jobKV := make(map[string]string)
	if IsJobScope(preMacro) {
		InjectVarsRespectingReserved(jobKV, preMacro.Vars)
	}
	if IsJobScope(postMacro) {
		InjectVarsRespectingReserved(jobKV, postMacro.Vars)
	}
	return newHookExecutor(s, jobHooks, &hookState{}), jobKV
}

// InjectVarsRespectingReserved copies src into dst, silently dropping
// keys with the reserved prefix ("__") so a user-supplied Vars entry
// cannot shadow runtime-populated reserved keys (USK-981 Q2). Matches
// the internal/job/job.go:mergeKVStore precedent.
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
//
// Local replication is preferred over importing internal/job for two
// reasons: (1) the package boundary is control plane (internal/mcp) →
// data path (internal/job), which the project conventions discourage;
// (2) the function is small enough that DRYing it would cost more in
// indirection than it saves.
func InjectVarsRespectingReserved(dst map[string]string, src map[string]string) {
	for k, v := range src {
		if macro.IsReservedKey(k) {
			continue
		}
		dst[k] = v
	}
}

// BumpHookIterationCount advances the hookState.requestCount by one so
// the next iteration's shouldRunPreMacro / shouldRunPostMacro engine
// gates evaluate against the post-iteration counter (USK-981). Pure
// counter increment — lastStatusCode / lastError remain at zero values
// because correctly wiring those requires deciding what counts as an
// "error" for the on_error gate (transport error vs 4xx vs 5xx vs
// pre-macro skip), which is deferred to USK-982. This makes
// RunInterval="every_n" and "once" work end-to-end without committing
// to on_error semantics yet.
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983) —
// converted from a method on *fuzzHTTPVariantLoop to a free function so
// the per-protocol variant loops can call it without duplicating the
// counter-advance logic.
func BumpHookIterationCount(exec *hookExecutor) {
	if exec == nil || exec.state == nil {
		return
	}
	exec.state.requestCount++
}

// IsJobScope reports whether cfg is configured as scope="job". Nil is
// always false. Empty scope defaults to "iteration".
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
func IsJobScope(cfg *MacroConfig) bool {
	return cfg != nil && cfg.Scope == "job"
}

// IsIterationScope reports whether cfg is configured as scope="iteration"
// (or empty, which defaults to iteration). Nil is always false.
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983).
func IsIterationScope(cfg *MacroConfig) bool {
	if cfg == nil {
		return false
	}
	return cfg.Scope == "" || cfg.Scope == "iteration"
}

// PrepareIteration builds and returns the per-variant kvStore for a
// fuzz iteration. The Vars injection order (matching USK-981) is:
//
//  1. jobKV copy (job-scope extracts and job-scope Vars)
//  2. iteration-scope Vars from preMacro (operator-supplied static overrides)
//  3. iteration-scope Vars from postMacro
//  4. connector.SeedIterationKV (per-iteration reserved keys:
//     __iteration, __nonce, and any upstream-proxy rotation extracts)
//
// The order matters: per-iteration reserved keys must be the last
// writer so they win on collision, and Vars must be injected with
// reserved-key silent-drop (USK-981 Q2) so a Vars entry like
// {"__iteration":"override"} is dropped at injection rather than
// shadowing the value the iteration loop will seed.
//
// Shared by fuzz_http / fuzz_ws / fuzz_grpc / fuzz_raw (USK-983) —
// extracts the per-protocol-neutral kvStore-build prefix from
// fuzz_http's prepareIteration so the sibling fuzz tools can reuse the
// exact same Vars-injection order without duplicating the merge logic.
// The upstream-proxy resolution and pre-macro dispatch that follow this
// step remain per-protocol because they touch protocol-specific row
// recording (`recordVariantError`, etc.).
func PrepareIteration(jobKV map[string]string, preMacro, postMacro *MacroConfig, variantIdx int) map[string]string {
	kvStore := make(map[string]string)
	for k, v := range jobKV {
		kvStore[k] = v
	}
	if IsIterationScope(preMacro) {
		InjectVarsRespectingReserved(kvStore, preMacro.Vars)
	}
	if IsIterationScope(postMacro) {
		InjectVarsRespectingReserved(kvStore, postMacro.Vars)
	}
	connector.SeedIterationKV(kvStore, variantIdx)
	return kvStore
}
