package macro

import (
	"fmt"
	"sort"
	"strings"
)

// maxAvailableVarSamples caps how many KV Store key names a single
// unresolved-variable warning lists before summarising the remainder.
//
// SECURITY (USK-1035): the hint carries KEY NAMES ONLY. A KV Store value may
// hold a session token or any other credential captured by an extraction rule
// from an attacker-influenced response body, so no value may ever reach a
// warning string or a slog attribute. Key names are already disclosed to the
// MCP client via run_macro's kv_store field; the server log is a different
// trust boundary and must keep carrying names only.
const maxAvailableVarSamples = 10

// unresolvedVarRemediation is appended to run-time unresolved-variable
// warnings. It states the diagnosis; availableVarsHint supplies the cure.
const unresolvedVarRemediation = "variable not found in KV Store"

// unresolvedVarDefineRemediation is appended to define-time
// unresolved-variable warnings. An unresolved name is a legitimate state at
// define time (run_macro's params.vars may supply it later), so the text must
// let the reader dismiss the warning when that is the plan.
const unresolvedVarDefineRemediation = "not defined by initial_vars, a preceding step's extract, or a reserved __ key; " +
	"it is sent literally on the wire unless run_macro supplies it via params.vars (ignore this warning if that is the plan)"

// templateVarName extracts the variable name from the interior of a §...§
// template expression: the first pipe-separated component, whitespace-trimmed.
// Shared with expandExpression (template.go) so the two cannot drift.
func templateVarName(expr string) string {
	return strings.TrimSpace(strings.SplitN(expr, "|", 2)[0])
}

// templateVarNames returns the variable name of every live template lookup
// site in s, in order of appearance and including duplicates. A "live lookup
// site" is a §...§ pair whose interior ExpandTemplate would resolve against
// the KV Store.
//
// BINDING CONTRACT: this walker mirrors ExpandTemplate (template.go) by
// construction — same strings.Index pairing, same left-to-right consumption,
// same templateVarName interior parse. A change to ExpandTemplate's pairing or
// expression semantics REQUIRES the matching change here; the invariant is
// pinned by TestUnresolvedVars_AgreesWithExpandTemplate.
//
// Consequences of that mirroring, all deliberate:
//   - `§ name §` IS a lookup site (expandExpression trims the interior), so it
//     is reported. Missing it would leave the silent-send hole this exists to
//     close.
//   - `§name | base64§` is reported under the name `name`; unknown encoders
//     already fail loudly in ApplyEncoders, so an unknown variable is the only
//     piped form that can reach the wire.
//   - `§unclosed` and a trailing unpaired `§` are NOT lookup sites —
//     ExpandTemplate emits them as literals.
//   - An empty interior (`§§`) is skipped: expandExpression returns an error
//     for it, so the step already fails loudly.
//
// The walk is read-only, regex-free (no ReDoS surface) and bounds-safe on
// arbitrary attacker-influenced bytes.
func templateVarNames(s string) []string {
	var names []string
	remaining := s

	for {
		openIdx := strings.Index(remaining, DelimOpen)
		if openIdx == -1 {
			break
		}
		after := remaining[openIdx+len(DelimOpen):]
		closeIdx := strings.Index(after, DelimClose)
		if closeIdx == -1 {
			// No closing delimiter — ExpandTemplate writes the rest as a
			// literal, so nothing here is a lookup site.
			break
		}
		if name := templateVarName(after[:closeIdx]); name != "" {
			names = append(names, name)
		}
		remaining = after[closeIdx+len(DelimClose):]
	}

	return names
}

// UnresolvedVars returns the sorted, deduplicated names of §variable§
// references in s that will NOT resolve against kvStore and therefore reach
// the wire as literal text.
//
// It is exact: a name is reported if and only if ExpandTemplate would leave
// its token in place (see templateVarNames for the binding contract). The scan
// is performed on the pre-expansion template, so a KV Store value that itself
// contains `§x§` — for example one extracted from a hostile upstream response
// — cannot manufacture warnings.
//
// The returned slice contains variable NAMES only; it never contains values.
func UnresolvedVars(s string, kvStore map[string]string) []string {
	return sortedUnresolved(templateVarNames(s), func(name string) bool {
		_, ok := kvStore[name]
		return ok
	})
}

// sortedUnresolved filters names by the resolves predicate, deduplicates the
// misses, and returns them sorted so callers emit stable output (no map
// iteration order ever reaches a warning).
func sortedUnresolved(names []string, resolves func(string) bool) []string {
	var seen map[string]struct{}
	for _, name := range names {
		if resolves(name) {
			continue
		}
		if seen == nil {
			seen = make(map[string]struct{})
		}
		seen[name] = struct{}{}
	}
	if len(seen) == 0 {
		return nil
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// DetectUnresolvedVars scans a step's four Override* fields BEFORE template
// expansion and reports §name§ references that do not resolve against the
// live KV Store. Those tokens are sent verbatim on the wire, which — for the
// common case of a misspelt variable name — used to be completely silent
// (USK-1035).
//
// It is the §-syntax counterpart of DetectUnresolvedTemplates, which stays the
// post-substitution scanner for the FOREIGN syntaxes ({{var}} / ${var} /
// %var%). The two emit separate warning lines with separate remediations.
//
// Scan surface: OverrideMethod, OverrideURL, OverrideHeaders (values; names
// are sorted so the output is deterministic) and OverrideBody, in that order.
// The recorded base flow's bytes are deliberately NOT scanned: they are
// victim traffic in which a literal § is legitimate content (statute section
// numbers, SSTI probes), and buildRequest never expands them.
//
// Returns one human-readable warning per scan location, each listing up to
// maxSamplesPerLocation distinct tokens plus the available KV Store key names.
// A nil return means every §name§ reference in the step resolves. This
// function is read-only: it never rewrites, drops, or "corrects" an
// operator-authored token.
func DetectUnresolvedVars(step *Step, kvStore map[string]string) []string {
	if step == nil {
		return nil
	}

	var warnings []string
	for _, loc := range stepTemplateLocations(step) {
		names := UnresolvedVars(loc.value, kvStore)
		if len(names) == 0 {
			continue
		}
		warnings = append(warnings, fmt.Sprintf("%s: %s — %s; %s",
			loc.label, formatVarTokens(names), unresolvedVarRemediation, availableVarsHint(kvStore)))
	}
	return warnings
}

// ValidateMacroTemplates statically checks a macro definition's step override
// fields and returns non-fatal warnings. It is intended for define time, so
// that a mistyped template surfaces before the first request is sent instead
// of after a misleading HTTP 200 on a literal token.
//
// Two categories are reported per (step, field):
//
//   - foreign templating syntax ({{var}} / ${var} / %var%), which is never
//     substituted, together with the §name§ form to use instead;
//   - a §name§ reference that resolves against neither initial_vars nor a
//     PRECEDING step's extract rules.
//
// It NEVER returns an error, by design (USK-1035): supplying a variable later
// through run_macro's params.vars is a legitimate workflow, as is relying on a
// runtime-injected reserved __ key, so an unresolved name at define time is
// not necessarily a defect. Reserved keys (IsReservedKey) are skipped entirely
// because they are injected by the fuzz / upstream-proxy runtime and cannot be
// resolved statically.
//
// A step's own extract rules are NOT in scope for that same step: extraction
// runs after the request has been sent.
func ValidateMacroTemplates(m *Macro) []string {
	if m == nil {
		return nil
	}

	known := make(map[string]struct{}, len(m.InitialVars))
	for name := range m.InitialVars {
		known[name] = struct{}{}
	}

	var warnings []string
	for i := range m.Steps {
		step := &m.Steps[i]
		for _, loc := range stepTemplateLocations(step) {
			if msg := scanForResiduals(loc.value); msg != "" {
				warnings = append(warnings, fmt.Sprintf("step[%s] %s: %s", step.ID, loc.label, msg))
			}
			names := sortedUnresolved(templateVarNames(loc.value), func(name string) bool {
				if IsReservedKey(name) {
					// Injected by the runtime; unknowable at define time.
					return true
				}
				_, ok := known[name]
				return ok
			})
			if len(names) > 0 {
				warnings = append(warnings, fmt.Sprintf("step[%s] %s: %s — %s",
					step.ID, loc.label, formatVarTokens(names), unresolvedVarDefineRemediation))
			}
		}
		// Only after the step is scanned do its own extracts become
		// available, mirroring execution order.
		for j := range step.Extract {
			if name := step.Extract[j].Name; name != "" {
				known[name] = struct{}{}
			}
		}
	}

	return warnings
}

// templateLocation is a single template-bearing field of a step, paired with
// the label used to identify it in warning text.
type templateLocation struct {
	label string
	value string
}

// stepTemplateLocations returns the step's four Override* fields that
// buildRequest runs through ExpandTemplate, in a deterministic order. Header
// names are sorted so repeated calls produce identical warning ordering.
func stepTemplateLocations(step *Step) []templateLocation {
	var locs []templateLocation

	if step.OverrideMethod != "" {
		locs = append(locs, templateLocation{label: "method", value: step.OverrideMethod})
	}
	if step.OverrideURL != "" {
		locs = append(locs, templateLocation{label: "url", value: step.OverrideURL})
	}
	if len(step.OverrideHeaders) > 0 {
		names := make([]string, 0, len(step.OverrideHeaders))
		for name := range step.OverrideHeaders {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			locs = append(locs, templateLocation{label: "header:" + name, value: step.OverrideHeaders[name]})
		}
	}
	if step.OverrideBody != nil {
		locs = append(locs, templateLocation{label: "body", value: *step.OverrideBody})
	}

	return locs
}

// formatVarTokens renders unresolved variable names back into their §name§
// wire form, capped at maxSamplesPerLocation.
func formatVarTokens(names []string) string {
	tokens := make([]string, 0, len(names))
	for _, name := range names {
		tokens = append(tokens, DelimOpen+name+DelimClose)
	}
	return joinSamples(tokens, maxSamplesPerLocation)
}

// availableVarsHint renders the KV Store key names an operator can actually
// reference, capped at maxAvailableVarSamples and sorted for determinism.
//
// SECURITY: key names only — see maxAvailableVarSamples.
func availableVarsHint(kvStore map[string]string) string {
	if len(kvStore) == 0 {
		return "the KV Store is empty (supply variables via the macro's initial_vars or run_macro params.vars)"
	}
	names := make([]string, 0, len(kvStore))
	for name := range kvStore {
		names = append(names, name)
	}
	sort.Strings(names)
	return "available: " + joinSamples(names, maxAvailableVarSamples)
}
