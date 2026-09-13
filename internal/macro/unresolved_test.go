package macro

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"
)

// strPtr returns a pointer to s, for Step.OverrideBody.
func strPtr(s string) *string { return &s }

func TestTemplateVarNames_LookupSites(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "plain", input: "Cookie=§session§", want: []string{"session"}},
		{name: "encoder pipe", input: "§session | base64§", want: []string{"session"}},
		{name: "encoder chain", input: "§session|base64|upper§", want: []string{"session"}},
		{name: "inner whitespace", input: "§ session §", want: []string{"session"}},
		{name: "adjacent pairs", input: "§a§§b§", want: []string{"a", "b"}},
		{name: "separated pairs", input: "x=§a§&y=§b§", want: []string{"a", "b"}},
		{name: "duplicates preserved in order", input: "§a§-§a§", want: []string{"a", "a"}},
		{name: "odd delimiter count keeps trailing literal", input: "§a§b§", want: []string{"a"}},

		// Non-lookup sites.
		{name: "no delimiters", input: "plain text", want: nil},
		{name: "bare delimiter", input: "§", want: nil},
		{name: "unclosed", input: "§session", want: nil},
		{name: "digits after delimiter unclosed", input: "§123", want: nil},
		{name: "empty interior", input: "§§", want: nil},
		{name: "whitespace-only interior", input: "§  §", want: nil},
		{name: "empty string", input: "", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := templateVarNames(tc.input)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("templateVarNames(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

func TestUnresolvedVars_ResolvedAndUnresolved(t *testing.T) {
	kv := map[string]string{"session": "abc", "csrf": "def"}

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{name: "all resolved", input: "§session§/§csrf§", want: nil},
		{name: "typo reported", input: "§sesion§", want: []string{"sesion"}},
		{name: "mixed", input: "§session§-§nope§", want: []string{"nope"}},
		{name: "encoder pipe unresolved", input: "§nope | base64§", want: []string{"nope"}},
		{name: "encoder pipe resolved", input: "§session | base64§", want: nil},
		{name: "whitespace unresolved", input: "§ nope §", want: []string{"nope"}},
		{name: "whitespace resolved", input: "§ session §", want: nil},
		{name: "adjacent pairs deduped and sorted", input: "§z§§a§§z§", want: []string{"a", "z"}},
		{name: "unclosed is not a lookup site", input: "§nope", want: nil},
		{name: "bare delimiter", input: "100§", want: nil},
		{name: "empty interior", input: "§§", want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := UnresolvedVars(tc.input, kv)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("UnresolvedVars(%q) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// referenceLookupSites is an INDEPENDENT reimplementation of "which §...§
// pairs does ExpandTemplate treat as lookup sites". It deliberately uses
// strings.Split rather than the production strings.Index walk so that the
// agreement test below is a genuine cross-check and not a tautology.
//
// Splitting on the delimiter yields the interiors at odd indices; the final
// segment is only an interior if a closing delimiter followed it, i.e. if its
// index is less than len(parts)-1.
func referenceLookupSites(t *testing.T, s string) []string {
	t.Helper()
	parts := strings.Split(s, DelimOpen)
	var exprs []string
	for i := 1; i < len(parts)-1; i += 2 {
		exprs = append(exprs, parts[i])
	}
	return exprs
}

// referenceUnresolved derives the expected unresolved-name set from
// referenceLookupSites, applying expandExpression's documented interior
// parse (first pipe component, trimmed) and kvStore membership.
func referenceUnresolved(t *testing.T, s string, kv map[string]string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	for _, expr := range referenceLookupSites(t, s) {
		name := strings.TrimSpace(strings.SplitN(expr, "|", 2)[0])
		if name == "" {
			continue
		}
		if _, ok := kv[name]; ok {
			continue
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// TestUnresolvedVars_AgreesWithExpandTemplate pins the binding contract
// documented on templateVarNames: a name is reported by the scanner if and
// only if ExpandTemplate leaves its token on the wire as a literal.
//
// Two independent checks per corpus entry:
//  1. set agreement against referenceUnresolved (a different algorithm);
//  2. liveness — supplying a reported name changes ExpandTemplate's output,
//     which proves the site was a real lookup site and not a false positive.
func TestUnresolvedVars_AgreesWithExpandTemplate(t *testing.T) {
	kv := map[string]string{"session": "abc", "csrf": "def", "__nonce": "n1"}

	corpus := []string{
		"",
		"plain text with no delimiters",
		"§session§",
		"§missing§",
		"§ missing §",
		"§missing | base64§",
		"§session | base64 | upper§",
		"§a§§b§",
		"§a§b§",
		"§a§b§c§",
		"§unclosed",
		"prefix §unclosed",
		"§",
		"§§",
		"§  §",
		"Cookie=§session§; XSRF=§missing§; extra=§session§",
		"https://example.com/§user_id§/edit?t=§csrf§",
		"§__nonce§",
		"§__not_injected§",
		"Article §12 of the code",           // literal § usage, single delimiter
		"Article §12§ and §34§ of the code", // literal § usage that IS paired
		"{{session}} and §session§",
		"§missing§§missing§§other§",
	}

	for _, input := range corpus {
		t.Run(input, func(t *testing.T) {
			got := UnresolvedVars(input, kv)
			want := referenceUnresolved(t, input, kv)
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("UnresolvedVars(%q) = %v, want %v (reference impl)", input, got, want)
			}

			expanded, err := ExpandTemplate(input, kv)
			if err != nil {
				// Expansion already fails loudly (empty variable name /
				// unknown encoder), so the silent-send hole cannot occur.
				return
			}
			for _, name := range got {
				augmented := make(map[string]string, len(kv)+1)
				for k, v := range kv {
					augmented[k] = v
				}
				augmented[name] = "RESOLVED-" + name
				expanded2, err2 := ExpandTemplate(input, augmented)
				if err2 != nil {
					// Resolving the name reached the encoder chain, which
					// only happens for a live lookup site.
					continue
				}
				if expanded2 == expanded {
					t.Errorf("name %q reported unresolved for %q but supplying it did not change the expansion (%q) — false positive",
						name, input, expanded)
				}
				if containsStr(UnresolvedVars(input, augmented), name) {
					t.Errorf("name %q still reported after being supplied for %q", name, input)
				}
			}
		})
	}
}

func containsStr(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestUnresolvedVars_DoesNotScanKVValues(t *testing.T) {
	// A value extracted from a hostile upstream response may itself contain
	// §x§. Because the scan runs pre-expansion, that must not produce a
	// warning (a post-substitution regex would have spammed one).
	kv := map[string]string{"body": "§injected_by_upstream§"}
	if got := UnresolvedVars("payload=§body§", kv); got != nil {
		t.Errorf("UnresolvedVars = %v, want nil (KV values must not be scanned)", got)
	}
}

func TestDetectUnresolvedVars_NilStep(t *testing.T) {
	if got := DetectUnresolvedVars(nil, nil); got != nil {
		t.Errorf("DetectUnresolvedVars(nil) = %v, want nil", got)
	}
}

func TestDetectUnresolvedVars_CleanStep(t *testing.T) {
	step := &Step{
		ID:              "s1",
		OverrideURL:     "https://example.com/§user_id§",
		OverrideHeaders: map[string]string{"Cookie": "PHPSESSID=§session_cookie§"},
		OverrideBody:    strPtr("token=§csrf_token§"),
	}
	kv := map[string]string{"user_id": "1", "session_cookie": "x", "csrf_token": "y"}
	if got := DetectUnresolvedVars(step, kv); got != nil {
		t.Errorf("DetectUnresolvedVars = %v, want nil", got)
	}
}

func TestDetectUnresolvedVars_AllLocationsScanned(t *testing.T) {
	step := &Step{
		ID:             "s1",
		OverrideMethod: "§verb§",
		OverrideURL:    "https://example.com/§path§",
		OverrideHeaders: map[string]string{
			"Z-Last":  "§zz§",
			"A-First": "§aa§",
		},
		OverrideBody: strPtr("body=§payload§"),
	}

	got := DetectUnresolvedVars(step, map[string]string{})
	if len(got) != 5 {
		t.Fatalf("len(warnings) = %d, want 5; got %v", len(got), got)
	}
	// Deterministic order: method, url, headers (name-sorted), body.
	wantPrefixes := []string{"method: ", "url: ", "header:A-First: ", "header:Z-Last: ", "body: "}
	for i, p := range wantPrefixes {
		if !strings.HasPrefix(got[i], p) {
			t.Errorf("warnings[%d] = %q, want prefix %q", i, got[i], p)
		}
	}
}

// TestDetectUnresolvedVars_TypoWarningShape covers the Issue's second
// acceptance criterion: a misspelt §sesion_cookie§ produces a warning that
// names the token and lists the variable names that ARE available.
func TestDetectUnresolvedVars_TypoWarningShape(t *testing.T) {
	step := &Step{
		ID:              "s1",
		OverrideHeaders: map[string]string{"Cookie": "PHPSESSID=§sesion_cookie§"},
	}
	kv := map[string]string{"session_cookie": "v1", "csrf_token": "v2", "__nonce": "v3"}

	got := DetectUnresolvedVars(step, kv)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	w := got[0]
	for _, want := range []string{
		"header:Cookie: ",
		"§sesion_cookie§",
		"variable not found in KV Store",
		"available: ",
		"__nonce",
		"csrf_token",
		"session_cookie",
	} {
		if !strings.Contains(w, want) {
			t.Errorf("warning = %q, missing %q", w, want)
		}
	}
}

// TestDetectUnresolvedVars_NeverLeaksKVValues is the security regression
// guard: the available-variable hint must list key NAMES only. KV Store
// values routinely hold session tokens harvested by extraction rules, and the
// warning is copied verbatim into the server log, which carries no KV values
// today.
func TestDetectUnresolvedVars_NeverLeaksKVValues(t *testing.T) {
	const sentinel = "SENTINEL-SESSION-TOKEN-3f9a1c"
	kv := map[string]string{
		"session_cookie": sentinel,
		"csrf_token":     sentinel + "-2",
		"__nonce":        sentinel + "-3",
	}
	step := &Step{
		ID:             "s1",
		OverrideMethod: "§m§",
		OverrideURL:    "https://example.com/§u§",
		OverrideHeaders: map[string]string{
			"Cookie": "PHPSESSID=§sesion_cookie§",
		},
		OverrideBody: strPtr("t=§csrf§"),
	}

	warnings := DetectUnresolvedVars(step, kv)
	if len(warnings) == 0 {
		t.Fatal("expected warnings, got none")
	}
	for i, w := range warnings {
		if strings.Contains(w, sentinel) {
			t.Errorf("warnings[%d] leaked a KV Store value: %q", i, w)
		}
	}

	// Same guard on the define-time path.
	defineWarnings := ValidateMacroTemplates(&Macro{
		Name:        "m",
		Steps:       []Step{*step},
		InitialVars: kv,
	})
	for i, w := range defineWarnings {
		if strings.Contains(w, sentinel) {
			t.Errorf("define warnings[%d] leaked a KV Store value: %q", i, w)
		}
	}
}

func TestDetectUnresolvedVars_EmptyKVStoreHint(t *testing.T) {
	step := &Step{ID: "s1", OverrideURL: "https://example.com/§x§"}
	got := DetectUnresolvedVars(step, nil)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1", len(got))
	}
	if !strings.Contains(got[0], "the KV Store is empty") {
		t.Errorf("warning = %q, want empty-store hint", got[0])
	}
	if strings.Contains(got[0], "available: ") {
		t.Errorf("warning = %q, should not claim available vars", got[0])
	}
}

func TestDetectUnresolvedVars_SampleCaps(t *testing.T) {
	// 7 distinct unresolved names (cap 5) and 12 available names (cap 10).
	body := "§a§§b§§c§§d§§e§§f§§g§"
	step := &Step{ID: "s1", OverrideBody: strPtr(body)}
	kv := map[string]string{}
	for _, k := range []string{"k01", "k02", "k03", "k04", "k05", "k06", "k07", "k08", "k09", "k10", "k11", "k12"} {
		kv[k] = "v"
	}

	got := DetectUnresolvedVars(step, kv)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1", len(got))
	}
	if !strings.Contains(got[0], "...(2 more)") {
		t.Errorf("warning = %q, want token truncation marker '...(2 more)'", got[0])
	}
	if strings.Count(got[0], "...(2 more)") != 2 {
		t.Errorf("warning = %q, want both the token and the available-name lists truncated", got[0])
	}
}

func TestDetectUnresolvedVars_Deterministic(t *testing.T) {
	step := &Step{
		ID:          "s1",
		OverrideURL: "https://example.com/§zz§/§aa§/§mm§",
		OverrideHeaders: map[string]string{
			"C": "§c1§", "A": "§a1§", "B": "§b1§",
		},
	}
	kv := map[string]string{"k1": "1", "k2": "2", "k3": "3", "k4": "4"}

	first := DetectUnresolvedVars(step, kv)
	for i := 0; i < 20; i++ {
		got := DetectUnresolvedVars(step, kv)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("iteration %d produced different warnings:\n%v\n%v", i, got, first)
		}
	}
}

// TestDetectUnresolvedVars_DoesNotMutateStep guards MITM Principle #1: the
// detector is read-only and must never "correct" an operator-authored token.
func TestDetectUnresolvedVars_DoesNotMutateStep(t *testing.T) {
	body := "token=§sesion_cookie§"
	step := &Step{
		ID:              "s1",
		OverrideMethod:  "§verb§",
		OverrideURL:     "https://example.com/§path§",
		OverrideHeaders: map[string]string{"Cookie": "§sesion_cookie§"},
		OverrideBody:    strPtr(body),
	}
	kv := map[string]string{"session_cookie": "v"}

	_ = DetectUnresolvedVars(step, kv)

	if step.OverrideMethod != "§verb§" {
		t.Errorf("OverrideMethod mutated: %q", step.OverrideMethod)
	}
	if step.OverrideURL != "https://example.com/§path§" {
		t.Errorf("OverrideURL mutated: %q", step.OverrideURL)
	}
	if step.OverrideHeaders["Cookie"] != "§sesion_cookie§" {
		t.Errorf("OverrideHeaders mutated: %q", step.OverrideHeaders["Cookie"])
	}
	if *step.OverrideBody != body {
		t.Errorf("OverrideBody mutated: %q", *step.OverrideBody)
	}
	if _, ok := kv["sesion_cookie"]; ok {
		t.Error("detector wrote a best-match value into the KV Store")
	}
}

// TestValidateMacroTemplates_ForeignSyntaxSuggestsSectionSign covers the
// Issue's first acceptance criterion: defining a macro whose override_headers
// carry {{session}} warns at define time, and the warning contains the
// correct §session§ form.
func TestValidateMacroTemplates_ForeignSyntaxSuggestsSectionSign(t *testing.T) {
	m := &Macro{
		Name: "auth",
		Steps: []Step{
			{
				ID:              "login",
				StreamID:        "f1",
				OverrideHeaders: map[string]string{"Cookie": "PHPSESSID={{session}}"},
			},
		},
	}

	got := ValidateMacroTemplates(m)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	for _, want := range []string{
		"step[login]",
		"header:Cookie",
		"{{session}}",
		"§session§",
		"U+00A7",
	} {
		if !strings.Contains(got[0], want) {
			t.Errorf("warning = %q, missing %q", got[0], want)
		}
	}
}

func TestValidateMacroTemplates_UnresolvedNames(t *testing.T) {
	tests := []struct {
		name        string
		macro       *Macro
		wantCount   int
		wantHas     []string
		wantMissing []string
	}{
		{
			name:      "nil macro",
			macro:     nil,
			wantCount: 0,
		},
		{
			name: "resolved from initial_vars",
			macro: &Macro{
				Steps:       []Step{{ID: "s1", OverrideBody: strPtr("p=§password§")}},
				InitialVars: map[string]string{"password": "x"},
			},
			wantCount: 0,
		},
		{
			name: "resolved from preceding step extract",
			macro: &Macro{
				Steps: []Step{
					{ID: "s1", Extract: []ExtractionRule{{Name: "session_cookie"}}},
					{ID: "s2", OverrideHeaders: map[string]string{"Cookie": "§session_cookie§"}},
				},
			},
			wantCount: 0,
		},
		{
			name: "own extract is not in scope for the same step",
			macro: &Macro{
				Steps: []Step{
					{
						ID:              "s1",
						OverrideHeaders: map[string]string{"Cookie": "§own§"},
						Extract:         []ExtractionRule{{Name: "own"}},
					},
				},
			},
			wantCount: 1,
			wantHas:   []string{"§own§", "params.vars"},
		},
		{
			name: "forward reference to a later step's extract warns",
			macro: &Macro{
				Steps: []Step{
					{ID: "s1", OverrideURL: "https://example.com/§later§"},
					{ID: "s2", Extract: []ExtractionRule{{Name: "later"}}},
				},
			},
			wantCount: 1,
			wantHas:   []string{"step[s1]", "url:", "§later§"},
		},
		{
			name: "reserved key is suppressed",
			macro: &Macro{
				Steps: []Step{{ID: "s1", OverrideBody: strPtr("n=§__nonce§&i=§__iteration§")}},
			},
			wantCount: 0,
		},
		{
			name: "typo reported with the define-time remediation",
			macro: &Macro{
				Steps:       []Step{{ID: "s1", OverrideHeaders: map[string]string{"Cookie": "§sesion_cookie§"}}},
				InitialVars: map[string]string{"session_cookie": "v"},
			},
			wantCount:   1,
			wantHas:     []string{"§sesion_cookie§", "initial_vars", "params.vars"},
			wantMissing: []string{"variable not found in KV Store"},
		},
		{
			name: "foreign syntax and unresolved var are separate lines",
			macro: &Macro{
				Steps: []Step{{
					ID:              "s1",
					OverrideHeaders: map[string]string{"Cookie": "a={{foo}}; b=§bar§"},
				}},
			},
			wantCount: 2,
			wantHas:   []string{"§foo§", "§bar§"},
		},
		{
			name: "method and url scanned too",
			macro: &Macro{
				Steps: []Step{{ID: "s1", OverrideMethod: "§verb§", OverrideURL: "https://x/§p§"}},
			},
			wantCount: 2,
			wantHas:   []string{"method:", "url:"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ValidateMacroTemplates(tc.macro)
			if len(got) != tc.wantCount {
				t.Fatalf("len(warnings) = %d, want %d; got %v", len(got), tc.wantCount, got)
			}
			joined := strings.Join(got, "\n")
			for _, want := range tc.wantHas {
				if !strings.Contains(joined, want) {
					t.Errorf("warnings = %q, missing %q", joined, want)
				}
			}
			for _, unwanted := range tc.wantMissing {
				if strings.Contains(joined, unwanted) {
					t.Errorf("warnings = %q, should not contain %q", joined, unwanted)
				}
			}
		})
	}
}

func TestValidateMacroTemplates_Deterministic(t *testing.T) {
	m := &Macro{
		Name: "m",
		Steps: []Step{
			{
				ID: "s1",
				OverrideHeaders: map[string]string{
					"C": "§c1§", "A": "{{a1}}", "B": "§b1§",
				},
				OverrideURL: "https://example.com/§zz§/§aa§",
			},
			{ID: "s2", OverrideBody: strPtr("§q§§p§")},
		},
		InitialVars: map[string]string{"k1": "1", "k2": "2"},
	}

	first := ValidateMacroTemplates(m)
	if len(first) == 0 {
		t.Fatal("expected warnings")
	}
	for i := 0; i < 20; i++ {
		got := ValidateMacroTemplates(m)
		if !reflect.DeepEqual(got, first) {
			t.Fatalf("iteration %d produced different warnings:\n%v\n%v", i, got, first)
		}
	}
}

// TestValidateMacroTemplates_RegexScanBoundedSectionScanIsNot is the
// anti-regression guard for USK-1035 review F-1/S-2. The regex-based
// foreign-syntax scan is capped at MaxUnresolvedScanBytes so an unbounded
// override_body cannot drive unbounded regex work (CWE-770), while the
// regex-free §name§ walk stays uncapped — truncating it would reinstate the
// silent-send hole this Issue exists to close.
func TestValidateMacroTemplates_RegexScanBoundedSectionScanIsNot(t *testing.T) {
	filler := strings.Repeat("a", MaxUnresolvedScanBytes)
	body := "{{near}}" + filler + "{{far}} §typo§"
	m := &Macro{
		Name:  "big",
		Steps: []Step{{ID: "s1", OverrideBody: strPtr(body)}},
	}

	joined := strings.Join(ValidateMacroTemplates(m), "\n")

	if !strings.Contains(joined, "{{near}}") {
		t.Errorf("warnings = %q, want the foreign token inside the %d-byte window reported",
			joined, MaxUnresolvedScanBytes)
	}
	if strings.Contains(joined, "{{far}}") {
		t.Errorf("warnings = %q, foreign token beyond %d bytes must not be scanned",
			joined, MaxUnresolvedScanBytes)
	}
	if !strings.Contains(joined, "§typo§") {
		t.Errorf("warnings = %q, want the §name§ scan to report a token beyond the regex window",
			joined)
	}
}

// TestDetectUnresolvedVars_SectionScanIgnoresRegexWindow pins the same
// guarantee on the run-time path: a misspelt variable a megabyte into the body
// still warns.
func TestDetectUnresolvedVars_SectionScanIgnoresRegexWindow(t *testing.T) {
	body := strings.Repeat("a", MaxUnresolvedScanBytes+1) + "§typo§"
	step := &Step{ID: "s1", OverrideBody: strPtr(body)}

	got := DetectUnresolvedVars(step, map[string]string{"session": "v"})
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	if !strings.Contains(got[0], "§typo§") {
		t.Errorf("warning = %q, want §typo§ reported past the %d-byte regex window",
			got[0], MaxUnresolvedScanBytes)
	}
}

// TestAvailableVarsHint_ResponseHeaderKeysDoNotStarveAuthoredNames covers
// USK-1035 review F-2: `_` (0x5F) sorts before every lowercase letter, so a
// single sort would let the runtime __response_headers__* projection (up to
// 256 keys in the fuzz post_macro path) occupy every sample slot — hiding the
// very names the operator mistyped.
func TestAvailableVarsHint_ResponseHeaderKeysDoNotStarveAuthoredNames(t *testing.T) {
	kv := map[string]string{
		"session_cookie": "v",
		"csrf_token":     "v",
	}
	for i := 0; i < 40; i++ {
		kv[fmt.Sprintf("__response_headers__x_custom_%02d__", i)] = "v"
	}

	step := &Step{ID: "s1", OverrideHeaders: map[string]string{"Cookie": "§sesion_cookie§"}}
	got := DetectUnresolvedVars(step, kv)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	w := got[0]

	for _, want := range []string{"csrf_token", "session_cookie"} {
		if !strings.Contains(w, want) {
			t.Errorf("warning = %q, missing operator-authored name %q", w, want)
		}
	}
	// Reserved keys stay visible in the slots the authored names leave free:
	// §__response_status§ and friends are legitimately referenceable.
	if !strings.Contains(w, "__response_headers__") {
		t.Errorf("warning = %q, want reserved keys still listed after the authored ones", w)
	}
	if authoredIdx, reservedIdx := strings.Index(w, "csrf_token"), strings.Index(w, "__response_headers__"); authoredIdx > reservedIdx {
		t.Errorf("warning = %q, want authored names listed before reserved keys", w)
	}
}

// TestAvailableVarsHint_ReservedOnlyStoreStillLists guards the fallback half
// of F-2: reserved keys must not become permanently invisible.
func TestAvailableVarsHint_ReservedOnlyStoreStillLists(t *testing.T) {
	kv := map[string]string{"__nonce": "v", "__iteration": "v"}
	step := &Step{ID: "s1", OverrideURL: "https://example.com/§typo§"}

	got := DetectUnresolvedVars(step, kv)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	for _, want := range []string{"__iteration", "__nonce"} {
		if !strings.Contains(got[0], want) {
			t.Errorf("warning = %q, missing reserved key %q", got[0], want)
		}
	}
	if strings.Contains(got[0], "the KV Store is empty") {
		t.Errorf("warning = %q, store is not empty", got[0])
	}
}

// TestVarNameRendering_TruncatesOverlongNames covers USK-1035 review S-1
// (CWE-779): injectResponseVars caps response header VALUES but not NAMES, so
// an attacker-chosen header name would otherwise be rendered verbatim into a
// warning that engine.go logs once per step per fuzz iteration. The same bound
// applies to an operator-authored §<very long name>§ token.
func TestVarNameRendering_TruncatesOverlongNames(t *testing.T) {
	longKey := "__response_headers__" + strings.Repeat("a", 300) + "__"
	longName := strings.Repeat("b", 300)
	kv := map[string]string{longKey: "v"}
	step := &Step{ID: "s1", OverrideBody: strPtr(DelimOpen + longName + DelimClose)}

	got := DetectUnresolvedVars(step, kv)
	if len(got) != 1 {
		t.Fatalf("len(warnings) = %d, want 1; got %v", len(got), got)
	}
	w := got[0]

	if strings.Contains(w, longName) {
		t.Errorf("warning rendered the operator-authored name in full: %q", w)
	}
	if strings.Contains(w, longKey) {
		t.Errorf("warning rendered the KV Store key name in full: %q", w)
	}
	if !strings.Contains(w, strings.Repeat("b", maxRenderedVarNameBytes)) {
		t.Errorf("warning = %q, want the first %d bytes of the name kept", w, maxRenderedVarNameBytes)
	}
	if n := strings.Count(w, varNameElision); n != 2 {
		t.Errorf("warning = %q, want 2 elision markers, got %d", w, n)
	}
	if !utf8.ValidString(w) {
		t.Errorf("warning is not valid UTF-8: %q", w)
	}
}

func TestTruncateVarName(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantCut bool
	}{
		{name: "short", input: "session_cookie", wantCut: false},
		{name: "empty", input: "", wantCut: false},
		{name: "exactly at cap", input: strings.Repeat("a", maxRenderedVarNameBytes), wantCut: false},
		{name: "one byte over", input: strings.Repeat("a", maxRenderedVarNameBytes+1), wantCut: true},
		// 30 × U+3042 = 90 bytes; the cut at 64 lands mid-rune and must back
		// off so the rendered name stays valid UTF-8 in slog / JSON output.
		{name: "multibyte", input: strings.Repeat("あ", 30), wantCut: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := truncateVarName(tc.input)
			if !tc.wantCut {
				if got != tc.input {
					t.Fatalf("truncateVarName(%d bytes) = %q, want the input unchanged", len(tc.input), got)
				}
				return
			}
			if !strings.HasSuffix(got, varNameElision) {
				t.Errorf("truncateVarName(%d bytes) = %q, want the elision marker", len(tc.input), got)
			}
			if n := len(got) - len(varNameElision); n > maxRenderedVarNameBytes {
				t.Errorf("rendered %d name bytes, want <= %d", n, maxRenderedVarNameBytes)
			}
			if !utf8.ValidString(got) {
				t.Errorf("truncateVarName(%q) = %q, not valid UTF-8", tc.input, got)
			}
			if !strings.HasPrefix(tc.input, strings.TrimSuffix(got, varNameElision)) {
				t.Errorf("truncateVarName(%q) = %q, want a prefix of the input", tc.input, got)
			}
		})
	}
}
