package macro

import (
	"context"
	"strings"
	"testing"
)

// newUnresolvedTestEngine builds an engine over a single recorded flow,
// capturing the header, URL, and body actually handed to SendFunc so tests can
// assert that the wire copy is untouched.
func newUnresolvedTestEngine(t *testing.T, sent *SendRequest) *Engine {
	t.Helper()
	fetcher := &mockFlowFetcher{
		flows: map[string]*SendRequest{
			"sess1": {
				Method:  "POST",
				URL:     "https://example.com/api",
				Headers: map[string][]string{},
				Body:    []byte("base"),
			},
		},
	}
	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		*sent = *req
		return &SendResponse{StatusCode: 200}, nil
	}
	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return engine
}

// TestEngine_Run_UnresolvedVarWarning is the run-time half of USK-1035: a
// correctly-spelled §…§ template whose variable name is misspelt used to be
// sent with zero signal. It must now produce a step warning that names the
// token and lists the variable names that ARE available — while the wire copy
// keeps the operator's literal bytes.
func TestEngine_Run_UnresolvedVarWarning(t *testing.T) {
	var sent SendRequest
	engine := newUnresolvedTestEngine(t, &sent)

	m := &Macro{
		Name: "typo-test",
		Steps: []Step{
			{
				ID:       "step1",
				StreamID: "sess1",
				// Operator typo: session_cookie is the real name.
				OverrideHeaders: map[string]string{"Cookie": "PHPSESSID=§sesion_cookie§"},
			},
		},
		InitialVars: map[string]string{"session_cookie": "real-token-value", "csrf_token": "t"},
	}

	result, err := engine.Run(context.Background(), m, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("len(StepResults) = %d, want 1", len(result.StepResults))
	}
	sr := result.StepResults[0]
	if sr.Status != "warning" {
		t.Errorf("step Status = %q, want %q", sr.Status, "warning")
	}
	if len(sr.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want 1; got %v", len(sr.Warnings), sr.Warnings)
	}
	for _, want := range []string{"header:Cookie", "§sesion_cookie§", "available: ", "session_cookie", "csrf_token"} {
		if !strings.Contains(sr.Warnings[0], want) {
			t.Errorf("Warnings[0] = %q, missing %q", sr.Warnings[0], want)
		}
	}
	// SECURITY: names only — the KV Store value must never be echoed.
	if strings.Contains(sr.Warnings[0], "real-token-value") {
		t.Errorf("Warnings[0] leaked a KV Store value: %q", sr.Warnings[0])
	}
	// MITM Principle #1: the wire carries the operator's bytes verbatim.
	if got := sent.Headers["Cookie"]; len(got) != 1 || got[0] != "PHPSESSID=§sesion_cookie§" {
		t.Errorf("sent Cookie = %v, want the literal token (detector must not rewrite the wire)", got)
	}
}

// TestEngine_Run_UnresolvedVar_SuppliedByRunVarsSucceeds pins the workflow the
// Issue explicitly protects: a variable absent from initial_vars but supplied
// at run time through run_macro's params.vars resolves normally and produces
// no warning.
func TestEngine_Run_UnresolvedVar_SuppliedByRunVarsSucceeds(t *testing.T) {
	var sent SendRequest
	engine := newUnresolvedTestEngine(t, &sent)

	m := &Macro{
		Name: "late-vars",
		Steps: []Step{
			{
				ID:              "step1",
				StreamID:        "sess1",
				OverrideHeaders: map[string]string{"Cookie": "PHPSESSID=§session_cookie§"},
			},
		},
	}

	// Static define-time validation warns, because the name is unknown
	// until run time.
	if got := ValidateMacroTemplates(m); len(got) != 1 {
		t.Fatalf("ValidateMacroTemplates len = %d, want 1; got %v", len(got), got)
	}

	result, err := engine.Run(context.Background(), m, map[string]string{"session_cookie": "abc123"})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	sr := result.StepResults[0]
	if sr.Status != "completed" {
		t.Errorf("step Status = %q, want %q; warnings=%v", sr.Status, "completed", sr.Warnings)
	}
	if len(sr.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", sr.Warnings)
	}
	if got := sent.Headers["Cookie"]; len(got) != 1 || got[0] != "PHPSESSID=abc123" {
		t.Errorf("sent Cookie = %v, want the expanded value", got)
	}
}

// TestEngine_Run_UnresolvedVar_ResolvedByPriorExtract verifies that a value
// captured by an earlier step's extraction rule satisfies a later step's
// template without warning — the canonical multi-step macro shape.
func TestEngine_Run_UnresolvedVar_ResolvedByPriorExtract(t *testing.T) {
	fetcher := &mockFlowFetcher{
		flows: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/login", Headers: map[string][]string{}},
		},
	}
	var secondCookie string
	calls := 0
	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		calls++
		if calls == 2 {
			if v := req.Headers["Cookie"]; len(v) > 0 {
				secondCookie = v[0]
			}
		}
		return &SendResponse{
			StatusCode: 200,
			Body:       []byte(`{"token":"tok-42"}`),
		}, nil
	}
	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	m := &Macro{
		Name: "extract-chain",
		Steps: []Step{
			{
				ID:       "login",
				StreamID: "sess1",
				Extract: []ExtractionRule{{
					Name:   "session_cookie",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceBody,
					Regex:  `"token":"([^"]+)"`,
					Group:  1,
				}},
			},
			{
				ID:              "use",
				StreamID:        "sess1",
				OverrideHeaders: map[string]string{"Cookie": "§session_cookie§"},
			},
		},
	}

	// No define-time warning either: the name comes from a preceding step.
	if got := ValidateMacroTemplates(m); len(got) != 0 {
		t.Fatalf("ValidateMacroTemplates = %v, want none", got)
	}

	result, err := engine.Run(context.Background(), m, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	for _, sr := range result.StepResults {
		if sr.Status != "completed" {
			t.Errorf("step %q Status = %q, want %q; warnings=%v", sr.ID, sr.Status, "completed", sr.Warnings)
		}
	}
	if secondCookie != "tok-42" {
		t.Errorf("second step Cookie = %q, want %q", secondCookie, "tok-42")
	}
}

// TestEngine_Run_ForeignAndUnresolvedWarnSeparately asserts the two detectors
// emit independent lines with independent remediations, so an operator who
// made both mistakes sees both fixes.
func TestEngine_Run_ForeignAndUnresolvedWarnSeparately(t *testing.T) {
	var sent SendRequest
	engine := newUnresolvedTestEngine(t, &sent)

	m := &Macro{
		Name: "both",
		Steps: []Step{
			{
				ID:              "step1",
				StreamID:        "sess1",
				OverrideHeaders: map[string]string{"X-A": "{{foo}}"},
				OverrideBody:    strPtr("b=§bar§"),
			},
		},
	}

	result, err := engine.Run(context.Background(), m, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	sr := result.StepResults[0]
	if len(sr.Warnings) != 2 {
		t.Fatalf("len(Warnings) = %d, want 2; got %v", len(sr.Warnings), sr.Warnings)
	}
	joined := strings.Join(sr.Warnings, "\n")
	for _, want := range []string{"{{foo}}", "§foo§", "not expanded", "§bar§", "variable not found in KV Store"} {
		if !strings.Contains(joined, want) {
			t.Errorf("warnings %q missing %q", joined, want)
		}
	}
}
