package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// TestExecute_DefineMacro_ForeignSyntaxWarns is acceptance criterion #1 of
// USK-1035: defining a macro whose override_headers carry {{session}} must
// succeed AND return a warning whose text contains the correct §session§
// form. Before this, a define_macro call with foreign syntax was accepted in
// total silence and the mistake only surfaced as a misleading HTTP 200.
func TestExecute_DefineMacro_ForeignSyntaxWarns(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "foreign-syntax",
			"steps": []any{
				map[string]any{
					"id":               "login",
					"flow_id":          "recorded-login",
					"override_headers": map[string]any{"Cookie": "PHPSESSID={{session}}"},
				},
			},
		},
	})

	if result.IsError {
		t.Fatalf("define_macro must not fail on foreign syntax: %v", result.Content)
	}

	var out macroDefineMacroResult
	unmarshalExecuteResult(t, result, &out)

	if !out.Created {
		t.Error("Created = false, want true (the macro must still be saved)")
	}
	if len(out.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want 1; got %v", len(out.Warnings), out.Warnings)
	}
	for _, want := range []string{"step[login]", "header:Cookie", "{{session}}", "§session§"} {
		if !strings.Contains(out.Warnings[0], want) {
			t.Errorf("Warnings[0] = %q, missing %q", out.Warnings[0], want)
		}
	}
}

// TestExecute_DefineMacro_UnresolvedVarWarns covers the define-time half of
// the §var§ check: a name that resolves against neither initial_vars nor a
// preceding step's extract is reported, with text telling the reader the
// warning is dismissible when run_macro will supply the value.
func TestExecute_DefineMacro_UnresolvedVarWarns(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "unresolved-var",
			"steps": []any{
				map[string]any{
					"id":               "get-csrf",
					"flow_id":          "recorded-csrf",
					"override_headers": map[string]any{"Cookie": "PHPSESSID=§sesion_cookie§"},
				},
			},
			"initial_vars": map[string]any{"session_cookie": "seed"},
		},
	})

	if result.IsError {
		t.Fatalf("define_macro must not fail on an unresolved variable: %v", result.Content)
	}

	var out macroDefineMacroResult
	unmarshalExecuteResult(t, result, &out)

	if len(out.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want 1; got %v", len(out.Warnings), out.Warnings)
	}
	for _, want := range []string{"step[get-csrf]", "§sesion_cookie§", "params.vars"} {
		if !strings.Contains(out.Warnings[0], want) {
			t.Errorf("Warnings[0] = %q, missing %q", out.Warnings[0], want)
		}
	}
}

// TestExecute_DefineMacro_CleanDefinitionHasNoWarnings guards against a
// warning-spam regression on correct macros: the field must be omitted
// entirely when every template resolves.
func TestExecute_DefineMacro_CleanDefinitionHasNoWarnings(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupMacroTestSession(t, store)

	result := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "clean",
			"steps": []any{
				map[string]any{
					"id":            "login",
					"flow_id":       "recorded-login",
					"override_body": "username=admin&password=§password§",
					"extract": []any{
						map[string]any{
							"name":        "session_cookie",
							"from":        "response",
							"source":      "header",
							"header_name": "Set-Cookie",
							"regex":       "PHPSESSID=([^;]+)",
							"group":       1,
						},
					},
				},
				map[string]any{
					"id":               "get-csrf",
					"flow_id":          "recorded-csrf",
					"override_headers": map[string]any{"Cookie": "PHPSESSID=§session_cookie§"},
				},
			},
			"initial_vars": map[string]any{"password": "admin123"},
		},
	})

	if result.IsError {
		t.Fatalf("define_macro failed: %v", result.Content)
	}

	var out macroDefineMacroResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Warnings) != 0 {
		t.Errorf("Warnings = %v, want none", out.Warnings)
	}
}

// TestExecute_DefineMacro_WarnedVarStillRunnableViaRunVars pins the workflow
// the Issue explicitly protects: define_macro warns about a variable that is
// only supplied later through run_macro's params.vars, and the macro still
// executes successfully with the value substituted on the wire.
func TestExecute_DefineMacro_WarnedVarStillRunnableViaRunVars(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	var gotHeader string
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Get("X-Token")
		body, _ := io.ReadAll(r.Body)
		w.WriteHeader(200)
		_, _ = w.Write(body)
	}))
	defer echoServer.Close()

	u, _ := url.Parse(echoServer.URL + "/api/test")
	ctx := context.Background()

	fl := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Body:      []byte("hello"),
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "late-vars",
			"steps": []any{
				map[string]any{
					"id":               "step1",
					"flow_id":          fl.ID,
					"override_headers": map[string]any{"X-Token": "§late_token§"},
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}
	var defineOut macroDefineMacroResult
	unmarshalExecuteResult(t, defineResult, &defineOut)
	if len(defineOut.Warnings) != 1 {
		t.Fatalf("expected 1 define-time warning, got %v", defineOut.Warnings)
	}

	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "late-vars",
			"vars": map[string]any{"late_token": "supplied-at-run-time"},
		},
	})
	if runResult.IsError {
		t.Fatalf("run_macro failed: %v", runResult.Content)
	}

	var runOut macroRunMacroResult
	unmarshalExecuteResult(t, runResult, &runOut)
	if runOut.Status != "completed" {
		t.Errorf("run status = %q, want %q (error=%q)", runOut.Status, "completed", runOut.Error)
	}
	if len(runOut.StepResults) != 1 {
		t.Fatalf("len(StepResults) = %d, want 1", len(runOut.StepResults))
	}
	if runOut.StepResults[0].Status != "completed" {
		t.Errorf("step status = %q, want %q; warnings=%v",
			runOut.StepResults[0].Status, "completed", runOut.StepResults[0].Warnings)
	}
	if gotHeader != "supplied-at-run-time" {
		t.Errorf("upstream saw X-Token = %q, want the substituted value", gotHeader)
	}
}

// TestExecute_RunMacro_UnresolvedVarWarns is acceptance criterion #2 seen
// through the MCP boundary: a typo'd variable produces a step warning listing
// the available variable NAMES, and never a KV Store value.
func TestExecute_RunMacro_UnresolvedVarWarns(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)

	const secret = "SENTINEL-SESSION-VALUE-71bd"

	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer echoServer.Close()

	u, _ := url.Parse(echoServer.URL + "/api/test")
	ctx := context.Background()

	fl := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	cs := setupMacroTestSession(t, store)

	callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "typo-macro",
			"steps": []any{
				map[string]any{
					"id":               "step1",
					"flow_id":          fl.ID,
					"override_headers": map[string]any{"Cookie": "PHPSESSID=§sesion_cookie§"},
				},
			},
			"initial_vars": map[string]any{"session_cookie": secret},
		},
	})

	result := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{"name": "typo-macro"},
	})
	if result.IsError {
		t.Fatalf("run_macro failed: %v", result.Content)
	}

	var out macroRunMacroResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.StepResults) != 1 {
		t.Fatalf("len(StepResults) = %d, want 1", len(out.StepResults))
	}
	sr := out.StepResults[0]
	if sr.Status != "warning" {
		t.Errorf("step status = %q, want %q", sr.Status, "warning")
	}
	if len(sr.Warnings) != 1 {
		t.Fatalf("len(Warnings) = %d, want 1; got %v", len(sr.Warnings), sr.Warnings)
	}
	for _, want := range []string{"§sesion_cookie§", "available: ", "session_cookie"} {
		if !strings.Contains(sr.Warnings[0], want) {
			t.Errorf("Warnings[0] = %q, missing %q", sr.Warnings[0], want)
		}
	}
	if strings.Contains(sr.Warnings[0], secret) {
		t.Errorf("Warnings[0] leaked a KV Store value: %q", sr.Warnings[0])
	}
}
