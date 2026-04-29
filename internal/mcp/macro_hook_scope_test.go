package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/macro"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// TestMacroSendFunc_TargetScope_BlocksAfterTemplateExpansion verifies that
// macroSendFunc checks httpReq.URL against target scope rules, blocking
// requests to out-of-scope hosts even when the URL was produced by template
// expansion (TOCTOU fix for USK-210).
func TestMacroSendFunc_TargetScope_BlocksAfterTemplateExpansion(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: ts})
	sendFunc := s.macroSendFunc("test-macro")

	// Simulate a request to a blocked host (as if template expanded to this URL).
	_, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    "http://169.254.169.254/latest/meta-data/",
		StepID: "step-1",
	})
	if err == nil {
		t.Fatal("expected error for out-of-scope URL, got nil")
	}
	if !strings.Contains(err.Error(), "target scope") {
		t.Errorf("error should mention target scope, got: %v", err)
	}
}

// TestMacroSendFunc_TargetScope_AllowsInScope verifies that macroSendFunc
// allows requests to in-scope hosts.
func TestMacroSendFunc_TargetScope_AllowsInScope(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	serverURL, _ := url.Parse(echoServer.URL)

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: ts})
	sendFunc := s.macroSendFunc("test-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/api/test",
		StepID: "step-1",
	})
	if err != nil {
		t.Fatalf("expected success for in-scope URL, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestMacroSendFunc_TargetScope_NoRulesAllowsAll verifies that macroSendFunc
// allows all requests when no target scope rules are configured.
func TestMacroSendFunc_TargetScope_NoRulesAllowsAll(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	// No target scope rules.
	s := mkServerFromLegacyDeps(legacyDeps{targetScope: proxy.NewTargetScope()})
	sendFunc := s.macroSendFunc("test-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/any/path",
		StepID: "step-1",
	})
	if err != nil {
		t.Fatalf("expected success with no scope rules, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestHookMacroSendFunc_TargetScope_BlocksAfterTemplateExpansion verifies that
// hookMacroSendFunc checks httpReq.URL against target scope rules, blocking
// requests to out-of-scope hosts (TOCTOU fix for USK-210).
func TestHookMacroSendFunc_TargetScope_BlocksAfterTemplateExpansion(t *testing.T) {
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: ts})
	sendFunc := hookMacroSendFunc(s, "hook-macro")

	// Simulate a request to a blocked host.
	_, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    "http://169.254.169.254/latest/meta-data/",
		StepID: "hook-step-1",
	})
	if err == nil {
		t.Fatal("expected error for out-of-scope URL, got nil")
	}
	if !strings.Contains(err.Error(), "target scope") {
		t.Errorf("error should mention target scope, got: %v", err)
	}
}

// TestHookMacroSendFunc_TargetScope_AllowsInScope verifies that hookMacroSendFunc
// allows requests to in-scope hosts.
func TestHookMacroSendFunc_TargetScope_AllowsInScope(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	serverURL, _ := url.Parse(echoServer.URL)

	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: serverURL.Hostname()},
	}, nil)

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: ts})
	sendFunc := hookMacroSendFunc(s, "hook-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/api/test",
		StepID: "hook-step-1",
	})
	if err != nil {
		t.Fatalf("expected success for in-scope URL, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestHookMacroSendFunc_TargetScope_NoRulesAllowsAll verifies that hookMacroSendFunc
// allows all requests when no target scope rules are configured.
func TestHookMacroSendFunc_TargetScope_NoRulesAllowsAll(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: proxy.NewTargetScope()})
	sendFunc := hookMacroSendFunc(s, "hook-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/any/path",
		StepID: "hook-step-1",
	})
	if err != nil {
		t.Fatalf("expected success with no scope rules, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestMacroSendFunc_TargetScope_NilScope verifies that macroSendFunc
// allows all requests when targetScope is nil.
func TestMacroSendFunc_TargetScope_NilScope(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: nil})
	sendFunc := s.macroSendFunc("test-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/any/path",
		StepID: "step-1",
	})
	if err != nil {
		t.Fatalf("expected success with nil scope, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestHookMacroSendFunc_TargetScope_NilScope verifies that hookMacroSendFunc
// allows all requests when targetScope is nil.
func TestHookMacroSendFunc_TargetScope_NilScope(t *testing.T) {
	echoServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer echoServer.Close()

	s := mkServerFromLegacyDeps(legacyDeps{targetScope: nil})
	sendFunc := hookMacroSendFunc(s, "hook-macro")

	resp, err := sendFunc(context.Background(), &macro.SendRequest{
		Method: "GET",
		URL:    echoServer.URL + "/any/path",
		StepID: "hook-step-1",
	})
	if err != nil {
		t.Fatalf("expected success with nil scope, got: %v", err)
	}
	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}
}

// TestRunMacro_TemplateExpansion_TargetScopeBypass_Blocked is an integration test
// that verifies the TOCTOU vulnerability is fixed end-to-end.
// It simulates the attack described in USK-210:
//  1. Target Scope allows only allowed.example.com
//  2. Macro step 1: requests allowed.example.com, extracts target_url from response
//  3. Macro step 2: override_url is §target_url§ (template)
//  4. The pre-run check skips §target_url§ (unparseable host),
//     but the send-time check blocks the expanded URL.
func TestRunMacro_TemplateExpansion_TargetScopeBypass_Blocked(t *testing.T) {
	// Step 1 server: returns an evil URL in response body.
	step1Server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Target-URL", "http://169.254.169.254/latest/meta-data/")
		w.WriteHeader(200)
		w.Write([]byte(`{"target_url":"http://169.254.169.254/latest/meta-data/"}`))
	}))
	defer step1Server.Close()

	store := newTestStore(t)
	ctx := context.Background()
	step1URL, _ := url.Parse(step1Server.URL + "/api/info")

	// Save flow for step 1.
	fl1 := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl1.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       step1URL,
		Headers:   map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Save flow for step 2 (template URL, will be expanded).
	fl2 := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl2.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       step1URL, // base URL doesn't matter; override_url takes precedence
		Headers:   map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	step1URLParsed, _ := url.Parse(step1Server.URL)

	// Set up target scope: only allow the step1 server.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: step1URLParsed.Hostname()},
	}, nil)

	s := newServer(ctx, nil, store, nil, WithTargetScope(ts))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	// Define macro: step 1 extracts target_url, step 2 uses §target_url§ as override_url.
	defineResult := callMacro(t, cs, map[string]any{
		"action": "define_macro",
		"params": map[string]any{
			"name": "bypass-macro",
			"steps": []any{
				map[string]any{
					"id":      "fetch-url",
					"flow_id": fl1.ID,
					"extract": []any{
						map[string]any{
							"name":        "target_url",
							"from":        "response",
							"source":      "header",
							"header_name": "X-Target-URL",
						},
					},
				},
				map[string]any{
					"id":           "use-url",
					"flow_id":      fl2.ID,
					"override_url": "§target_url§",
				},
			},
		},
	})
	if defineResult.IsError {
		t.Fatalf("define_macro failed: %v", defineResult.Content)
	}

	// Run the macro. Step 2 should be blocked because the expanded URL
	// (169.254.169.254) is not in the target scope.
	runResult := callMacro(t, cs, map[string]any{
		"action": "run_macro",
		"params": map[string]any{
			"name": "bypass-macro",
		},
	})

	// The macro should fail because of the target scope check at send time.
	// The error may come as a macro execution error (step failed).
	if !runResult.IsError {
		// Check if the result shows a failed status.
		var out macroRunMacroResult
		unmarshalExecuteResult(t, runResult, &out)
		if out.Status == "completed" {
			t.Fatal("expected macro to fail due to target scope violation, but it completed successfully")
		}
		// If status is not "completed", the macro engine caught the error.
		found := false
		for _, sr := range out.StepResults {
			if sr.ID == "use-url" && strings.Contains(sr.Error, "target scope") {
				found = true
				break
			}
		}
		if !found && !strings.Contains(out.Error, "target scope") {
			t.Errorf("expected target scope error in macro result, got: %+v", out)
		}
	} else {
		// Error at the MCP level — check that it mentions target scope.
		text := runResult.Content[0].(*gomcp.TextContent).Text
		if !strings.Contains(text, "target scope") {
			t.Errorf("error should mention target scope, got: %s", text)
		}
	}
}

// TestHookMacro_TemplateExpansion_TargetScopeBypass_Blocked is an integration test
// verifying the hook path is also protected against template expansion bypass.
func TestHookMacro_TemplateExpansion_TargetScopeBypass_Blocked(t *testing.T) {
	// Macro step server returns an evil URL.
	macroServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Target", "http://169.254.169.254/latest/meta-data/")
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer macroServer.Close()

	store := newTestStore(t)
	ctx := context.Background()

	macroURL, _ := url.Parse(macroServer.URL + "/get-url")

	// Save flows for the 2-step hook macro.
	fl1 := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl1); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: fl1.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: macroURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	fl2 := &flow.Stream{Protocol: "HTTP/1.x", Timestamp: time.Now().UTC()}
	if err := store.SaveStream(ctx, fl2); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID: fl2.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: macroURL,
		Headers: map[string][]string{},
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	macroURLParsed, _ := url.Parse(macroServer.URL)

	// Target scope: only allow macroServer.
	ts := proxy.NewTargetScope()
	ts.SetAgentRules([]proxy.TargetRule{
		{Hostname: macroURLParsed.Hostname()},
	}, nil)

	s := mkServerFromLegacyDeps(legacyDeps{
		store:       store,
		targetScope: ts,
	})

	// Define a 2-step macro: step 1 extracts URL, step 2 uses it.
	cfg := macroConfig{
		Steps: []macroStepInput{
			{
				ID:       "get-target",
				StreamID: fl1.ID,
				Extract: []extractionInput{
					{
						Name:       "evil_url",
						From:       "response",
						Source:     "header",
						HeaderName: "X-Target",
					},
				},
			},
			{
				ID:          "visit-target",
				StreamID:    fl2.ID,
				OverrideURL: "§evil_url§",
			},
		},
	}
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("marshal config: %v", err)
	}
	if err := store.SaveMacro(ctx, "evil-hook-macro", "test", string(cfgJSON)); err != nil {
		t.Fatalf("SaveMacro: %v", err)
	}

	// Run the macro via hookExecutor.
	he := newHookExecutor(s, &hooksInput{
		PreSend: &hookConfig{
			Macro:       "evil-hook-macro",
			RunInterval: "always",
		},
	}, &hookState{})

	_, execErr := he.executePreSend(ctx)

	// The macro should fail because step 2's expanded URL is out of scope.
	if execErr == nil {
		t.Fatal("expected error for out-of-scope URL after template expansion, got nil")
	}
	if !strings.Contains(execErr.Error(), "target scope") {
		t.Errorf("error should mention target scope, got: %v", execErr)
	}
}
