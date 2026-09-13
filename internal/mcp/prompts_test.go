package mcp

import (
	"context"
	"regexp"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// setupPromptTestSession creates an MCP client session for prompt tests.
// Mirrors setupResourceTestSession from resources_test.go.
func setupPromptTestSession(t *testing.T) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	ca := newTestCA(t)
	s := newServer(ctx, ca, nil, nil)
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

	return cs
}

// expectedPromptNames is the canonical set of user-facing playbooks
// exposed via prompts/list. Keep this list in sync with userPrompts in
// prompts.go.
var expectedPromptNames = []string{
	"verify-idor",
	"verify-sqli",
	"verify-xss",
	"verify-csrf",
	"audit-auth",
	"fuzz-endpoint",
	"replay-with-mods",
	"capture-traffic",
	"stateful-fuzz-loop",
}

func TestListPrompts_AllRegistered(t *testing.T) {
	cs := setupPromptTestSession(t)

	result, err := cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	gotNames := make(map[string]bool, len(result.Prompts))
	for _, p := range result.Prompts {
		gotNames[p.Name] = true
	}

	for _, name := range expectedPromptNames {
		if !gotNames[name] {
			t.Errorf("missing prompt: %s", name)
		}
	}

	if len(result.Prompts) != len(expectedPromptNames) {
		t.Errorf("prompt count = %d, want %d", len(result.Prompts), len(expectedPromptNames))
	}
}

func TestListPrompts_DescriptionsPresent(t *testing.T) {
	cs := setupPromptTestSession(t)

	result, err := cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	for _, p := range result.Prompts {
		t.Run(p.Name, func(t *testing.T) {
			if p.Description == "" {
				t.Error("description is empty")
			}
			// Description budget: 80–200 chars per spec §6.3 estimate.
			if len(p.Description) < 80 {
				t.Errorf("description too short (%d chars, want >=80): %q", len(p.Description), p.Description)
			}
			if len(p.Description) > 250 {
				t.Errorf("description too long (%d chars, want <=250): %q", len(p.Description), p.Description)
			}
			if p.Title == "" {
				t.Error("title is empty")
			}
		})
	}
}

func TestGetPrompt_ReturnsInlineBody(t *testing.T) {
	cs := setupPromptTestSession(t)

	// Each entry provides a complete set of required arguments so the
	// handler can return successfully. The wantContains substring asserts
	// the body content matches the right playbook.
	tests := []struct {
		name         string
		args         map[string]string
		wantContains string
	}{
		{
			name: "verify-idor",
			args: map[string]string{
				"target_flow_id": "abc123",
				"id_field":       "$.user_id",
				"candidate_ids":  "1,2,3",
			},
			wantContains: "Insecure Direct Object Reference",
		},
		{
			name: "verify-sqli",
			args: map[string]string{
				"target_flow_id":  "abc123",
				"injection_point": "body",
			},
			wantContains: "SQL injection",
		},
		{
			name: "verify-xss",
			args: map[string]string{
				"target_flow_id":  "abc123",
				"injection_point": "raw_query",
			},
			wantContains: "Reflected XSS",
		},
		{
			name: "verify-csrf",
			args: map[string]string{
				"target_flow_id":    "abc123",
				"token_header_name": "X-CSRF-Token",
			},
			wantContains: "CSRF",
		},
		{
			name: "audit-auth",
			args: map[string]string{
				"target_flow_id":   "abc123",
				"auth_header_name": "Authorization",
			},
			wantContains: "Audit Authentication",
		},
		{
			name: "fuzz-endpoint",
			args: map[string]string{
				"target_flow_id": "abc123",
				"position_path":  "body",
				"payload_set":    "boundary",
			},
			wantContains: "Fuzz an Endpoint",
		},
		{
			name: "replay-with-mods",
			args: map[string]string{
				"target_flow_id":   "abc123",
				"mods_description": "swap auth",
			},
			wantContains: "Replay a Recorded Request",
		},
		{
			name: "capture-traffic",
			args: map[string]string{
				"target_host": "*.target.example.com",
			},
			wantContains: "playwright-cli",
		},
		{
			name: "stateful-fuzz-loop",
			args: map[string]string{
				"setup_macro_name":    "setup-item",
				"teardown_macro_name": "teardown",
				"target_flow_id":      "abc123",
			},
			wantContains: "Stateful-Fuzz Loop",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := cs.GetPrompt(context.Background(), &gomcp.GetPromptParams{
				Name:      tt.name,
				Arguments: tt.args,
			})
			if err != nil {
				t.Fatalf("GetPrompt(%s): %v", tt.name, err)
			}
			if len(result.Messages) != 1 {
				t.Fatalf("expected 1 message, got %d", len(result.Messages))
			}
			msg := result.Messages[0]
			if msg.Role != "user" {
				t.Errorf("role = %q, want %q", msg.Role, "user")
			}
			tc, ok := msg.Content.(*gomcp.TextContent)
			if !ok {
				t.Fatalf("content type = %T, want *TextContent", msg.Content)
			}
			if tc.Text == "" {
				t.Fatal("text is empty")
			}
			if !strings.Contains(tc.Text, tt.wantContains) {
				t.Errorf("text does not contain %q", tt.wantContains)
			}
			if result.Description == "" {
				t.Error("result description is empty")
			}
		})
	}
}

func TestGetPrompt_ArgumentSubstitution(t *testing.T) {
	cs := setupPromptTestSession(t)

	const flowID = "flow-XYZ-substitution-marker"
	const idField = "$.special_id_marker"

	result, err := cs.GetPrompt(context.Background(), &gomcp.GetPromptParams{
		Name: "verify-idor",
		Arguments: map[string]string{
			"target_flow_id": flowID,
			"id_field":       idField,
			"candidate_ids":  "1,2,3",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}

	tc, ok := result.Messages[0].Content.(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *TextContent", result.Messages[0].Content)
	}

	// Substitution actually happened.
	if !strings.Contains(tc.Text, flowID) {
		t.Errorf("substituted text does not contain flow id %q", flowID)
	}
	if !strings.Contains(tc.Text, idField) {
		t.Errorf("substituted text does not contain id_field %q", idField)
	}

	// Placeholders are fully removed.
	if strings.Contains(tc.Text, "{{target_flow_id}}") {
		t.Error("text still contains {{target_flow_id}} placeholder")
	}
	if strings.Contains(tc.Text, "{{id_field}}") {
		t.Error("text still contains {{id_field}} placeholder")
	}
	if strings.Contains(tc.Text, "{{candidate_ids}}") {
		t.Error("text still contains {{candidate_ids}} placeholder")
	}
}

func TestGetPrompt_RequiredArgumentMissing(t *testing.T) {
	cs := setupPromptTestSession(t)

	// verify-idor has three required arguments; omit one to trigger
	// the required-arg validation path in makePromptHandler.
	_, err := cs.GetPrompt(context.Background(), &gomcp.GetPromptParams{
		Name: "verify-idor",
		Arguments: map[string]string{
			"target_flow_id": "abc123",
			// id_field intentionally missing.
			"candidate_ids": "1,2,3",
		},
	})
	if err == nil {
		t.Fatal("expected error when required argument is missing, got nil")
	}
	if !strings.Contains(err.Error(), "id_field") {
		t.Errorf("error = %q, want it to mention the missing argument name", err.Error())
	}
}

func TestGetPrompt_RequiredArgumentEmpty(t *testing.T) {
	cs := setupPromptTestSession(t)

	// Empty string counts as missing for required arguments.
	_, err := cs.GetPrompt(context.Background(), &gomcp.GetPromptParams{
		Name: "verify-idor",
		Arguments: map[string]string{
			"target_flow_id": "abc123",
			"id_field":       "",
			"candidate_ids":  "1,2,3",
		},
	})
	if err == nil {
		t.Fatal("expected error when required argument is empty, got nil")
	}
}

func TestGetPrompt_OptionalArgumentDefault(t *testing.T) {
	cs := setupPromptTestSession(t)

	// capture-traffic has an optional listen_addr. When omitted, the
	// placeholder is substituted with an empty string. The handler must
	// not error, and the body should explicitly note the default address.
	result, err := cs.GetPrompt(context.Background(), &gomcp.GetPromptParams{
		Name: "capture-traffic",
		Arguments: map[string]string{
			"target_host": "*.example.com",
		},
	})
	if err != nil {
		t.Fatalf("GetPrompt: %v", err)
	}

	tc, ok := result.Messages[0].Content.(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *TextContent", result.Messages[0].Content)
	}
	if strings.Contains(tc.Text, "{{listen_addr}}") {
		t.Error("text still contains {{listen_addr}} placeholder")
	}
	if !strings.Contains(tc.Text, "*.example.com") {
		t.Errorf("text does not contain substituted target_host %q", "*.example.com")
	}
}

func TestPromptMetadata(t *testing.T) {
	cs := setupPromptTestSession(t)

	result, err := cs.ListPrompts(context.Background(), nil)
	if err != nil {
		t.Fatalf("ListPrompts: %v", err)
	}

	for _, p := range result.Prompts {
		t.Run(p.Name, func(t *testing.T) {
			if p.Name == "" {
				t.Error("name is empty")
			}
			// Names should be lowercase-kebab — no underscores, no
			// uppercase, no spaces.
			if strings.ContainsAny(p.Name, "_ ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
				t.Errorf("name %q is not lowercase-kebab", p.Name)
			}
			for _, a := range p.Arguments {
				if a.Name == "" {
					t.Error("argument name is empty")
				}
				if a.Description == "" {
					t.Errorf("argument %q has no description", a.Name)
				}
				// Argument names should be snake_case so {{arg_name}}
				// placeholders are unambiguous.
				if strings.ContainsAny(a.Name, "- ABCDEFGHIJKLMNOPQRSTUVWXYZ") {
					t.Errorf("argument name %q is not snake_case", a.Name)
				}
			}
		})
	}
}

func TestPromptDefinitions_NoDuplicates(t *testing.T) {
	names := make(map[string]bool)
	files := make(map[string]bool)
	for _, pd := range userPrompts {
		if names[pd.name] {
			t.Errorf("duplicate prompt name: %s", pd.name)
		}
		names[pd.name] = true
		if files[pd.filename] {
			t.Errorf("duplicate prompt filename: %s", pd.filename)
		}
		files[pd.filename] = true
	}
}

func TestPromptDefinitions_AllFilesExist(t *testing.T) {
	for _, pd := range userPrompts {
		t.Run(pd.name, func(t *testing.T) {
			data, err := promptsFS.ReadFile(pd.filename)
			if err != nil {
				t.Fatalf("cannot read embedded file %s: %v", pd.filename, err)
			}
			if len(data) == 0 {
				t.Errorf("embedded file %s is empty", pd.filename)
			}
			text := string(data)
			if !strings.HasPrefix(text, "# ") {
				t.Errorf("prompt body %s does not start with a markdown heading", pd.filename)
			}
		})
	}
}

func TestMakePromptHandler_Direct(t *testing.T) {
	// Unit test the handler factory directly to cover the no-arguments
	// path without going through the MCP transport.
	pd := promptDef{
		name:        "verify-idor",
		description: "test",
		filename:    "prompts/verify-idor.md",
		arguments: []*gomcp.PromptArgument{
			{Name: "target_flow_id", Required: true},
			{Name: "id_field", Required: true},
			{Name: "candidate_ids", Required: true},
		},
	}
	h := makePromptHandler(pd)

	// Required arguments missing → error.
	_, err := h(context.Background(), &gomcp.GetPromptRequest{
		Params: &gomcp.GetPromptParams{Name: pd.name},
	})
	if err == nil {
		t.Fatal("expected error when arguments are missing, got nil")
	}

	// Nil request must not panic (defensive).
	_, err = h(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error when request is nil, got nil")
	}
}

func TestMakePromptHandler_InvalidFilename(t *testing.T) {
	pd := promptDef{
		name:     "broken",
		filename: "prompts/nonexistent.md",
	}
	h := makePromptHandler(pd)
	_, err := h(context.Background(), &gomcp.GetPromptRequest{
		Params: &gomcp.GetPromptParams{Name: pd.name},
	})
	if err == nil {
		t.Fatal("expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "read embedded prompt") {
		t.Errorf("error = %q, want it to contain 'read embedded prompt'", err.Error())
	}
}

// promptPlaceholderRe matches an identifier-shaped {{name}} double-brace
// placeholder. The token shape is reused verbatim from
// internal/macro/detector.go:34 (reHandlebars). An identifier-anchored
// interior (no leading dot, no spaces) is required so that Go
// text/template's {{.Field}} form (which prompts.go:17-20 deliberately
// treats as *not* a placeholder) and spaced/illustrative {{ name }} prose
// are correctly ignored. It is a package-level compile-time var — never
// built from prompt content (Principle 5).
var promptPlaceholderRe = regexp.MustCompile(`\{\{([A-Za-z_][A-Za-z0-9_]{0,63})\}\}`)

// promptLiteralMarkers lists, per prompt, the {{ident}} tokens that appear
// in a playbook body on purpose but are NOT declared arguments — they are
// template-injection probe markers meant to reach the wire literally.
//
// Keyed per-prompt (not a flat global set) so a marker declared for one
// playbook cannot silence a genuine collision in another. Every entry MUST
// still be present in its playbook (asserted below), so a removed marker
// does not leave a dead exception behind.
var promptLiteralMarkers = map[string][]string{
	"verify-xss": {"YP_TEMPLATE"},
}

// TestPrompts_ArgumentCorpusConsistency asserts bidirectional consistency
// between each prompt's declared arguments (userPrompts) and the {{ident}}
// placeholders in its embedded playbook body:
//
//	(a) every {{ident}} token in a body is either a declared argument of
//	    that prompt or an allowlisted literal marker for that prompt; and
//	(b) every declared argument appears as {{name}} in that prompt's body,
//	    so the caller-supplied value is not silently dropped.
//
// It reads the RAW embedded body (never the expanded form) so that literal
// markers it exists to find are still present (Principle 3).
func TestPrompts_ArgumentCorpusConsistency(t *testing.T) {
	for _, pd := range userPrompts {
		pd := pd
		t.Run(pd.name, func(t *testing.T) {
			body, err := promptsFS.ReadFile(pd.filename)
			if err != nil {
				t.Fatalf("read embedded prompt %s: %v", pd.filename, err)
			}
			raw := string(body)

			declared := make(map[string]bool, len(pd.arguments))
			for _, a := range pd.arguments {
				declared[a.Name] = true
			}
			markers := make(map[string]bool)
			for _, m := range promptLiteralMarkers[pd.name] {
				markers[m] = true
			}

			// Direction (a): every {{ident}} token is declared or an
			// allowlisted literal marker.
			for _, m := range promptPlaceholderRe.FindAllStringSubmatch(raw, -1) {
				tok := m[1]
				if declared[tok] || markers[tok] {
					continue
				}
				t.Errorf("%s: {{%s}} is neither a declared argument of prompt %q "+
					"nor an allowlisted literal marker; declare it in userPrompts "+
					"or add it to promptLiteralMarkers[%q]", pd.filename, tok, pd.name, pd.name)
			}

			// Direction (b): every declared argument is actually interpolated.
			for _, a := range pd.arguments {
				if !strings.Contains(raw, "{{"+a.Name+"}}") {
					t.Errorf("%s: declared argument %q has no {{%s}} placeholder in the "+
						"body — the caller's value is silently dropped", pd.filename, a.Name, a.Name)
				}
			}
		})
	}
}

// TestPrompts_LiteralMarkerAllowlistNotStale ensures every allowlisted
// literal marker is still present in its playbook, so a removed marker does
// not leave a dead exception behind.
func TestPrompts_LiteralMarkerAllowlistNotStale(t *testing.T) {
	byName := make(map[string]promptDef, len(userPrompts))
	for _, pd := range userPrompts {
		byName[pd.name] = pd
	}
	for name, markers := range promptLiteralMarkers {
		pd, ok := byName[name]
		if !ok {
			t.Errorf("promptLiteralMarkers references unknown prompt %q", name)
			continue
		}
		body, err := promptsFS.ReadFile(pd.filename)
		if err != nil {
			t.Fatalf("read embedded prompt %s: %v", pd.filename, err)
		}
		raw := string(body)
		for _, m := range markers {
			if !strings.Contains(raw, "{{"+m+"}}") {
				t.Errorf("%s: allowlisted literal marker {{%s}} is no longer present; "+
					"remove the stale entry from promptLiteralMarkers[%q]", pd.filename, m, name)
			}
		}
	}
}

// TestGetPrompt_VerifyXSSMarkersRetainedLiterally pins the intended
// behaviour that verify-xss's template-injection markers survive
// prompts/get expansion unchanged: {{YP_TEMPLATE}} is not a declared
// argument (so ReplaceAll never touches it) and the section-sign marker is
// a macro KV-store token that this handler never expands.
func TestGetPrompt_VerifyXSSMarkersRetainedLiterally(t *testing.T) {
	var pd promptDef
	for _, p := range userPrompts {
		if p.name == "verify-xss" {
			pd = p
			break
		}
	}
	if pd.name == "" {
		t.Fatal("verify-xss prompt not found in userPrompts")
	}

	h := makePromptHandler(pd)
	res, err := h(context.Background(), &gomcp.GetPromptRequest{
		Params: &gomcp.GetPromptParams{
			Name: pd.name,
			Arguments: map[string]string{
				"target_flow_id":  "flow-123",
				"injection_point": "raw_query",
			},
		},
	})
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	tc, ok := res.Messages[0].Content.(*gomcp.TextContent)
	if !ok {
		t.Fatalf("content type = %T, want *gomcp.TextContent", res.Messages[0].Content)
	}
	for _, want := range []string{"{{YP_TEMPLATE}}", "§YP_TEMPLATE§"} {
		if !strings.Contains(tc.Text, want) {
			t.Errorf("expanded body missing literal marker %q", want)
		}
	}
	// The declared arguments themselves must have been substituted away.
	for _, gone := range []string{"{{target_flow_id}}", "{{injection_point}}"} {
		if strings.Contains(tc.Text, gone) {
			t.Errorf("declared-argument placeholder %q survived expansion", gone)
		}
	}
}

// TestGetPrompt_NoDeclaredPlaceholderLeftAfterExpansion asserts that, for
// every prompt, once all declared arguments are given non-empty values, no
// {{arg}} token for any *declared* argument remains in the expanded body.
// This is corpus-wide (Decision #4) and complements
// TestGetPrompt_ArgumentSubstitution / TestGetPrompt_OptionalArgumentDefault,
// which additionally assert the substituted value appears.
func TestGetPrompt_NoDeclaredPlaceholderLeftAfterExpansion(t *testing.T) {
	for _, pd := range userPrompts {
		pd := pd
		t.Run(pd.name, func(t *testing.T) {
			args := make(map[string]string, len(pd.arguments))
			for _, a := range pd.arguments {
				// A value with no braces so it cannot reintroduce a token.
				args[a.Name] = "val-" + a.Name
			}
			h := makePromptHandler(pd)
			res, err := h(context.Background(), &gomcp.GetPromptRequest{
				Params: &gomcp.GetPromptParams{Name: pd.name, Arguments: args},
			})
			if err != nil {
				t.Fatalf("handler: %v", err)
			}
			tc, ok := res.Messages[0].Content.(*gomcp.TextContent)
			if !ok {
				t.Fatalf("content type = %T, want *gomcp.TextContent", res.Messages[0].Content)
			}
			for _, a := range pd.arguments {
				if strings.Contains(tc.Text, "{{"+a.Name+"}}") {
					t.Errorf("%s: {{%s}} still present after expansion with all args set", pd.filename, a.Name)
				}
			}
		})
	}
}

// TestPromptPlaceholderRe_TokenShape proves the placeholder regex matches
// snake_case identifiers while ignoring Go text/template's {{.Field}} form
// and spaced/illustrative interiors.
func TestPromptPlaceholderRe_TokenShape(t *testing.T) {
	tests := []struct {
		name  string
		in    string
		match bool
	}{
		{"snake_case", "{{snake_case}}", true},
		{"single_lower", "{{a}}", true},
		{"leading_underscore", "{{_x}}", true},
		{"go_template_field", "{{.Field}}", false},
		{"spaced_interior", "{{ spaced }}", false},
		{"leading_space", "{{ name}}", false},
		{"dotted_interior", "{{foo.bar}}", false},
		{"empty", "{{}}", false},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := promptPlaceholderRe.MatchString(tc.in)
			if got != tc.match {
				t.Errorf("MatchString(%q) = %v, want %v", tc.in, got, tc.match)
			}
		})
	}
}
