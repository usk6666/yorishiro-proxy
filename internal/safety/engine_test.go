package safety

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// kvGet returns the value of the first header matching name (case-insensitive).
func kvGet(kvs []envelope.KeyValue, name string) string {
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value
		}
	}
	return ""
}

func TestNewEngine_EmptyConfig(t *testing.T) {
	e, err := NewEngine(Config{})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if len(e.InputRules()) != 0 {
		t.Errorf("expected 0 input rules, got %d", len(e.InputRules()))
	}
	if len(e.OutputRules()) != 0 {
		t.Errorf("expected 0 output rules, got %d", len(e.OutputRules()))
	}
}

func TestNewEngine_CustomRule(t *testing.T) {
	cfg := Config{
		InputRules: []RuleConfig{
			{
				ID:      "test-1",
				Name:    "Test Rule",
				Pattern: `(?i)\bDROP\b`,
				Targets: []string{"body", "query"},
				Action:  "block",
			},
		},
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if len(e.InputRules()) != 1 {
		t.Fatalf("expected 1 input rule, got %d", len(e.InputRules()))
	}
	r := e.InputRules()[0]
	if r.ID != "test-1" {
		t.Errorf("rule ID = %q, want %q", r.ID, "test-1")
	}
	if r.Category != "custom" {
		t.Errorf("rule Category = %q, want %q", r.Category, "custom")
	}
	if len(r.Targets) != 2 {
		t.Errorf("rule Targets = %d, want 2", len(r.Targets))
	}
}

func TestNewEngine_PresetExpansion(t *testing.T) {
	cfg := Config{
		InputRules: []RuleConfig{
			{Preset: "destructive-sql"},
		},
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if len(e.InputRules()) != len(destructiveSQLRules) {
		t.Fatalf("expected %d input rules from preset, got %d", len(destructiveSQLRules), len(e.InputRules()))
	}
	for _, r := range e.InputRules() {
		if r.Category != "destructive-sql" {
			t.Errorf("rule %q category = %q, want %q", r.ID, r.Category, "destructive-sql")
		}
	}
}

func TestNewEngine_PresetReplacementOverride(t *testing.T) {
	cfg := Config{
		OutputRules: []RuleConfig{
			{
				Preset:      "destructive-sql",
				Action:      "mask",
				Replacement: "[CUSTOM]",
			},
		},
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if len(e.OutputRules()) != len(destructiveSQLRules) {
		t.Fatalf("expected %d output rules, got %d", len(destructiveSQLRules), len(e.OutputRules()))
	}
	for _, r := range e.OutputRules() {
		if r.Replacement != "[CUSTOM]" {
			t.Errorf("rule %q replacement = %q, want %q", r.ID, r.Replacement, "[CUSTOM]")
		}
		if r.Action != ActionMask {
			t.Errorf("rule %q action = %v, want ActionMask", r.ID, r.Action)
		}
	}
}

func TestNewEngine_Errors(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
	}{
		{
			name: "invalid pattern",
			cfg: Config{
				InputRules: []RuleConfig{
					{ID: "bad", Pattern: `(?P<`, Targets: []string{"body"}, Action: "block"},
				},
			},
		},
		{
			name: "unknown preset",
			cfg: Config{
				InputRules: []RuleConfig{
					{Preset: "nonexistent"},
				},
			},
		},
		{
			name: "invalid action",
			cfg: Config{
				InputRules: []RuleConfig{
					{ID: "r1", Pattern: `test`, Targets: []string{"body"}, Action: "nuke"},
				},
			},
		},
		{
			name: "invalid target",
			cfg: Config{
				InputRules: []RuleConfig{
					{ID: "r1", Pattern: `test`, Targets: []string{"foobar"}, Action: "block"},
				},
			},
		},
		{
			name: "pattern and preset mutually exclusive",
			cfg: Config{
				InputRules: []RuleConfig{
					{ID: "r1", Pattern: `test`, Preset: "destructive-sql", Targets: []string{"body"}, Action: "block"},
				},
			},
		},
		{
			name: "duplicate rule ID",
			cfg: Config{
				InputRules: []RuleConfig{
					{ID: "dup", Pattern: `a`, Targets: []string{"body"}, Action: "block"},
					{ID: "dup", Pattern: `b`, Targets: []string{"body"}, Action: "block"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine(tt.cfg)
			if err == nil {
				t.Error("NewEngine() expected error, got nil")
			}
		})
	}
}

func TestCheckInput_BodyMatch(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})

	tests := []struct {
		name    string
		body    []byte
		wantNil bool
	}{
		{"matches DROP TABLE", []byte("SELECT 1; DROP TABLE users"), false},
		{"case insensitive", []byte("drop table foo"), false},
		{"no match", []byte("SELECT * FROM users"), true},
		{"empty body", nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := e.CheckInput(tt.body, "", nil)
			if tt.wantNil && v != nil {
				t.Errorf("CheckInput() = %+v, want nil", v)
			}
			if !tt.wantNil && v == nil {
				t.Error("CheckInput() = nil, want violation")
			}
			if !tt.wantNil && v != nil {
				if v.RuleID != "drop" {
					t.Errorf("violation RuleID = %q, want %q", v.RuleID, "drop")
				}
				if v.Target != TargetBody {
					t.Errorf("violation Target = %v, want %v", v.Target, TargetBody)
				}
			}
		})
	}
}

func TestCheckInput_URLMatch(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "admin", Pattern: `/admin`, Targets: []string{"url"}, Action: "block"},
		},
	})

	v := e.CheckInput(nil, "http://example.com/admin/delete", nil)
	if v == nil {
		t.Fatal("expected violation for /admin URL")
	}
	if v.MatchedOn != "/admin" {
		t.Errorf("MatchedOn = %q, want %q", v.MatchedOn, "/admin")
	}
}

func TestCheckInput_QueryMatch(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "sqli", Pattern: `(?i)UNION\s+SELECT`, Targets: []string{"query"}, Action: "block"},
		},
	})

	tests := []struct {
		name    string
		rawURL  string
		wantNil bool
	}{
		{"match in query", "http://example.com/search?q=1 UNION SELECT 1", false},
		{"no query string", "http://example.com/search", true},
		{"no match in query", "http://example.com/search?q=hello", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := e.CheckInput(nil, tt.rawURL, nil)
			if tt.wantNil && v != nil {
				t.Errorf("CheckInput() = %+v, want nil", v)
			}
			if !tt.wantNil && v == nil {
				t.Error("CheckInput() = nil, want violation")
			}
		})
	}
}

func TestCheckInput_HeaderMatch(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "evil-header", Pattern: `evil`, Targets: []string{"header"}, Action: "block"},
		},
	})

	h := []envelope.KeyValue{{Name: "X-Custom", Value: "this is evil"}}
	v := e.CheckInput(nil, "", h)
	if v == nil {
		t.Fatal("expected violation for header match")
	}
	if v.MatchedOn != "evil" {
		t.Errorf("MatchedOn = %q, want %q", v.MatchedOn, "evil")
	}
}

func TestCheckInput_HeadersMatch(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "headers-check", Pattern: `X-Secret: token123`, Targets: []string{"headers"}, Action: "block"},
		},
	})

	h := []envelope.KeyValue{{Name: "X-Secret", Value: "token123"}}
	v := e.CheckInput(nil, "", h)
	if v == nil {
		t.Fatal("expected violation for headers match")
	}
}

func TestCheckInput_NoRules(t *testing.T) {
	e := mustEngine(t, Config{})
	v := e.CheckInput([]byte("DROP TABLE users"), "http://evil.com", nil)
	if v != nil {
		t.Errorf("expected nil with no rules, got %+v", v)
	}
}

func TestCheckInput_FirstRuleWins(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "first", Pattern: `DROP`, Targets: []string{"body"}, Action: "block"},
			{ID: "second", Pattern: `DROP`, Targets: []string{"body"}, Action: "log_only"},
		},
	})

	v := e.CheckInput([]byte("DROP TABLE"), "", nil)
	if v == nil {
		t.Fatal("expected violation")
	}
	if v.RuleID != "first" {
		t.Errorf("RuleID = %q, want %q", v.RuleID, "first")
	}
}

func TestFilterOutput_Mask(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-secret",
				Pattern:     `secret-\w+`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[REDACTED]",
			},
		},
	})

	result := e.FilterOutput([]byte("token=secret-abc123 key=secret-xyz789"))
	if !result.Masked {
		t.Error("expected Masked to be true")
	}
	want := "token=[REDACTED] key=[REDACTED]"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match entry, got %d", len(result.Matches))
	}
	if result.Matches[0].Count != 2 {
		t.Errorf("match count = %d, want 2", result.Matches[0].Count)
	}
}

func TestFilterOutput_LogOnly(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:      "log-secret",
				Pattern: `secret`,
				Targets: []string{"body"},
				Action:  "log_only",
			},
		},
	})

	data := []byte("this is a secret")
	result := e.FilterOutput(data)
	if result.Masked {
		t.Error("expected Masked to be false for log_only")
	}
	if string(result.Data) != string(data) {
		t.Errorf("Data should be unchanged, got %q", string(result.Data))
	}
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(result.Matches))
	}
}

func TestFilterOutput_NoMatch(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-x",
				Pattern:     `XXXX`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "Y",
			},
		},
	})

	result := e.FilterOutput([]byte("nothing here"))
	if result.Masked {
		t.Error("expected Masked to be false")
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result.Matches))
	}
}

func TestFilterOutput_NonBodyTargetIgnored(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "url-only",
				Pattern:     `secret`,
				Targets:     []string{"url"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})

	result := e.FilterOutput([]byte("secret data"))
	if result.Masked {
		t.Error("url-target rule should not apply to body output")
	}
}

func TestFilterOutputHeaders_Mask(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-token",
				Pattern:     `Bearer \w+`,
				Targets:     []string{"headers"},
				Action:      "mask",
				Replacement: "Bearer [REDACTED]",
			},
		},
	})

	h := []envelope.KeyValue{{Name: "Authorization", Value: "Bearer abc123"}}
	result, matches := e.FilterOutputHeaders(h)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if kvGet(result, "Authorization") != "Bearer [REDACTED]" {
		t.Errorf("Authorization = %q, want %q", kvGet(result, "Authorization"), "Bearer [REDACTED]")
	}
}

func TestFilterOutputHeaders_NoModifyOriginal(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-h",
				Pattern:     `secret`,
				Targets:     []string{"headers"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})

	h := []envelope.KeyValue{{Name: "X-Data", Value: "secret"}}
	_, _ = e.FilterOutputHeaders(h)
	// Original should be unchanged.
	if kvGet(h, "X-Data") != "secret" {
		t.Errorf("original header modified: got %q", kvGet(h, "X-Data"))
	}
}

func TestFilterOutput_CaptureGroupReplacement(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "partial-mask",
				Pattern:     `(user=)\w+`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "${1}[REDACTED]",
			},
		},
	})

	result := e.FilterOutput([]byte("data: user=admin"))
	want := "data: user=[REDACTED]"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
}

func TestCheckInput_WithPreset(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{Preset: "destructive-sql"},
		},
	})

	tests := []struct {
		name    string
		body    string
		wantNil bool
	}{
		{"DROP TABLE matches", "DROP TABLE users", false},
		{"drop database matches", "drop database mydb", false},
		{"TRUNCATE TABLE matches", "TRUNCATE TABLE logs", false},
		{"DELETE without WHERE matches", "DELETE FROM users", false},
		{"ALTER TABLE DROP matches", "ALTER TABLE users DROP COLUMN email", false},
		{"EXEC xp_ matches", "EXEC xp_cmdshell 'whoami'", false},
		{"SELECT is allowed", "SELECT * FROM users", true},
		{"INSERT is allowed", "INSERT INTO users VALUES (1)", true},
		{"DELETE with WHERE is allowed", "DELETE FROM users WHERE id=1", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := e.CheckInput([]byte(tt.body), "", nil)
			if tt.wantNil && v != nil {
				t.Errorf("CheckInput() = %+v, want nil", v)
			}
			if !tt.wantNil && v == nil {
				t.Error("CheckInput() = nil, want violation")
			}
		})
	}
}

func TestNewEngine_CustomRuleDefaultsNameToID(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "my-rule", Pattern: `test`, Targets: []string{"body"}, Action: "block"},
		},
	})
	r := e.InputRules()[0]
	if r.Name != "my-rule" {
		t.Errorf("Name = %q, want %q", r.Name, "my-rule")
	}
}

func TestNewEngine_HeaderColonTarget(t *testing.T) {
	cfg := Config{
		InputRules: []RuleConfig{
			{ID: "loc", Pattern: `evil`, Targets: []string{"header:Location"}, Action: "block"},
		},
	}
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	if len(e.InputRules()) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(e.InputRules()))
	}
	r := e.InputRules()[0]
	if r.Targets[0] != TargetHeader {
		t.Errorf("target = %v, want TargetHeader", r.Targets[0])
	}
	if r.HeaderName != "Location" {
		t.Errorf("HeaderName = %q, want %q", r.HeaderName, "Location")
	}
}

func TestCheckInput_HeaderColonTarget_SpecificHeader(t *testing.T) {
	e := mustEngine(t, Config{
		InputRules: []RuleConfig{
			{ID: "loc-evil", Pattern: `evil`, Targets: []string{"header:Location"}, Action: "block"},
		},
	})

	// Should match when the specific header contains the pattern.
	h := []envelope.KeyValue{{Name: "Location", Value: "http://evil.com"}}
	v := e.CheckInput(nil, "", h)
	if v == nil {
		t.Fatal("expected violation for Location header match")
	}
	if v.MatchedOn != "evil" {
		t.Errorf("MatchedOn = %q, want %q", v.MatchedOn, "evil")
	}

	// Should NOT match when a different header contains the pattern.
	h2 := []envelope.KeyValue{{Name: "X-Other", Value: "evil-value"}}
	v2 := e.CheckInput(nil, "", h2)
	if v2 != nil {
		t.Errorf("expected nil for non-Location header, got %+v", v2)
	}
}

func TestFilterOutputHeaders_SpecificHeader(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-loc",
				Pattern:     `evil`,
				Targets:     []string{"header:Location"},
				Action:      "mask",
				Replacement: "[SAFE]",
			},
		},
	})

	h := []envelope.KeyValue{
		{Name: "Location", Value: "http://evil.com"},
		{Name: "X-Other", Value: "also evil"},
	}
	result, matches := e.FilterOutputHeaders(h)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	// Location should be masked.
	if kvGet(result, "Location") != "http://[SAFE].com" {
		t.Errorf("Location = %q, want %q", kvGet(result, "Location"), "http://[SAFE].com")
	}
	// X-Other should NOT be masked (rule targets only Location).
	if kvGet(result, "X-Other") != "also evil" {
		t.Errorf("X-Other = %q, want %q", kvGet(result, "X-Other"), "also evil")
	}
}

func TestOutputMatch_ActionField(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{ID: "block-secret", Pattern: `secret`, Targets: []string{"body"}, Action: "block"},
			{ID: "mask-token", Pattern: `token-\w+`, Targets: []string{"body"}, Action: "mask", Replacement: "[REDACTED]"},
			{ID: "log-info", Pattern: `info`, Targets: []string{"body"}, Action: "log_only"},
		},
	})

	result := e.FilterOutput([]byte("secret token-abc info"))
	if len(result.Matches) != 3 {
		t.Fatalf("expected 3 matches, got %d", len(result.Matches))
	}
	wantActions := map[string]Action{
		"block-secret": ActionBlock,
		"mask-token":   ActionMask,
		"log-info":     ActionLogOnly,
	}
	for _, m := range result.Matches {
		want, ok := wantActions[m.RuleID]
		if !ok {
			t.Errorf("unexpected match RuleID = %q", m.RuleID)
			continue
		}
		if m.Action != want {
			t.Errorf("match %q Action = %v, want %v", m.RuleID, m.Action, want)
		}
	}
}

// mustEngine is a test helper that creates an Engine or fails the test.
func mustEngine(t *testing.T, cfg Config) *Engine {
	t.Helper()
	e, err := NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return e
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		input   string
		want    Target
		wantErr bool
	}{
		{"body", TargetBody, false},
		{"BODY", TargetBody, false},
		{"url", TargetURL, false},
		{"query", TargetQuery, false},
		{"header", TargetHeader, false},
		{"headers", TargetHeaders, false},
		{"unknown", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseTarget(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseTarget(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseTarget(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestParseAction(t *testing.T) {
	tests := []struct {
		input   string
		want    Action
		wantErr bool
	}{
		{"block", ActionBlock, false},
		{"BLOCK", ActionBlock, false},
		{"mask", ActionMask, false},
		{"log_only", ActionLogOnly, false},
		{"nuke", 0, true},
		{"", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got, err := ParseAction(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseAction(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseAction(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestTargetString(t *testing.T) {
	if s := TargetBody.String(); s != "body" {
		t.Errorf("TargetBody.String() = %q, want %q", s, "body")
	}
	if s := Target(99).String(); s != "Target(99)" {
		t.Errorf("Target(99).String() = %q, want %q", s, "Target(99)")
	}
}

func TestActionString(t *testing.T) {
	if s := ActionBlock.String(); s != "block" {
		t.Errorf("ActionBlock.String() = %q, want %q", s, "block")
	}
	if s := Action(99).String(); s != "Action(99)" {
		t.Errorf("Action(99).String() = %q, want %q", s, "Action(99)")
	}
}

func TestPresetNames_Engine(t *testing.T) {
	names := PresetNames()
	if len(names) < 6 {
		t.Errorf("expected at least 6 presets, got %d", len(names))
	}
	found := make(map[string]bool)
	for _, n := range names {
		found[n] = true
	}
	required := []string{
		PresetDestructiveSQL,
		PresetDestructiveOSCommand,
		PresetCreditCard,
		PresetJapanMyNumber,
		PresetEmail,
		PresetJapanPhone,
	}
	for _, name := range required {
		if !found[name] {
			t.Errorf("missing preset: %s", name)
		}
	}
}

func TestLookupPreset_NotFound_Engine(t *testing.T) {
	_, err := LookupPreset("nonexistent")
	if err == nil {
		t.Error("LookupPreset(nonexistent) expected error, got nil")
	}
}

func TestFilterOutput_ValidatorAccepts(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "validated",
				Pattern:     `\b\d{4}\b`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[MASKED]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Add validator: only mask even numbers.
	e.outputRules[0].Validator = func(match []byte) bool {
		last := match[len(match)-1]
		return (last-'0')%2 == 0
	}

	result := e.FilterOutput([]byte("pin 1234 code 1357 id 2468"))
	want := "pin [MASKED] code 1357 id [MASKED]"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
	if !result.Masked {
		t.Error("expected Masked to be true")
	}
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match entry, got %d", len(result.Matches))
	}
	if result.Matches[0].Count != 2 {
		t.Errorf("match count = %d, want 2", result.Matches[0].Count)
	}
}

func TestFilterOutput_ValidatorRejectsAll(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "reject-all",
				Pattern:     `\d+`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	e.outputRules[0].Validator = func(match []byte) bool {
		return false // reject all matches
	}

	data := []byte("abc 123 def 456")
	result := e.FilterOutput(data)
	if result.Masked {
		t.Error("expected Masked to be false when validator rejects all")
	}
	if string(result.Data) != string(data) {
		t.Errorf("Data = %q, want unchanged %q", string(result.Data), string(data))
	}
	if len(result.Matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(result.Matches))
	}
}

func TestFilterOutput_ValidatorWithCaptureGroups(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "capture-validated",
				Pattern:     `(\d{4})-(\d{4})`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "****-$2",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Only mask if the first group starts with "12".
	e.outputRules[0].Validator = func(match []byte) bool {
		return len(match) >= 2 && match[0] == '1' && match[1] == '2'
	}

	result := e.FilterOutput([]byte("card 1234-5678 alt 9876-5432"))
	want := "card ****-5678 alt 9876-5432"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
}

func TestFilterOutput_ValidatorLogOnly(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:      "log-validated",
				Pattern: `\b\d{3}\b`,
				Targets: []string{"body"},
				Action:  "log_only",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Only count numbers starting with "1".
	e.outputRules[0].Validator = func(match []byte) bool {
		return match[0] == '1'
	}

	data := []byte("values: 123 456 178")
	result := e.FilterOutput(data)
	if result.Masked {
		t.Error("expected Masked to be false for log_only")
	}
	if string(result.Data) != string(data) {
		t.Errorf("data should be unchanged")
	}
	if len(result.Matches) != 1 {
		t.Fatalf("expected 1 match entry, got %d", len(result.Matches))
	}
	if result.Matches[0].Count != 2 {
		t.Errorf("count = %d, want 2", result.Matches[0].Count)
	}
}

func TestFilterOutputHeaders_ValidatorAccepts(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "hdr-validated",
				Pattern:     `\d{4}`,
				Targets:     []string{"headers"},
				Action:      "mask",
				Replacement: "****",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Only mask numbers starting with "1".
	e.outputRules[0].Validator = func(match []byte) bool {
		return match[0] == '1'
	}

	h := []envelope.KeyValue{{Name: "X-Data", Value: "id=1234 code=5678"}}
	result, matches := e.FilterOutputHeaders(h)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Count != 1 {
		t.Errorf("count = %d, want 1", matches[0].Count)
	}
	got := kvGet(result, "X-Data")
	want := "id=**** code=5678"
	if got != want {
		t.Errorf("X-Data = %q, want %q", got, want)
	}
}

func TestFilterOutputHeaders_ValidatorRejectsAll(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "hdr-reject",
				Pattern:     `\d+`,
				Targets:     []string{"headers"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	e.outputRules[0].Validator = func(match []byte) bool {
		return false
	}

	h := []envelope.KeyValue{{Name: "X-Val", Value: "abc 123"}}
	result, matches := e.FilterOutputHeaders(h)
	if len(matches) != 0 {
		t.Errorf("expected 0 matches, got %d", len(matches))
	}
	if kvGet(result, "X-Val") != "abc 123" {
		t.Errorf("header should be unchanged, got %q", kvGet(result, "X-Val"))
	}
}

func TestFilterOutputHeaders_ValidatorSpecificHeader(t *testing.T) {
	e, err := NewEngine(Config{
		OutputRules: []RuleConfig{
			{
				ID:          "hdr-specific-validated",
				Pattern:     `secret\d+`,
				Targets:     []string{"header:X-Token"},
				Action:      "mask",
				Replacement: "[REDACTED]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	// Only mask if the digit part is "1".
	e.outputRules[0].Validator = func(match []byte) bool {
		return len(match) > 6 && match[6] == '1'
	}

	h := []envelope.KeyValue{
		{Name: "X-Token", Value: "secret1 secret2"},
		{Name: "X-Other", Value: "secret1"},
	}
	result, matches := e.FilterOutputHeaders(h)
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}
	if matches[0].Count != 1 {
		t.Errorf("count = %d, want 1", matches[0].Count)
	}
	if kvGet(result, "X-Token") != "[REDACTED] secret2" {
		t.Errorf("X-Token = %q, want %q", kvGet(result, "X-Token"), "[REDACTED] secret2")
	}
	// X-Other should be untouched (rule targets only X-Token).
	if kvGet(result, "X-Other") != "secret1" {
		t.Errorf("X-Other = %q, want %q", kvGet(result, "X-Other"), "secret1")
	}
}

func TestFilterOutput_MultipleRulesSequential(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-email",
				Pattern:     `(\w+)@(\w+\.\w+)`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "$1@[MASKED]",
			},
			{
				ID:          "mask-ssn",
				Pattern:     `\d{3}-\d{2}-\d{4}`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[SSN-REDACTED]",
			},
		},
	})

	result := e.FilterOutput([]byte("email: user@example.com ssn: 123-45-6789"))
	want := "email: user@[MASKED] ssn: [SSN-REDACTED]"
	if string(result.Data) != want {
		t.Errorf("Data = %q, want %q", string(result.Data), want)
	}
	if !result.Masked {
		t.Error("expected Masked to be true")
	}
	if len(result.Matches) != 2 {
		t.Fatalf("expected 2 match entries, got %d", len(result.Matches))
	}
}

func TestFilterOutput_BinaryDataSafe(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-bin",
				Pattern:     `secret`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})

	// Data with null bytes and non-UTF8 sequences.
	data := []byte{0x00, 0xFF, 's', 'e', 'c', 'r', 'e', 't', 0x00, 0xFE}
	result := e.FilterOutput(data)
	if !result.Masked {
		t.Error("expected Masked to be true")
	}
	want := []byte{0x00, 0xFF, '[', 'X', ']', 0x00, 0xFE}
	if string(result.Data) != string(want) {
		t.Errorf("Data = %v, want %v", result.Data, want)
	}
}

func TestFilterOutput_EmptyData(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-any",
				Pattern:     `\w+`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})

	result := e.FilterOutput([]byte{})
	if result.Masked {
		t.Error("expected Masked to be false for empty data")
	}
	if len(result.Data) != 0 {
		t.Errorf("expected empty data, got %q", string(result.Data))
	}
}

func TestFilterOutput_NilData(t *testing.T) {
	e := mustEngine(t, Config{
		OutputRules: []RuleConfig{
			{
				ID:          "mask-nil",
				Pattern:     `test`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[X]",
			},
		},
	})

	result := e.FilterOutput(nil)
	if result.Masked {
		t.Error("expected Masked to be false for nil data")
	}
	if result.Data != nil {
		t.Errorf("expected nil data, got %v", result.Data)
	}
}
