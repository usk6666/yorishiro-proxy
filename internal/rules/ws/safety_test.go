package ws

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

func TestSafetyEngine_NewSafetyEngine_EmptyRules(t *testing.T) {
	e := NewSafetyEngine()
	if e.RuleCount() != 0 {
		t.Errorf("expected 0 rules, got %d", e.RuleCount())
	}
}

// TestSafetyEngine_NoAutoLoadHTTPPresets verifies that simply constructing
// a WS SafetyEngine does not pull in HTTP presets (destructive-sql, etc.).
// Operators must explicitly add WS-targeted rules.
func TestSafetyEngine_NoAutoLoadHTTPPresets(t *testing.T) {
	e := NewSafetyEngine()
	if e.RuleCount() != 0 {
		t.Fatalf("WS SafetyEngine auto-loaded %d rules; expected 0", e.RuleCount())
	}

	// Even a payload that would trip every HTTP destructive-SQL preset
	// must produce no violation when no rules are registered.
	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("DROP TABLE users")}
	if v := e.CheckInput(context.Background(), msg); v != nil {
		t.Errorf("unexpected violation with no rules loaded: %+v", v)
	}
}

func TestSafetyEngine_TargetPayload_CustomRule(t *testing.T) {
	e := NewSafetyEngine()
	pat, err := common.CompilePattern(`(?i)password=`)
	if err != nil {
		t.Fatal(err)
	}
	e.AddRule(common.CompiledRule{
		ID:       "ws:password-leak",
		Name:     "password in payload",
		Pattern:  pat,
		Targets:  []common.Target{TargetPayload},
		Category: "custom",
	})

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`{"login":"admin","password=hunter2"}`),
	}
	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation")
	}
	if v.RuleID != "ws:password-leak" {
		t.Errorf("RuleID = %q", v.RuleID)
	}
	if v.Target != string(TargetPayload) {
		t.Errorf("Target = %q, want %q", v.Target, TargetPayload)
	}
}

func TestSafetyEngine_TargetPayload_NoMatch(t *testing.T) {
	e := NewSafetyEngine()
	pat, _ := common.CompilePattern(`evil`)
	e.AddRule(common.CompiledRule{
		ID:      "ws:evil",
		Pattern: pat,
		Targets: []common.Target{TargetPayload},
	})

	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte(`hello world`)}
	if v := e.CheckInput(context.Background(), msg); v != nil {
		t.Errorf("unexpected violation: %+v", v)
	}
}

func TestSafetyEngine_TargetOpcode_RegexMatch(t *testing.T) {
	e := NewSafetyEngine()
	// Match any control frame (Close=0x8, Ping=0x9, Pong=0xA).
	pat, _ := common.CompilePattern(`^0x[89A]$`)
	e.AddRule(common.CompiledRule{
		ID:      "ws:control-frame",
		Name:    "control frame observed",
		Pattern: pat,
		Targets: []common.Target{TargetOpcode},
	})

	cases := []struct {
		op   envelope.WSOpcode
		want bool
	}{
		{envelope.WSText, false},
		{envelope.WSBinary, false},
		{envelope.WSContinuation, false},
		{envelope.WSClose, true},
		{envelope.WSPing, true},
		{envelope.WSPong, true},
	}
	for _, c := range cases {
		msg := &envelope.WSMessage{Opcode: c.op}
		v := e.CheckInput(context.Background(), msg)
		if c.want && v == nil {
			t.Errorf("opcode 0x%X: expected violation", uint8(c.op))
		}
		if !c.want && v != nil {
			t.Errorf("opcode 0x%X: unexpected violation %+v", uint8(c.op), v)
		}
	}
}

// TestSafetyEngine_MultiTarget_SingleRule verifies a single rule with both
// TargetPayload and TargetOpcode evaluates each in order until a match.
func TestSafetyEngine_MultiTarget_SingleRule(t *testing.T) {
	e := NewSafetyEngine()
	pat, _ := common.CompilePattern(`^0x8$|secret`)
	e.AddRule(common.CompiledRule{
		ID:      "ws:multi",
		Pattern: pat,
		// Order matters: payload first, then opcode.
		Targets: []common.Target{TargetPayload, TargetOpcode},
	})

	// Payload match wins (text frame with "secret").
	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte(`my secret data`)}
	v := e.CheckInput(context.Background(), msg)
	if v == nil || v.Target != string(TargetPayload) {
		t.Errorf("expected payload-target violation, got %+v", v)
	}

	// Payload no-match → falls through to opcode target.
	msg2 := &envelope.WSMessage{Opcode: envelope.WSClose, Payload: []byte("ok")}
	v2 := e.CheckInput(context.Background(), msg2)
	if v2 == nil || v2.Target != string(TargetOpcode) {
		t.Errorf("expected opcode-target violation, got %+v", v2)
	}
}

func TestSafetyEngine_CheckInputAll(t *testing.T) {
	e := NewSafetyEngine()
	pat1, _ := common.CompilePattern(`secret`)
	pat2, _ := common.CompilePattern(`password`)
	e.AddRule(common.CompiledRule{
		ID: "r1", Pattern: pat1, Targets: []common.Target{TargetPayload},
	})
	e.AddRule(common.CompiledRule{
		ID: "r2", Pattern: pat2, Targets: []common.Target{TargetPayload},
	})

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`secret + password`),
	}
	violations := e.CheckInputAll(context.Background(), msg)
	if len(violations) != 2 {
		t.Errorf("expected 2 violations, got %d", len(violations))
	}
}

func TestSafetyEngine_SetRules(t *testing.T) {
	e := NewSafetyEngine()
	pat, _ := common.CompilePattern(`evil`)
	e.AddRule(common.CompiledRule{ID: "r1", Pattern: pat, Targets: []common.Target{TargetPayload}})
	if e.RuleCount() != 1 {
		t.Fatal("expected 1 rule after AddRule")
	}
	e.SetRules(nil)
	if e.RuleCount() != 0 {
		t.Errorf("SetRules(nil) did not clear rules: %d", e.RuleCount())
	}
}

func TestSafetyEngine_NilMessage(t *testing.T) {
	e := NewSafetyEngine()
	pat, _ := common.CompilePattern(`x`)
	e.AddRule(common.CompiledRule{ID: "r1", Pattern: pat, Targets: []common.Target{TargetPayload}})

	if v := e.CheckInput(context.Background(), nil); v != nil {
		t.Errorf("expected nil violation for nil msg, got %+v", v)
	}
	if violations := e.CheckInputAll(context.Background(), nil); len(violations) != 0 {
		t.Errorf("expected no violations for nil msg, got %d", len(violations))
	}
}

func TestSafetyEngine_UnknownTarget_Skipped(t *testing.T) {
	e := NewSafetyEngine()
	pat, _ := common.CompilePattern(`.+`)
	// Rule with only an unknown target — engine must silently skip.
	e.AddRule(common.CompiledRule{
		ID:      "r1",
		Pattern: pat,
		Targets: []common.Target{common.Target("unknown-target")},
	})
	msg := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hello")}
	if v := e.CheckInput(context.Background(), msg); v != nil {
		t.Errorf("unknown target should be skipped, got %+v", v)
	}
}
