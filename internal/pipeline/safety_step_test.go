package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

func mustSafetyEngine(t *testing.T, cfg safety.Config) *safety.Engine {
	t.Helper()
	e, err := safety.NewEngine(cfg)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	return e
}

func TestSafetyStep_Send_BodyBlock(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("DROP TABLE users"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop", r.Action)
	}
}

func TestSafetyStep_Send_BodyClean(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("SELECT * FROM users"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue", r.Action)
	}
}

func TestSafetyStep_Send_URLBlock(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-admin", Pattern: `admin/delete`, Targets: []string{"url"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	u, _ := url.Parse("http://example.com/admin/delete")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       u,
		Body:      []byte("safe body"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop", r.Action)
	}
}

func TestSafetyStep_Send_HeaderBlock(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-evil", Pattern: `evil`, Targets: []string{"header"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Headers:   []exchange.KeyValue{{Name: "X-Custom", Value: "this is evil"}},
		Body:      []byte("safe body"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop", r.Action)
	}
}

func TestSafetyStep_Receive_Passthrough(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Body:      []byte("DROP TABLE users"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue for Receive direction", r.Action)
	}
}

func TestSafetyStep_BodyNil_Passthrough(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-admin", Pattern: `admin/delete`, Targets: []string{"url"}, Action: "block"},
			{ID: "block-body", Pattern: `DROP`, Targets: []string{"body"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	u, _ := url.Parse("http://example.com/admin/delete")
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       u,
		Body:      nil, // passthrough mode
	}

	// URL still checked even with nil body.
	r := step.Process(context.Background(), ex)
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop (URL should still be checked)", r.Action)
	}
}

func TestSafetyStep_BodyNil_HeadersChecked(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-evil-hdr", Pattern: `evil`, Targets: []string{"header"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Headers:   []exchange.KeyValue{{Name: "X-Data", Value: "evil-payload"}},
		Body:      nil, // passthrough mode
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Drop {
		t.Errorf("Action = %v, want Drop (headers should be checked with nil body)", r.Action)
	}
}

func TestSafetyStep_NilEngine(t *testing.T) {
	step := NewSafetyStep(nil)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("DROP TABLE users"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue for nil engine", r.Action)
	}
}

func TestSafetyStep_LogOnly_Continue(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "log-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "log_only"},
		},
	})
	step := NewSafetyStep(engine)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("DROP TABLE users"),
	}

	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Action = %v, want Continue for log_only action", r.Action)
	}
}

func TestSafetyStep_ExchangeNotMutated(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})
	step := NewSafetyStep(engine)

	body := []byte("DROP TABLE users")
	headers := []exchange.KeyValue{{Name: "X-Test", Value: "value"}}
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      body,
		Headers:   headers,
	}

	_ = step.Process(context.Background(), ex)

	// Exchange should not be mutated by InputFilter.
	if string(ex.Body) != "DROP TABLE users" {
		t.Errorf("Body mutated: got %q", string(ex.Body))
	}
	if len(ex.Headers) != 1 || ex.Headers[0].Value != "value" {
		t.Errorf("Headers mutated: got %v", ex.Headers)
	}
}

func TestSafetyStep_Pipeline_Integration(t *testing.T) {
	engine := mustSafetyEngine(t, safety.Config{
		InputRules: []safety.RuleConfig{
			{ID: "block-drop", Pattern: `(?i)\bDROP\s+TABLE\b`, Targets: []string{"body"}, Action: "block"},
		},
	})

	p := New(NewSafetyStep(engine))

	// Blocked exchange.
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("DROP TABLE users"),
	}
	_, action, _ := p.Run(context.Background(), ex)
	if action != Drop {
		t.Errorf("Pipeline action = %v, want Drop", action)
	}

	// Clean exchange.
	ex2 := &exchange.Exchange{
		Direction: exchange.Send,
		Body:      []byte("SELECT * FROM users"),
	}
	_, action2, _ := p.Run(context.Background(), ex2)
	if action2 != Continue {
		t.Errorf("Pipeline action = %v, want Continue", action2)
	}
}
