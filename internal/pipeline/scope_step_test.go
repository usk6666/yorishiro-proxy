package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestScopeStep_Process(t *testing.T) {
	// Build a TargetScope that denies example.com via policy deny.
	scope := proxy.NewTargetScope()
	scope.SetPolicyRules(nil, []proxy.TargetRule{
		{Hostname: "example.com"},
	})

	step := NewScopeStep(scope)

	tests := []struct {
		name       string
		ex         *exchange.Exchange
		wantAction Action
		wantMeta   string // expected BlockedBy value, empty if none
	}{
		{
			name: "send direction with denied URL returns Drop",
			ex: &exchange.Exchange{
				Direction: exchange.Send,
				URL:       mustParseURL("http://example.com/path"),
			},
			wantAction: Drop,
			wantMeta:   "target_scope",
		},
		{
			name: "send direction with allowed URL returns Continue",
			ex: &exchange.Exchange{
				Direction: exchange.Send,
				URL:       mustParseURL("http://allowed.com/path"),
			},
			wantAction: Continue,
		},
		{
			name: "receive direction is skipped",
			ex: &exchange.Exchange{
				Direction: exchange.Receive,
				URL:       mustParseURL("http://example.com/path"),
			},
			wantAction: Continue,
		},
		{
			name: "nil URL (TCP) returns Continue",
			ex: &exchange.Exchange{
				Direction: exchange.Send,
				URL:       nil,
			},
			wantAction: Continue,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := step.Process(context.Background(), tt.ex)
			if r.Action != tt.wantAction {
				t.Errorf("Process() Action = %v, want %v", r.Action, tt.wantAction)
			}
			if tt.wantMeta != "" {
				got, ok := tt.ex.Metadata["BlockedBy"]
				if !ok {
					t.Error("Process() expected BlockedBy in Metadata, not found")
				} else if got != tt.wantMeta {
					t.Errorf("Process() Metadata[BlockedBy] = %v, want %v", got, tt.wantMeta)
				}
			}
		})
	}
}

func TestScopeStep_Process_NilScope(t *testing.T) {
	step := NewScopeStep(nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       mustParseURL("http://example.com/"),
	}
	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Process() with nil scope Action = %v, want Continue", r.Action)
	}
}

func TestScopeStep_Process_NoRules(t *testing.T) {
	scope := proxy.NewTargetScope() // no rules configured
	step := NewScopeStep(scope)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       mustParseURL("http://example.com/"),
	}
	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Process() with no rules Action = %v, want Continue", r.Action)
	}
}

func TestScopeStep_Process_PolicyAllow(t *testing.T) {
	scope := proxy.NewTargetScope()
	scope.SetPolicyRules([]proxy.TargetRule{
		{Hostname: "allowed.com"},
	}, nil)

	step := NewScopeStep(scope)

	t.Run("URL in allow list passes", func(t *testing.T) {
		ex := &exchange.Exchange{
			Direction: exchange.Send,
			URL:       mustParseURL("http://allowed.com/"),
		}
		r := step.Process(context.Background(), ex)
		if r.Action != Continue {
			t.Errorf("Process() Action = %v, want Continue", r.Action)
		}
	})

	t.Run("URL not in allow list is dropped", func(t *testing.T) {
		ex := &exchange.Exchange{
			Direction: exchange.Send,
			URL:       mustParseURL("http://other.com/"),
		}
		r := step.Process(context.Background(), ex)
		if r.Action != Drop {
			t.Errorf("Process() Action = %v, want Drop", r.Action)
		}
		if ex.Metadata["BlockedReason"] != "not in policy allow list" {
			t.Errorf("Process() BlockedReason = %v, want 'not in policy allow list'", ex.Metadata["BlockedReason"])
		}
	})
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}
