//go:build legacy

package pipeline

import (
	"context"
	"net/url"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

func TestRateLimitStep_Process(t *testing.T) {
	tests := []struct {
		name       string
		ex         *exchange.Exchange
		wantAction Action
	}{
		{
			name: "receive direction is skipped",
			ex: &exchange.Exchange{
				Direction: exchange.Receive,
				URL:       mustParseURL("http://example.com/"),
			},
			wantAction: Continue,
		},
		{
			name: "nil URL returns Continue",
			ex: &exchange.Exchange{
				Direction: exchange.Send,
				URL:       nil,
			},
			wantAction: Continue,
		},
	}

	// Use a limiter with a very low rate so the first call may or may not pass,
	// but the direction/URL checks above should always return Continue.
	limiter := proxy.NewRateLimiter()
	limiter.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 1,
	})
	step := NewRateLimitStep(limiter)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := step.Process(context.Background(), tt.ex)
			if r.Action != tt.wantAction {
				t.Errorf("Process() Action = %v, want %v", r.Action, tt.wantAction)
			}
		})
	}
}

func TestRateLimitStep_Process_NilLimiter(t *testing.T) {
	step := NewRateLimitStep(nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       mustParseURL("http://example.com/"),
	}
	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Process() with nil limiter Action = %v, want Continue", r.Action)
	}
}

func TestRateLimitStep_Process_NoLimits(t *testing.T) {
	limiter := proxy.NewRateLimiter() // no limits configured
	step := NewRateLimitStep(limiter)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       mustParseURL("http://example.com/"),
	}
	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Process() with no limits Action = %v, want Continue", r.Action)
	}
}

func TestRateLimitStep_Process_WithinRate(t *testing.T) {
	limiter := proxy.NewRateLimiter()
	limiter.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 1000, // high enough that single call always passes
	})
	step := NewRateLimitStep(limiter)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		URL:       mustParseURL("http://example.com/"),
	}
	r := step.Process(context.Background(), ex)
	if r.Action != Continue {
		t.Errorf("Process() Action = %v, want Continue", r.Action)
	}
}

func TestRateLimitStep_Process_ExceedsRate(t *testing.T) {
	limiter := proxy.NewRateLimiter()
	// Set an extremely low rate: 0.001 RPS with burst=1.
	// The first request consumes the burst token. The second should be denied.
	limiter.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 0.001,
	})
	step := NewRateLimitStep(limiter)

	makeExchange := func() *exchange.Exchange {
		return &exchange.Exchange{
			Direction: exchange.Send,
			URL: &url.URL{
				Scheme: "http",
				Host:   "example.com",
			},
		}
	}

	// First request: should pass (consumes burst token).
	ex1 := makeExchange()
	r1 := step.Process(context.Background(), ex1)
	if r1.Action != Continue {
		t.Fatalf("Process() first request Action = %v, want Continue", r1.Action)
	}

	// Second request: should be rate limited.
	ex2 := makeExchange()
	r2 := step.Process(context.Background(), ex2)
	if r2.Action != Drop {
		t.Errorf("Process() second request Action = %v, want Drop", r2.Action)
	}
	if ex2.Metadata == nil {
		t.Fatal("Process() expected Metadata to be set on rate-limited exchange")
	}
	if ex2.Metadata["BlockedBy"] != "rate_limit" {
		t.Errorf("Process() Metadata[BlockedBy] = %v, want rate_limit", ex2.Metadata["BlockedBy"])
	}
	if _, ok := ex2.Metadata["rate_limit_type"]; !ok {
		t.Error("Process() expected rate_limit_type in Metadata")
	}
}
