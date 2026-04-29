package mcp

import (
	"context"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupSecurityRateLimitTestSession creates an MCP client session with rate limiter.
func setupSecurityRateLimitTestSession(t *testing.T, rl *proxy.RateLimiter) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if rl != nil {
		opts = append(opts, WithRateLimiter(rl))
	}

	s := newServer(ctx, nil, nil, nil, opts...)
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

func TestSecurity_GetRateLimits_EmptyDefault(t *testing.T) {
	rl := proxy.NewRateLimiter()
	cs := setupSecurityRateLimitTestSession(t, rl)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_rate_limits",
		}),
	})
	if err != nil {
		t.Fatalf("get_rate_limits: %v", err)
	}

	var out getRateLimitsResult
	securityUnmarshalResult(t, result, &out)

	if out.Policy.MaxRequestsPerSecond != 0 {
		t.Errorf("policy.max_rps = %v, want 0", out.Policy.MaxRequestsPerSecond)
	}
	if out.Effective.MaxRequestsPerSecond != 0 {
		t.Errorf("effective.max_rps = %v, want 0", out.Effective.MaxRequestsPerSecond)
	}
}

func TestSecurity_SetRateLimits_AgentOnly(t *testing.T) {
	rl := proxy.NewRateLimiter()
	cs := setupSecurityRateLimitTestSession(t, rl)

	rps := float64(10)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &rps,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_rate_limits: %v", err)
	}

	var out rateLimitResult
	securityUnmarshalResult(t, result, &out)

	if out.Status != "updated" {
		t.Errorf("status = %q, want updated", out.Status)
	}
	if out.Effective.MaxRequestsPerSecond != 10 {
		t.Errorf("effective.max_rps = %v, want 10", out.Effective.MaxRequestsPerSecond)
	}
	if out.Agent.MaxRequestsPerSecond != 10 {
		t.Errorf("agent.max_rps = %v, want 10", out.Agent.MaxRequestsPerSecond)
	}
}

func TestSecurity_SetRateLimits_WithPolicy(t *testing.T) {
	rl := proxy.NewRateLimiter()
	rl.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 20,
	})
	cs := setupSecurityRateLimitTestSession(t, rl)

	// Set agent limits within policy.
	rps := float64(10)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &rps,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_rate_limits: %v", err)
	}

	var out rateLimitResult
	securityUnmarshalResult(t, result, &out)
	if out.Effective.MaxRequestsPerSecond != 10 {
		t.Errorf("effective.max_rps = %v, want 10", out.Effective.MaxRequestsPerSecond)
	}
}

func TestSecurity_SetRateLimits_ExceedsPolicy(t *testing.T) {
	rl := proxy.NewRateLimiter()
	rl.SetPolicyLimits(proxy.RateLimitConfig{
		MaxRequestsPerSecond: 10,
	})
	cs := setupSecurityRateLimitTestSession(t, rl)

	// Agent tries to exceed policy.
	rps := float64(20)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &rps,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error when agent exceeds policy")
	}
}

func TestSecurity_SetRateLimits_NegativeValue(t *testing.T) {
	rl := proxy.NewRateLimiter()
	cs := setupSecurityRateLimitTestSession(t, rl)

	negative := float64(-1)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &negative,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Fatal("expected error for negative rate limit")
	}
}

func TestSecurity_SetRateLimits_ClearLimits(t *testing.T) {
	rl := proxy.NewRateLimiter()
	cs := setupSecurityRateLimitTestSession(t, rl)

	// Set limits.
	rps := float64(10)
	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &rps,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_rate_limits: %v", err)
	}

	// Clear limits by setting to 0.
	zero := float64(0)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_rate_limits",
			Params: securityParams{
				MaxRequestsPerSecond: &zero,
			},
		}),
	})
	if err != nil {
		t.Fatalf("clear rate_limits: %v", err)
	}

	var out rateLimitResult
	securityUnmarshalResult(t, result, &out)
	if out.Effective.MaxRequestsPerSecond != 0 {
		t.Errorf("effective.max_rps = %v, want 0", out.Effective.MaxRequestsPerSecond)
	}
}
