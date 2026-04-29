package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
)

// setupSecurityBudgetTestSession creates an MCP client session with a budget manager.
func setupSecurityBudgetTestSession(t *testing.T, bm *proxy.BudgetManager) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	var opts []ServerOption
	if bm != nil {
		opts = append(opts, WithBudgetManager(bm))
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

func TestSecurity_GetBudget_EmptyDefault(t *testing.T) {
	bm := proxy.NewBudgetManager()
	cs := setupSecurityBudgetTestSession(t, bm)

	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "get_budget",
		}),
	})
	if err != nil {
		t.Fatalf("get_budget: %v", err)
	}

	var out getBudgetResult
	securityUnmarshalResult(t, result, &out)

	if out.Policy.MaxTotalRequests != 0 {
		t.Errorf("policy.max_total_requests = %v, want 0", out.Policy.MaxTotalRequests)
	}
	if out.Effective.MaxTotalRequests != 0 {
		t.Errorf("effective.max_total_requests = %v, want 0", out.Effective.MaxTotalRequests)
	}
	if out.RequestCount != 0 {
		t.Errorf("request_count = %v, want 0", out.RequestCount)
	}
}

func TestSecurity_SetBudget_AgentOnly(t *testing.T) {
	bm := proxy.NewBudgetManager()
	cs := setupSecurityBudgetTestSession(t, bm)

	maxReqs := int64(500)
	maxDur := "30m"
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &maxReqs,
				MaxDuration:      &maxDur,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_budget: %v", err)
	}

	var out budgetResult
	securityUnmarshalResult(t, result, &out)

	if out.Status != "updated" {
		t.Errorf("status = %q, want %q", out.Status, "updated")
	}
	if out.Effective.MaxTotalRequests != 500 {
		t.Errorf("effective.max_total_requests = %d, want 500", out.Effective.MaxTotalRequests)
	}
	if out.Effective.MaxDuration != 30*time.Minute {
		t.Errorf("effective.max_duration = %v, want 30m", out.Effective.MaxDuration)
	}
}

func TestSecurity_SetBudget_WithPolicy(t *testing.T) {
	bm := proxy.NewBudgetManager()
	bm.SetPolicyBudget(proxy.BudgetConfig{
		MaxTotalRequests: 1000,
		MaxDuration:      time.Hour,
	})
	cs := setupSecurityBudgetTestSession(t, bm)

	maxReqs := int64(500)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &maxReqs,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_budget: %v", err)
	}

	var out budgetResult
	securityUnmarshalResult(t, result, &out)

	if out.Effective.MaxTotalRequests != 500 {
		t.Errorf("effective.max_total_requests = %d, want 500", out.Effective.MaxTotalRequests)
	}
}

func TestSecurity_SetBudget_ExceedsPolicy(t *testing.T) {
	bm := proxy.NewBudgetManager()
	bm.SetPolicyBudget(proxy.BudgetConfig{
		MaxTotalRequests: 100,
	})
	cs := setupSecurityBudgetTestSession(t, bm)

	maxReqs := int64(200)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &maxReqs,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error when agent exceeds policy")
	}
}

func TestSecurity_SetBudget_NegativeValue(t *testing.T) {
	bm := proxy.NewBudgetManager()
	cs := setupSecurityBudgetTestSession(t, bm)

	maxReqs := int64(-1)
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &maxReqs,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for negative budget value")
	}
}

func TestSecurity_SetBudget_InvalidDuration(t *testing.T) {
	bm := proxy.NewBudgetManager()
	cs := setupSecurityBudgetTestSession(t, bm)

	maxDur := "invalid"
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxDuration: &maxDur,
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if !result.IsError {
		t.Error("expected error for invalid duration")
	}
}

func TestSecurity_SetBudget_ClearBudget(t *testing.T) {
	bm := proxy.NewBudgetManager()
	cs := setupSecurityBudgetTestSession(t, bm)

	// Set budget first.
	maxReqs := int64(500)
	_, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &maxReqs,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_budget: %v", err)
	}

	// Clear budget by setting to 0.
	zero := int64(0)
	zeroDur := "0s"
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "security",
		Arguments: securityMarshal(t, securityInput{
			Action: "set_budget",
			Params: securityParams{
				MaxTotalRequests: &zero,
				MaxDuration:      &zeroDur,
			},
		}),
	})
	if err != nil {
		t.Fatalf("set_budget (clear): %v", err)
	}

	var out budgetResult
	securityUnmarshalResult(t, result, &out)

	if out.Effective.MaxTotalRequests != 0 {
		t.Errorf("effective.max_total_requests = %d, want 0", out.Effective.MaxTotalRequests)
	}
	if out.Effective.MaxDuration != 0 {
		t.Errorf("effective.max_duration = %v, want 0", out.Effective.MaxDuration)
	}
}
