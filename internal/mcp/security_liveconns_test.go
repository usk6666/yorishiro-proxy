package mcp

import (
	"context"
	"errors"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1160: an Agent Layer write through the security tool reconciles the
// live-connection registry, so a live connection the new rules deny is
// closed (the "security_tool" trigger), while a write that still admits it
// leaves it alone.
func TestSecurity_TargetScopeWritesReconcileLiveConns(t *testing.T) {
	tests := []struct {
		name    string
		input   securityInput
		wantCut bool
	}{
		{
			name: "update_target_scope add_denies",
			input: securityInput{Action: "update_target_scope", Params: securityParams{
				AddDenies: []targetRuleInput{{Hostname: "live.test"}},
			}},
			wantCut: true,
		},
		{
			name: "set_target_scope allows elsewhere",
			input: securityInput{Action: "set_target_scope", Params: securityParams{
				Allows: []targetRuleInput{{Hostname: "other.test"}},
			}},
			wantCut: true,
		},
		{
			name: "update_target_scope unrelated deny",
			input: securityInput{Action: "update_target_scope", Params: securityParams{
				AddDenies: []targetRuleInput{{Hostname: "other.test"}},
			}},
			wantCut: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := connector.NewTargetScope()
			reg := connector.NewLiveConns(nil)
			connCtx, release, err := reg.Register(context.Background(), connector.LiveConn{
				ConnID: "c1", Via: "connect", Target: "live.test:443",
				Admit: func() (bool, string) { return ts.CheckTarget("https", "live.test", 443, "") },
			})
			if err != nil {
				t.Fatalf("Register: %v", err)
			}
			defer release()

			ctx := context.Background()
			s := newServer(ctx, nil, nil, nil, WithTargetScope(ts), WithLiveConns(reg))
			ct, st := gomcp.NewInMemoryTransports()
			ss, err := s.server.Connect(ctx, st, nil)
			if err != nil {
				t.Fatalf("server connect: %v", err)
			}
			defer ss.Close()
			cs, err := gomcp.NewClient(&gomcp.Implementation{Name: "t", Version: "v0"}, nil).Connect(ctx, ct, nil)
			if err != nil {
				t.Fatalf("client connect: %v", err)
			}
			defer cs.Close()

			res, err := cs.CallTool(ctx, &gomcp.CallToolParams{Name: "security", Arguments: securityMarshal(t, tt.input)})
			if err != nil || res.IsError {
				t.Fatalf("CallTool: err=%v result=%+v", err, res)
			}
			cut := errors.Is(context.Cause(connCtx), connector.ErrTargetScopeRevoked)
			if cut != tt.wantCut {
				t.Errorf("live connection cut = %v (cause %v), want %v", cut, context.Cause(connCtx), tt.wantCut)
			}
		})
	}
}
