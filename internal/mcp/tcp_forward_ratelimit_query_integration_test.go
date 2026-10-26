//go:build e2e && !e2e_smoke

package mcp

// tcp_forward_ratelimit_query_integration_test.go — USK-1380: a tcp_forwards
// connection refused by the rate-limit gate leaves a blocked_by=rate_limit
// Stream that the query tool returns under filter.blocked_by. The Manager
// writes to the same SQLite store the MCP session reads.

import (
	"context"
	"encoding/json"
	"net"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

func TestQuery_TCPForwardRateLimitRefusalBlockedBy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newTestStore(t)

	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen upstream: %v", err)
	}
	defer upstream.Close()
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	rl := connector.NewRateLimiter()
	rl.SetPolicyLimits(connector.RateLimitConfig{MaxRequestsPerSecond: 0.001})
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	logger := testutil.DiscardLogger()
	mgr, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger: logger,
		StackFactory: func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
			return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
				Logger:       logger,
				ListenerName: name,
				ListenAddr:   addr,
				FlowStore:    store,
				BuildConfig:  buildCfg,
				RateLimiter:  rl,
			})
		},
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	defer func() { _ = mgr.StopAll(context.Background()) }()
	if err := mgr.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: upstream.Addr().String(), Protocol: "raw"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]

	// Spend the burst, then open the connection the gate refuses.
	if d := rl.Check("spend.example"); d != nil {
		t.Fatalf("pre-spend denied: %+v", d)
	}
	c, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	_, _ = c.Write([]byte("over-limit"))
	_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Read(make([]byte, 16))
	_ = c.Close()

	cs := setupListenerCaptureMCPSession(t, store)
	var out queryFlowsResult
	deadline := time.Now().Add(5 * time.Second)
	for {
		res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "query",
			Arguments: map[string]any{
				"resource": "flows",
				"filter":   map[string]any{"blocked_by": "rate_limit"},
			},
		})
		if err != nil {
			t.Fatalf("CallTool query: %v", err)
		}
		if res.IsError {
			t.Fatalf("query error: %s", extractTextContent(res))
		}
		out = queryFlowsResult{}
		if err := json.Unmarshal([]byte(extractTextContent(res)), &out); err != nil {
			t.Fatalf("decode query result: %v", err)
		}
		if len(out.Flows) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(out.Flows) != 1 {
		t.Fatalf("query blocked_by=rate_limit returned %d rows, want 1: %+v", len(out.Flows), out.Flows)
	}
	row := out.Flows[0]
	if row.BlockedBy != "rate_limit" || row.State != "error" || row.Protocol != "raw" {
		t.Errorf("row = %+v, want blocked_by rate_limit, state error, protocol raw", row)
	}
	if row.ListenerName != proxybuild.DefaultListenerName {
		t.Errorf("row ListenerName = %q, want %q", row.ListenerName, proxybuild.DefaultListenerName)
	}
}
