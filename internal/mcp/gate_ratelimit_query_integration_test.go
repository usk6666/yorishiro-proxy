//go:build e2e && !e2e_smoke

package mcp

// gate_ratelimit_query_integration_test.go — USK-1381: CONNECT, plain-HTTP
// forward and SOCKS5 connections the main listener's rate-limit gate
// refuses each leave a blocked_by=rate_limit Stream that the query tool
// returns under filter.blocked_by. The Manager writes to the same SQLite
// store the MCP session reads. Template:
// tcp_forward_ratelimit_query_integration_test.go.

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"sort"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// gateRefusalExchange dials proxyAddr, writes req and drains the reply
// until the proxy closes the connection.
func gateRefusalExchange(t *testing.T, proxyAddr string, req []byte) []byte {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Write(req); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, _ := io.ReadAll(c)
	return got
}

func TestQuery_GateRateLimitRefusalBlockedBy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newTestStore(t)

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
	_, proxyAddr := mgr.Status()

	// Spend the burst, then open one refused connection per gate. The
	// targets are never dialled.
	if d := rl.Check("spend.example"); d != nil {
		t.Fatalf("pre-spend denied: %+v", d)
	}
	const target = "127.0.0.1:9"
	if got := gateRefusalExchange(t, proxyAddr, []byte("CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")); !strings.HasPrefix(string(got), "HTTP/1.1 429") {
		t.Fatalf("CONNECT answered %q, want 429", got)
	}
	if got := gateRefusalExchange(t, proxyAddr, []byte("GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\n\r\n")); !strings.HasPrefix(string(got), "HTTP/1.1 429") {
		t.Fatalf("forward answered %q, want 429", got)
	}
	socks := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	socks = binary.BigEndian.AppendUint16(socks, 9)
	if got := gateRefusalExchange(t, proxyAddr, socks); len(got) < 4 || got[3] != 0x02 {
		t.Fatalf("SOCKS5 answered %x, want method selection then REP=0x02", got)
	}

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
		if len(out.Flows) >= 3 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(out.Flows) != 3 {
		t.Fatalf("query blocked_by=rate_limit returned %d rows, want 3: %+v", len(out.Flows), out.Flows)
	}
	var protocols []string
	for _, row := range out.Flows {
		if row.BlockedBy != "rate_limit" || row.State != "error" {
			t.Errorf("row = %+v, want blocked_by rate_limit, state error", row)
		}
		if row.ListenerName != proxybuild.DefaultListenerName {
			t.Errorf("row ListenerName = %q, want %q", row.ListenerName, proxybuild.DefaultListenerName)
		}
		protocols = append(protocols, row.Protocol)
	}
	sort.Strings(protocols)
	if strings.Join(protocols, ",") != "http,http,raw" {
		t.Errorf("row protocols = %v, want http (CONNECT), http (forward), raw (SOCKS5)", protocols)
	}
}
