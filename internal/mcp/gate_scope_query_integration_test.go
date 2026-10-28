//go:build e2e && !e2e_smoke

package mcp

// gate_scope_query_integration_test.go — USK-1403: CONNECT, plain-HTTP
// forward, SOCKS5 and tcp_forwards connections the scope gates refuse each
// leave a blocked_by=target_scope Stream that the query tool returns under
// filter.blocked_by. The Manager writes to the same SQLite store the MCP
// session reads. Template: gate_ratelimit_query_integration_test.go.

import (
	"context"
	"encoding/binary"
	"encoding/json"
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

func TestQuery_GateScopeRefusalBlockedBy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := newTestStore(t)

	scope := connector.NewTargetScope()
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
				Scope:        scope,
				LiveConns:    connector.NewLiveConns(logger),
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

	// The forward starts while its target is still in scope (the
	// start-time check would reject it otherwise); the deny lands after.
	const target = "127.0.0.1:9"
	if err := mgr.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{"0": {Target: target, Protocol: "raw"}},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	fwdAddr := mgr.TCPForwardAddrs()["0"]
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", Ports: []int{9}}})

	if got := gateRefusalExchange(t, proxyAddr, []byte("CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\n\r\n")); !strings.HasPrefix(string(got), "HTTP/1.1 403") {
		t.Fatalf("CONNECT answered %q, want 403", got)
	}
	if got := gateRefusalExchange(t, proxyAddr, []byte("GET http://"+target+"/ HTTP/1.1\r\nHost: "+target+"\r\n\r\n")); !strings.HasPrefix(string(got), "HTTP/1.1 403") {
		t.Fatalf("forward answered %q, want 403", got)
	}
	socks := []byte{0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1}
	socks = binary.BigEndian.AppendUint16(socks, 9)
	if got := gateRefusalExchange(t, proxyAddr, socks); len(got) < 4 || got[3] != 0x02 {
		t.Fatalf("SOCKS5 answered %x, want method selection then REP=0x02", got)
	}
	c, err := net.DialTimeout("tcp", fwdAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial forward: %v", err)
	}
	_, _ = c.Write([]byte("denied"))
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
				"filter":   map[string]any{"blocked_by": "target_scope"},
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
		if len(out.Flows) >= 4 || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(out.Flows) != 4 {
		t.Fatalf("query blocked_by=target_scope returned %d rows, want 4: %+v", len(out.Flows), out.Flows)
	}
	var vias []string
	for _, row := range out.Flows {
		if row.BlockedBy != "target_scope" || row.State != "error" {
			t.Errorf("row = %+v, want blocked_by target_scope, state error", row)
		}
		if row.ListenerName != proxybuild.DefaultListenerName {
			t.Errorf("row ListenerName = %q, want %q", row.ListenerName, proxybuild.DefaultListenerName)
		}
		vias = append(vias, row.Tags["via"]+"/"+row.Protocol)
	}
	sort.Strings(vias)
	if got, want := strings.Join(vias, ","), "connect/http,http1-forward/http,socks5/raw,tcp-forward/raw"; got != want {
		t.Errorf("row via/protocol = %s, want %s", got, want)
	}
}
