package mcp

import (
	"context"
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// setupWirePathSafetySession wires an MCP server whose Input SafetyFilter
// carries the destructive-os-command preset (url target included).
func setupWirePathSafetySession(t *testing.T) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{Preset: "destructive-os-command"}},
	})
	if err != nil {
		t.Fatalf("safety.NewEngine: %v", err)
	}
	store := newTestStore(t)
	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil, WithSafetyEngine(engine))
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "wirepath-safety", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

func callWirePathSafetyTool(t *testing.T, cs *gomcp.ClientSession, name string, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("CallTool %s: %v", name, err)
	}
	return res
}

func assertSafetyBlocked(t *testing.T, res *gomcp.CallToolResult) {
	t.Helper()
	if !res.IsError {
		t.Fatalf("expected the SafetyFilter to block the call, got success: %s", extractTextContent(res))
	}
	if text := extractTextContent(res); !strings.Contains(text, "SafetyFilter blocked") {
		t.Fatalf("expected a SafetyFilter block, got a different error: %s", text)
	}
}

// TestResendHTTP_SafetyBlocksEncodedWirePath: an HTTP/1-recorded flow whose
// wire path is "/%6dkfs.ext4" (decoded "/mkfs.ext4") must be blocked by the
// MCP-plane Input SafetyFilter. Before USK-1139 the HTTP/1.x Flow.URL held
// the decoded path, so the preset matched; the url target must now match
// either the wire form or its percent-decoded form (USK-1139 S-2).
func TestResendHTTP_SafetyBlocksEncodedWirePath(t *testing.T) {
	cs, store := setupWirePathSafetySession(t)
	ctx := context.Background()
	// 127.0.0.1:1 refuses connections, so a call that is NOT blocked fails
	// fast with a dial error instead of the SafetyFilter message.
	const authority = "127.0.0.1:1"
	st := &flow.Stream{ID: "wp-safety-http", Protocol: "http", Scheme: "http"}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	if err := store.SaveFlow(ctx, &flow.Flow{
		StreamID:  st.ID,
		Sequence:  0,
		Direction: "send",
		Method:    "GET",
		URL:       envelope.URLFromWirePath("http", authority, "/%6dkfs.ext4", ""),
		Headers:   map[string][]string{"Host": {authority}},
	}); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	res := callWirePathSafetyTool(t, cs, "resend_http", map[string]any{
		"flow_id":    st.ID,
		"timeout_ms": 2000,
	})
	assertSafetyBlocked(t, res)
}

// TestResendWS_SafetyBlocksEncodedUpgradePath is the WebSocket twin: the
// upgrade URL's path is matched in either form.
func TestResendWS_SafetyBlocksEncodedUpgradePath(t *testing.T) {
	cs, _ := setupWirePathSafetySession(t)
	res := callWirePathSafetyTool(t, cs, "resend_ws", map[string]any{
		"target_addr": "127.0.0.1:1",
		"scheme":      "ws",
		"path":        "/%6dkfs.ext4",
		"opcode":      "text",
		"payload":     "hello",
		"timeout_ms":  2000,
	})
	assertSafetyBlocked(t, res)
}
