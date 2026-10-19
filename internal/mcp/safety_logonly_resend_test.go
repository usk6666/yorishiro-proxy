package mcp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/safety"
)

// setupSafetyActionSession wires an MCP server whose Input SafetyFilter
// carries the destructive-sql preset with the given section-level action —
// the same RuleConfig shape mcpserver.InitSafetyFilter builds from
// safety_filter.input.action.
func setupSafetyActionSession(t *testing.T, action string) *gomcp.ClientSession {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{{Preset: "destructive-sql", Action: action}},
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
	client := gomcp.NewClient(&gomcp.Implementation{Name: "safety-action", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// TestResendHTTP_SafetyInputAction drives the real resend_http tool with a
// destructive body. Under log_only the request must reach the upstream and
// the tool must succeed (USK-1109); under block it must still be refused
// before anything is sent.
func TestResendHTTP_SafetyInputAction(t *testing.T) {
	for _, tc := range []struct {
		action      string
		wantBlocked bool
	}{
		{action: "log_only", wantBlocked: false},
		{action: "block", wantBlocked: true},
	} {
		t.Run(tc.action, func(t *testing.T) {
			var hits atomic.Int32
			var gotBody atomic.Pointer[string]
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				b, _ := io.ReadAll(r.Body)
				s := string(b)
				gotBody.Store(&s)
				hits.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)
			authority := strings.TrimPrefix(upstream.URL, "http://")

			cs := setupSafetyActionSession(t, tc.action)
			res := callWirePathSafetyTool(t, cs, "resend_http", map[string]any{
				"method":    "POST",
				"scheme":    "http",
				"authority": authority,
				"path":      "/api/query",
				"headers": []map[string]any{
					{"name": "Host", "value": authority},
					{"name": "Content-Type", "value": "text/plain"},
				},
				"body":          "DROP TABLE users",
				"body_encoding": "text",
				"timeout_ms":    5000,
			})

			if tc.wantBlocked {
				assertSafetyBlocked(t, res)
				if n := hits.Load(); n != 0 {
					t.Errorf("upstream hits = %d, want 0 under block", n)
				}
				return
			}
			if res.IsError {
				t.Fatalf("log_only: tool returned error: %s", extractTextContent(res))
			}
			if n := hits.Load(); n != 1 {
				t.Fatalf("upstream hits = %d, want 1 under log_only", n)
			}
			if b := gotBody.Load(); b == nil || *b != "DROP TABLE users" {
				t.Errorf("upstream body = %v, want %q", b, "DROP TABLE users")
			}
		})
	}
}
