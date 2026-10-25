//go:build e2e && !e2e_smoke

package mcp

// stream_user_tag_integration_test.go — USK-1362 coverage: the
// user-supplied `tag` of resend_* / fuzz_* must land on the Stream on
// every path that leaves a Stream behind, not only on success. A failed
// attempt (State="error") carries both tags["tag"] and tags["error"],
// and is therefore selectable via `query resource=flows filter.tag`.
//
// Every test drives the real MCP tool. Fixtures (refused-dial address,
// read-then-close upstream, session setups, seeds) are shared with
// stream_error_tag_integration_test.go.

import (
	"context"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

const userTagValue = "usk1362-probe"

// assertUserTagged checks st carries tags["tag"] == want.
func assertUserTagged(t *testing.T, st *flow.Stream, want string) {
	t.Helper()
	if got := st.Tags["tag"]; got != want {
		t.Errorf("Stream %s tags[\"tag\"] = %q, want %q (tags=%v)", st.ID, got, want, st.Tags)
	}
}

// resendRefusedDialRunners returns per-tool closures that call a resend_*
// tool against addr with the given user tag.
func resendRefusedDialRunners() []struct {
	name string
	run  func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store)
} {
	return []struct {
		name string
		run  func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store)
	}{
		{
			name: "resend_http",
			run: func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store) {
				cs, store, _, _ := setupResendHTTPSession(t)
				return callResendHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": addr,
					"path":      "/",
					"headers": []map[string]any{
						{"name": "Host", "value": addr},
					},
					"tag":        tag,
					"timeout_ms": 5000,
				}), cs, store
			},
		},
		{
			name: "resend_ws",
			run: func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store) {
				cs, store, _, _ := setupResendWSSession(t)
				seedID := seedResendWSFlow(t, store, addr, false)
				return callResendWS(t, cs, map[string]any{
					"flow_id":    seedID,
					"opcode":     "text",
					"payload":    "x",
					"tag":        tag,
					"timeout_ms": 5000,
				}), cs, store
			},
		},
		{
			name: "resend_grpc",
			run: func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store) {
				cs, store, _, _ := setupResendGRPCSession(t)
				return callResendGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     resendGRPCServiceName,
					"method":      resendGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "x"},
					},
					"tag":        tag,
					"timeout_ms": 5000,
				}), cs, store
			},
		},
		{
			name: "resend_raw",
			run: func(t *testing.T, addr, tag string) (*gomcp.CallToolResult, *gomcp.ClientSession, flow.Store) {
				cs, store, _ := setupResendRawSession(t)
				seedID := seedRawStream(t, store, []byte("ping"))
				res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
					Name: "resend_raw",
					Arguments: map[string]any{
						"flow_id":     seedID,
						"target_addr": addr,
						"tag":         tag,
						"timeout_ms":  5000,
					},
				})
				if err != nil {
					t.Fatalf("CallTool resend_raw: %v", err)
				}
				return res, cs, store
			},
		},
	}
}

// TestResendTools_RefusedDial_RecordsUserTag: a resend_* to a refused
// port leaves a State="error" Stream that carries the user's tag next to
// tags["error"].
func TestResendTools_RefusedDial_RecordsUserTag(t *testing.T) {
	for _, tt := range resendRefusedDialRunners() {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			res, _, store := tt.run(t, addr, userTagValue)
			if !res.IsError {
				t.Fatalf("expected refused dial to surface as IsError, got success")
			}
			st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
			assertErrorTagged(t, st, "refused")
			assertUserTagged(t, st, userTagValue)
		})
	}
}

// TestResendTools_RefusedDial_QueryFlowsFilterTag_RecordsUserTag: the
// failed attempt is returned by `query resource=flows filter.tag=<tag>`,
// so failed attempts no longer drop out of tag-filtered listings.
func TestResendTools_RefusedDial_QueryFlowsFilterTag_RecordsUserTag(t *testing.T) {
	for _, tt := range resendRefusedDialRunners() {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			res, cs, store := tt.run(t, addr, userTagValue)
			if !res.IsError {
				t.Fatalf("expected refused dial to surface as IsError, got success")
			}
			want := findOriginStream(t, store, flow.OriginResend).ID
			ids, _, total := queryFlowIDs(t, cs, map[string]any{"tag": userTagValue}, 100)
			if strings.Join(ids, ",") != want || total != 1 {
				t.Errorf("flows(tag=%s) ids=%v total=%d, want [%s] total=1", userTagValue, ids, total, want)
			}
		})
	}
}

// TestResendTools_EmptyTag_RefusedDial_NoUserTag is a guard: without a
// user tag, the failed Stream gets no "tag" key.
func TestResendTools_EmptyTag_RefusedDial_NoUserTag(t *testing.T) {
	for _, tt := range resendRefusedDialRunners() {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			res, _, store := tt.run(t, addr, "")
			if !res.IsError {
				t.Fatalf("expected refused dial to surface as IsError, got success")
			}
			st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
			assertErrorTagged(t, st, "refused")
			if v, ok := st.Tags["tag"]; ok {
				t.Errorf("Stream %s tags[\"tag\"] = %q present without a user tag; want absent", st.ID, v)
			}
		})
	}
}

// TestFuzzTools_RefusedDial_RecordsUserTagPerVariant: every failed fuzz
// variant Stream carries the user's tag next to its tags["error"].
func TestFuzzTools_RefusedDial_RecordsUserTagPerVariant(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T, addr string) ([]string, flow.Store)
	}{
		{
			name: "fuzz_http",
			run: func(t *testing.T, addr string) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzHTTPSession(t)
				result := callFuzzHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": addr,
					"path":      "/seed",
					"headers": []map[string]any{
						{"name": "Host", "value": addr},
					},
					"positions": []map[string]any{
						{"path": "path", "payloads": []string{"/v1", "/v2"}},
					},
					"tag":        userTagValue,
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_ws",
			run: func(t *testing.T, addr string) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzWSSession(t)
				result := callFuzzWS(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "ws",
					"path":        "/echo",
					"opcode":      "text",
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"tag":        userTagValue,
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_grpc",
			run: func(t *testing.T, addr string) ([]string, flow.Store) {
				cs, store, _ := setupFuzzGRPCSession(t)
				result := callFuzzGRPC(t, cs, map[string]any{
					"target_addr": addr,
					"scheme":      "https",
					"service":     fuzzGRPCServiceName,
					"method":      fuzzGRPCMethodUnary,
					"messages": []map[string]any{
						{"payload": "seed"},
					},
					"positions": []map[string]any{
						{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
					},
					"tag":        userTagValue,
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
		{
			name: "fuzz_raw",
			run: func(t *testing.T, addr string) ([]string, flow.Store) {
				cs, store, _, _ := setupFuzzRawSession(t)
				result := callFuzzRaw(t, cs, map[string]any{
					"target_addr": addr,
					"positions": []map[string]any{
						{"path": "payload", "payloads": []string{"v1", "v2"}},
					},
					"tag":        userTagValue,
					"timeout_ms": 5000,
				})
				var ids []string
				for _, r := range result.Variants {
					ids = append(ids, r.StreamID)
				}
				return ids, store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr := closedLoopbackAddr(t)
			ids, store := tt.run(t, addr)
			if len(ids) != 2 {
				t.Fatalf("got %d variants, want 2", len(ids))
			}
			for i, id := range ids {
				if id == "" {
					t.Fatalf("variants[%d] stream_id empty", i)
				}
				st := getStream(t, store, id)
				assertErrorTagged(t, st, "refused")
				assertUserTagged(t, st, userTagValue)
			}
		})
	}
}

// TestResendTools_UpstreamClosesWithoutResponse_RecordsUserTag: a
// receive-side failure after the request was sent also keeps the tag.
func TestResendTools_UpstreamClosesWithoutResponse_RecordsUserTag(t *testing.T) {
	tests := []struct {
		name string
		run  func(t *testing.T) (*gomcp.CallToolResult, flow.Store)
	}{
		{
			name: "resend_ws_eof",
			run: func(t *testing.T) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendWSSession(t)
				addr := startWSUpgradeThenCloseServer(t)
				seedID := seedResendWSFlow(t, store, addr, false)
				return callResendWS(t, cs, map[string]any{
					"flow_id":    seedID,
					"opcode":     "text",
					"payload":    "x",
					"tag":        userTagValue,
					"timeout_ms": 5000,
				}), store
			},
		},
		{
			name: "resend_http_aborted",
			run: func(t *testing.T) (*gomcp.CallToolResult, flow.Store) {
				cs, store, _, _ := setupResendHTTPSession(t)
				addr := startReadThenCloseServer(t)
				return callResendHTTP(t, cs, map[string]any{
					"method":    "GET",
					"scheme":    "http",
					"authority": addr,
					"path":      "/",
					"headers": []map[string]any{
						{"name": "Host", "value": addr},
					},
					"tag":        userTagValue,
					"timeout_ms": 5000,
				}), store
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, store := tt.run(t)
			if !res.IsError {
				t.Fatalf("expected no-response close to surface as IsError, got success")
			}
			st := getStream(t, store, findOriginStream(t, store, flow.OriginResend).ID)
			assertErrorTagged(t, st, "")
			assertUserTagged(t, st, userTagValue)
		})
	}
}

// TestBudget_ResendHTTP_BlockedStreamRecordsUserTag: the budget-blocked
// audit Stream carries the tag of the call it records.
func TestBudget_ResendHTTP_BlockedStreamRecordsUserTag(t *testing.T) {
	echo := startBudgetTestEcho(t)
	authority := strings.TrimPrefix(echo.URL, "http://")

	bm := connector.NewBudgetManager()
	bm.SetPolicyBudget(connector.BudgetConfig{MaxTotalRequests: 1})
	cs, store := setupBudgetEnforcementSession(t, bm)
	bm.Start(nil)
	defer bm.Stop()

	call := func(tag string) *gomcp.CallToolResult {
		t.Helper()
		res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "resend_http",
			Arguments: map[string]any{
				"method":     "GET",
				"scheme":     "http",
				"authority":  authority,
				"path":       "/",
				"tag":        tag,
				"timeout_ms": 3000,
			},
		})
		if err != nil {
			t.Fatalf("CallTool resend_http: %v", err)
		}
		return res
	}
	if res := call("within-budget"); res.IsError {
		t.Fatalf("first call: tool error before budget exhaustion: %s", extractTextContent(res))
	}
	if res := call(userTagValue); !res.IsError {
		t.Fatalf("over-budget call: expected tool error; got success")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	streams, err := store.ListStreams(ctx, flow.StreamListOptions{BlockedBy: "budget"})
	if err != nil {
		t.Fatalf("ListStreams(blocked_by=budget): %v", err)
	}
	if len(streams) != 1 {
		t.Fatalf("blocked_by=budget streams: got %d, want exactly 1", len(streams))
	}
	st := getStream(t, store, streams[0].ID)
	if st.State != "error" {
		t.Errorf("audit stream State = %q, want error", st.State)
	}
	assertUserTagged(t, st, userTagValue)
}
