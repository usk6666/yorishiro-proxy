//go:build e2e

package mcp

import (
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- Helpers for Output Filter tests ---

// newOutputFilterEngine creates a safety engine with PII output filter presets.
func newOutputFilterEngine(t *testing.T, outputRules []safety.RuleConfig) *safety.Engine {
	t.Helper()
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: outputRules,
	})
	if err != nil {
		t.Fatalf("create output filter engine: %v", err)
	}
	return engine
}

// startCustomUpstreamServer starts an HTTP upstream server that returns custom
// responses based on the request path. This is needed because output filter tests
// require the upstream to return PII data in the response body/headers.
func startCustomUpstreamServer(t *testing.T, handler gohttp.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &gohttp.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })
	return listener.Addr().String()
}

// setupOutputFilterEnv creates a fully-wired MCP test environment with the
// output filter engine configured at both MCP and proxy layers.
func setupOutputFilterEnv(t *testing.T, engine *safety.Engine, opts ...ServerOption) (*testEnv, flow.Store) {
	t.Helper()
	store := newSafetyTestStore(t)
	env := setupSafetyFilterEnvWithStore(t, store, engine, opts...)
	return env, store
}

// --- Test constants ---

// Test credit card numbers. These are well-known test/fake numbers that pass Luhn.
const (
	testCreditCardSeparated  = "4111-1111-1111-1111"
	testCreditCardContinuous = "4111111111111111"
	// A random 16-digit number that does NOT pass Luhn.
	testFakeNumber = "1234567890123456"
)

const testEmail = "testuser@example.com"
const testJapanPhone = "090-1234-5678"

// --- Proxy Layer Tests ---

// TestOutputFilter_Proxy_CreditCardMask verifies that credit card numbers in
// the response body are masked to [MASKED:credit_card].
func TestOutputFilter_Proxy_CreditCardMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Your card: %s confirmed", testCreditCardSeparated)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})
	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/card", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	bodyStr := string(body)
	if strings.Contains(bodyStr, testCreditCardSeparated) {
		t.Errorf("response body still contains raw credit card number: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "[MASKED:credit_card]") {
		t.Errorf("response body missing [MASKED:credit_card], got: %s", bodyStr)
	}

	client.CloseIdleConnections()
}

// TestOutputFilter_Proxy_EmailMask verifies that email addresses in the
// response body are masked.
func TestOutputFilter_Proxy_EmailMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Contact: %s for details", testEmail)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "email", Action: "mask"},
	})
	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/email", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	bodyStr := string(body)
	if strings.Contains(bodyStr, testEmail) {
		t.Errorf("response body still contains raw email: %s", bodyStr)
	}
	if !strings.Contains(bodyStr, "[MASKED:email]") {
		t.Errorf("response body missing [MASKED:email], got: %s", bodyStr)
	}

	client.CloseIdleConnections()
}

// TestOutputFilter_Proxy_AllHeadersMask verifies that when targets includes
// "headers", all header values are masked.
func TestOutputFilter_Proxy_AllHeadersMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Set-Cookie", "session="+testEmail)
		w.Header().Set("X-Custom", "data-"+testEmail)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	})

	// The preset defines targets as body-only, but we need headers target.
	// For "headers" target, we need a custom rule since presets define their own targets.
	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{
			ID:          "email-headers",
			Name:        "Email in all headers",
			Pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Targets:     []string{"headers"},
			Action:      "mask",
			Replacement: "[MASKED:email]",
		},
	})

	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/headers", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	// Check Set-Cookie header is masked.
	setCookie := resp.Header.Get("Set-Cookie")
	if strings.Contains(setCookie, testEmail) {
		t.Errorf("Set-Cookie still contains raw email: %s", setCookie)
	}

	// Check X-Custom header is masked.
	xCustom := resp.Header.Get("X-Custom")
	if strings.Contains(xCustom, testEmail) {
		t.Errorf("X-Custom still contains raw email: %s", xCustom)
	}

	client.CloseIdleConnections()
}

// TestOutputFilter_Proxy_SpecificHeaderMask verifies that when targets includes
// "header:Set-Cookie", only the Set-Cookie header is masked.
func TestOutputFilter_Proxy_SpecificHeaderMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Set-Cookie", "session="+testEmail)
		w.Header().Set("X-Custom", "data-"+testEmail)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{
			ID:          "email-set-cookie",
			Name:        "Email in Set-Cookie",
			Pattern:     `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`,
			Targets:     []string{"header:Set-Cookie"},
			Action:      "mask",
			Replacement: "[MASKED:email]",
		},
	})

	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/specific-header", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()

	// Set-Cookie should be masked.
	setCookie := resp.Header.Get("Set-Cookie")
	if strings.Contains(setCookie, testEmail) {
		t.Errorf("Set-Cookie still contains raw email: %s", setCookie)
	}
	if !strings.Contains(setCookie, "[MASKED:email]") {
		t.Errorf("Set-Cookie missing [MASKED:email], got: %s", setCookie)
	}

	// X-Custom should NOT be masked (specific header targeting).
	xCustom := resp.Header.Get("X-Custom")
	if !strings.Contains(xCustom, testEmail) {
		t.Errorf("X-Custom should still contain raw email, got: %s", xCustom)
	}

	client.CloseIdleConnections()
}

// TestOutputFilter_Proxy_RawDataPreserved verifies that the Flow Store contains
// the original unmasked response data even after masking is applied to the client.
func TestOutputFilter_Proxy_RawDataPreserved(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Card: %s", testCreditCardSeparated)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})
	env, store := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/raw", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Verify client received masked body.
	if strings.Contains(string(body), testCreditCardSeparated) {
		t.Errorf("client-side body still contains raw credit card")
	}

	client.CloseIdleConnections()

	// Wait for async flow persistence.
	time.Sleep(200 * time.Millisecond)

	// Verify raw data in store is unmasked.
	ctx := context.Background()
	flows, err := store.ListStreams(ctx, flow.StreamListOptions{Limit: 10})
	if err != nil {
		t.Fatalf("ListFlows: %v", err)
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded")
	}

	msgs, err := store.GetFlows(ctx, flows[0].ID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	// Find the receive (response) message.
	var rawBody []byte
	for _, m := range msgs {
		if m.Direction == "receive" {
			rawBody = m.Body
			break
		}
	}
	if rawBody == nil {
		t.Fatal("no receive message found in store")
	}

	if !strings.Contains(string(rawBody), testCreditCardSeparated) {
		t.Errorf("raw body in store should contain unmasked credit card, got: %s", string(rawBody))
	}
}

// TestOutputFilter_Proxy_ContentLengthRecalculated verifies that Content-Length
// is correctly recalculated after body masking.
func TestOutputFilter_Proxy_ContentLengthRecalculated(t *testing.T) {
	originalBody := fmt.Sprintf("Card: %s end", testCreditCardSeparated)
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, originalBody)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})
	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/cl", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	// Content-Length should match actual body length.
	if resp.ContentLength >= 0 && resp.ContentLength != int64(len(body)) {
		t.Errorf("Content-Length = %d, actual body length = %d", resp.ContentLength, len(body))
	}

	// Body should be masked.
	if strings.Contains(string(body), testCreditCardSeparated) {
		t.Errorf("body still contains raw credit card")
	}

	client.CloseIdleConnections()
}

// TestOutputFilter_Proxy_NoMatchPassthrough verifies that responses without
// matching PII data are returned unchanged.
func TestOutputFilter_Proxy_NoMatchPassthrough(t *testing.T) {
	safeBody := "This is a safe response with no PII data."
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, safeBody)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
		{Preset: "email", Action: "mask"},
	})
	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/safe", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	if string(body) != safeBody {
		t.Errorf("body should be unchanged, got: %q, want: %q", string(body), safeBody)
	}

	client.CloseIdleConnections()
}

// --- MCP Tool Layer Tests ---

// TestOutputFilter_MCP_QueryMessagesMask verifies that get_messages returns
// masked body content while the store retains raw data.
func TestOutputFilter_MCP_QueryMessagesMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Email: %s Card: %s", testEmail, testCreditCardSeparated)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
		{Preset: "email", Action: "mask"},
	})
	env, store := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/pii", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	client.CloseIdleConnections()

	time.Sleep(200 * time.Millisecond)

	// Get flow ID.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatal("no flows recorded")
	}
	flowID := listResult.Flows[0].ID

	// Query messages via MCP — should be masked.
	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})
	if msgResult.Count < 1 {
		t.Fatal("no messages returned")
	}

	// Find response message.
	for _, msg := range msgResult.Messages {
		if msg.Direction == "receive" {
			if strings.Contains(msg.Body, testEmail) {
				t.Errorf("MCP query messages body contains raw email: %s", msg.Body)
			}
			if strings.Contains(msg.Body, testCreditCardSeparated) {
				t.Errorf("MCP query messages body contains raw credit card: %s", msg.Body)
			}
			if !strings.Contains(msg.Body, "[MASKED:email]") {
				t.Errorf("MCP query messages body missing [MASKED:email], got: %s", msg.Body)
			}
			if !strings.Contains(msg.Body, "[MASKED:credit_card]") {
				t.Errorf("MCP query messages body missing [MASKED:credit_card], got: %s", msg.Body)
			}
		}
	}

	// Verify raw data in store is unmasked (scenario 11).
	ctx := context.Background()
	rawMsgs, err := store.GetFlows(ctx, flowID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	for _, m := range rawMsgs {
		if m.Direction == "receive" {
			if !strings.Contains(string(m.Body), testEmail) {
				t.Errorf("raw store body should contain unmasked email, got: %s", string(m.Body))
			}
			if !strings.Contains(string(m.Body), testCreditCardSeparated) {
				t.Errorf("raw store body should contain unmasked credit card, got: %s", string(m.Body))
			}
		}
	}
}

// TestOutputFilter_MCP_ResendResultMask verifies that resend results have
// masked response data.
func TestOutputFilter_MCP_ResendResultMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Card: %s", testCreditCardSeparated)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})
	env, _ := setupOutputFilterEnv(t, engine)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/resend", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	client.CloseIdleConnections()

	time.Sleep(200 * time.Millisecond)

	// Get flow ID.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatal("no flows recorded")
	}
	flowID := listResult.Flows[0].ID

	// Resend — response body should be masked.
	resendResult := callTool[resendActionResult](t, env.cs, "resend", map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
		},
	})

	if strings.Contains(resendResult.ResponseBody, testCreditCardSeparated) {
		t.Errorf("resend response body contains raw credit card: %s", resendResult.ResponseBody)
	}
	if !strings.Contains(resendResult.ResponseBody, "[MASKED:credit_card]") {
		t.Errorf("resend response body missing [MASKED:credit_card], got: %s", resendResult.ResponseBody)
	}
}

// TestOutputFilter_MCP_FuzzResultMask verifies that fuzz results queried via MCP
// have their underlying flow data masked. Fuzz results themselves don't contain
// response body inline, but when queried through the messages resource the bodies
// are masked.
func TestOutputFilter_MCP_FuzzResultMask(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Card: %s", testCreditCardSeparated)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})
	mainStore := newSafetyTestStore(t)
	fuzzStore := newFuzzStore(t)
	fuzzEngine := fuzzer.NewEngine(mainStore, mainStore, fuzzStore, NewDefaultHTTPClient(), "")
	fuzzRegistry := fuzzer.NewJobRegistry()
	fuzzRunner := fuzzer.NewRunner(fuzzEngine, fuzzRegistry)

	env := setupSafetyFilterEnvWithStore(t, mainStore, engine,
		WithFuzzRunner(fuzzRunner),
		WithFuzzStore(fuzzStore),
	)

	_ = callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Create a template flow directly.
	ctx := context.Background()
	u, _ := url.Parse(fmt.Sprintf("http://%s/api/fuzz", upstreamAddr))
	fl := &flow.Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now(),
		Duration:  100 * time.Millisecond,
	}
	if err := mainStore.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:  fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Method:    "GET",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Body:      []byte("test"),
	}); err != nil {
		t.Fatalf("AppendMessage(send): %v", err)
	}
	if err := mainStore.SaveFlow(ctx, &flow.Flow{
		StreamID:   fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: 200,
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage(recv): %v", err)
	}

	// Run fuzz with a single safe payload.
	result, err := env.cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "fuzz",
		Arguments: map[string]any{
			"action": "fuzz",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"attack_type": "sequential",
				"positions": []any{
					map[string]any{
						"id":          "pos-1",
						"location":    "query",
						"name":        "q",
						"payload_set": "test",
					},
				},
				"payload_sets": map[string]any{
					"test": map[string]any{
						"type":   "wordlist",
						"values": []any{"safe_value"},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool(fuzz): %v", err)
	}
	if result.IsError {
		tc := result.Content[0].(*gomcp.TextContent)
		t.Fatalf("fuzz call failed: %s", tc.Text)
	}

	// Wait for fuzz to complete.
	deadline := time.Now().Add(5 * time.Second)
	var jobResult queryFuzzJobsResult
	for time.Now().Before(deadline) {
		jobResult = callTool[queryFuzzJobsResult](t, env.cs, "query", map[string]any{
			"resource": "fuzz_jobs",
			"filter":   map[string]any{"status": "completed"},
		})
		if jobResult.Count > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if jobResult.Count == 0 {
		t.Fatal("fuzz job did not complete")
	}

	// Query fuzz results to get the flow_id of the fuzz result.
	fuzzResults := callTool[queryFuzzResultsResult](t, env.cs, "query", map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  jobResult.Jobs[0].ID,
	})
	if fuzzResults.Count == 0 {
		t.Fatal("no fuzz results")
	}

	// Query messages for the fuzz result flow — body should be masked.
	fuzzFlowID := fuzzResults.Results[0].StreamID
	if fuzzFlowID == "" {
		t.Skip("fuzz result has no flow_id, skipping message check")
	}

	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       fuzzFlowID,
	})

	for _, msg := range msgResult.Messages {
		if msg.Direction == "receive" && strings.Contains(msg.Body, testCreditCardSeparated) {
			t.Errorf("fuzz result message body contains raw credit card: %s", msg.Body)
		}
	}
}

// --- Preset Tests ---

// TestOutputFilter_Preset_LuhnValidation verifies that only credit card numbers
// passing Luhn validation are masked; random digit strings are not.
func TestOutputFilter_Preset_LuhnValidation(t *testing.T) {
	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
	})

	tests := []struct {
		name       string
		input      string
		wantMasked bool
	}{
		{
			name:       "valid card separated",
			input:      fmt.Sprintf("Card: %s", testCreditCardSeparated),
			wantMasked: true,
		},
		{
			name:       "valid card continuous",
			input:      fmt.Sprintf("Num: %s", testCreditCardContinuous),
			wantMasked: true,
		},
		{
			name:       "invalid random digits",
			input:      fmt.Sprintf("Ref: %s", testFakeNumber),
			wantMasked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := engine.FilterOutput([]byte(tt.input))
			if tt.wantMasked {
				if !result.Masked {
					t.Errorf("expected masking, but result.Masked=false for input %q", tt.input)
				}
				if strings.Contains(string(result.Data), testCreditCardSeparated) ||
					strings.Contains(string(result.Data), testCreditCardContinuous) {
					t.Errorf("masked result still contains raw card number: %s", string(result.Data))
				}
			} else {
				if result.Masked {
					t.Errorf("expected no masking, but result.Masked=true for input %q", tt.input)
				}
				if string(result.Data) != tt.input {
					t.Errorf("unmasked result should be unchanged, got: %q, want: %q", string(result.Data), tt.input)
				}
			}
		})
	}
}

// TestOutputFilter_Preset_ReplacementOverride verifies that a custom replacement
// pattern can be used to override the preset default (e.g., partial masking).
func TestOutputFilter_Preset_ReplacementOverride(t *testing.T) {
	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{
			Preset:      "credit-card",
			Action:      "mask",
			Replacement: "****-****-****-$4",
		},
	})

	input := fmt.Sprintf("Card: %s", testCreditCardSeparated)
	result := engine.FilterOutput([]byte(input))

	if !result.Masked {
		t.Fatal("expected masking, but result.Masked=false")
	}

	output := string(result.Data)
	// The separated pattern has groups: (\d{4})[-\s](\d{4})[-\s](\d{4})[-\s](\d{4})
	// $4 should be the last 4 digits "1111".
	if !strings.Contains(output, "****-****-****-1111") {
		t.Errorf("expected partial mask pattern, got: %s", output)
	}
	if strings.Contains(output, testCreditCardSeparated) {
		t.Errorf("output still contains full card number: %s", output)
	}
}

// TestOutputFilter_Preset_MultiplePresets verifies that multiple PII presets
// (credit-card, email, japan-phone) can be applied simultaneously.
func TestOutputFilter_Preset_MultiplePresets(t *testing.T) {
	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "credit-card", Action: "mask"},
		{Preset: "email", Action: "mask"},
		{Preset: "japan-phone", Action: "mask"},
	})

	input := fmt.Sprintf("Card: %s, Email: %s, Phone: %s",
		testCreditCardSeparated, testEmail, testJapanPhone)
	result := engine.FilterOutput([]byte(input))

	if !result.Masked {
		t.Fatal("expected masking, but result.Masked=false")
	}

	output := string(result.Data)

	if strings.Contains(output, testCreditCardSeparated) {
		t.Errorf("output still contains credit card: %s", output)
	}
	if strings.Contains(output, testEmail) {
		t.Errorf("output still contains email: %s", output)
	}
	if strings.Contains(output, testJapanPhone) {
		t.Errorf("output still contains phone: %s", output)
	}

	if !strings.Contains(output, "[MASKED:credit_card]") {
		t.Errorf("output missing [MASKED:credit_card]: %s", output)
	}
	if !strings.Contains(output, "[MASKED:email]") {
		t.Errorf("output missing [MASKED:email]: %s", output)
	}
	if !strings.Contains(output, "[MASKED:phone]") {
		t.Errorf("output missing [MASKED:phone]: %s", output)
	}

	// Should have 3 match entries.
	if len(result.Matches) < 3 {
		t.Errorf("expected at least 3 match entries, got %d", len(result.Matches))
	}
}

// --- Config Tests ---

// TestOutputFilter_Config_OutputRulesLoading verifies that output filter rules
// are correctly loaded via the safety.Config/NewEngine configuration path.
func TestOutputFilter_Config_OutputRulesLoading(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{Preset: "credit-card", Action: "mask"},
			{Preset: "email", Action: "mask"},
			{
				ID:          "custom-ssn",
				Name:        "Custom SSN pattern",
				Pattern:     `\d{3}-\d{2}-\d{4}`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "[MASKED:ssn]",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	rules := engine.OutputRules()
	if len(rules) == 0 {
		t.Fatal("expected output rules, got none")
	}

	// Verify preset rules are loaded.
	hasCreditCard := false
	hasEmail := false
	hasCustomSSN := false
	for _, r := range rules {
		switch {
		case strings.HasPrefix(r.ID, "credit-card:"):
			hasCreditCard = true
		case strings.HasPrefix(r.ID, "email:"):
			hasEmail = true
		case r.ID == "custom-ssn":
			hasCustomSSN = true
			if r.Category != "custom" {
				t.Errorf("custom rule category = %q, want %q", r.Category, "custom")
			}
		}
	}
	if !hasCreditCard {
		t.Error("credit-card preset rules not found")
	}
	if !hasEmail {
		t.Error("email preset rules not found")
	}
	if !hasCustomSSN {
		t.Error("custom-ssn rule not found")
	}

	// Verify custom rule works.
	result := engine.FilterOutput([]byte("SSN: 123-45-6789"))
	if !result.Masked {
		t.Error("expected masking for SSN pattern")
	}
	if !strings.Contains(string(result.Data), "[MASKED:ssn]") {
		t.Errorf("expected [MASKED:ssn] in output, got: %s", string(result.Data))
	}

	// Verify preset credit-card works.
	result2 := engine.FilterOutput([]byte(fmt.Sprintf("Card: %s", testCreditCardSeparated)))
	if !result2.Masked {
		t.Error("expected masking for credit card")
	}
}

// --- MCP Layer: Raw Data Preservation (Scenario 11) ---

// TestOutputFilter_MCP_RawDataPreserved verifies that when querying data through
// MCP tools, the body is masked, but the underlying Flow Store still contains
// the original unmasked data.
func TestOutputFilter_MCP_RawDataPreserved(t *testing.T) {
	upstreamAddr := startCustomUpstreamServer(t, func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprintf(w, "Secret email: %s", testEmail)
	})

	engine := newOutputFilterEngine(t, []safety.RuleConfig{
		{Preset: "email", Action: "mask"},
	})

	store := newSafetyTestStore(t)
	ctx := context.Background()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, testutil.DiscardLogger())
	httpHandler.SetSafetyEngine(engine)
	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, testutil.DiscardLogger())
	t.Cleanup(func() { manager.Stop(context.Background()) })

	mcpServer := NewServer(ctx, ca, store, manager,
		WithSafetyEngine(engine),
		WithSafetyEngineSetter(httpHandler),
	)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "output-filter-raw-test",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	env := &testEnv{cs: cs, store: store, manager: manager}

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	httpClient := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/raw-check", upstreamAddr)

	resp, err := httpClient.Get(targetURL)
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	resp.Body.Close()
	httpClient.CloseIdleConnections()

	time.Sleep(200 * time.Millisecond)

	// Get flow via MCP — body should be masked.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatal("no flows recorded")
	}
	flowID := listResult.Flows[0].ID

	msgResult := callTool[queryMessagesResult](t, env.cs, "query", map[string]any{
		"resource": "messages",
		"id":       flowID,
	})

	for _, msg := range msgResult.Messages {
		if msg.Direction == "receive" {
			if strings.Contains(msg.Body, testEmail) {
				t.Errorf("MCP message body should be masked, still contains: %s", testEmail)
			}
		}
	}

	// Directly read from store — should have raw unmasked data.
	rawMsgs, err := store.GetFlows(ctx, flowID, flow.FlowListOptions{})
	if err != nil {
		t.Fatalf("GetMessages from store: %v", err)
	}
	for _, m := range rawMsgs {
		if m.Direction == "receive" {
			if !strings.Contains(string(m.Body), testEmail) {
				t.Errorf("raw store body should contain unmasked email, got: %s", string(m.Body))
			}
		}
	}
}

// --- Helpers ---
