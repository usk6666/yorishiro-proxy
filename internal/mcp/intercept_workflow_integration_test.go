//go:build e2e

package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- USK-532: End-to-end intercept workflow integration tests ---

// startAuthServer starts an HTTP server that simulates an authentication flow.
// POST /login returns a JSON token. GET /admin checks for a valid Bearer token
// and returns different responses based on the role claim. GET /data returns
// different status codes based on query parameters (for fuzzing tests).
func startAuthServer(t *testing.T) string {
	t.Helper()

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		switch {
		case r.Method == "POST" && r.URL.Path == "/login":
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(gohttp.StatusOK)
			// Return a token that encodes what was received.
			fmt.Fprintf(w, `{"token":"tok-%s","expires_in":3600}`, string(body))

		case r.URL.Path == "/admin":
			auth := r.Header.Get("Authorization")
			if auth == "" {
				w.WriteHeader(gohttp.StatusUnauthorized)
				fmt.Fprint(w, `{"error":"no token"}`)
				return
			}
			// Simulate role-based access: admin token gets 200, others get 403.
			if strings.Contains(auth, "admin") {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(gohttp.StatusOK)
				fmt.Fprint(w, `{"data":"secret-admin-panel","role":"admin"}`)
			} else {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(gohttp.StatusForbidden)
				fmt.Fprint(w, `{"error":"forbidden","role":"viewer"}`)
			}

		case r.URL.Path == "/data":
			// Respond based on the "id" query parameter for fuzzing tests.
			id := r.URL.Query().Get("id")
			switch id {
			case "1":
				w.WriteHeader(gohttp.StatusOK)
				fmt.Fprint(w, `{"result":"item-1"}`)
			case "9999":
				w.WriteHeader(gohttp.StatusNotFound)
				fmt.Fprint(w, `{"error":"not found"}`)
			case "' OR 1=1--":
				w.WriteHeader(gohttp.StatusInternalServerError)
				fmt.Fprint(w, `{"error":"internal server error"}`)
			default:
				w.WriteHeader(gohttp.StatusOK)
				fmt.Fprintf(w, `{"result":"item-%s"}`, id)
			}

		default:
			w.Header().Set("Content-Type", "text/plain")
			w.WriteHeader(gohttp.StatusOK)
			body, _ := io.ReadAll(r.Body)
			if len(body) > 0 {
				fmt.Fprintf(w, "echo: %s", body)
			} else {
				fmt.Fprint(w, "ok")
			}
		}
	})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &gohttp.Server{Handler: handler}
	go server.Serve(listener)
	t.Cleanup(func() { server.Close() })

	return listener.Addr().String()
}

// TestE2E_InterceptWorkflow_BasicFlow verifies the core intercept workflow:
// configure intercept rule -> proxy_start -> send traffic -> request held in
// queue -> inspect via query -> modify_and_forward -> upstream receives modified
// request -> client gets response -> flow recording includes variant.
func TestE2E_InterceptWorkflow_BasicFlow(t *testing.T) {
	upstreamAddr := startAuthServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	// 1. Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// 2. Configure intercept rule for /admin path.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "rule-admin",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": "/admin.*",
						"methods":      []string{"GET"},
					},
				},
			},
		},
	})

	// 3. Send a GET /admin request through proxy (will be intercepted).
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/admin", upstreamAddr)

	var (
		wg       sync.WaitGroup
		respBody string
		respCode int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := gohttp.NewRequest("GET", targetURL, nil)
		req.Header.Set("Authorization", "Bearer viewer-token")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		respCode = resp.StatusCode
		b, _ := io.ReadAll(resp.Body)
		respBody = string(b)
	}()

	// 4. Poll intercept queue until request appears.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			if qResult.Items[0].Phase != "request" {
				t.Errorf("queue item phase = %q, want request", qResult.Items[0].Phase)
			}
			if qResult.Items[0].Method != "GET" {
				t.Errorf("queue item method = %q, want GET", qResult.Items[0].Method)
			}
			if !strings.Contains(qResult.Items[0].URL, "/admin") {
				t.Errorf("queue item URL = %q, want to contain /admin", qResult.Items[0].URL)
			}
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for request to appear in intercept queue")
	}

	// 5. Modify and forward: inject admin token to escalate privileges.
	modResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": interceptID,
			"override_headers": map[string]string{
				"Authorization": "Bearer admin-token",
			},
		},
	})
	if modResult.Action != "modify_and_forward" {
		t.Errorf("action = %q, want modify_and_forward", modResult.Action)
	}

	// 6. Wait for client to receive response.
	wg.Wait()

	// The server should see the admin token and return 200.
	if respCode != gohttp.StatusOK {
		t.Errorf("client response code = %d, want %d", respCode, gohttp.StatusOK)
	}
	if !strings.Contains(respBody, "secret-admin-panel") {
		t.Errorf("client body = %q, want to contain 'secret-admin-panel'", respBody)
	}

	client.CloseIdleConnections()

	// 7. Wait for flow recording and verify variant recording.
	time.Sleep(500 * time.Millisecond)

	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if flowsResult.Total == 0 {
		t.Fatal("no flows recorded")
	}

	var flowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/admin") {
			flowID = f.ID
			break
		}
	}
	if flowID == "" {
		t.Fatal("could not find flow for /admin")
	}

	// Verify flow detail shows the modified request was used.
	flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})
	if flowDetail.ResponseStatusCode != gohttp.StatusOK {
		t.Errorf("flow response status = %d, want %d", flowDetail.ResponseStatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(flowDetail.ResponseBody, "secret-admin-panel") {
		t.Errorf("flow response body = %q, want to contain 'secret-admin-panel'", flowDetail.ResponseBody)
	}

	// Verify variant recording: original request should be preserved.
	if flowDetail.OriginalRequest != nil {
		// The original request should have the viewer token.
		authHeader := flowDetail.OriginalRequest.Headers["Authorization"]
		if len(authHeader) == 0 || !strings.Contains(authHeader[0], "viewer-token") {
			t.Errorf("original request Authorization = %v, want viewer-token", authHeader)
		}
	}

	// The modified request (current) should have the admin token.
	authHeader := flowDetail.RequestHeaders["Authorization"]
	if len(authHeader) == 0 || !strings.Contains(authHeader[0], "admin-token") {
		t.Errorf("modified request Authorization = %v, want admin-token", authHeader)
	}
}

// TestE2E_InterceptWorkflow_AuthChain verifies a multi-step authentication
// workflow: login to get token -> intercept next request -> inject token ->
// verify access -> resend with different token -> compare results.
func TestE2E_InterceptWorkflow_AuthChain(t *testing.T) {
	upstreamAddr := startAuthServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	client := proxyHTTPClient(startResult.ListenAddr)

	// Step 1: Send login request through proxy (not intercepted).
	loginURL := fmt.Sprintf("http://%s/login", upstreamAddr)
	loginResp, err := client.Post(loginURL, "text/plain", strings.NewReader("alice"))
	if err != nil {
		t.Fatalf("login request: %v", err)
	}
	loginBody, _ := io.ReadAll(loginResp.Body)
	loginResp.Body.Close()

	if loginResp.StatusCode != gohttp.StatusOK {
		t.Fatalf("login status = %d, want %d", loginResp.StatusCode, gohttp.StatusOK)
	}

	// Extract token from login response.
	var loginResult map[string]any
	if err := json.Unmarshal(loginBody, &loginResult); err != nil {
		t.Fatalf("unmarshal login response: %v", err)
	}
	token, ok := loginResult["token"].(string)
	if !ok || token == "" {
		t.Fatalf("login response missing token: %v", loginResult)
	}

	// Step 2: Configure intercept for /admin requests.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "rule-auth-chain",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": "/admin.*",
					},
				},
			},
		},
	})

	// Step 3: Send /admin request with viewer token (will be intercepted).
	adminURL := fmt.Sprintf("http://%s/admin", upstreamAddr)
	var (
		wg            sync.WaitGroup
		adminRespBody string
		adminRespCode int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		req, _ := gohttp.NewRequest("GET", adminURL, nil)
		req.Header.Set("Authorization", "Bearer viewer-token")
		resp, err := client.Do(req)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		adminRespCode = resp.StatusCode
		b, _ := io.ReadAll(resp.Body)
		adminRespBody = string(b)
	}()

	// Step 4: Wait for intercept and inject admin token.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for /admin request in intercept queue")
	}

	// Inject admin token (privilege escalation).
	_ = callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id": interceptID,
			"override_headers": map[string]string{
				"Authorization": "Bearer admin-token",
			},
		},
	})

	wg.Wait()

	// Admin should succeed with injected token.
	if adminRespCode != gohttp.StatusOK {
		t.Errorf("admin response code = %d, want %d", adminRespCode, gohttp.StatusOK)
	}
	if !strings.Contains(adminRespBody, "secret-admin-panel") {
		t.Errorf("admin body = %q, want to contain 'secret-admin-panel'", adminRespBody)
	}

	client.CloseIdleConnections()

	// Step 5: Wait for flows to be recorded.
	time.Sleep(500 * time.Millisecond)

	// Step 6: Find the admin flow for resend.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})

	var adminFlowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/admin") {
			adminFlowID = f.ID
			break
		}
	}
	if adminFlowID == "" {
		t.Fatal("could not find admin flow for resend")
	}

	// Step 7: Resend with a different (viewer) token to compare access levels.
	resendResult := callTool[resendActionResult](t, env.cs, "resend", map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": adminFlowID,
			"override_headers": map[string]any{
				"Authorization": "Bearer viewer-only-token",
			},
			"tag": "viewer-attempt",
		},
	})

	if resendResult.NewFlowID == "" {
		t.Error("resend new_flow_id is empty")
	}
	// Viewer token should get 403.
	if resendResult.StatusCode != gohttp.StatusForbidden {
		t.Errorf("resend status_code = %d, want %d", resendResult.StatusCode, gohttp.StatusForbidden)
	}
	if !strings.Contains(resendResult.ResponseBody, "forbidden") {
		t.Errorf("resend response_body = %q, want to contain 'forbidden'", resendResult.ResponseBody)
	}

	// Step 8: Compare the admin flow (200) with the resend flow (403).
	cmpResult := callTool[compareResult](t, env.cs, "resend", map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": adminFlowID,
			"flow_id_b": resendResult.NewFlowID,
		},
	})

	// Status codes should differ.
	if cmpResult.StatusCode == nil {
		t.Fatal("compare status_code is nil")
	}
	if !cmpResult.StatusCode.Changed {
		t.Error("compare status_code.changed = false, want true")
	}
	if cmpResult.StatusCode.A != gohttp.StatusOK {
		t.Errorf("compare status_code.a = %d, want %d", cmpResult.StatusCode.A, gohttp.StatusOK)
	}
	if cmpResult.StatusCode.B != gohttp.StatusForbidden {
		t.Errorf("compare status_code.b = %d, want %d", cmpResult.StatusCode.B, gohttp.StatusForbidden)
	}

	// Bodies should differ.
	if cmpResult.Body == nil {
		t.Fatal("compare body is nil")
	}
	if cmpResult.Body.Identical {
		t.Error("compare body.identical = true, want false (different responses)")
	}
}

// TestE2E_InterceptWorkflow_ParameterFuzzing verifies a parameter fuzzing
// workflow: send initial request -> resend multiple times with different
// parameters -> each result recorded as separate flow -> detect anomalous
// status codes.
func TestE2E_InterceptWorkflow_ParameterFuzzing(t *testing.T) {
	upstreamAddr := startAuthServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Step 1: Send initial request through proxy.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/data?id=1", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("initial request: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	// Wait for flow recording.
	time.Sleep(500 * time.Millisecond)

	// Step 2: Find the original flow.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if flowsResult.Count == 0 {
		t.Fatal("no flows recorded")
	}

	var originalFlowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/data") {
			originalFlowID = f.ID
			break
		}
	}
	if originalFlowID == "" {
		t.Fatal("could not find flow for /data")
	}

	// Step 3: Resend with different parameter values (fuzzing).
	fuzzCases := []struct {
		id             string
		tag            string
		wantStatusCode int
	}{
		{id: "9999", tag: "fuzz-not-found", wantStatusCode: 404},
		{id: "2", tag: "fuzz-normal", wantStatusCode: 200},
	}

	resendFlowIDs := make([]string, 0, len(fuzzCases))
	for _, fc := range fuzzCases {
		overrideURL := fmt.Sprintf("http://%s/data?id=%s", upstreamAddr, fc.id)
		resendResult := callTool[resendActionResult](t, env.cs, "resend", map[string]any{
			"action": "resend",
			"params": map[string]any{
				"flow_id":      originalFlowID,
				"override_url": overrideURL,
				"tag":          fc.tag,
			},
		})

		if resendResult.NewFlowID == "" {
			t.Errorf("resend %s: new_flow_id is empty", fc.tag)
			continue
		}
		resendFlowIDs = append(resendFlowIDs, resendResult.NewFlowID)

		if resendResult.StatusCode != fc.wantStatusCode {
			t.Errorf("resend %s: status_code = %d, want %d", fc.tag, resendResult.StatusCode, fc.wantStatusCode)
		}

		if resendResult.Tag != fc.tag {
			t.Errorf("resend %s: tag = %q, want %q", fc.tag, resendResult.Tag, fc.tag)
		}
	}

	// Step 4: Verify each resend flow is recorded individually.
	time.Sleep(300 * time.Millisecond)

	allFlows := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	// At least the original + 2 resend flows.
	if allFlows.Total < 3 {
		t.Errorf("total flows = %d, want at least 3 (1 original + 2 resends)", allFlows.Total)
	}

	// Step 5: Query each resend flow to verify it was recorded independently.
	for i, flowID := range resendFlowIDs {
		flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
			"resource": "flow",
			"id":       flowID,
		})
		if flowDetail.ID != flowID {
			t.Errorf("resend flow %d: ID = %q, want %q", i, flowDetail.ID, flowID)
		}
		if flowDetail.State != "complete" {
			t.Errorf("resend flow %d: state = %q, want complete", i, flowDetail.State)
		}
		if flowDetail.ResponseStatusCode != fuzzCases[i].wantStatusCode {
			t.Errorf("resend flow %d: response status = %d, want %d",
				i, flowDetail.ResponseStatusCode, fuzzCases[i].wantStatusCode)
		}
	}

	// Step 6: Compare the not-found result (404) with the normal result (200)
	// to detect the anomaly.
	if len(resendFlowIDs) >= 2 {
		cmpResult := callTool[compareResult](t, env.cs, "resend", map[string]any{
			"action": "compare",
			"params": map[string]any{
				"flow_id_a": resendFlowIDs[1], // normal (200)
				"flow_id_b": resendFlowIDs[0], // not-found (404)
			},
		})
		if cmpResult.StatusCode == nil {
			t.Fatal("compare status_code is nil")
		}
		if !cmpResult.StatusCode.Changed {
			t.Error("compare status_code.changed = false, want true (200 vs 404)")
		}
	}
}

// TestE2E_InterceptWorkflow_ResendHeaderOverride verifies that resend correctly
// applies header overrides (Cookie, Authorization) and they reach the upstream.
func TestE2E_InterceptWorkflow_ResendHeaderOverride(t *testing.T) {
	upstreamAddr := startAuthServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Send a request through proxy to create a flow.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/admin", upstreamAddr)
	req, _ := gohttp.NewRequest("GET", targetURL, nil)
	req.Header.Set("Authorization", "Bearer viewer-token")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("initial request: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	// The initial request should get 403 (viewer token).
	if resp.StatusCode != gohttp.StatusForbidden {
		t.Errorf("initial response code = %d, want %d", resp.StatusCode, gohttp.StatusForbidden)
	}

	// Wait for flow recording.
	time.Sleep(500 * time.Millisecond)

	// Find the flow.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	var flowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/admin") {
			flowID = f.ID
			break
		}
	}
	if flowID == "" {
		t.Fatal("could not find flow for /admin")
	}

	// Resend with admin Authorization header override.
	resendResult := callTool[resendActionResult](t, env.cs, "resend", map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
			"override_headers": map[string]any{
				"Authorization": "Bearer admin-token",
			},
		},
	})

	// The resend with admin token should get 200.
	if resendResult.StatusCode != gohttp.StatusOK {
		t.Errorf("resend status_code = %d, want %d", resendResult.StatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(resendResult.ResponseBody, "secret-admin-panel") {
		t.Errorf("resend response_body = %q, want to contain 'secret-admin-panel'", resendResult.ResponseBody)
	}
	if resendResult.NewFlowID == "" {
		t.Error("resend new_flow_id is empty")
	}

	// Verify the new flow is queryable.
	newFlowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       resendResult.NewFlowID,
	})
	if newFlowDetail.ResponseStatusCode != gohttp.StatusOK {
		t.Errorf("new flow response status = %d, want %d", newFlowDetail.ResponseStatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(newFlowDetail.ResponseBody, "secret-admin-panel") {
		t.Errorf("new flow response body = %q, want to contain 'secret-admin-panel'", newFlowDetail.ResponseBody)
	}

	// Compare the original (403) and resend (200) flows.
	cmpResult := callTool[compareResult](t, env.cs, "resend", map[string]any{
		"action": "compare",
		"params": map[string]any{
			"flow_id_a": flowID,
			"flow_id_b": resendResult.NewFlowID,
		},
	})
	if cmpResult.StatusCode == nil {
		t.Fatal("compare status_code is nil")
	}
	if !cmpResult.StatusCode.Changed {
		t.Error("compare status_code.changed = false, want true")
	}
	if cmpResult.StatusCode.A != gohttp.StatusForbidden {
		t.Errorf("compare status_code.a = %d, want %d", cmpResult.StatusCode.A, gohttp.StatusForbidden)
	}
	if cmpResult.StatusCode.B != gohttp.StatusOK {
		t.Errorf("compare status_code.b = %d, want %d", cmpResult.StatusCode.B, gohttp.StatusOK)
	}
}

// TestE2E_InterceptWorkflow_FlowRecordingCompleteness verifies that the
// intercept workflow produces complete flow records with correct protocol,
// flow type, state, and message content.
func TestE2E_InterceptWorkflow_FlowRecordingCompleteness(t *testing.T) {
	upstreamAddr := startAuthServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Configure intercept for all requests.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "rule-all",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/login", upstreamAddr)

	// Send POST with body.
	var (
		wg       sync.WaitGroup
		respCode int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Post(targetURL, "text/plain", strings.NewReader("testuser"))
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		respCode = resp.StatusCode
	}()

	// Wait for intercept.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			item := qResult.Items[0]
			// Verify the intercepted item carries the request body.
			if item.Body == "" {
				t.Error("intercepted item body is empty, expected request body")
			}
			if !strings.Contains(item.Body, "testuser") {
				t.Errorf("intercepted item body = %q, want to contain 'testuser'", item.Body)
			}
			interceptID = item.ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for request in intercept queue")
	}

	// Release without modification.
	_ = callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "release",
		"params": map[string]any{
			"intercept_id": interceptID,
		},
	})

	wg.Wait()
	client.CloseIdleConnections()

	if respCode != gohttp.StatusOK {
		t.Errorf("response code = %d, want %d", respCode, gohttp.StatusOK)
	}

	// Wait for flow recording.
	time.Sleep(500 * time.Millisecond)

	// Verify flow recording completeness.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if flowsResult.Total == 0 {
		t.Fatal("no flows recorded")
	}

	var flowEntry queryFlowsEntry
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/login") {
			flowEntry = f
			break
		}
	}
	if flowEntry.ID == "" {
		t.Fatal("could not find flow for /login")
	}

	// Verify flow metadata.
	if flowEntry.Protocol != "HTTP/1.x" {
		t.Errorf("flow protocol = %q, want HTTP/1.x", flowEntry.Protocol)
	}
	if flowEntry.FlowType != "unary" {
		t.Errorf("flow type = %q, want unary", flowEntry.FlowType)
	}
	if flowEntry.State != "complete" {
		t.Errorf("flow state = %q, want complete", flowEntry.State)
	}
	if flowEntry.Method != "POST" {
		t.Errorf("flow method = %q, want POST", flowEntry.Method)
	}
	if flowEntry.StatusCode != gohttp.StatusOK {
		t.Errorf("flow status_code = %d, want %d", flowEntry.StatusCode, gohttp.StatusOK)
	}

	// Verify detailed flow content.
	flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowEntry.ID,
	})

	// Request body should be recorded.
	if !strings.Contains(flowDetail.RequestBody, "testuser") {
		t.Errorf("flow request body = %q, want to contain 'testuser'", flowDetail.RequestBody)
	}

	// Response body should be recorded.
	if !strings.Contains(flowDetail.ResponseBody, "tok-") {
		t.Errorf("flow response body = %q, want to contain 'tok-'", flowDetail.ResponseBody)
	}

	// Response status code should be correct.
	if flowDetail.ResponseStatusCode != gohttp.StatusOK {
		t.Errorf("flow response status = %d, want %d", flowDetail.ResponseStatusCode, gohttp.StatusOK)
	}

	// Duration should be positive.
	if flowDetail.DurationMs < 0 {
		t.Errorf("flow duration = %d, want >= 0", flowDetail.DurationMs)
	}
}
