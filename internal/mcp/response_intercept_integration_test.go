//go:build e2e

package mcp

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- Response-side intercept e2e tests (USK-528) ---

// startSecurityHeaderServer starts an HTTP server that returns security headers
// and a JSON body. Used for testing response intercept scenarios relevant to
// pentest workflows: privilege escalation, information leak detection, and
// security header analysis.
func startSecurityHeaderServer(t *testing.T) string {
	t.Helper()

	handler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'self'")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Custom-Secret", "internal-token-12345")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, `{"user":"alice","role":"viewer","secret":"s3cret"}`)
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

// TestE2E_ResponseIntercept_Release verifies the response intercept lifecycle:
// configure direction:"response" rule -> send request -> response is held in
// queue -> agent inspects queue -> releases -> client receives original response.
func TestE2E_ResponseIntercept_Release(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Configure response intercept rule.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "resp-catch-all",
					"enabled":   true,
					"direction": "response",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/test", upstreamAddr)

	// Send request in background -- it will block waiting for response intercept.
	var (
		wg       sync.WaitGroup
		respBody string
		respCode int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		defer resp.Body.Close()
		respCode = resp.StatusCode
		b, _ := io.ReadAll(resp.Body)
		respBody = string(b)
	}()

	// Wait for the response to appear in the intercept queue.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			// Verify it is a response-phase intercept.
			if qResult.Items[0].Phase != "response" {
				t.Errorf("queue item phase = %q, want response", qResult.Items[0].Phase)
			}
			if qResult.Items[0].StatusCode != gohttp.StatusOK {
				t.Errorf("queue item status_code = %d, want %d", qResult.Items[0].StatusCode, gohttp.StatusOK)
			}
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for response to appear in intercept queue")
	}

	// Release the intercepted response.
	releaseResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "release",
		"params": map[string]any{
			"intercept_id": interceptID,
		},
	})
	if releaseResult.Action != "release" {
		t.Errorf("action = %q, want release", releaseResult.Action)
	}
	if releaseResult.Phase != "response" {
		t.Errorf("phase = %q, want response", releaseResult.Phase)
	}
	if releaseResult.StatusCode != gohttp.StatusOK {
		t.Errorf("status_code = %d, want %d", releaseResult.StatusCode, gohttp.StatusOK)
	}

	// Wait for client to finish and verify it got the original response.
	wg.Wait()
	if respCode != gohttp.StatusOK {
		t.Errorf("client response code = %d, want %d", respCode, gohttp.StatusOK)
	}
	if !strings.Contains(respBody, "alice") {
		t.Errorf("client response body = %q, want to contain 'alice'", respBody)
	}

	client.CloseIdleConnections()
}

// TestE2E_ResponseIntercept_ModifyAndForward verifies that a response can be
// intercepted and modified before forwarding to the client. This simulates
// a pentest scenario: removing security headers (CSP, X-Frame-Options) to
// assess XSS/Clickjacking impact, and modifying the response body.
func TestE2E_ResponseIntercept_ModifyAndForward(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Configure response intercept rule.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "resp-modify",
					"enabled":   true,
					"direction": "response",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/admin", upstreamAddr)

	var (
		wg         sync.WaitGroup
		clientResp *gohttp.Response
		clientBody string
		clientErr  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		clientResp, clientErr = client.Get(targetURL)
		if clientErr != nil {
			return
		}
		b, _ := io.ReadAll(clientResp.Body)
		clientResp.Body.Close()
		clientBody = string(b)
	}()

	// Wait for the response intercept.
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
		t.Fatal("timed out waiting for response intercept")
	}

	// Modify response: remove security headers, change body.
	modifiedBody := `{"user":"alice","role":"admin","secret":"s3cret"}`
	modResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":           interceptID,
			"override_response_body": modifiedBody,
			"remove_response_headers": []string{
				"Content-Security-Policy",
				"X-Frame-Options",
			},
			"add_response_headers": map[string]string{
				"X-Modified-By": "pentest-agent",
			},
		},
	})
	if modResult.Action != "modify_and_forward" {
		t.Errorf("action = %q, want modify_and_forward", modResult.Action)
	}
	if modResult.Phase != "response" {
		t.Errorf("phase = %q, want response", modResult.Phase)
	}

	// Wait for client to finish.
	wg.Wait()
	if clientErr != nil {
		t.Fatalf("client request failed: %v", clientErr)
	}

	// Verify the client received the modified response.
	if clientResp.StatusCode != gohttp.StatusOK {
		t.Errorf("client response code = %d, want %d", clientResp.StatusCode, gohttp.StatusOK)
	}

	// Body should be modified.
	if !strings.Contains(clientBody, `"role":"admin"`) {
		t.Errorf("client body = %q, want to contain modified role", clientBody)
	}

	// Security headers should be removed.
	if clientResp.Header.Get("Content-Security-Policy") != "" {
		t.Error("expected Content-Security-Policy to be removed")
	}
	if clientResp.Header.Get("X-Frame-Options") != "" {
		t.Error("expected X-Frame-Options to be removed")
	}

	// Added header should be present.
	if clientResp.Header.Get("X-Modified-By") != "pentest-agent" {
		t.Errorf("X-Modified-By = %q, want pentest-agent", clientResp.Header.Get("X-Modified-By"))
	}

	// Preserved header should still be present.
	if clientResp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", clientResp.Header.Get("X-Content-Type-Options"))
	}

	client.CloseIdleConnections()
}

// TestE2E_ResponseIntercept_Drop verifies that dropping an intercepted response
// returns an error (502) to the client. This tests the scenario where a pentest
// agent blocks a response entirely.
func TestE2E_ResponseIntercept_Drop(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "resp-drop",
					"enabled":   true,
					"direction": "response",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/blocked", upstreamAddr)

	var (
		wg       sync.WaitGroup
		respCode int
		respErr  error
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			respErr = err
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
		respCode = resp.StatusCode
	}()

	// Wait for the response intercept.
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
		t.Fatal("timed out waiting for response intercept")
	}

	// Drop the intercepted response.
	dropResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "drop",
		"params": map[string]any{
			"intercept_id": interceptID,
		},
	})
	if dropResult.Action != "drop" {
		t.Errorf("action = %q, want drop", dropResult.Action)
	}

	// Wait for client to finish.
	wg.Wait()

	// Client should receive a 502 Bad Gateway (or a connection error).
	if respErr != nil {
		// Connection error is also acceptable for drop.
		return
	}
	if respCode != 502 {
		t.Errorf("client response code = %d, want 502 (Bad Gateway)", respCode)
	}

	client.CloseIdleConnections()
}

// TestE2E_ResponseIntercept_RawModifyAndForward verifies that raw mode response
// intercept allows modifying the raw response bytes before forwarding to client.
func TestE2E_ResponseIntercept_RawModifyAndForward(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "resp-raw",
					"enabled":   true,
					"direction": "response",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/raw-resp", upstreamAddr)

	var (
		wg         sync.WaitGroup
		clientBody string
		clientCode int
	)
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		clientCode = resp.StatusCode
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		clientBody = string(b)
	}()

	// Wait for the response intercept.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			if qResult.Items[0].Phase != "response" {
				t.Errorf("queue item phase = %q, want response", qResult.Items[0].Phase)
			}
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for response intercept")
	}

	// Build a modified raw HTTP response.
	modifiedRaw := "HTTP/1.1 403 Forbidden\r\n" +
		"Content-Type: text/plain\r\n" +
		"X-Injected: raw-response\r\n" +
		"Content-Length: 16\r\n" +
		"\r\n" +
		"access forbidden"
	modifiedB64 := base64.StdEncoding.EncodeToString([]byte(modifiedRaw))

	modResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":        interceptID,
			"mode":                "raw",
			"raw_override_base64": modifiedB64,
		},
	})
	if modResult.Action != "modify_and_forward" {
		t.Errorf("action = %q, want modify_and_forward", modResult.Action)
	}

	// Wait for client to finish.
	wg.Wait()

	// The raw response should have been forwarded as-is.
	if clientCode != 403 {
		t.Errorf("client response code = %d, want 403", clientCode)
	}
	if !strings.Contains(clientBody, "access forbidden") {
		t.Errorf("client body = %q, want to contain 'access forbidden'", clientBody)
	}

	client.CloseIdleConnections()
}

// TestE2E_ResponseIntercept_VariantRecording verifies that when a response is
// intercepted and modified, both the original and modified response are recorded
// as variants in the flow store.
func TestE2E_ResponseIntercept_VariantRecording(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "resp-variant",
					"enabled":   true,
					"direction": "response",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/variant-resp", upstreamAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait for the response intercept.
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
		t.Fatal("timed out waiting for response intercept")
	}

	// Modify the response body to simulate privilege escalation testing.
	modifiedBody := `{"user":"alice","role":"admin","secret":"s3cret"}`
	_ = callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":           interceptID,
			"override_response_body": modifiedBody,
		},
	})

	wg.Wait()
	client.CloseIdleConnections()

	// Allow time for flow recording to complete.
	time.Sleep(500 * time.Millisecond)

	// Query all flows and find the one for our request.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if flowsResult.Total == 0 {
		t.Fatal("no flows recorded")
	}

	var flowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/api/variant-resp") {
			flowID = f.ID
			break
		}
	}
	if flowID == "" {
		t.Fatal("could not find flow for /api/variant-resp")
	}

	// Query the flow detail and verify variant recording.
	flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// The flow should have the modified response as the primary response.
	if flowDetail.ResponseStatusCode != gohttp.StatusOK {
		t.Errorf("response status = %d, want %d", flowDetail.ResponseStatusCode, gohttp.StatusOK)
	}

	// The response body should contain the modified content.
	if !strings.Contains(flowDetail.ResponseBody, `"role":"admin"`) {
		t.Errorf("response body = %q, want modified body with admin role", flowDetail.ResponseBody)
	}

	// OriginalResponse should be populated with the pre-modification data.
	if flowDetail.OriginalResponse == nil {
		t.Fatal("expected OriginalResponse to be non-nil (variant recording should preserve original response)")
	}
	if flowDetail.OriginalResponse.StatusCode != gohttp.StatusOK {
		t.Errorf("original response status = %d, want %d", flowDetail.OriginalResponse.StatusCode, gohttp.StatusOK)
	}
	if !strings.Contains(flowDetail.OriginalResponse.Body, `"role":"viewer"`) {
		t.Errorf("original response body = %q, want original body with viewer role", flowDetail.OriginalResponse.Body)
	}
}

// TestE2E_Resend_ResponseDetails verifies that the resend tool returns complete
// response details (status code, headers, body) enabling comparison analysis
// for privilege escalation testing.
func TestE2E_Resend_ResponseDetails(t *testing.T) {
	upstreamAddr := startSecurityHeaderServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// First, make a request through the proxy to create a flow.
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/resend-test", upstreamAddr)

	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("initial request failed: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()
	client.CloseIdleConnections()

	// Allow time for flow recording.
	time.Sleep(500 * time.Millisecond)

	// Find the flow.
	flowsResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	var flowID string
	for _, f := range flowsResult.Flows {
		if strings.Contains(f.URL, "/api/resend-test") {
			flowID = f.ID
			break
		}
	}
	if flowID == "" {
		t.Fatal("could not find flow for /api/resend-test")
	}

	// Resend the request and verify response details are returned.
	resendResult := callTool[resendActionResult](t, env.cs, "resend", map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": flowID,
		},
	})

	// Verify response status code.
	if resendResult.StatusCode != gohttp.StatusOK {
		t.Errorf("resend status_code = %d, want %d", resendResult.StatusCode, gohttp.StatusOK)
	}

	// Verify response body is returned.
	if !strings.Contains(resendResult.ResponseBody, "alice") {
		t.Errorf("resend response_body = %q, want to contain 'alice'", resendResult.ResponseBody)
	}

	// Verify response headers are returned.
	if resendResult.ResponseHeaders == nil {
		t.Fatal("resend response_headers is nil")
	}

	// Check specific security headers are present in the resend response.
	csp := resendResult.ResponseHeaders["Content-Security-Policy"]
	if len(csp) == 0 || csp[0] != "default-src 'self'" {
		t.Errorf("resend CSP header = %v, want [\"default-src 'self'\"]", csp)
	}

	xfo := resendResult.ResponseHeaders["X-Frame-Options"]
	if len(xfo) == 0 || xfo[0] != "DENY" {
		t.Errorf("resend X-Frame-Options = %v, want [\"DENY\"]", xfo)
	}

	// Verify a new flow ID was created for the resend.
	if resendResult.NewFlowID == "" {
		t.Error("resend new_flow_id is empty")
	}
}
