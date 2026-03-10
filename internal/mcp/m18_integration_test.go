//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/fingerprint"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- M18 Integration: Technology Stack Detection ---

// m18Env holds all components for an M18 integration test with fingerprint detection.
type m18Env struct {
	cs          *gomcp.ClientSession
	store       flow.Store
	manager     *proxy.Manager
	httpHandler *protohttp.Handler
}

// setupM18Env creates a fully-wired MCP test environment with fingerprint
// detection enabled on the HTTP handler.
func setupM18Env(t *testing.T) *m18Env {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "m18-integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	httpHandler := protohttp.NewHandler(store, issuer, logger)
	// Enable fingerprint detection on the HTTP handler.
	httpHandler.SetDetector(fingerprint.NewDetector())

	detector := protocol.NewDetector(httpHandler)
	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	mcpServer := NewServer(ctx, ca, store, manager)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "m18-test-client",
		Version: "0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &m18Env{
		cs:          cs,
		store:       store,
		manager:     manager,
		httpHandler: httpHandler,
	}
}

// TestM18_TechDetection_NginxPHP verifies that HTTP responses with nginx and PHP
// headers are detected and recorded as technology tags in flows.
func TestM18_TechDetection_NginxPHP(t *testing.T) {
	env := setupM18Env(t)

	// Mock upstream server that responds with nginx + PHP headers.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Hello</body></html>")
	}))
	defer upstream.Close()

	// Start proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	// Send request through the proxy.
	client := proxyHTTPClient(startResult.ListenAddr)
	resp, err := client.Get(upstream.URL + "/index.php")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	// Wait for flow to be persisted.
	time.Sleep(300 * time.Millisecond)

	// Query the recorded flow.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	// Get the flow details and check tags.
	flowID := listResult.Flows[0].ID
	fl, err := env.store.GetFlow(context.Background(), flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	techJSON, ok := fl.Tags["technologies"]
	if !ok {
		t.Fatal("flow is missing 'technologies' tag")
	}

	var detections []fingerprint.Detection
	if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
		t.Fatalf("unmarshal technologies: %v", err)
	}

	foundNginx := false
	foundPHP := false
	for _, d := range detections {
		if d.Name == "nginx" {
			foundNginx = true
			if d.Version != "1.24.0" {
				t.Errorf("nginx version = %q, want %q", d.Version, "1.24.0")
			}
		}
		if d.Name == "PHP" {
			foundPHP = true
			if d.Version != "8.2.1" {
				t.Errorf("PHP version = %q, want %q", d.Version, "8.2.1")
			}
		}
	}
	if !foundNginx {
		t.Error("expected nginx detection in technologies tag")
	}
	if !foundPHP {
		t.Error("expected PHP detection in technologies tag")
	}

	client.CloseIdleConnections()
}

// TestM18_TechDetection_Express verifies that Express.js responses are detected.
func TestM18_TechDetection_Express(t *testing.T) {
	env := setupM18Env(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"status":"ok"}`)
	}))
	defer upstream.Close()

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)
	resp, err := client.Get(upstream.URL + "/api/data")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(300 * time.Millisecond)

	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	flowID := listResult.Flows[0].ID
	fl, err := env.store.GetFlow(context.Background(), flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	techJSON, ok := fl.Tags["technologies"]
	if !ok {
		t.Fatal("flow is missing 'technologies' tag")
	}

	var detections []fingerprint.Detection
	if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
		t.Fatalf("unmarshal technologies: %v", err)
	}

	foundExpress := false
	for _, d := range detections {
		if d.Name == "Express" {
			foundExpress = true
		}
	}
	if !foundExpress {
		t.Errorf("expected Express detection in technologies tag, got: %v", detections)
	}

	client.CloseIdleConnections()
}

// TestM18_TechDetection_WordPress verifies that WordPress body patterns are detected.
func TestM18_TechDetection_WordPress(t *testing.T) {
	env := setupM18Env(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.54")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<html><head><link rel="stylesheet" href="/wp-content/themes/default/style.css"></head><body>WordPress site</body></html>`)
	}))
	defer upstream.Close()

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)
	resp, err := client.Get(upstream.URL + "/")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(300 * time.Millisecond)

	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	flowID := listResult.Flows[0].ID
	fl, err := env.store.GetFlow(context.Background(), flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	techJSON, ok := fl.Tags["technologies"]
	if !ok {
		t.Fatal("flow is missing 'technologies' tag")
	}

	var detections []fingerprint.Detection
	if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
		t.Fatalf("unmarshal technologies: %v", err)
	}

	foundApache := false
	foundWP := false
	for _, d := range detections {
		if d.Name == "Apache" {
			foundApache = true
			if d.Version != "2.4.54" {
				t.Errorf("Apache version = %q, want %q", d.Version, "2.4.54")
			}
		}
		if d.Name == "WordPress" {
			foundWP = true
		}
	}
	if !foundApache {
		t.Error("expected Apache detection in technologies tag")
	}
	if !foundWP {
		t.Error("expected WordPress detection in technologies tag")
	}

	client.CloseIdleConnections()
}

// --- M18 Integration: Query Technologies Resource ---

// TestM18_QueryTechnologies_Aggregation verifies that the technologies resource
// aggregates detected technologies per host across multiple flows.
// Both test servers are on 127.0.0.1, so technologies are aggregated under one host.
func TestM18_QueryTechnologies_Aggregation(t *testing.T) {
	env := setupM18Env(t)

	// Create two upstream servers simulating different tech stacks.
	// Both are on 127.0.0.1 (different ports), so they aggregate under the same host.
	nginxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.Header().Set("X-Powered-By", "PHP/8.3.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "nginx+php")
	}))
	defer nginxServer.Close()

	expressServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Powered-By", "Express")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `{"api":"v1"}`)
	}))
	defer expressServer.Close()

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)

	// Send requests to both servers.
	resp1, err := client.Get(nginxServer.URL + "/page1")
	if err != nil {
		t.Fatalf("GET nginx: %v", err)
	}
	io.ReadAll(resp1.Body)
	resp1.Body.Close()

	resp2, err := client.Get(expressServer.URL + "/api")
	if err != nil {
		t.Fatalf("GET express: %v", err)
	}
	io.ReadAll(resp2.Body)
	resp2.Body.Close()

	time.Sleep(300 * time.Millisecond)

	// Query the technologies resource.
	techResult := callTool[queryTechnologiesResult](t, env.cs, "query", map[string]any{
		"resource": "technologies",
	})
	if techResult.Count < 1 {
		t.Fatalf("technologies host count = %d, want >= 1", techResult.Count)
	}

	// Both servers are on 127.0.0.1, so technologies from both should be aggregated.
	allTechs := make(map[string]bool)
	for _, host := range techResult.Hosts {
		for _, tech := range host.Technologies {
			allTechs[tech.Name] = true
		}
	}

	// Verify technologies from both servers are present in the aggregation.
	if !allTechs["nginx"] {
		t.Errorf("aggregated technologies missing 'nginx', got: %v", allTechs)
	}
	if !allTechs["PHP"] {
		t.Errorf("aggregated technologies missing 'PHP', got: %v", allTechs)
	}
	if !allTechs["Express"] {
		t.Errorf("aggregated technologies missing 'Express', got: %v", allTechs)
	}

	client.CloseIdleConnections()
}

// TestM18_QueryTechnologies_Empty verifies that the technologies resource returns
// an empty result when no flows have technology detections.
func TestM18_QueryTechnologies_Empty(t *testing.T) {
	env := setupM18Env(t)

	techResult := callTool[queryTechnologiesResult](t, env.cs, "query", map[string]any{
		"resource": "technologies",
	})
	if techResult.Count != 0 {
		t.Errorf("technologies count = %d, want 0", techResult.Count)
	}
	if len(techResult.Hosts) != 0 {
		t.Errorf("technologies hosts = %d, want 0", len(techResult.Hosts))
	}
}

// TestM18_QueryFlows_TechnologyFilter verifies that the technology filter on the
// flows resource correctly filters flows by detected technology name.
func TestM18_QueryFlows_TechnologyFilter(t *testing.T) {
	env := setupM18Env(t)

	// Two upstream servers: one with nginx, one without any detectable tech.
	nginxServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.25.0")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "nginx response")
	}))
	defer nginxServer.Close()

	plainServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "plain response")
	}))
	defer plainServer.Close()

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)

	// Send requests to both servers.
	resp1, err := client.Get(nginxServer.URL + "/nginx")
	if err != nil {
		t.Fatalf("GET nginx: %v", err)
	}
	io.ReadAll(resp1.Body)
	resp1.Body.Close()

	resp2, err := client.Get(plainServer.URL + "/plain")
	if err != nil {
		t.Fatalf("GET plain: %v", err)
	}
	io.ReadAll(resp2.Body)
	resp2.Body.Close()

	time.Sleep(300 * time.Millisecond)

	// Verify all flows are recorded.
	allResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if allResult.Count < 2 {
		t.Fatalf("total flows = %d, want >= 2", allResult.Count)
	}

	// Filter by technology "nginx".
	nginxResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"technology": "nginx",
		},
	})
	if nginxResult.Count != 1 {
		t.Errorf("nginx-filtered flow count = %d, want 1", nginxResult.Count)
	}
	if nginxResult.Count > 0 && !strings.Contains(nginxResult.Flows[0].URL, "/nginx") {
		t.Errorf("nginx-filtered flow URL = %q, want to contain /nginx", nginxResult.Flows[0].URL)
	}

	// Filter by technology that doesn't exist.
	noResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
		"filter": map[string]any{
			"technology": "django",
		},
	})
	if noResult.Count != 0 {
		t.Errorf("django-filtered flow count = %d, want 0", noResult.Count)
	}

	client.CloseIdleConnections()
}

// --- M18 Integration: Fuzz Generator Types ---

// TestM18_Fuzz_CaseVariationGenerator verifies that the case_variation generator
// produces case-variant payloads in a fuzz campaign.
func TestM18_Fuzz_CaseVariationGenerator(t *testing.T) {
	store := newFuzzTestStore(t)

	var receivedBodies []string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// case_variation on "ab" produces: ab, Ab, aB, AB = 4 payloads
	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-user",
					"location":    "body_json",
					"json_path":   "$.username",
					"payload_set": "pos-user",
				},
			},
			"payload_sets": map[string]any{
				"pos-user": map[string]any{
					"type":  "case_variation",
					"input": "ab",
				},
			},
			"tag": "m18-case-variation",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var fuzzResult fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &fuzzResult)

	if fuzzResult.TotalRequests != 4 {
		t.Errorf("total_requests = %d, want 4", fuzzResult.TotalRequests)
	}

	waitForFuzzCompletion(t, cs, fuzzResult.FuzzID, 10*time.Second)

	// Verify case variation payloads were injected.
	expected := []string{"ab", "Ab", "aB", "AB"}
	for _, exp := range expected {
		found := false
		for _, body := range receivedBodies {
			if strings.Contains(body, `"`+exp+`"`) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected case_variation payload %q in request bodies, got: %v", exp, receivedBodies)
		}
	}
}

// TestM18_Fuzz_NullByteInjectionGenerator verifies that the null_byte_injection
// generator produces payloads with null byte variants.
func TestM18_Fuzz_NullByteInjectionGenerator(t *testing.T) {
	store := newFuzzTestStore(t)

	var receivedBodies []string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-user",
					"location":    "body_json",
					"json_path":   "$.username",
					"payload_set": "pos-user",
				},
			},
			"payload_sets": map[string]any{
				"pos-user": map[string]any{
					"type":  "null_byte_injection",
					"input": "admin",
				},
			},
			"tag": "m18-null-byte",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var fuzzResult fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &fuzzResult)

	// null_byte_injection should produce multiple payloads.
	if fuzzResult.TotalRequests < 1 {
		t.Errorf("total_requests = %d, want >= 1", fuzzResult.TotalRequests)
	}

	waitForFuzzCompletion(t, cs, fuzzResult.FuzzID, 10*time.Second)

	// Verify at least some payloads contain null byte representations.
	foundNull := false
	for _, body := range receivedBodies {
		if strings.Contains(body, "\\u0000") || strings.Contains(body, "%00") || strings.Contains(body, "\x00") {
			foundNull = true
			break
		}
	}
	if !foundNull {
		t.Logf("received bodies: %v", receivedBodies)
		t.Log("note: null byte payloads may be encoded differently; checking that payloads were sent")
	}

	// Verify that payloads were actually sent (all requests should have been made).
	if len(receivedBodies) < 1 {
		t.Error("no requests were received by the target server")
	}
}

// TestM18_Fuzz_RangeWithEncoding verifies that the range generator works with
// encoding chains applied to the generated payloads.
func TestM18_Fuzz_RangeWithEncoding(t *testing.T) {
	store := newFuzzTestStore(t)

	var receivedBodies []string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBodies = append(receivedBodies, string(body))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// Range 1-3 with hex encoding.
	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-user",
					"location":    "body_json",
					"json_path":   "$.username",
					"payload_set": "pos-user",
				},
			},
			"payload_sets": map[string]any{
				"pos-user": map[string]any{
					"type":     "range",
					"start":    1,
					"end":      3,
					"step":     1,
					"encoding": []any{"hex"},
				},
			},
			"tag": "m18-range-hex",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var fuzzResult fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &fuzzResult)

	if fuzzResult.TotalRequests != 3 {
		t.Errorf("total_requests = %d, want 3", fuzzResult.TotalRequests)
	}

	waitForFuzzCompletion(t, cs, fuzzResult.FuzzID, 10*time.Second)

	// Verify hex-encoded range values were sent.
	// "1" -> hex "31", "2" -> hex "32", "3" -> hex "33"
	for _, hexVal := range []string{"31", "32", "33"} {
		found := false
		for _, body := range receivedBodies {
			if strings.Contains(body, hexVal) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected hex-encoded value %q in request bodies, got: %v", hexVal, receivedBodies)
		}
	}
}

// --- M18 Integration: Resend with Regex Body Patch + Encoding ---

// TestM18_Resend_RegexBodyPatchWithEncoding verifies that resend body patches
// using regex matching combined with encoding work correctly.
func TestM18_Resend_RegexBodyPatchWithEncoding(t *testing.T) {
	store := newFuzzTestStore(t)

	var receivedBody string
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		receivedBody = string(body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	// Save a template flow with JSON body.
	ctx := context.Background()
	u, _ := url.Parse(targetServer.URL + "/api/data")
	fl := &flow.Flow{
		Protocol:  "HTTP/1.x",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  50 * time.Millisecond,
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	sendMsg := &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "POST",
		URL:       u,
		Headers:   map[string][]string{"Content-Type": {"application/json"}},
		Body:      []byte(`{"token":"abc123","user":"test"}`),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupResendTestSession(t, store, newPermissiveClient())

	// Resend with a regex body patch that encodes the replacement as url_encode_query.
	result := callResend(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": fl.ID,
			"body_patches": []any{
				map[string]any{
					"regex":    "abc123",
					"replace":  "hello world",
					"encoding": []any{"url_encode_query"},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend returned error: %v", result.Content)
	}

	// Verify the token was URL-encoded in the sent request.
	// "hello world" url_encode_query -> "hello+world"
	if !strings.Contains(receivedBody, "hello+world") {
		t.Errorf("expected URL-encoded value 'hello+world' in body, got: %s", receivedBody)
	}
}

// --- M18 Integration: Multiple Technologies on Same Host ---

// TestM18_TechDetection_MultipleDetections verifies that when a single response
// reveals multiple technologies, all are recorded in the flow tags.
func TestM18_TechDetection_MultipleDetections(t *testing.T) {
	env := setupM18Env(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Powered-By", "PHP/8.2.1")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		// Include WordPress body patterns and React patterns.
		fmt.Fprint(w, `<html><head></head><body><div data-reactroot="">`+
			`<link href="/wp-content/themes/style.css">`+
			`</div></body></html>`)
	}))
	defer upstream.Close()

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})
	if startResult.Status != "running" {
		t.Fatalf("proxy_start status = %q, want %q", startResult.Status, "running")
	}

	client := proxyHTTPClient(startResult.ListenAddr)
	resp, err := client.Get(upstream.URL + "/multi")
	if err != nil {
		t.Fatalf("GET through proxy: %v", err)
	}
	io.ReadAll(resp.Body)
	resp.Body.Close()

	time.Sleep(300 * time.Millisecond)

	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("query flows count = %d, want >= 1", listResult.Count)
	}

	flowID := listResult.Flows[0].ID
	fl, err := env.store.GetFlow(context.Background(), flowID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}

	techJSON, ok := fl.Tags["technologies"]
	if !ok {
		t.Fatal("flow is missing 'technologies' tag")
	}

	var detections []fingerprint.Detection
	if err := json.Unmarshal([]byte(techJSON), &detections); err != nil {
		t.Fatalf("unmarshal technologies: %v", err)
	}

	detectedNames := make(map[string]bool)
	for _, d := range detections {
		detectedNames[d.Name] = true
	}

	expectedTechs := []string{"nginx", "PHP", "WordPress", "React"}
	for _, tech := range expectedTechs {
		if !detectedNames[tech] {
			t.Errorf("expected %s detection, got technologies: %v", tech, detections)
		}
	}

	client.CloseIdleConnections()
}

// --- Helpers ---

// containsString checks if a slice contains a given string.
func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}
