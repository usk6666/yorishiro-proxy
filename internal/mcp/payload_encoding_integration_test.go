//go:build e2e

package mcp

import (
	"context"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

// --- M18 Integration: Payload Encoding ---

// TestM18_Fuzz_WithEncoding verifies that fuzzing with an encoding chain
// applies codec transformations to generated payloads before injection.
func TestM18_Fuzz_WithEncoding(t *testing.T) {
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
					"type":     "wordlist",
					"values":   []any{"admin", "root"},
					"encoding": []any{"base64"},
				},
			},
			"tag": "m18-encoding-fuzz",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var fuzzResult fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &fuzzResult)

	if fuzzResult.FuzzID == "" {
		t.Fatal("expected non-empty fuzz_id")
	}
	if fuzzResult.TotalRequests != 2 {
		t.Errorf("total_requests = %d, want 2", fuzzResult.TotalRequests)
	}

	// Wait for completion.
	waitForFuzzCompletion(t, cs, fuzzResult.FuzzID, 10*time.Second)

	// Verify that payloads were base64-encoded in the requests.
	adminB64 := base64.StdEncoding.EncodeToString([]byte("admin"))
	rootB64 := base64.StdEncoding.EncodeToString([]byte("root"))

	foundAdmin := false
	foundRoot := false
	for _, body := range receivedBodies {
		if strings.Contains(body, adminB64) {
			foundAdmin = true
		}
		if strings.Contains(body, rootB64) {
			foundRoot = true
		}
	}
	if !foundAdmin {
		t.Errorf("expected base64-encoded 'admin' (%s) in request bodies, got: %v", adminB64, receivedBodies)
	}
	if !foundRoot {
		t.Errorf("expected base64-encoded 'root' (%s) in request bodies, got: %v", rootB64, receivedBodies)
	}
}

// TestM18_Fuzz_CharsetGenerator verifies that the charset generator type
// works correctly in a fuzz campaign.
func TestM18_Fuzz_CharsetGenerator(t *testing.T) {
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

	// charset "ab" with length 2 produces: aa, ab, ba, bb = 4 payloads
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
					"type":    "charset",
					"charset": "ab",
					"length":  2,
				},
			},
			"tag": "m18-charset-fuzz",
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

	// Verify charset payloads were injected.
	expected := []string{"aa", "ab", "ba", "bb"}
	for _, exp := range expected {
		found := false
		for _, body := range receivedBodies {
			if strings.Contains(body, `"`+exp+`"`) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected charset payload %q in request bodies", exp)
		}
	}
}

// TestM18_Resend_BodyPatchEncoding verifies that resend body patches with
// encoding apply codec transformations before patching.
func TestM18_Resend_BodyPatchEncoding(t *testing.T) {
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

	// Save a template flow with a JSON body containing a token field.
	ctx := context.Background()
	u, _ := url.Parse(targetServer.URL + "/api/auth")
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
		Body:      []byte(`{"token":"old_token","user":"test"}`),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	cs := setupResendTestSession(t, store, newPermissiveClient())

	// Resend with a body patch that encodes the value as base64.
	result := callResend(t, cs, map[string]any{
		"action": "resend",
		"params": map[string]any{
			"flow_id": fl.ID,
			"body_patches": []any{
				map[string]any{
					"json_path": "$.token",
					"value":     "my-secret-token",
					"encoding":  []any{"base64"},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("resend returned error: %v", result.Content)
	}

	// Verify the token was base64-encoded in the sent request.
	expectedEncoded := base64.StdEncoding.EncodeToString([]byte("my-secret-token"))
	if !strings.Contains(receivedBody, expectedEncoded) {
		t.Errorf("expected base64-encoded token %q in body, got: %s", expectedEncoded, receivedBody)
	}
}

// waitForFuzzCompletion polls fuzz_jobs until the given job completes or times out.
func waitForFuzzCompletion(t *testing.T, cs *gomcp.ClientSession, fuzzID string, timeout time.Duration) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for fuzz job %s to complete", fuzzID)
		default:
		}

		qResult := callQueryRaw(t, cs, map[string]any{
			"resource": "fuzz_jobs",
		})
		if qResult.IsError {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		var jobs queryFuzzJobsResult
		unmarshalQueryResultRaw(t, qResult, &jobs)

		for _, j := range jobs.Jobs {
			if j.ID == fuzzID && (j.Status == "completed" || j.Status == "error") {
				return
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// setupResendTestSession creates an MCP session suitable for resend tests.
func setupResendTestSession(t *testing.T, store flow.Store, doer *http.Client) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	s := NewServer(ctx, nil, store, nil)
	s.deps.replayDoer = doer
	ct, st := gomcp.NewInMemoryTransports()

	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "test-client",
		Version: "v0.0.1",
	}, nil)

	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs
}

// callResend is a helper that calls the resend tool.
func callResend(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(resend): %v", err)
	}
	return result
}

// Note: unmarshalExecuteResult is defined in macro_handlers_test.go
