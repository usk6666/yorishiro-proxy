//go:build e2e

package mcp

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- M3 Integration: Fuzzer ---

// callFuzz is a helper that calls the fuzz tool with the given arguments.
func callFuzz(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool(fuzz): %v", err)
	}
	return result
}

// setupFuzzTestSession creates an MCP client flow with a real fuzzer runner,
// backed by a real SQLite store (which satisfies both flow.Store and flow.FuzzStore).
func setupFuzzTestSession(t *testing.T, store flow.Store, fuzzStore flow.FuzzStore, doer *http.Client) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	engine := fuzzer.NewEngine(store, store, fuzzStore, doer, "")
	registry := fuzzer.NewJobRegistry()
	runner := fuzzer.NewRunner(engine, registry)

	s := NewServer(ctx, nil, store, nil,
		WithFuzzRunner(runner),
		WithFuzzStore(fuzzStore),
	)
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

// newFuzzTestStore creates a SQLite store that satisfies both flow.Store and flow.FuzzStore.
func newFuzzTestStore(t *testing.T) *flow.SQLiteStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "fuzz_test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(context.Background(), dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })
	return store
}

// saveFuzzTemplateSession creates a template flow suitable for fuzzing.
func saveFuzzTemplateSession(t *testing.T, store flow.Store, serverURL string) string {
	t.Helper()
	ctx := context.Background()

	u, _ := url.Parse(serverURL + "/api/login")
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
		Body:      []byte(`{"username":"admin","password":"password123"}`),
	}
	if err := store.AppendMessage(ctx, sendMsg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	return fl.ID
}

// TestM3_Fuzz_Sequential verifies that a sequential fuzz campaign executes all
// payload combinations, records results in the DB, and reports completion.
func TestM3_Fuzz_Sequential(t *testing.T) {
	store := newFuzzTestStore(t)

	// Target server that accepts any request.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(body)
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// Start a sequential fuzz job with a small wordlist.
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
					"type":   "wordlist",
					"values": []any{"admin", "root", "test"},
				},
			},
			"tag": "m3-seq-fuzz",
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
	if fuzzResult.Status != "running" {
		t.Errorf("status = %q, want running", fuzzResult.Status)
	}
	if fuzzResult.TotalRequests != 3 {
		t.Errorf("total_requests = %d, want 3", fuzzResult.TotalRequests)
	}
	if fuzzResult.Tag != "m3-seq-fuzz" {
		t.Errorf("tag = %q, want m3-seq-fuzz", fuzzResult.Tag)
	}

	// Wait for the fuzz job to complete.
	fuzzID := fuzzResult.FuzzID
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for fuzz job to complete")
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

		found := false
		for _, j := range jobs.Jobs {
			if j.ID == fuzzID {
				found = true
				if j.Status == "completed" || j.Status == "error" {
					// Job completed, verify results.
					goto done
				}
			}
		}
		if !found {
			t.Fatal("fuzz job not found in query")
		}
		time.Sleep(200 * time.Millisecond)
	}

done:
	// Query fuzz results for this job.
	rResult := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  fuzzID,
	})
	if rResult.IsError {
		t.Fatalf("query fuzz_results returned error: %v", rResult.Content)
	}

	var fuzzResults queryFuzzResultsResult
	unmarshalQueryResultRaw(t, rResult, &fuzzResults)

	if fuzzResults.Total != 3 {
		t.Errorf("fuzz_results total = %d, want 3", fuzzResults.Total)
	}
	if fuzzResults.Count < 1 {
		t.Errorf("fuzz_results count = %d, want >= 1", fuzzResults.Count)
	}
}

// TestM3_Fuzz_PauseResume verifies that a running fuzz job can be paused and resumed.
func TestM3_Fuzz_PauseResume(t *testing.T) {
	store := newFuzzTestStore(t)

	// A slow server to give us time to pause.
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(50 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// Start a fuzz job with many payloads so it takes a while.
	payloads := make([]any, 50)
	for i := range payloads {
		payloads[i] = "payload-" + time.Now().Format("150405") + "-" + string(rune('a'+i%26))
	}

	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-pw",
					"location":    "body_json",
					"json_path":   "$.password",
					"payload_set": "pos-pw",
				},
			},
			"payload_sets": map[string]any{
				"pos-pw": map[string]any{
					"type":   "wordlist",
					"values": payloads,
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)
	fuzzID := ar.FuzzID

	// Give it a moment to start processing.
	time.Sleep(200 * time.Millisecond)

	// Pause the job.
	pauseResult := callFuzz(t, cs, map[string]any{
		"action": "fuzz_pause",
		"params": map[string]any{"fuzz_id": fuzzID},
	})
	if pauseResult.IsError {
		t.Fatalf("fuzz_pause returned error: %v", pauseResult.Content)
	}

	var pauseOut executeFuzzControlResult
	unmarshalExecuteResult(t, pauseResult, &pauseOut)
	if pauseOut.Status != "paused" {
		t.Errorf("pause status = %q, want paused", pauseOut.Status)
	}

	// Resume the job.
	resumeResult := callFuzz(t, cs, map[string]any{
		"action": "fuzz_resume",
		"params": map[string]any{"fuzz_id": fuzzID},
	})
	if resumeResult.IsError {
		t.Fatalf("fuzz_resume returned error: %v", resumeResult.Content)
	}

	var resumeOut executeFuzzControlResult
	unmarshalExecuteResult(t, resumeResult, &resumeOut)
	if resumeOut.Status != "running" {
		t.Errorf("resume status = %q, want running", resumeOut.Status)
	}

	// Cancel the job to clean up (don't wait for all 50 payloads).
	cancelResult := callFuzz(t, cs, map[string]any{
		"action": "fuzz_cancel",
		"params": map[string]any{"fuzz_id": fuzzID},
	})
	if cancelResult.IsError {
		t.Fatalf("fuzz_cancel returned error: %v", cancelResult.Content)
	}
}

// TestM3_Fuzz_Cancel verifies that a running fuzz job can be cancelled.
func TestM3_Fuzz_Cancel(t *testing.T) {
	store := newFuzzTestStore(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// Start with a large number of payloads.
	payloads := make([]any, 100)
	for i := range payloads {
		payloads[i] = "val-" + string(rune('A'+i%26))
	}

	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-pw",
					"location":    "body_json",
					"json_path":   "$.password",
					"payload_set": "pos-pw",
				},
			},
			"payload_sets": map[string]any{
				"pos-pw": map[string]any{
					"type":   "wordlist",
					"values": payloads,
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)
	fuzzID := ar.FuzzID

	time.Sleep(100 * time.Millisecond)

	// Cancel.
	cancelResult := callFuzz(t, cs, map[string]any{
		"action": "fuzz_cancel",
		"params": map[string]any{"fuzz_id": fuzzID},
	})
	if cancelResult.IsError {
		t.Fatalf("fuzz_cancel returned error: %v", cancelResult.Content)
	}

	var cancelOut executeFuzzControlResult
	unmarshalExecuteResult(t, cancelResult, &cancelOut)
	if cancelOut.FuzzID != fuzzID {
		t.Errorf("fuzz_id = %q, want %q", cancelOut.FuzzID, fuzzID)
	}
	if cancelOut.Action != "fuzz_cancel" {
		t.Errorf("action = %q, want fuzz_cancel", cancelOut.Action)
	}

	// Wait a moment, then verify the job is in a terminal state.
	time.Sleep(500 * time.Millisecond)

	qResult := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
	})
	if !qResult.IsError {
		var jobs queryFuzzJobsResult
		unmarshalQueryResultRaw(t, qResult, &jobs)
		for _, j := range jobs.Jobs {
			if j.ID == fuzzID {
				if j.Status == "running" {
					t.Errorf("job still running after cancel")
				}
				// completed < total proves early cancellation.
				if j.CompletedCount >= j.Total {
					// It completed all before the cancel took effect -- acceptable.
					t.Logf("job completed all %d items before cancel", j.Total)
				}
			}
		}
	}
}

// TestM3_Fuzz_StopOnStatusCode verifies that a fuzz job automatically stops
// when a specific response status code is received.
func TestM3_Fuzz_StopOnStatusCode(t *testing.T) {
	store := newFuzzTestStore(t)

	var requestCount atomic.Int32
	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		body, _ := io.ReadAll(r.Body)
		var parsed map[string]any
		json.Unmarshal(body, &parsed)

		// Return 403 when password is "forbidden".
		if pw, ok := parsed["password"].(string); ok && pw == "forbidden" {
			w.WriteHeader(403)
			w.Write([]byte(`{"error":"forbidden"}`))
			return
		}
		w.WriteHeader(200)
		w.Write([]byte(`{"ok":true}`))
	}))
	defer targetServer.Close()

	sessID := saveFuzzTemplateSession(t, store, targetServer.URL)
	cs := setupFuzzTestSession(t, store, store, newPermissiveClient())

	// "forbidden" appears at position 3, so the job should stop before processing all 5.
	result := callFuzz(t, cs, map[string]any{
		"action": "fuzz",
		"params": map[string]any{
			"flow_id":     sessID,
			"attack_type": "sequential",
			"positions": []any{
				map[string]any{
					"id":          "pos-pw",
					"location":    "body_json",
					"json_path":   "$.password",
					"payload_set": "pos-pw",
				},
			},
			"payload_sets": map[string]any{
				"pos-pw": map[string]any{
					"type":   "wordlist",
					"values": []any{"admin", "test", "forbidden", "should-not-reach-1", "should-not-reach-2"},
				},
			},
			"stop_on": map[string]any{
				"status_codes": []any{403},
			},
			"tag": "stop-on-403",
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)

	// Wait for the job to complete.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for fuzz job")
		default:
		}

		qr := callQueryRaw(t, cs, map[string]any{"resource": "fuzz_jobs"})
		if qr.IsError {
			time.Sleep(100 * time.Millisecond)
			continue
		}
		var jobs queryFuzzJobsResult
		unmarshalQueryResultRaw(t, qr, &jobs)

		for _, j := range jobs.Jobs {
			if j.ID == ar.FuzzID && (j.Status == "completed" || j.Status == "error") {
				goto done
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
done:
	// The job should have stopped early (not all 5 payloads processed).
	// It could have processed at most 3 (admin, test, forbidden).
	if rc := requestCount.Load(); rc > 4 {
		t.Errorf("requestCount = %d, expected <= 4 (stop-on 403 should halt early)", rc)
	}
}

// TestM3_Fuzz_QueryFuzzResults verifies that fuzz results can be queried with
// filtering and summary statistics.
func TestM3_Fuzz_QueryFuzzResults(t *testing.T) {
	store := newFuzzTestStore(t)

	targetServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
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
					"id":          "pos-pw",
					"location":    "body_json",
					"json_path":   "$.password",
					"payload_set": "pos-pw",
				},
			},
			"payload_sets": map[string]any{
				"pos-pw": map[string]any{
					"type":   "wordlist",
					"values": []any{"a", "b"},
				},
			},
		},
	})
	if result.IsError {
		t.Fatalf("fuzz returned error: %v", result.Content)
	}

	var ar fuzzer.AsyncResult
	unmarshalExecuteResult(t, result, &ar)

	// Wait for completion.
	deadline := time.After(10 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("timed out waiting for fuzz job")
		default:
		}
		qr := callQueryRaw(t, cs, map[string]any{"resource": "fuzz_jobs"})
		if !qr.IsError {
			var jobs queryFuzzJobsResult
			unmarshalQueryResultRaw(t, qr, &jobs)
			for _, j := range jobs.Jobs {
				if j.ID == ar.FuzzID && (j.Status == "completed" || j.Status == "error") {
					goto done
				}
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
done:

	// Query with summary.
	rr := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  ar.FuzzID,
	})
	if rr.IsError {
		t.Fatalf("query fuzz_results error: %v", rr.Content)
	}

	var fuzzResults queryFuzzResultsResult
	unmarshalQueryResultRaw(t, rr, &fuzzResults)

	if fuzzResults.Total != 2 {
		t.Errorf("total = %d, want 2", fuzzResults.Total)
	}
	if fuzzResults.Summary == nil {
		t.Fatal("summary is nil")
	}
	if fuzzResults.Summary.StatusDistribution == nil {
		t.Error("status_distribution is nil")
	}
}
