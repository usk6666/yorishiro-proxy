package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// newTestFuzzStore returns a *session.SQLiteStore that satisfies both session.Store
// and session.FuzzStore for testing.
func newTestFuzzStore(t *testing.T) *session.SQLiteStore {
	t.Helper()
	return newTestSQLiteStore(t)
}

// newTestSQLiteStore creates an SQLiteStore for testing (returns concrete type).
func newTestSQLiteStore(t *testing.T) *session.SQLiteStore {
	t.Helper()
	store := newTestStore(t)
	// newTestStore returns session.Store; we know it's *session.SQLiteStore in tests.
	sqlStore, ok := store.(*session.SQLiteStore)
	if !ok {
		t.Fatalf("expected *session.SQLiteStore, got %T", store)
	}
	return sqlStore
}

// setupFuzzQueryTestSession creates an MCP client session for fuzz query tests
// with both store and fuzzStore configured.
func setupFuzzQueryTestSession(t *testing.T, store session.Store, fuzzStore session.FuzzStore) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()

	opts := []ServerOption{}
	if fuzzStore != nil {
		opts = append(opts, WithFuzzStore(fuzzStore))
	}

	s := NewServer(ctx, nil, store, nil, opts...)
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

// seedFuzzJob creates a fuzz job in the store for testing.
func seedFuzzJob(t *testing.T, store session.FuzzStore, status, tag string) *session.FuzzJob {
	t.Helper()
	ctx := context.Background()

	job := &session.FuzzJob{
		SessionID: "sess-template",
		Config:    `{"attack_type":"sequential"}`,
		Status:    status,
		Tag:       tag,
		CreatedAt: time.Now().UTC(),
		Total:     10,
	}

	if status == "completed" {
		now := time.Now().UTC()
		job.CompletedAt = &now
		job.CompletedCount = 10
	}

	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}
	return job
}

// seedFuzzResult creates a fuzz result in the store for testing.
func seedFuzzResult(t *testing.T, store *session.SQLiteStore, fuzzID string, index, statusCode, durationMs int, body string) *session.FuzzResult {
	t.Helper()
	ctx := context.Background()

	// Create a result session with a receive message.
	sess := &session.Session{
		Protocol:    "HTTP/1.x",
		SessionType: "unary",
		State:       "complete",
		Timestamp:   time.Now(),
	}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}

	// Append receive message with body.
	msg := &session.Message{
		ID:         sess.ID + "-recv",
		SessionID:  sess.ID,
		Sequence:   0,
		Direction:  "receive",
		Timestamp:  time.Now(),
		StatusCode: statusCode,
		Body:       []byte(body),
	}
	if err := store.AppendMessage(ctx, msg); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	result := &session.FuzzResult{
		FuzzID:         fuzzID,
		IndexNum:       index,
		SessionID:      sess.ID,
		Payloads:       `{"pos-0":"payload-` + fmt.Sprintf("%d", index) + `"}`,
		StatusCode:     statusCode,
		ResponseLength: len(body),
		DurationMs:     durationMs,
	}

	if err := store.SaveFuzzResult(ctx, result); err != nil {
		t.Fatalf("SaveFuzzResult: %v", err)
	}
	return result
}

// --- fuzz_jobs tests ---

func TestQuery_FuzzJobs_NilStore(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, nil) // no fuzz store

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil fuzz store")
	}
}

func TestQuery_FuzzJobs_Empty(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
}

func TestQuery_FuzzJobs_WithData(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	seedFuzzJob(t, store, "running", "scan-1")
	seedFuzzJob(t, store, "completed", "scan-1")
	seedFuzzJob(t, store, "running", "scan-2")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}

	// Verify entry fields.
	for _, job := range out.Jobs {
		if job.ID == "" {
			t.Error("job ID is empty")
		}
		if job.SessionID != "sess-template" {
			t.Errorf("session_id = %q, want sess-template", job.SessionID)
		}
		if job.CreatedAt == "" {
			t.Error("created_at is empty")
		}
	}
}

func TestQuery_FuzzJobs_FilterByStatus(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	seedFuzzJob(t, store, "running", "")
	seedFuzzJob(t, store, "completed", "")
	seedFuzzJob(t, store, "running", "")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"filter":   map[string]any{"status": "running"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}
	for _, job := range out.Jobs {
		if job.Status != "running" {
			t.Errorf("job status = %q, want running", job.Status)
		}
	}
}

func TestQuery_FuzzJobs_FilterByTag(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	seedFuzzJob(t, store, "running", "scan-1")
	seedFuzzJob(t, store, "completed", "scan-2")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"filter":   map[string]any{"tag": "scan-1"},
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
	if out.Jobs[0].Tag != "scan-1" {
		t.Errorf("tag = %q, want scan-1", out.Jobs[0].Tag)
	}
}

func TestQuery_FuzzJobs_Pagination(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	for i := 0; i < 5; i++ {
		seedFuzzJob(t, store, "completed", fmt.Sprintf("job-%d", i))
	}

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"limit":    2,
		"offset":   0,
	})
	if result.IsError {
		t.Fatalf("page 1: expected success: %v", result.Content)
	}

	var page1 queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &page1)

	if page1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", page1.Count)
	}
	if page1.Total != 5 {
		t.Errorf("page 1 total = %d, want 5", page1.Total)
	}

	// Page 2.
	result = callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"limit":    2,
		"offset":   2,
	})
	if result.IsError {
		t.Fatalf("page 2: expected success: %v", result.Content)
	}

	var page2 queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &page2)
	if page2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", page2.Count)
	}
}

func TestQuery_FuzzJobs_NegativeOffset(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"offset":   -1,
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestQuery_FuzzJobs_CompletedAt(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	seedFuzzJob(t, store, "completed", "done")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzJobsResult
	unmarshalQueryResultRaw(t, result, &out)

	if len(out.Jobs) != 1 {
		t.Fatalf("jobs = %d, want 1", len(out.Jobs))
	}
	if out.Jobs[0].CompletedAt == nil {
		t.Error("completed_at should not be nil for completed job")
	}
}

func TestQuery_FuzzJobs_Fields(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	seedFuzzJob(t, store, "running", "test-tag")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_jobs",
		"fields":   []string{"id", "status"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	// Parse as raw map to verify fields filtering.
	var raw map[string]json.RawMessage
	unmarshalQueryResultRaw(t, result, &raw)

	// Metadata fields should always be present.
	if _, ok := raw["count"]; !ok {
		t.Error("count field should always be present")
	}
	if _, ok := raw["total"]; !ok {
		t.Error("total field should always be present")
	}
	if _, ok := raw["jobs"]; !ok {
		t.Fatal("jobs field should be present")
	}

	// Verify jobs entries only have requested fields.
	var jobs []map[string]json.RawMessage
	if err := json.Unmarshal(raw["jobs"], &jobs); err != nil {
		t.Fatalf("unmarshal jobs: %v", err)
	}
	if len(jobs) != 1 {
		t.Fatalf("jobs len = %d, want 1", len(jobs))
	}
	if _, ok := jobs[0]["id"]; !ok {
		t.Error("id field should be present in filtered result")
	}
	if _, ok := jobs[0]["status"]; !ok {
		t.Error("status field should be present in filtered result")
	}
	if _, ok := jobs[0]["tag"]; ok {
		t.Error("tag field should NOT be present in filtered result")
	}
	if _, ok := jobs[0]["session_id"]; ok {
		t.Error("session_id field should NOT be present in filtered result")
	}
}

// --- fuzz_results tests ---

func TestQuery_FuzzResults_NilStore(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, nil)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  "fuzz-1",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for nil fuzz store")
	}
}

func TestQuery_FuzzResults_MissingFuzzID(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for missing fuzz_id")
	}
}

func TestQuery_FuzzResults_Empty(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 0 {
		t.Errorf("count = %d, want 0", out.Count)
	}
	if out.Total != 0 {
		t.Errorf("total = %d, want 0", out.Total)
	}
	if out.Summary == nil {
		t.Fatal("summary should not be nil")
	}
}

func TestQuery_FuzzResults_WithData(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 200, 50, `{"ok":true}`)
	seedFuzzResult(t, store, job.ID, 1, 401, 30, `{"error":"unauthorized"}`)
	seedFuzzResult(t, store, job.ID, 2, 200, 45, `{"ok":true,"role":"admin"}`)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
	})
	if result.IsError {
		t.Fatalf("expected success, got error: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 3 {
		t.Errorf("count = %d, want 3", out.Count)
	}
	if out.Total != 3 {
		t.Errorf("total = %d, want 3", out.Total)
	}

	// Verify entry fields.
	r0 := out.Results[0]
	if r0.IndexNum != 0 {
		t.Errorf("results[0].index = %d, want 0", r0.IndexNum)
	}
	if r0.StatusCode != 200 {
		t.Errorf("results[0].status_code = %d, want 200", r0.StatusCode)
	}
	if r0.DurationMs != 50 {
		t.Errorf("results[0].duration_ms = %d, want 50", r0.DurationMs)
	}
	if r0.Payloads["pos-0"] != "payload-0" {
		t.Errorf("results[0].payloads = %v, want {pos-0: payload-0}", r0.Payloads)
	}

	// Verify summary.
	if out.Summary == nil {
		t.Fatal("summary is nil")
	}
	if out.Summary.StatusDistribution["200"] != 2 {
		t.Errorf("status_distribution[200] = %d, want 2", out.Summary.StatusDistribution["200"])
	}
	if out.Summary.StatusDistribution["401"] != 1 {
		t.Errorf("status_distribution[401] = %d, want 1", out.Summary.StatusDistribution["401"])
	}
	expectedTotal := 50 + 30 + 45
	if out.Summary.TotalDurationMs != expectedTotal {
		t.Errorf("total_duration_ms = %d, want %d", out.Summary.TotalDurationMs, expectedTotal)
	}
	expectedAvg := expectedTotal / 3
	if out.Summary.AvgDurationMs != expectedAvg {
		t.Errorf("avg_duration_ms = %d, want %d", out.Summary.AvgDurationMs, expectedAvg)
	}
}

func TestQuery_FuzzResults_FilterByStatusCode(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 200, 50, `{}`)
	seedFuzzResult(t, store, job.ID, 1, 401, 30, `{}`)
	seedFuzzResult(t, store, job.ID, 2, 200, 45, `{}`)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"status_code": 200},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 2 {
		t.Errorf("count = %d, want 2", out.Count)
	}
	if out.Total != 2 {
		t.Errorf("total = %d, want 2", out.Total)
	}
	for _, r := range out.Results {
		if r.StatusCode != 200 {
			t.Errorf("result status_code = %d, want 200", r.StatusCode)
		}
	}
}

func TestQuery_FuzzResults_FilterByBodyContains(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 200, 50, `{"role":"admin"}`)
	seedFuzzResult(t, store, job.ID, 1, 200, 30, `{"role":"user"}`)
	seedFuzzResult(t, store, job.ID, 2, 200, 45, `{"error":"denied"}`)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"body_contains": "admin"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Count != 1 {
		t.Errorf("count = %d, want 1", out.Count)
	}
}

func TestQuery_FuzzResults_SortBy(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 500, 50, `{}`)
	seedFuzzResult(t, store, job.ID, 1, 200, 30, `{}`)
	seedFuzzResult(t, store, job.ID, 2, 301, 45, `{}`)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"sort_by":  "status_code",
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if len(out.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(out.Results))
	}
	if out.Results[0].StatusCode != 200 {
		t.Errorf("results[0].status_code = %d, want 200", out.Results[0].StatusCode)
	}
	if out.Results[1].StatusCode != 301 {
		t.Errorf("results[1].status_code = %d, want 301", out.Results[1].StatusCode)
	}
	if out.Results[2].StatusCode != 500 {
		t.Errorf("results[2].status_code = %d, want 500", out.Results[2].StatusCode)
	}
}

func TestQuery_FuzzResults_Pagination(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	for i := 0; i < 5; i++ {
		seedFuzzResult(t, store, job.ID, i, 200, 50, `{}`)
	}

	// Page 1.
	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"limit":    2,
		"offset":   0,
	})
	if result.IsError {
		t.Fatalf("page 1: expected success: %v", result.Content)
	}

	var page1 queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &page1)
	if page1.Count != 2 {
		t.Errorf("page 1 count = %d, want 2", page1.Count)
	}
	if page1.Total != 5 {
		t.Errorf("page 1 total = %d, want 5", page1.Total)
	}

	// Page 2.
	result = callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"limit":    2,
		"offset":   2,
	})
	if result.IsError {
		t.Fatalf("page 2: expected success: %v", result.Content)
	}

	var page2 queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &page2)
	if page2.Count != 2 {
		t.Errorf("page 2 count = %d, want 2", page2.Count)
	}

	// Page beyond total.
	result = callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"limit":    2,
		"offset":   10,
	})
	if result.IsError {
		t.Fatalf("page 3: expected success: %v", result.Content)
	}

	var page3 queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &page3)
	if page3.Count != 0 {
		t.Errorf("page 3 count = %d, want 0", page3.Count)
	}
	if page3.Total != 5 {
		t.Errorf("page 3 total = %d, want 5", page3.Total)
	}
}

func TestQuery_FuzzResults_NegativeOffset(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  "fuzz-1",
		"offset":   -1,
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for negative offset")
	}
}

func TestQuery_FuzzResults_Fields(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 200, 50, `{}`)

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"fields":   []string{"index", "status_code", "duration_ms"},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var raw map[string]json.RawMessage
	unmarshalQueryResultRaw(t, result, &raw)

	// Metadata should always be present.
	if _, ok := raw["count"]; !ok {
		t.Error("count field should always be present")
	}
	if _, ok := raw["total"]; !ok {
		t.Error("total field should always be present")
	}
	if _, ok := raw["summary"]; !ok {
		t.Error("summary field should always be present")
	}
	if _, ok := raw["results"]; !ok {
		t.Fatal("results field should be present")
	}

	// Verify results entries only have requested fields.
	var results []map[string]json.RawMessage
	if err := json.Unmarshal(raw["results"], &results); err != nil {
		t.Fatalf("unmarshal results: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("results len = %d, want 1", len(results))
	}
	if _, ok := results[0]["index"]; !ok {
		t.Error("index field should be present in filtered result")
	}
	if _, ok := results[0]["status_code"]; !ok {
		t.Error("status_code field should be present in filtered result")
	}
	if _, ok := results[0]["duration_ms"]; !ok {
		t.Error("duration_ms field should be present in filtered result")
	}
	if _, ok := results[0]["payloads"]; ok {
		t.Error("payloads field should NOT be present in filtered result")
	}
	if _, ok := results[0]["session_id"]; ok {
		t.Error("session_id field should NOT be present in filtered result")
	}
}

func TestQuery_FuzzResults_SummaryWithFilter(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)

	job := seedFuzzJob(t, store, "completed", "test")
	seedFuzzResult(t, store, job.ID, 0, 200, 100, `{}`)
	seedFuzzResult(t, store, job.ID, 1, 401, 200, `{}`)
	seedFuzzResult(t, store, job.ID, 2, 200, 150, `{}`)

	// Filter by status_code=200; summary should only cover matching results.
	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
		"filter":   map[string]any{"status_code": 200},
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if out.Summary == nil {
		t.Fatal("summary is nil")
	}
	if out.Summary.StatusDistribution["200"] != 2 {
		t.Errorf("status_distribution[200] = %d, want 2", out.Summary.StatusDistribution["200"])
	}
	if _, ok := out.Summary.StatusDistribution["401"]; ok {
		t.Error("status_distribution should not contain 401 when filtered")
	}
	if out.Summary.TotalDurationMs != 250 {
		t.Errorf("total_duration_ms = %d, want 250", out.Summary.TotalDurationMs)
	}
	if out.Summary.AvgDurationMs != 125 {
		t.Errorf("avg_duration_ms = %d, want 125", out.Summary.AvgDurationMs)
	}
}

func TestQuery_FuzzResults_ErrorField(t *testing.T) {
	store := newTestFuzzStore(t)
	cs := setupFuzzQueryTestSession(t, store, store)
	ctx := context.Background()

	job := seedFuzzJob(t, store, "completed", "test")

	// Create a result with an error.
	sess := &session.Session{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveSession(ctx, sess); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	errResult := &session.FuzzResult{
		FuzzID:    job.ID,
		IndexNum:  0,
		SessionID: sess.ID,
		Payloads:  `{"pos-0":"test"}`,
		Error:     "connection refused",
	}
	if err := store.SaveFuzzResult(ctx, errResult); err != nil {
		t.Fatalf("SaveFuzzResult: %v", err)
	}

	result := callQueryRaw(t, cs, map[string]any{
		"resource": "fuzz_results",
		"fuzz_id":  job.ID,
	})
	if result.IsError {
		t.Fatalf("expected success: %v", result.Content)
	}

	var out queryFuzzResultsResult
	unmarshalQueryResultRaw(t, result, &out)

	if len(out.Results) != 1 {
		t.Fatalf("results = %d, want 1", len(out.Results))
	}
	if out.Results[0].Error != "connection refused" {
		t.Errorf("error = %q, want 'connection refused'", out.Results[0].Error)
	}
}
