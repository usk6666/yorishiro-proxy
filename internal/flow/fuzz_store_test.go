package flow

import (
	"context"
	"testing"
	"time"
)

func TestFuzzJobStore_SaveAndGet(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	job := &FuzzJob{
		StreamID:  "fl-1",
		Config:    `{"attack_type":"sequential"}`,
		Status:    "running",
		Tag:       "test-tag",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		Total:     10,
	}

	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	if job.ID == "" {
		t.Fatal("job ID should be auto-generated")
	}

	got, err := store.GetFuzzJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetFuzzJob: %v", err)
	}

	if got.StreamID != "fl-1" {
		t.Errorf("StreamID = %q, want %q", got.StreamID, "fl-1")
	}
	if got.Status != "running" {
		t.Errorf("Status = %q, want %q", got.Status, "running")
	}
	if got.Tag != "test-tag" {
		t.Errorf("Tag = %q, want %q", got.Tag, "test-tag")
	}
	if got.Total != 10 {
		t.Errorf("Total = %d, want 10", got.Total)
	}
	if got.CompletedAt != nil {
		t.Errorf("CompletedAt should be nil, got %v", got.CompletedAt)
	}
}

func TestFuzzJobStore_Update(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	job := &FuzzJob{
		StreamID:  "fl-1",
		Config:    `{}`,
		Status:    "running",
		CreatedAt: time.Now().UTC().Truncate(time.Millisecond),
		Total:     5,
	}

	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Millisecond)
	job.Status = "completed"
	job.CompletedAt = &now
	job.CompletedCount = 4
	job.ErrorCount = 1

	if err := store.UpdateFuzzJob(ctx, job); err != nil {
		t.Fatalf("UpdateFuzzJob: %v", err)
	}

	got, err := store.GetFuzzJob(ctx, job.ID)
	if err != nil {
		t.Fatalf("GetFuzzJob: %v", err)
	}

	if got.Status != "completed" {
		t.Errorf("Status = %q, want %q", got.Status, "completed")
	}
	if got.CompletedCount != 4 {
		t.Errorf("CompletedCount = %d, want 4", got.CompletedCount)
	}
	if got.ErrorCount != 1 {
		t.Errorf("ErrorCount = %d, want 1", got.ErrorCount)
	}
	if got.CompletedAt == nil {
		t.Error("CompletedAt should not be nil")
	}
}

func TestFuzzJobStore_GetNotFound(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	_, err := store.GetFuzzJob(ctx, "nonexistent")
	if err == nil {
		t.Error("expected error for nonexistent job")
	}
}

func TestFuzzResultStore_SaveAndList(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create a template flow first (for FK reference).
	fl := &Stream{
		Protocol:  "HTTP/1.x",
		State:     "complete",
		Timestamp: time.Now(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	// Create a fuzz job.
	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "running",
		CreatedAt: time.Now().UTC(),
		Total:     3,
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	// Create result sessions.
	resultSessions := make([]*Stream, 3)
	for i := range 3 {
		s := &Stream{
			Protocol:  "HTTP/1.x",
			State:     "complete",
			Timestamp: time.Now(),
		}
		if err := store.SaveStream(ctx, s); err != nil {
			t.Fatalf("SaveFlow for result: %v", err)
		}
		resultSessions[i] = s
	}

	// Save results.
	results := []*FuzzResult{
		{FuzzID: job.ID, IndexNum: 0, StreamID: resultSessions[0].ID, Payloads: `{"pos-0":"a"}`, StatusCode: 200, ResponseLength: 100, DurationMs: 50},
		{FuzzID: job.ID, IndexNum: 1, StreamID: resultSessions[1].ID, Payloads: `{"pos-0":"b"}`, StatusCode: 401, ResponseLength: 20, DurationMs: 30},
		{FuzzID: job.ID, IndexNum: 2, StreamID: resultSessions[2].ID, Payloads: `{"pos-0":"c"}`, StatusCode: 200, ResponseLength: 150, DurationMs: 45, Error: ""},
	}
	for _, r := range results {
		if err := store.SaveFuzzResult(ctx, r); err != nil {
			t.Fatalf("SaveFuzzResult: %v", err)
		}
	}

	// List all results.
	got, err := store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}

	// Verify ordering.
	for i, r := range got {
		if r.IndexNum != i {
			t.Errorf("result[%d].IndexNum = %d, want %d", i, r.IndexNum, i)
		}
	}
}

func TestFuzzResultStore_ListWithFilter(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{
		Protocol:  "HTTP/1.x",
		Timestamp: time.Now(),
	}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "completed",
		CreatedAt: time.Now().UTC(),
		Total:     3,
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	// Create result sessions.
	for i := range 3 {
		s := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
		if err := store.SaveStream(ctx, s); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
		statusCode := 200
		if i == 1 {
			statusCode = 401
		}
		r := &FuzzResult{
			FuzzID: job.ID, IndexNum: i, StreamID: s.ID,
			Payloads: `{}`, StatusCode: statusCode,
		}
		if err := store.SaveFuzzResult(ctx, r); err != nil {
			t.Fatalf("SaveFuzzResult: %v", err)
		}
	}

	// Filter by status code.
	got, err := store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{StatusCode: 200})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d results with status 200, want 2", len(got))
	}

	// Limit and offset.
	got, err = store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{Limit: 1, Offset: 1})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d results with limit 1 offset 1, want 1", len(got))
	}
	if got[0].IndexNum != 1 {
		t.Errorf("result.IndexNum = %d, want 1", got[0].IndexNum)
	}
}

func TestFuzzResultStore_ErrorField(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "completed",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	errSess := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, errSess); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	r := &FuzzResult{
		FuzzID:   job.ID,
		IndexNum: 0,
		StreamID: errSess.ID,
		Payloads: `{}`,
		Error:    "connection refused",
	}
	if err := store.SaveFuzzResult(ctx, r); err != nil {
		t.Fatalf("SaveFuzzResult: %v", err)
	}

	got, err := store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d results, want 1", len(got))
	}
	if got[0].Error != "connection refused" {
		t.Errorf("error = %q, want %q", got[0].Error, "connection refused")
	}
}

func TestPayloadsToJSON(t *testing.T) {
	t.Parallel()
	m := map[string]string{"pos-0": "val1", "pos-1": "val2"}
	got := PayloadsToJSON(m)
	if got == "{}" || got == "" {
		t.Error("expected non-empty JSON")
	}

	parsed, err := PayloadsFromJSON(got)
	if err != nil {
		t.Fatalf("PayloadsFromJSON: %v", err)
	}
	if parsed["pos-0"] != "val1" || parsed["pos-1"] != "val2" {
		t.Errorf("parsed = %v", parsed)
	}
}

func TestPayloadsFromJSON_Invalid(t *testing.T) {
	t.Parallel()
	_, err := PayloadsFromJSON("not-json")
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestSchemaV2_Migration(t *testing.T) {
	t.Parallel()
	// The newTestStore helper runs migrations; just verify the tables exist.
	store := newTestStore(t)
	ctx := context.Background()

	// Verify fuzz_jobs table exists.
	job := &FuzzJob{
		StreamID:  "test",
		Config:    `{}`,
		Status:    "running",
		CreatedAt: time.Now().UTC(),
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("fuzz_jobs table not created: %v", err)
	}
}

// --- ListFuzzJobs tests ---

func TestListFuzzJobs_Empty(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	jobs, err := store.ListFuzzJobs(ctx, FuzzJobListOptions{})
	if err != nil {
		t.Fatalf("ListFuzzJobs: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("got %d jobs, want 0", len(jobs))
	}
}

func TestListFuzzJobs_WithData(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	// Create jobs with different statuses and tags.
	for _, tc := range []struct {
		status string
		tag    string
	}{
		{"running", "scan-1"},
		{"completed", "scan-1"},
		{"running", "scan-2"},
		{"error", ""},
	} {
		job := &FuzzJob{
			StreamID:  "fl-1",
			Config:    `{}`,
			Status:    tc.status,
			Tag:       tc.tag,
			CreatedAt: time.Now().UTC(),
			Total:     10,
		}
		if err := store.SaveFuzzJob(ctx, job); err != nil {
			t.Fatalf("SaveFuzzJob: %v", err)
		}
	}

	tests := []struct {
		name     string
		opts     FuzzJobListOptions
		wantLen  int
		wantDesc string
	}{
		{
			name:    "no filter",
			opts:    FuzzJobListOptions{},
			wantLen: 4,
		},
		{
			name:    "filter by status running",
			opts:    FuzzJobListOptions{Status: "running"},
			wantLen: 2,
		},
		{
			name:    "filter by status completed",
			opts:    FuzzJobListOptions{Status: "completed"},
			wantLen: 1,
		},
		{
			name:    "filter by tag scan-1",
			opts:    FuzzJobListOptions{Tag: "scan-1"},
			wantLen: 2,
		},
		{
			name:    "filter by status and tag",
			opts:    FuzzJobListOptions{Status: "running", Tag: "scan-1"},
			wantLen: 1,
		},
		{
			name:    "limit",
			opts:    FuzzJobListOptions{Limit: 2},
			wantLen: 2,
		},
		{
			name:    "offset",
			opts:    FuzzJobListOptions{Limit: 2, Offset: 3},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jobs, err := store.ListFuzzJobs(ctx, tt.opts)
			if err != nil {
				t.Fatalf("ListFuzzJobs: %v", err)
			}
			if len(jobs) != tt.wantLen {
				t.Errorf("got %d jobs, want %d", len(jobs), tt.wantLen)
			}
		})
	}
}

func TestCountFuzzJobs(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	for _, status := range []string{"running", "completed", "running"} {
		job := &FuzzJob{
			StreamID:  "fl-1",
			Config:    `{}`,
			Status:    status,
			CreatedAt: time.Now().UTC(),
		}
		if err := store.SaveFuzzJob(ctx, job); err != nil {
			t.Fatalf("SaveFuzzJob: %v", err)
		}
	}

	count, err := store.CountFuzzJobs(ctx, FuzzJobListOptions{})
	if err != nil {
		t.Fatalf("CountFuzzJobs: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}

	count, err = store.CountFuzzJobs(ctx, FuzzJobListOptions{Status: "running"})
	if err != nil {
		t.Fatalf("CountFuzzJobs(running): %v", err)
	}
	if count != 2 {
		t.Errorf("count(running) = %d, want 2", count)
	}
}

// --- CountFuzzResults tests ---

func TestCountFuzzResults(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "completed",
		CreatedAt: time.Now().UTC(),
		Total:     3,
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	for i := range 3 {
		s := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
		if err := store.SaveStream(ctx, s); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
		statusCode := 200
		if i == 1 {
			statusCode = 401
		}
		r := &FuzzResult{
			FuzzID: job.ID, IndexNum: i, StreamID: s.ID,
			Payloads: `{}`, StatusCode: statusCode,
		}
		if err := store.SaveFuzzResult(ctx, r); err != nil {
			t.Fatalf("SaveFuzzResult: %v", err)
		}
	}

	count, err := store.CountFuzzResults(ctx, job.ID, FuzzResultListOptions{})
	if err != nil {
		t.Fatalf("CountFuzzResults: %v", err)
	}
	if count != 3 {
		t.Errorf("count = %d, want 3", count)
	}

	count, err = store.CountFuzzResults(ctx, job.ID, FuzzResultListOptions{StatusCode: 200})
	if err != nil {
		t.Fatalf("CountFuzzResults(200): %v", err)
	}
	if count != 2 {
		t.Errorf("count(200) = %d, want 2", count)
	}
}

// --- SortBy and BodyContains tests ---

func TestListFuzzResults_SortBy(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "completed",
		CreatedAt: time.Now().UTC(),
		Total:     3,
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	// Create results with varying status codes.
	for i, sc := range []int{500, 200, 301} {
		s := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
		if err := store.SaveStream(ctx, s); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}
		r := &FuzzResult{
			FuzzID: job.ID, IndexNum: i, StreamID: s.ID,
			Payloads: `{}`, StatusCode: sc, DurationMs: (3 - i) * 100,
		}
		if err := store.SaveFuzzResult(ctx, r); err != nil {
			t.Fatalf("SaveFuzzResult: %v", err)
		}
	}

	// Sort by status_code.
	got, err := store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{SortBy: "status_code"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d results, want 3", len(got))
	}
	if got[0].StatusCode != 200 {
		t.Errorf("results[0].StatusCode = %d, want 200", got[0].StatusCode)
	}
	if got[1].StatusCode != 301 {
		t.Errorf("results[1].StatusCode = %d, want 301", got[1].StatusCode)
	}
	if got[2].StatusCode != 500 {
		t.Errorf("results[2].StatusCode = %d, want 500", got[2].StatusCode)
	}

	// Sort by duration_ms.
	got, err = store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{SortBy: "duration_ms"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if got[0].DurationMs > got[1].DurationMs || got[1].DurationMs > got[2].DurationMs {
		t.Errorf("results not sorted by duration_ms: %d, %d, %d", got[0].DurationMs, got[1].DurationMs, got[2].DurationMs)
	}

	// Invalid sort_by falls back to index_num.
	got, err = store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{SortBy: "invalid"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if got[0].IndexNum != 0 || got[1].IndexNum != 1 || got[2].IndexNum != 2 {
		t.Errorf("expected default index_num sort, got indices: %d, %d, %d", got[0].IndexNum, got[1].IndexNum, got[2].IndexNum)
	}
}

func TestListFuzzResults_BodyContains(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	ctx := context.Background()

	fl := &Stream{Protocol: "HTTP/1.x", Timestamp: time.Now()}
	if err := store.SaveStream(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	job := &FuzzJob{
		StreamID:  fl.ID,
		Config:    `{}`,
		Status:    "completed",
		CreatedAt: time.Now().UTC(),
		Total:     3,
	}
	if err := store.SaveFuzzJob(ctx, job); err != nil {
		t.Fatalf("SaveFuzzJob: %v", err)
	}

	// Create results with sessions that have response messages containing different bodies.
	bodies := []string{`{"role":"admin","ok":true}`, `{"role":"user","ok":true}`, `{"error":"denied"}`}
	for i, body := range bodies {
		s := &Stream{Protocol: "HTTP/1.x", State: "complete", Timestamp: time.Now()}
		if err := store.SaveStream(ctx, s); err != nil {
			t.Fatalf("SaveFlow: %v", err)
		}

		// Append a receive message with the body.
		msg := &Flow{
			ID:        s.ID + "-recv",
			StreamID:  s.ID,
			Sequence:  0,
			Direction: "receive",
			Timestamp: time.Now(),
			Body:      []byte(body),
		}
		if err := store.SaveFlow(ctx, msg); err != nil {
			t.Fatalf("AppendMessage: %v", err)
		}

		r := &FuzzResult{
			FuzzID: job.ID, IndexNum: i, StreamID: s.ID,
			Payloads: `{}`, StatusCode: 200,
		}
		if err := store.SaveFuzzResult(ctx, r); err != nil {
			t.Fatalf("SaveFuzzResult: %v", err)
		}
	}

	// Filter by body_contains "admin".
	got, err := store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{BodyContains: "admin"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 1 {
		t.Errorf("got %d results with body_contains=admin, want 1", len(got))
	}

	// Filter by body_contains "ok".
	got, err = store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{BodyContains: "ok"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 2 {
		t.Errorf("got %d results with body_contains=ok, want 2", len(got))
	}

	// No match.
	got, err = store.ListFuzzResults(ctx, job.ID, FuzzResultListOptions{BodyContains: "nonexistent"})
	if err != nil {
		t.Fatalf("ListFuzzResults: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("got %d results with body_contains=nonexistent, want 0", len(got))
	}
}
