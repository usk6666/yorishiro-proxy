package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/session"
)

// mockSessionFetcher implements SessionFetcher for testing.
type mockSessionFetcher struct {
	session  *session.Session
	messages []*session.Message
	getErr   error
	msgErr   error
}

func (m *mockSessionFetcher) GetSession(_ context.Context, id string) (*session.Session, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	if m.session == nil {
		return nil, fmt.Errorf("session not found")
	}
	return m.session, nil
}

func (m *mockSessionFetcher) GetMessages(_ context.Context, _ string, _ session.MessageListOptions) ([]*session.Message, error) {
	if m.msgErr != nil {
		return nil, m.msgErr
	}
	return m.messages, nil
}

// mockSessionRecorder implements SessionRecorder for testing.
type mockSessionRecorder struct {
	sessions []*session.Session
	messages []*session.Message
	saveErr  error
	msgErr   error
}

func (m *mockSessionRecorder) SaveSession(_ context.Context, s *session.Session) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	if s.ID == "" {
		s.ID = fmt.Sprintf("sess-%d", len(m.sessions))
	}
	m.sessions = append(m.sessions, s)
	return nil
}

func (m *mockSessionRecorder) AppendMessage(_ context.Context, msg *session.Message) error {
	if m.msgErr != nil {
		return m.msgErr
	}
	m.messages = append(m.messages, msg)
	return nil
}

// mockFuzzJobStore implements FuzzJobStore for testing.
type mockFuzzJobStore struct {
	jobs    []*session.FuzzJob
	results []*session.FuzzResult
	saveErr error
}

func (m *mockFuzzJobStore) SaveFuzzJob(_ context.Context, job *session.FuzzJob) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.jobs = append(m.jobs, job)
	return nil
}

func (m *mockFuzzJobStore) UpdateFuzzJob(_ context.Context, job *session.FuzzJob) error {
	for i, j := range m.jobs {
		if j.ID == job.ID {
			m.jobs[i] = job
			return nil
		}
	}
	return nil
}

func (m *mockFuzzJobStore) SaveFuzzResult(_ context.Context, result *session.FuzzResult) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.results = append(m.results, result)
	return nil
}

// mockHTTPDoer implements HTTPDoer for testing.
type mockHTTPDoer struct {
	responses []*http.Response
	index     int
	err       error
}

func (m *mockHTTPDoer) Do(_ *http.Request) (*http.Response, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.index >= len(m.responses) {
		return &http.Response{
			StatusCode: 200,
			Body:       io.NopCloser(strings.NewReader("default")),
			Header:     http.Header{},
		}, nil
	}
	resp := m.responses[m.index]
	m.index++
	return resp, nil
}

func newMockResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     http.Header{},
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     Config
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: Config{
				SessionID:  "sess-1",
				AttackType: "sequential",
				Positions: []Position{
					{ID: "pos-0", Location: "header", Name: "X-A", PayloadSet: "set-a"},
				},
				PayloadSets: map[string]PayloadSet{
					"set-a": {Type: "wordlist", Values: []string{"a"}},
				},
			},
		},
		{
			name:    "missing session_id",
			cfg:     Config{AttackType: "sequential"},
			wantErr: true,
		},
		{
			name:    "missing attack_type",
			cfg:     Config{SessionID: "sess-1"},
			wantErr: true,
		},
		{
			name: "invalid attack_type",
			cfg: Config{
				SessionID:  "sess-1",
				AttackType: "invalid",
				Positions:  []Position{{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"}},
				PayloadSets: map[string]PayloadSet{
					"s": {Type: "wordlist", Values: []string{"a"}},
				},
			},
			wantErr: true,
		},
		{
			name: "no positions",
			cfg: Config{
				SessionID:  "sess-1",
				AttackType: "sequential",
			},
			wantErr: true,
		},
		{
			name: "duplicate position ids",
			cfg: Config{
				SessionID:  "sess-1",
				AttackType: "sequential",
				Positions: []Position{
					{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"},
					{ID: "pos-0", Location: "query", Name: "q", PayloadSet: "s"},
				},
				PayloadSets: map[string]PayloadSet{
					"s": {Type: "wordlist", Values: []string{"a"}},
				},
			},
			wantErr: true,
		},
		{
			name: "missing payload set reference",
			cfg: Config{
				SessionID:  "sess-1",
				AttackType: "sequential",
				Positions: []Position{
					{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "missing"},
				},
				PayloadSets: map[string]PayloadSet{},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_Run_Sequential(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api?key=val")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers: map[string][]string{
					"Authorization": {"Bearer old-token"},
					"Content-Type":  {"application/json"},
				},
				Body: []byte(`{"user":"admin"}`),
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{
		responses: []*http.Response{
			newMockResponse(401, "unauthorized"),
			newMockResponse(200, "welcome"),
			newMockResponse(403, "forbidden"),
		},
	}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	cfg := Config{
		SessionID:  "template-1",
		AttackType: "sequential",
		Positions: []Position{
			{
				ID: "pos-0", Location: "header", Name: "Authorization",
				Match: "Bearer (.*)", PayloadSet: "tokens",
			},
		},
		PayloadSets: map[string]PayloadSet{
			"tokens": {Type: "wordlist", Values: []string{"token1", "token2", "admin-token"}},
		},
		Tag: "auth-test",
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("status = %q, want %q", result.Status, "completed")
	}
	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if result.Completed != 3 {
		t.Errorf("completed = %d, want 3", result.Completed)
	}
	if result.Errors != 0 {
		t.Errorf("errors = %d, want 0", result.Errors)
	}
	if result.Tag != "auth-test" {
		t.Errorf("tag = %q, want %q", result.Tag, "auth-test")
	}
	if result.FuzzID == "" {
		t.Error("fuzz_id is empty")
	}

	// Verify DB records.
	if len(fuzzStore.jobs) != 1 {
		t.Fatalf("jobs count = %d, want 1", len(fuzzStore.jobs))
	}
	if len(fuzzStore.results) != 3 {
		t.Fatalf("results count = %d, want 3", len(fuzzStore.results))
	}

	// Verify sessions were recorded.
	if len(recorder.sessions) != 3 {
		t.Fatalf("recorded sessions = %d, want 3", len(recorder.sessions))
	}

	// Verify messages (send + receive for each iteration).
	if len(recorder.messages) != 6 {
		t.Fatalf("recorded messages = %d, want 6", len(recorder.messages))
	}

	// Verify result payloads.
	for i, r := range fuzzStore.results {
		if r.IndexNum != i {
			t.Errorf("result[%d].IndexNum = %d, want %d", i, r.IndexNum, i)
		}
	}
}

func TestEngine_Run_Parallel(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/login")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "template-1",
				Direction: "send",
				Method:    "POST",
				URL:       testURL,
				Headers:   map[string][]string{"Content-Type": {"application/json"}},
				Body:      []byte(`{"username":"admin","password":"old"}`),
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{
		responses: []*http.Response{
			newMockResponse(401, "fail"),
			newMockResponse(200, "success"),
		},
	}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	cfg := Config{
		SessionID:  "template-1",
		AttackType: "parallel",
		Positions: []Position{
			{ID: "pos-0", Location: "body_json", JSONPath: "$.username", PayloadSet: "users"},
			{ID: "pos-1", Location: "body_json", JSONPath: "$.password", PayloadSet: "passwords"},
		},
		PayloadSets: map[string]PayloadSet{
			"users":     {Type: "wordlist", Values: []string{"admin", "root"}},
			"passwords": {Type: "wordlist", Values: []string{"pass1", "pass2", "pass3"}},
		},
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	// parallel uses zip: min(2, 3) = 2 iterations.
	if result.Total != 2 {
		t.Errorf("total = %d, want 2", result.Total)
	}
	if result.Completed != 2 {
		t.Errorf("completed = %d, want 2", result.Completed)
	}
}

func TestEngine_Run_WithRemovePosition(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api?debug=true&key=val")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	cfg := Config{
		SessionID:  "template-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "pos-0", Location: "query", Name: "debug", Mode: "remove"},
		},
		PayloadSets: map[string]PayloadSet{},
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Total != 1 {
		t.Errorf("total = %d, want 1 (one remove iteration)", result.Total)
	}
	if result.Completed != 1 {
		t.Errorf("completed = %d, want 1", result.Completed)
	}
}

func TestEngine_Run_InvalidConfig(t *testing.T) {
	engine := NewEngine(nil, nil, nil, nil, "")

	cfg := Config{} // empty config
	_, err := engine.Run(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestEngine_Run_SessionNotFound(t *testing.T) {
	fetcher := &mockSessionFetcher{
		getErr: fmt.Errorf("not found"),
	}
	engine := NewEngine(fetcher, nil, nil, nil, "")

	cfg := Config{
		SessionID:  "nonexistent",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a"}},
		},
	}

	_, err := engine.Run(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for session not found")
	}
}

func TestEngine_Run_NoSendMessages(t *testing.T) {
	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{}, // no send messages
	}
	engine := NewEngine(fetcher, nil, nil, nil, "")

	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a"}},
		},
	}

	_, err := engine.Run(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for no send messages")
	}
}

func TestEngine_Run_ContextCancelled(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "sess-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}

	// Create a doer that blocks until context is cancelled.
	httpDoer := &mockHTTPDoer{
		err: fmt.Errorf("context cancelled"),
	}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a", "b", "c"}},
		},
	}

	_, err := engine.Run(ctx, cfg)
	if err == nil {
		t.Error("expected error for cancelled context")
	}
}

func TestEngine_Run_HTTPError(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "sess-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{
		err: fmt.Errorf("connection refused"),
	}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "p0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a"}},
		},
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v (should complete with errors)", err)
	}

	// The job should complete but have errors.
	if result.Status != "completed" {
		t.Errorf("status = %q, want %q", result.Status, "completed")
	}
	if result.Errors != 1 {
		t.Errorf("errors = %d, want 1", result.Errors)
	}

	// Verify error is recorded in the result.
	if len(fuzzStore.results) != 1 {
		t.Fatalf("results count = %d, want 1", len(fuzzStore.results))
	}
	if fuzzStore.results[0].Error == "" {
		t.Error("expected error message in result")
	}
}

func TestEngine_Run_RangePayloads(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/user/1")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "sess-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	start, end := 1, 3
	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "pos-0", Location: "path", Match: "/user/(\\d+)", PayloadSet: "ids"},
		},
		PayloadSets: map[string]PayloadSet{
			"ids": {Type: "range", Start: &start, End: &end},
		},
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Total != 3 {
		t.Errorf("total = %d, want 3", result.Total)
	}
	if result.Completed != 3 {
		t.Errorf("completed = %d, want 3", result.Completed)
	}
}

func TestEngine_Run_TimeoutMs(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "sess-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a"}},
		},
		TimeoutMs: 5000,
	}

	result, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Completed != 1 {
		t.Errorf("completed = %d, want 1", result.Completed)
	}
}

func TestBuildRequestData(t *testing.T) {
	u, _ := url.Parse("http://example.com/path")
	msg := &session.Message{
		Method: "POST",
		URL:    u,
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(`{"key":"value"}`),
	}

	data := BuildRequestData(msg)

	if data.Method != "POST" {
		t.Errorf("method = %q, want %q", data.Method, "POST")
	}
	if data.URL.String() != "http://example.com/path" {
		t.Errorf("url = %q", data.URL.String())
	}
	if len(data.Headers) != 1 {
		t.Errorf("headers count = %d, want 1", len(data.Headers))
	}
	if string(data.Body) != `{"key":"value"}` {
		t.Errorf("body = %q", string(data.Body))
	}
}

func TestResolvePayloads(t *testing.T) {
	intPtr := func(v int) *int { return &v }

	payloadSets := map[string]PayloadSet{
		"words": {Type: "wordlist", Values: []string{"a", "b"}},
		"nums":  {Type: "range", Start: intPtr(1), End: intPtr(3)},
	}

	resolved, err := ResolvePayloads(payloadSets, "")
	if err != nil {
		t.Fatalf("ResolvePayloads() error = %v", err)
	}

	if len(resolved["words"]) != 2 {
		t.Errorf("words count = %d, want 2", len(resolved["words"]))
	}
	if len(resolved["nums"]) != 3 {
		t.Errorf("nums count = %d, want 3", len(resolved["nums"]))
	}
}

// Verify that FuzzJob timestamps are tracked properly.
func TestEngine_Run_JobTimestamps(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockSessionFetcher{
		session: &session.Session{
			ID:       "sess-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*session.Message{
			{
				SessionID: "sess-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	recorder := &mockSessionRecorder{}
	fuzzStore := &mockFuzzJobStore{}
	httpDoer := &mockHTTPDoer{}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())

	before := time.Now()

	cfg := Config{
		SessionID:  "sess-1",
		AttackType: "sequential",
		Positions: []Position{
			{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"},
		},
		PayloadSets: map[string]PayloadSet{
			"s": {Type: "wordlist", Values: []string{"a"}},
		},
	}

	_, err := engine.Run(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	after := time.Now()

	if len(fuzzStore.jobs) != 1 {
		t.Fatalf("jobs count = %d, want 1", len(fuzzStore.jobs))
	}

	job := fuzzStore.jobs[0]
	if job.CreatedAt.Before(before) || job.CreatedAt.After(after) {
		t.Errorf("created_at %v not in [%v, %v]", job.CreatedAt, before, after)
	}
	if job.CompletedAt == nil {
		t.Error("completed_at is nil")
	} else if job.CompletedAt.Before(before) || job.CompletedAt.After(after) {
		t.Errorf("completed_at %v not in [%v, %v]", *job.CompletedAt, before, after)
	}
}
