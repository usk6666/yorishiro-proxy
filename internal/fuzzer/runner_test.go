package fuzzer

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// threadSafeMockFuzzJobStore is a thread-safe version of mockFuzzJobStore.
type threadSafeMockFuzzJobStore struct {
	mu      sync.Mutex
	jobs    []*flow.FuzzJob
	results []*flow.FuzzResult
	saveErr error
}

func (m *threadSafeMockFuzzJobStore) SaveFuzzJob(_ context.Context, job *flow.FuzzJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.jobs = append(m.jobs, job)
	return nil
}

func (m *threadSafeMockFuzzJobStore) UpdateFuzzJob(_ context.Context, job *flow.FuzzJob) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i, j := range m.jobs {
		if j.ID == job.ID {
			m.jobs[i] = job
			return nil
		}
	}
	return nil
}

func (m *threadSafeMockFuzzJobStore) SaveFuzzResult(_ context.Context, result *flow.FuzzResult) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	m.results = append(m.results, result)
	return nil
}

func (m *threadSafeMockFuzzJobStore) getResults() []*flow.FuzzResult {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := make([]*flow.FuzzResult, len(m.results))
	for i, r := range m.results {
		cpy := *r
		c[i] = &cpy
	}
	return c
}

func (m *threadSafeMockFuzzJobStore) getJobs() []*flow.FuzzJob {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := make([]*flow.FuzzJob, len(m.jobs))
	for i, j := range m.jobs {
		cpy := *j
		c[i] = &cpy
	}
	return c
}

// threadSafeMockFlowRecorder is a thread-safe version of mockFlowRecorder.
type threadSafeMockFlowRecorder struct {
	mu       sync.Mutex
	flows    []*flow.Flow
	messages []*flow.Message
	saveErr  error
}

func (m *threadSafeMockFlowRecorder) SaveFlow(_ context.Context, s *flow.Flow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.saveErr != nil {
		return m.saveErr
	}
	if s.ID == "" {
		s.ID = fmt.Sprintf("sess-%d", len(m.flows))
	}
	m.flows = append(m.flows, s)
	return nil
}

func (m *threadSafeMockFlowRecorder) AppendMessage(_ context.Context, msg *flow.Message) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.messages = append(m.messages, msg)
	return nil
}

// threadSafeMockHTTPDoer is a thread-safe mock HTTP doer.
type threadSafeMockHTTPDoer struct {
	mu        sync.Mutex
	responses []*http.Response
	index     int
	err       error
	callCount int
}

func (m *threadSafeMockHTTPDoer) Do(_ *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.callCount++
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

func (m *threadSafeMockHTTPDoer) getCallCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.callCount
}

func newTestRunner(t *testing.T) (*Runner, *threadSafeMockFuzzJobStore, *threadSafeMockHTTPDoer, *mockFlowFetcher) {
	t.Helper()
	testURL, _ := url.Parse("http://example.com/api?key=val")

	fetcher := &mockFlowFetcher{
		fl: &flow.Flow{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{
			{
				FlowID:    "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers: map[string][]string{
					"Authorization": {"Bearer old-token"},
				},
			},
		},
	}

	recorder := &threadSafeMockFlowRecorder{}
	fuzzStore := &threadSafeMockFuzzJobStore{}
	httpDoer := &threadSafeMockHTTPDoer{}

	engine := NewEngine(fetcher, recorder, fuzzStore, httpDoer, t.TempDir())
	registry := NewJobRegistry()
	runner := NewRunner(engine, registry)

	return runner, fuzzStore, httpDoer, fetcher
}

func TestRunConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     RunConfig
		wantErr bool
	}{
		{
			name: "valid config",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				Concurrency: 5,
			},
		},
		{
			name: "negative concurrency",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				Concurrency: -1,
			},
			wantErr: true,
		},
		{
			name: "concurrency exceeds max",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				Concurrency: maxConcurrency + 1,
			},
			wantErr: true,
		},
		{
			name: "concurrency at max",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				Concurrency: maxConcurrency,
			},
		},
		{
			name: "negative rate limit",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				RateLimitRPS: -1,
			},
			wantErr: true,
		},
		{
			name: "negative delay",
			cfg: RunConfig{
				Config: Config{
					FlowID:     "sess-1",
					AttackType: "sequential",
					Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{
						"s": {Type: "wordlist", Values: []string{"a"}},
					},
				},
				DelayMs: -1,
			},
			wantErr: true,
		},
		{
			name: "negative timeout_ms",
			cfg: RunConfig{
				Config: Config{
					FlowID:      "sess-1",
					AttackType:  "sequential",
					Positions:   []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{"s": {Type: "wordlist", Values: []string{"a"}}},
					TimeoutMs:   -1,
				},
			},
			wantErr: true,
		},
		{
			name: "timeout_ms exceeds max",
			cfg: RunConfig{
				Config: Config{
					FlowID:      "sess-1",
					AttackType:  "sequential",
					Positions:   []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{"s": {Type: "wordlist", Values: []string{"a"}}},
					TimeoutMs:   maxTimeoutMs + 1,
				},
			},
			wantErr: true,
		},
		{
			name: "timeout_ms at max",
			cfg: RunConfig{
				Config: Config{
					FlowID:      "sess-1",
					AttackType:  "sequential",
					Positions:   []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{"s": {Type: "wordlist", Values: []string{"a"}}},
					TimeoutMs:   maxTimeoutMs,
				},
			},
		},
		{
			name: "timeout_ms zero is valid",
			cfg: RunConfig{
				Config: Config{
					FlowID:      "sess-1",
					AttackType:  "sequential",
					Positions:   []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
					PayloadSets: map[string]PayloadSet{"s": {Type: "wordlist", Values: []string{"a"}}},
					TimeoutMs:   0,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRunner_Start_AsyncReturn(t *testing.T) {
	runner, _, _, _ := newTestRunner(t)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "Authorization", PayloadSet: "tokens"}},
			PayloadSets: map[string]PayloadSet{
				"tokens": {Type: "wordlist", Values: []string{"t1", "t2", "t3"}},
			},
			Tag: "test-tag",
		},
	}

	result, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	if result.FuzzID == "" {
		t.Error("FuzzID is empty")
	}
	if result.Status != "running" {
		t.Errorf("Status = %q, want %q", result.Status, "running")
	}
	if result.TotalRequests != 3 {
		t.Errorf("TotalRequests = %d, want 3", result.TotalRequests)
	}
	if result.Tag != "test-tag" {
		t.Errorf("Tag = %q, want %q", result.Tag, "test-tag")
	}
}

func TestRunner_Start_CompletesAsync(t *testing.T) {
	runner, fuzzStore, _, _ := newTestRunner(t)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "Authorization", PayloadSet: "tokens"}},
			PayloadSets: map[string]PayloadSet{
				"tokens": {Type: "wordlist", Values: []string{"t1", "t2"}},
			},
		},
	}

	result, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for the job to complete.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not complete in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && jobs[0].Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	results := fuzzStore.getResults()
	if len(results) != 2 {
		t.Errorf("results count = %d, want 2", len(results))
	}

	// Verify the controller is cleaned up from the registry.
	deadline2 := time.After(2 * time.Second)
	for {
		select {
		case <-deadline2:
			t.Fatal("controller was not removed from registry")
		default:
		}
		if runner.Registry().Get(result.FuzzID) == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunner_Start_InvalidConfig(t *testing.T) {
	runner, _, _, _ := newTestRunner(t)

	cfg := RunConfig{
		Config: Config{}, // invalid
	}

	_, err := runner.Start(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for invalid config")
	}
}

func TestRunner_Start_SessionNotFound(t *testing.T) {
	runner, _, _, fetcher := newTestRunner(t)
	fetcher.getErr = fmt.Errorf("not found")

	cfg := RunConfig{
		Config: Config{
			FlowID:     "nonexistent",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
			PayloadSets: map[string]PayloadSet{
				"s": {Type: "wordlist", Values: []string{"a"}},
			},
		},
	}

	_, err := runner.Start(context.Background(), cfg)
	if err == nil {
		t.Error("expected error for session not found")
	}
}

func TestRunner_PauseResumeCancel(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockFlowFetcher{
		fl: &flow.Flow{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{
			{
				FlowID:    "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	// Create a slow HTTP doer so we can control timing.
	slowDoer := &threadSafeMockHTTPDoer{}

	recorder := &threadSafeMockFlowRecorder{}
	fuzzStore := &threadSafeMockFuzzJobStore{}

	engine := NewEngine(fetcher, recorder, fuzzStore, slowDoer, t.TempDir())
	registry := NewJobRegistry()
	runner := NewRunner(engine, registry)

	// Many payloads so the job doesn't finish immediately.
	payloads := make([]string, 1000)
	for i := range payloads {
		payloads[i] = fmt.Sprintf("payload-%d", i)
	}

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
			PayloadSets: map[string]PayloadSet{
				"s": {Type: "wordlist", Values: payloads},
			},
		},
		DelayMs: 10, // small delay so pause has time to take effect
	}

	result, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait a bit then pause.
	time.Sleep(50 * time.Millisecond)

	ctrl := registry.Get(result.FuzzID)
	if ctrl == nil {
		t.Fatal("controller not found in registry")
	}

	if err := ctrl.Pause(); err != nil {
		t.Fatalf("Pause() error = %v", err)
	}
	if ctrl.Status() != StatusPaused {
		t.Errorf("status = %q, want %q", ctrl.Status(), StatusPaused)
	}

	// Resume.
	if err := ctrl.Resume(); err != nil {
		t.Fatalf("Resume() error = %v", err)
	}
	if ctrl.Status() != StatusRunning {
		t.Errorf("status = %q, want %q", ctrl.Status(), StatusRunning)
	}

	// Cancel.
	if err := ctrl.Cancel(); err != nil {
		t.Fatalf("Cancel() error = %v", err)
	}

	// Wait for the job to finish.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not finish after cancel")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && jobs[0].Status == "cancelled" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunner_Concurrency(t *testing.T) {
	runner, fuzzStore, httpDoer, _ := newTestRunner(t)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "Authorization", PayloadSet: "tokens"}},
			PayloadSets: map[string]PayloadSet{
				"tokens": {Type: "wordlist", Values: []string{"t1", "t2", "t3", "t4", "t5"}},
			},
		},
		Concurrency: 3,
	}

	_, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for completion.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not complete in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && jobs[0].Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// All 5 requests should have been made.
	if got := httpDoer.getCallCount(); got != 5 {
		t.Errorf("HTTP call count = %d, want 5", got)
	}

	results := fuzzStore.getResults()
	if len(results) != 5 {
		t.Errorf("results count = %d, want 5", len(results))
	}
}

func TestRunner_StopOnStatusCode(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockFlowFetcher{
		fl: &flow.Flow{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{
			{
				FlowID:    "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	doer := &threadSafeMockHTTPDoer{
		responses: []*http.Response{
			{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}},
			{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}},
			{StatusCode: 503, Body: io.NopCloser(strings.NewReader("unavailable")), Header: http.Header{}},
			{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}},
			{StatusCode: 200, Body: io.NopCloser(strings.NewReader("ok")), Header: http.Header{}},
		},
	}

	recorder := &threadSafeMockFlowRecorder{}
	fuzzStore := &threadSafeMockFuzzJobStore{}

	engine := NewEngine(fetcher, recorder, fuzzStore, doer, t.TempDir())
	registry := NewJobRegistry()
	runner := NewRunner(engine, registry)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
			PayloadSets: map[string]PayloadSet{
				"s": {Type: "wordlist", Values: []string{"a", "b", "c", "d", "e"}},
			},
		},
		StopOn: &StopCondition{
			StatusCodes: []int{503},
		},
	}

	_, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for the job to stop.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not stop in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && (jobs[0].Status == "error" || jobs[0].Status == "completed") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	jobs := fuzzStore.getJobs()
	if len(jobs) == 0 {
		t.Fatal("no jobs found")
	}
	if jobs[0].Status != "error" {
		t.Errorf("job status = %q, want %q", jobs[0].Status, "error")
	}

	// Should have stopped before processing all 5 payloads.
	results := fuzzStore.getResults()
	if len(results) >= 5 {
		t.Errorf("expected fewer than 5 results due to status code stop, got %d", len(results))
	}
}

func TestRunner_StopOnErrorCount(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockFlowFetcher{
		fl: &flow.Flow{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{
			{
				FlowID:    "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	doer := &threadSafeMockHTTPDoer{
		err: fmt.Errorf("connection refused"),
	}

	recorder := &threadSafeMockFlowRecorder{}
	fuzzStore := &threadSafeMockFuzzJobStore{}

	engine := NewEngine(fetcher, recorder, fuzzStore, doer, t.TempDir())
	registry := NewJobRegistry()
	runner := NewRunner(engine, registry)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
			PayloadSets: map[string]PayloadSet{
				"s": {Type: "wordlist", Values: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"}},
			},
		},
		StopOn: &StopCondition{
			ErrorCount: 3,
		},
	}

	_, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for the job to stop.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not stop in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && (jobs[0].Status == "error" || jobs[0].Status == "completed") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	jobs := fuzzStore.getJobs()
	if len(jobs) == 0 {
		t.Fatal("no jobs found")
	}
	if jobs[0].Status != "error" {
		t.Errorf("job status = %q, want %q", jobs[0].Status, "error")
	}
}

func TestRunner_MaxRetries(t *testing.T) {
	testURL, _ := url.Parse("http://example.com/api")

	fetcher := &mockFlowFetcher{
		fl: &flow.Flow{
			ID:       "template-1",
			Protocol: "HTTP/1.x",
		},
		messages: []*flow.Message{
			{
				FlowID:    "template-1",
				Direction: "send",
				Method:    "GET",
				URL:       testURL,
				Headers:   map[string][]string{},
			},
		},
	}

	doer := &threadSafeMockHTTPDoer{
		err: fmt.Errorf("transient error"),
	}

	recorder := &threadSafeMockFlowRecorder{}
	fuzzStore := &threadSafeMockFuzzJobStore{}

	engine := NewEngine(fetcher, recorder, fuzzStore, doer, t.TempDir())
	registry := NewJobRegistry()
	runner := NewRunner(engine, registry)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "X", PayloadSet: "s"}},
			PayloadSets: map[string]PayloadSet{
				"s": {Type: "wordlist", Values: []string{"a"}},
			},
		},
		MaxRetries: 2, // 3 attempts total
	}

	_, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for completion.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not complete in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && jobs[0].Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// With 1 payload and max_retries=2, we should have 3 attempts (1 + 2 retries).
	if got := doer.getCallCount(); got != 3 {
		t.Errorf("HTTP call count = %d, want 3 (1 original + 2 retries)", got)
	}
}

func TestRunner_DefaultConcurrency(t *testing.T) {
	runner, fuzzStore, _, _ := newTestRunner(t)

	cfg := RunConfig{
		Config: Config{
			FlowID:     "template-1",
			AttackType: "sequential",
			Positions:  []Position{{ID: "pos-0", Location: "header", Name: "Authorization", PayloadSet: "tokens"}},
			PayloadSets: map[string]PayloadSet{
				"tokens": {Type: "wordlist", Values: []string{"t1"}},
			},
		},
		// Concurrency not set, should default to 1.
	}

	_, err := runner.Start(context.Background(), cfg)
	if err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	// Wait for completion.
	deadline := time.After(5 * time.Second)
	for {
		select {
		case <-deadline:
			t.Fatal("job did not complete in time")
		default:
		}

		jobs := fuzzStore.getJobs()
		if len(jobs) > 0 && jobs[0].Status == "completed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	results := fuzzStore.getResults()
	if len(results) != 1 {
		t.Errorf("results count = %d, want 1", len(results))
	}
}
