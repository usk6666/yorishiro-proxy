package macro

import (
	"context"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"
)

// mockSessionFetcher is a test double for SessionFetcher.
type mockSessionFetcher struct {
	sessions map[string]*SendRequest
}

func (m *mockSessionFetcher) GetSessionRequest(_ context.Context, sessionID string) (*SendRequest, error) {
	req, ok := m.sessions[sessionID]
	if !ok {
		return nil, fmt.Errorf("session %q not found", sessionID)
	}
	return req, nil
}

// mockSendFunc creates a send function that returns predefined responses.
func mockSendFunc(responses map[string]*SendResponse) SendFunc {
	return func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		resp, ok := responses[req.URL]
		if !ok {
			return &SendResponse{StatusCode: 404, Body: []byte("not found")}, nil
		}
		return resp, nil
	}
}

func TestNewEngine(t *testing.T) {
	fetcher := &mockSessionFetcher{}
	send := func(context.Context, *SendRequest) (*SendResponse, error) { return nil, nil }

	tests := []struct {
		name    string
		send    SendFunc
		fetch   SessionFetcher
		wantErr bool
	}{
		{name: "valid", send: send, fetch: fetcher},
		{name: "nil send", send: nil, fetch: fetcher, wantErr: true},
		{name: "nil fetcher", send: send, fetch: nil, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewEngine(tt.send, tt.fetch)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewEngine() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidateMacro(t *testing.T) {
	tests := []struct {
		name    string
		macro   *Macro
		wantErr bool
	}{
		{
			name:    "nil macro",
			macro:   nil,
			wantErr: true,
		},
		{
			name:    "empty name",
			macro:   &Macro{Steps: []Step{{ID: "s1", SessionID: "sess1"}}},
			wantErr: true,
		},
		{
			name:    "no steps",
			macro:   &Macro{Name: "test"},
			wantErr: true,
		},
		{
			name: "too many steps",
			macro: func() *Macro {
				steps := make([]Step, MaxSteps+1)
				for i := range steps {
					steps[i] = Step{ID: fmt.Sprintf("s%d", i), SessionID: "sess"}
				}
				return &Macro{Name: "test", Steps: steps}
			}(),
			wantErr: true,
		},
		{
			name: "empty step ID",
			macro: &Macro{
				Name:  "test",
				Steps: []Step{{SessionID: "sess1"}},
			},
			wantErr: true,
		},
		{
			name: "duplicate step ID",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{ID: "s1", SessionID: "sess1"},
					{ID: "s1", SessionID: "sess2"},
				},
			},
			wantErr: true,
		},
		{
			name: "empty session ID",
			macro: &Macro{
				Name:  "test",
				Steps: []Step{{ID: "s1"}},
			},
			wantErr: true,
		},
		{
			name: "invalid on_error",
			macro: &Macro{
				Name:  "test",
				Steps: []Step{{ID: "s1", SessionID: "sess1", OnError: "invalid"}},
			},
			wantErr: true,
		},
		{
			name: "forward guard reference",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{ID: "s1", SessionID: "sess1", When: &Guard{Step: "s2"}},
					{ID: "s2", SessionID: "sess2"},
				},
			},
			wantErr: true,
		},
		{
			name: "extraction rule without name",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{
						ID: "s1", SessionID: "sess1",
						Extract: []ExtractionRule{{Source: ExtractionSourceBody, From: ExtractionFromResponse}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "extraction rule without source",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{
						ID: "s1", SessionID: "sess1",
						Extract: []ExtractionRule{{Name: "var1", From: ExtractionFromResponse}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "extraction rule without from",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{
						ID: "s1", SessionID: "sess1",
						Extract: []ExtractionRule{{Name: "var1", Source: ExtractionSourceBody}},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "valid macro",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{ID: "s1", SessionID: "sess1"},
					{ID: "s2", SessionID: "sess2", When: &Guard{Step: "s1", StatusCode: intPtr(200)}},
				},
			},
		},
		{
			name: "valid on_error values",
			macro: &Macro{
				Name: "test",
				Steps: []Step{
					{ID: "s1", SessionID: "sess1", OnError: OnErrorAbort},
					{ID: "s2", SessionID: "sess2", OnError: OnErrorSkip},
					{ID: "s3", SessionID: "sess3", OnError: OnErrorRetry},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateMacro(tt.macro)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateMacro() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestEngine_Run_SimpleSequence(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"login-session": {
				Method:  "POST",
				URL:     "https://example.com/login",
				Headers: map[string][]string{"Content-Type": {"application/x-www-form-urlencoded"}},
				Body:    []byte("user=admin&pass=secret"),
			},
			"csrf-session": {
				Method:  "GET",
				URL:     "https://example.com/csrf",
				Headers: map[string][]string{},
			},
		},
	}

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		switch req.URL {
		case "https://example.com/login":
			return &SendResponse{
				StatusCode: 302,
				Headers:    http.Header{"Set-Cookie": {"PHPSESSID=abc123; Path=/"}},
				Body:       []byte("redirecting"),
			}, nil
		case "https://example.com/csrf":
			return &SendResponse{
				StatusCode: 200,
				Headers:    http.Header{"Content-Type": {"application/json"}},
				Body:       []byte(`{"csrf_token":"xyz789"}`),
			}, nil
		default:
			return &SendResponse{StatusCode: 404}, nil
		}
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "auth-flow",
		Steps: []Step{
			{
				ID:        "login",
				SessionID: "login-session",
				Extract: []ExtractionRule{
					{
						Name:       "session_cookie",
						From:       ExtractionFromResponse,
						Source:     ExtractionSourceHeader,
						HeaderName: "Set-Cookie",
						Regex:      `PHPSESSID=([^;]+)`,
						Group:      1,
					},
				},
			},
			{
				ID:        "get-csrf",
				SessionID: "csrf-session",
				OverrideHeaders: map[string]string{
					"Cookie": "PHPSESSID={{session_cookie}}",
				},
				Extract: []ExtractionRule{
					{
						Name:     "csrf_token",
						From:     ExtractionFromResponse,
						Source:   ExtractionSourceBodyJSON,
						JSONPath: "$.csrf_token",
					},
				},
			},
		},
		InitialVars: map[string]string{
			"password": "admin123",
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if result.StepsExecuted != 2 {
		t.Errorf("result.StepsExecuted = %d, want 2", result.StepsExecuted)
	}
	if result.KVStore["session_cookie"] != "abc123" {
		t.Errorf("KVStore[session_cookie] = %q, want %q", result.KVStore["session_cookie"], "abc123")
	}
	if result.KVStore["csrf_token"] != "xyz789" {
		t.Errorf("KVStore[csrf_token] = %q, want %q", result.KVStore["csrf_token"], "xyz789")
	}
	if result.KVStore["password"] != "admin123" {
		t.Errorf("KVStore[password] = %q, want %q", result.KVStore["password"], "admin123")
	}
	if len(result.StepResults) != 2 {
		t.Fatalf("len(StepResults) = %d, want 2", len(result.StepResults))
	}
	if result.StepResults[0].StatusCode != 302 {
		t.Errorf("StepResults[0].StatusCode = %d, want 302", result.StepResults[0].StatusCode)
	}
	if result.StepResults[1].StatusCode != 200 {
		t.Errorf("StepResults[1].StatusCode = %d, want 200", result.StepResults[1].StatusCode)
	}
}

func TestEngine_Run_VarOverride(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/api"},
		},
	}
	sendFunc := func(_ context.Context, _ *SendRequest) (*SendResponse, error) {
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name:  "test",
		Steps: []Step{{ID: "s1", SessionID: "sess1"}},
		InitialVars: map[string]string{
			"key1": "initial",
			"key2": "unchanged",
		},
	}

	result, err := engine.Run(context.Background(), macro, map[string]string{
		"key1": "overridden",
		"key3": "new",
	})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.KVStore["key1"] != "overridden" {
		t.Errorf("KVStore[key1] = %q, want %q", result.KVStore["key1"], "overridden")
	}
	if result.KVStore["key2"] != "unchanged" {
		t.Errorf("KVStore[key2] = %q, want %q", result.KVStore["key2"], "unchanged")
	}
	if result.KVStore["key3"] != "new" {
		t.Errorf("KVStore[key3] = %q, want %q", result.KVStore["key3"], "new")
	}
}

func TestEngine_Run_StepGuardSkip(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/check"},
			"sess2": {Method: "POST", URL: "https://example.com/mfa"},
			"sess3": {Method: "GET", URL: "https://example.com/api"},
		},
	}

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		switch req.URL {
		case "https://example.com/check":
			return &SendResponse{StatusCode: 200}, nil // No MFA needed
		case "https://example.com/mfa":
			return &SendResponse{StatusCode: 200}, nil
		case "https://example.com/api":
			return &SendResponse{StatusCode: 200}, nil
		}
		return &SendResponse{StatusCode: 404}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "conditional",
		Steps: []Step{
			{ID: "check", SessionID: "sess1"},
			{
				ID:        "mfa",
				SessionID: "sess2",
				When:      &Guard{Step: "check", StatusCode: intPtr(302)}, // Only if redirect
			},
			{ID: "api", SessionID: "sess3"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if result.StepsExecuted != 2 {
		t.Errorf("result.StepsExecuted = %d, want 2", result.StepsExecuted)
	}
	if len(result.StepResults) != 3 {
		t.Fatalf("len(StepResults) = %d, want 3", len(result.StepResults))
	}
	if result.StepResults[1].Status != "skipped" {
		t.Errorf("StepResults[1].Status = %q, want %q", result.StepResults[1].Status, "skipped")
	}
}

func TestEngine_Run_StepGuardExecute(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/check"},
			"sess2": {Method: "POST", URL: "https://example.com/mfa"},
		},
	}

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		switch req.URL {
		case "https://example.com/check":
			return &SendResponse{
				StatusCode: 302,
				Headers:    http.Header{"Location": {"/mfa"}},
			}, nil
		case "https://example.com/mfa":
			return &SendResponse{StatusCode: 200}, nil
		}
		return &SendResponse{StatusCode: 404}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "conditional-execute",
		Steps: []Step{
			{ID: "check", SessionID: "sess1"},
			{
				ID:        "mfa",
				SessionID: "sess2",
				When: &Guard{
					Step:        "check",
					StatusCode:  intPtr(302),
					HeaderMatch: map[string]string{"Location": "/mfa.*"},
				},
			},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.StepsExecuted != 2 {
		t.Errorf("result.StepsExecuted = %d, want 2", result.StepsExecuted)
	}
	if result.StepResults[1].Status != "completed" {
		t.Errorf("StepResults[1].Status = %q, want %q", result.StepResults[1].Status, "completed")
	}
}

func TestEngine_Run_OnErrorAbort(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/fail"},
			"sess2": {Method: "GET", URL: "https://example.com/ok"},
		},
	}

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		if req.URL == "https://example.com/fail" {
			return nil, fmt.Errorf("connection refused")
		}
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "abort-test",
		Steps: []Step{
			{ID: "fail-step", SessionID: "sess1", OnError: OnErrorAbort},
			{ID: "never-reached", SessionID: "sess2"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "error" {
		t.Errorf("result.Status = %q, want %q", result.Status, "error")
	}
	if result.StepsExecuted != 0 {
		t.Errorf("result.StepsExecuted = %d, want 0", result.StepsExecuted)
	}
	if len(result.StepResults) != 1 {
		t.Fatalf("len(StepResults) = %d, want 1", len(result.StepResults))
	}
	if result.StepResults[0].Status != "error" {
		t.Errorf("StepResults[0].Status = %q, want %q", result.StepResults[0].Status, "error")
	}
}

func TestEngine_Run_OnErrorSkip(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/fail"},
			"sess2": {Method: "GET", URL: "https://example.com/ok"},
		},
	}

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		if req.URL == "https://example.com/fail" {
			return nil, fmt.Errorf("connection refused")
		}
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "skip-test",
		Steps: []Step{
			{ID: "fail-step", SessionID: "sess1", OnError: OnErrorSkip},
			{ID: "ok-step", SessionID: "sess2"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	// The failed step is counted because it was attempted (but skipped on error).
	// The ok-step is also counted.
	if result.StepsExecuted != 1 {
		t.Errorf("result.StepsExecuted = %d, want 1", result.StepsExecuted)
	}
	if len(result.StepResults) != 2 {
		t.Fatalf("len(StepResults) = %d, want 2", len(result.StepResults))
	}
	if result.StepResults[0].Status != "skipped" {
		t.Errorf("StepResults[0].Status = %q, want %q", result.StepResults[0].Status, "skipped")
	}
	if result.StepResults[1].Status != "completed" {
		t.Errorf("StepResults[1].Status = %q, want %q", result.StepResults[1].Status, "completed")
	}
}

func TestEngine_Run_OnErrorRetry(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/flaky"},
		},
	}

	var attempts atomic.Int32

	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		n := attempts.Add(1)
		if n < 3 {
			return nil, fmt.Errorf("temporary error (attempt %d)", n)
		}
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "retry-test",
		Steps: []Step{
			{
				ID:           "flaky-step",
				SessionID:    "sess1",
				OnError:      OnErrorRetry,
				RetryCount:   3,
				RetryDelayMs: 1, // Minimal delay for tests.
			},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if got := attempts.Load(); got != 3 {
		t.Errorf("attempts = %d, want 3", got)
	}
}

func TestEngine_Run_OnErrorRetryExhausted(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/always-fail"},
		},
	}

	sendFunc := func(_ context.Context, _ *SendRequest) (*SendResponse, error) {
		return nil, fmt.Errorf("permanent error")
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "retry-exhausted",
		Steps: []Step{
			{
				ID:           "always-fail",
				SessionID:    "sess1",
				OnError:      OnErrorRetry,
				RetryCount:   2,
				RetryDelayMs: 1,
			},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "error" {
		t.Errorf("result.Status = %q, want %q", result.Status, "error")
	}
}

func TestEngine_Run_MacroTimeout(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/slow"},
		},
	}

	sendFunc := func(ctx context.Context, _ *SendRequest) (*SendResponse, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return &SendResponse{StatusCode: 200}, nil
		}
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name:      "timeout-test",
		TimeoutMs: 100, // 100ms macro timeout.
		Steps: []Step{
			{ID: "slow-step", SessionID: "sess1", TimeoutMs: 5000},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "timeout" {
		t.Errorf("result.Status = %q, want %q", result.Status, "timeout")
	}
}

func TestEngine_Run_StepTimeout(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/slow"},
			"sess2": {Method: "GET", URL: "https://example.com/ok"},
		},
	}

	sendFunc := func(ctx context.Context, req *SendRequest) (*SendResponse, error) {
		if req.URL == "https://example.com/slow" {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(5 * time.Second):
				return &SendResponse{StatusCode: 200}, nil
			}
		}
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name:      "step-timeout-skip",
		TimeoutMs: 10_000, // Long macro timeout.
		Steps: []Step{
			{
				ID:        "slow-step",
				SessionID: "sess1",
				TimeoutMs: 100, // Short step timeout.
				OnError:   OnErrorSkip,
			},
			{ID: "ok-step", SessionID: "sess2"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if result.StepResults[0].Status != "skipped" {
		t.Errorf("StepResults[0].Status = %q, want %q", result.StepResults[0].Status, "skipped")
	}
}

func TestEngine_Run_TemplateExpansion(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {
				Method:  "POST",
				URL:     "https://example.com/api",
				Headers: map[string][]string{"Content-Type": {"application/json"}},
				Body:    []byte(`{}`),
			},
		},
	}

	var capturedReq *SendRequest
	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		capturedReq = req
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	body := `{"token":"{{csrf | url_encode}}"}`
	macro := &Macro{
		Name: "template-test",
		Steps: []Step{
			{
				ID:        "s1",
				SessionID: "sess1",
				OverrideHeaders: map[string]string{
					"Cookie":       "sid={{session_cookie}}",
					"X-CSRF-Token": "{{csrf}}",
				},
				OverrideBody: &body,
			},
		},
		InitialVars: map[string]string{
			"session_cookie": "abc123",
			"csrf":           "token with spaces",
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}

	if capturedReq == nil {
		t.Fatal("sendFunc was not called")
	}

	if got := capturedReq.Headers["Cookie"]; len(got) != 1 || got[0] != "sid=abc123" {
		t.Errorf("Cookie header = %v, want [sid=abc123]", got)
	}
	if got := capturedReq.Headers["X-CSRF-Token"]; len(got) != 1 || got[0] != "token with spaces" {
		t.Errorf("X-CSRF-Token header = %v, want [token with spaces]", got)
	}
	wantBody := `{"token":"token+with+spaces"}`
	if string(capturedReq.Body) != wantBody {
		t.Errorf("body = %q, want %q", string(capturedReq.Body), wantBody)
	}
}

func TestEngine_Run_RequiredExtractionFailure(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/api"},
		},
	}

	sendFunc := func(_ context.Context, _ *SendRequest) (*SendResponse, error) {
		return &SendResponse{
			StatusCode: 200,
			Body:       []byte("no token here"),
		}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "required-fail",
		Steps: []Step{
			{
				ID:        "s1",
				SessionID: "sess1",
				Extract: []ExtractionRule{
					{
						Name:     "token",
						From:     ExtractionFromResponse,
						Source:   ExtractionSourceBody,
						Regex:    `token=([^&]+)`,
						Group:    1,
						Required: true,
					},
				},
			},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "error" {
		t.Errorf("result.Status = %q, want %q", result.Status, "error")
	}
}

func TestEngine_Run_SessionFetchError(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{}, // Empty — no sessions.
	}

	sendFunc := func(_ context.Context, _ *SendRequest) (*SendResponse, error) {
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "missing-session",
		Steps: []Step{
			{ID: "s1", SessionID: "nonexistent"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "error" {
		t.Errorf("result.Status = %q, want %q", result.Status, "error")
	}
}

func TestEngine_Run_KVStoreIndependence(t *testing.T) {
	// Verify that each Run call gets an independent KV Store.
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/api"},
		},
	}

	sendFunc := func(_ context.Context, _ *SendRequest) (*SendResponse, error) {
		return &SendResponse{
			StatusCode: 200,
			Headers:    http.Header{"X-Token": {"unique-token"}},
		}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "kv-test",
		Steps: []Step{
			{
				ID:        "s1",
				SessionID: "sess1",
				Extract: []ExtractionRule{
					{
						Name:       "token",
						From:       ExtractionFromResponse,
						Source:     ExtractionSourceHeader,
						HeaderName: "X-Token",
					},
				},
			},
		},
	}

	result1, err := engine.Run(context.Background(), macro, map[string]string{"run": "first"})
	if err != nil {
		t.Fatalf("Run() 1 error = %v", err)
	}

	result2, err := engine.Run(context.Background(), macro, map[string]string{"run": "second"})
	if err != nil {
		t.Fatalf("Run() 2 error = %v", err)
	}

	// Both should have independent KV stores.
	if result1.KVStore["run"] != "first" {
		t.Errorf("result1.KVStore[run] = %q, want %q", result1.KVStore["run"], "first")
	}
	if result2.KVStore["run"] != "second" {
		t.Errorf("result2.KVStore[run] = %q, want %q", result2.KVStore["run"], "second")
	}
}

func TestEngine_Run_ContextCancellation(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/api"},
		},
	}

	sendFunc := func(ctx context.Context, _ *SendRequest) (*SendResponse, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(5 * time.Second):
			return &SendResponse{StatusCode: 200}, nil
		}
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	macro := &Macro{
		Name:      "cancel-test",
		TimeoutMs: 10_000,
		Steps: []Step{
			{ID: "s1", SessionID: "sess1"},
		},
	}

	result, err := engine.Run(ctx, macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "timeout" {
		t.Errorf("result.Status = %q, want %q", result.Status, "timeout")
	}
}

func TestEngine_Run_OverrideURL(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {
				Method: "GET",
				URL:    "https://example.com/original",
			},
		},
	}

	var capturedURL string
	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		capturedURL = req.URL
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "url-override",
		Steps: []Step{
			{
				ID:          "s1",
				SessionID:   "sess1",
				OverrideURL: "https://example.com/{{path}}",
			},
		},
		InitialVars: map[string]string{"path": "new-path"},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if capturedURL != "https://example.com/new-path" {
		t.Errorf("capturedURL = %q, want %q", capturedURL, "https://example.com/new-path")
	}
}

func TestEngine_Run_OverrideMethod(t *testing.T) {
	fetcher := &mockSessionFetcher{
		sessions: map[string]*SendRequest{
			"sess1": {Method: "GET", URL: "https://example.com/api"},
		},
	}

	var capturedMethod string
	sendFunc := func(_ context.Context, req *SendRequest) (*SendResponse, error) {
		capturedMethod = req.Method
		return &SendResponse{StatusCode: 200}, nil
	}

	engine, err := NewEngine(sendFunc, fetcher)
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}

	macro := &Macro{
		Name: "method-override",
		Steps: []Step{
			{ID: "s1", SessionID: "sess1", OverrideMethod: "POST"},
		},
	}

	result, err := engine.Run(context.Background(), macro, nil)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	if result.Status != "completed" {
		t.Errorf("result.Status = %q, want %q", result.Status, "completed")
	}
	if capturedMethod != "POST" {
		t.Errorf("capturedMethod = %q, want %q", capturedMethod, "POST")
	}
}

func TestBuildRequest(t *testing.T) {
	base := &SendRequest{
		Method:  "GET",
		URL:     "https://example.com/api",
		Headers: map[string][]string{"Accept": {"application/json"}, "Cookie": {"old=value"}},
		Body:    []byte("original body"),
	}

	kvStore := map[string]string{
		"token": "abc123",
	}

	body := "new body with {{token}}"
	step := &Step{
		ID:             "s1",
		SessionID:      "sess1",
		OverrideMethod: "POST",
		OverrideURL:    "https://example.com/new",
		OverrideHeaders: map[string]string{
			"Cookie":       "session={{token}}",
			"X-Custom":     "static",
		},
		OverrideBody: &body,
	}

	req, err := buildRequest(step, base, kvStore)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}

	if req.Method != "POST" {
		t.Errorf("Method = %q, want %q", req.Method, "POST")
	}
	if req.URL != "https://example.com/new" {
		t.Errorf("URL = %q, want %q", req.URL, "https://example.com/new")
	}
	// Original Accept header should be preserved.
	if got := req.Headers["Accept"]; len(got) != 1 || got[0] != "application/json" {
		t.Errorf("Accept = %v, want [application/json]", got)
	}
	// Cookie should be overridden.
	if got := req.Headers["Cookie"]; len(got) != 1 || got[0] != "session=abc123" {
		t.Errorf("Cookie = %v, want [session=abc123]", got)
	}
	if string(req.Body) != "new body with abc123" {
		t.Errorf("Body = %q, want %q", string(req.Body), "new body with abc123")
	}

	// Verify the original base was not mutated.
	if base.Method != "GET" {
		t.Error("base request was mutated")
	}
	if got := base.Headers["Cookie"]; len(got) != 1 || got[0] != "old=value" {
		t.Error("base headers were mutated")
	}
}

func TestBuildRequest_NoOverrides(t *testing.T) {
	base := &SendRequest{
		Method:  "GET",
		URL:     "https://example.com/api",
		Headers: map[string][]string{"Accept": {"*/*"}},
		Body:    []byte("body"),
	}

	step := &Step{ID: "s1", SessionID: "sess1"}
	kvStore := map[string]string{}

	req, err := buildRequest(step, base, kvStore)
	if err != nil {
		t.Fatalf("buildRequest() error = %v", err)
	}

	if req.Method != "GET" {
		t.Errorf("Method = %q, want %q", req.Method, "GET")
	}
	if req.URL != "https://example.com/api" {
		t.Errorf("URL = %q, want %q", req.URL, "https://example.com/api")
	}
	if string(req.Body) != "body" {
		t.Errorf("Body = %q, want %q", string(req.Body), "body")
	}
}

func TestCopyHeaders(t *testing.T) {
	original := map[string][]string{
		"A": {"1", "2"},
		"B": {"3"},
	}

	cp := copyHeaders(original)

	// Modify copy.
	cp["A"] = append(cp["A"], "modified")
	cp["C"] = []string{"new"}

	// Original should be unaffected.
	if len(original["A"]) != 2 {
		t.Errorf("original A was modified: %v", original["A"])
	}
	if _, exists := original["C"]; exists {
		t.Error("original has key C after copy modification")
	}
}

func TestCopyHeaders_Nil(t *testing.T) {
	cp := copyHeaders(nil)
	if cp == nil {
		t.Error("copyHeaders(nil) returned nil, want empty map")
	}
	if len(cp) != 0 {
		t.Errorf("copyHeaders(nil) returned non-empty map: %v", cp)
	}
}
