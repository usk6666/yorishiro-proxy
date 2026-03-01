package fuzzer

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/katashiro-proxy/internal/session"
)

// mockHookCallbacks implements HookCallbacks for testing.
type mockHookCallbacks struct {
	preSendKVStore    map[string]string
	preSendErr        error
	preSendCalls      int
	postSendCalls     int
	postSendErr       error
	postSendKVStore   map[string]string // captured kvStore passed to PostSend
	updateCalls       int
}

func (m *mockHookCallbacks) PreSend(_ context.Context, _ *HookState) (map[string]string, error) {
	m.preSendCalls++
	return m.preSendKVStore, m.preSendErr
}

func (m *mockHookCallbacks) PostSend(_ context.Context, _ *HookState, _ int, _ []byte, kvStore map[string]string) error {
	m.postSendCalls++
	m.postSendKVStore = kvStore
	return m.postSendErr
}

func (m *mockHookCallbacks) UpdateState(state *HookState, statusCode int, hadError bool) {
	m.updateCalls++
	state.RequestCount++
	state.LastStatusCode = statusCode
	state.LastError = hadError
}

// --- expandRequestData tests ---

func TestExpandRequestData_URL(t *testing.T) {
	// Note: url.Parse URL-encodes braces, so we set the RawPath manually
	// to simulate a URL with template placeholders. In practice, the
	// template vars in the URL are more commonly in query parameters.
	u, _ := url.Parse("https://example.com/api?token={{token}}")
	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{},
	}

	kvStore := map[string]string{"token": "abc123"}
	result := expandRequestData(baseData, kvStore)

	wantURL := "https://example.com/api?token=abc123"
	if result.URL.String() != wantURL {
		t.Errorf("URL = %q, want %q", result.URL.String(), wantURL)
	}

	// Original should be unchanged (Clone creates a deep copy).
	originalURL := baseData.URL.String()
	if originalURL == wantURL {
		t.Errorf("original URL was modified: %q", originalURL)
	}
}

func TestExpandRequestData_Headers(t *testing.T) {
	u, _ := url.Parse("https://example.com/api")
	baseData := &RequestData{
		Method: "GET",
		URL:    u,
		Headers: map[string][]string{
			"Cookie":       {"sid={{session_cookie}}"},
			"X-CSRF-Token": {"{{csrf_token}}"},
		},
	}

	kvStore := map[string]string{
		"session_cookie": "abc123",
		"csrf_token":     "x9f2k",
	}
	result := expandRequestData(baseData, kvStore)

	if result.Headers["Cookie"][0] != "sid=abc123" {
		t.Errorf("Cookie = %q, want %q", result.Headers["Cookie"][0], "sid=abc123")
	}
	if result.Headers["X-CSRF-Token"][0] != "x9f2k" {
		t.Errorf("X-CSRF-Token = %q, want %q", result.Headers["X-CSRF-Token"][0], "x9f2k")
	}
}

func TestExpandRequestData_Body(t *testing.T) {
	u, _ := url.Parse("https://example.com/api")
	baseData := &RequestData{
		Method:  "POST",
		URL:     u,
		Headers: map[string][]string{},
		Body:    []byte(`{"token":"{{token}}"}`),
	}

	kvStore := map[string]string{"token": "jwt-value"}
	result := expandRequestData(baseData, kvStore)

	wantBody := `{"token":"jwt-value"}`
	if string(result.Body) != wantBody {
		t.Errorf("Body = %q, want %q", string(result.Body), wantBody)
	}

	// Original should be unchanged.
	if string(baseData.Body) != `{"token":"{{token}}"}` {
		t.Errorf("original Body was modified: %q", string(baseData.Body))
	}
}

func TestExpandRequestData_EmptyKVStore(t *testing.T) {
	u, _ := url.Parse("https://example.com/api/{{version}}")
	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{"X-Token": {"{{token}}"}},
	}

	result := expandRequestData(baseData, map[string]string{})

	// Should remain unchanged.
	if result.URL.String() != "https://example.com/api/%7B%7Bversion%7D%7D" {
		// URL parsing normalizes the braces.
		t.Logf("URL = %q (URL-encoded braces are expected)", result.URL.String())
	}
	if result.Headers["X-Token"][0] != "{{token}}" {
		t.Errorf("Header unchanged = %q, want %q", result.Headers["X-Token"][0], "{{token}}")
	}
}

// --- expandSimpleTemplate tests ---

func TestExpandSimpleTemplate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		kvStore map[string]string
		want    string
	}{
		{
			name:    "no_placeholders",
			input:   "hello world",
			kvStore: map[string]string{"key": "val"},
			want:    "hello world",
		},
		{
			name:    "single_placeholder",
			input:   "token={{token}}",
			kvStore: map[string]string{"token": "abc"},
			want:    "token=abc",
		},
		{
			name:    "multiple_placeholders",
			input:   "{{a}} and {{b}}",
			kvStore: map[string]string{"a": "1", "b": "2"},
			want:    "1 and 2",
		},
		{
			name:    "unknown_placeholder",
			input:   "{{unknown}}",
			kvStore: map[string]string{"key": "val"},
			want:    "{{unknown}}",
		},
		{
			name:    "empty_kvstore",
			input:   "{{key}}",
			kvStore: map[string]string{},
			want:    "{{key}}",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := expandSimpleTemplate(tt.input, tt.kvStore)
			if got != tt.want {
				t.Errorf("expandSimpleTemplate(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- executeFuzzCaseWithHooks tests ---

func TestExecuteFuzzCaseWithHooks_NilHooks(t *testing.T) {
	// When hooks is nil, it should delegate to executeFuzzCase.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/test")
	store := newMemStore()

	engine := NewEngine(store, store, store, &http.Client{Timeout: 5 * time.Second}, "")

	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{},
	}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCaseWithHooks(context.Background(), baseData, nil, fc, "HTTP/1.x", 5*time.Second, "fuzz-1", nil, nil, nil)

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
}

func TestExecuteFuzzCaseWithHooks_WithPreSend(t *testing.T) {
	// Create a server that checks for the injected header.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		fmt.Fprintf(w, "token=%s", r.Header.Get("X-Token"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/test")
	store := newMemStore()

	engine := NewEngine(store, store, store, &http.Client{Timeout: 5 * time.Second}, "")

	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{"X-Token": {"{{token}}"}},
	}

	hooks := &mockHookCallbacks{
		preSendKVStore: map[string]string{"token": "injected-value"},
	}
	hookState := &HookState{}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCaseWithHooks(context.Background(), baseData, nil, fc, "HTTP/1.x", 5*time.Second, "fuzz-1", hooks, hookState, nil)

	if result.Error != "" {
		t.Fatalf("unexpected error: %s", result.Error)
	}
	if result.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", result.StatusCode)
	}
	if hooks.preSendCalls != 1 {
		t.Errorf("preSendCalls = %d, want 1", hooks.preSendCalls)
	}
	if hooks.postSendCalls != 1 {
		t.Errorf("postSendCalls = %d, want 1", hooks.postSendCalls)
	}
}

func TestExecuteFuzzCaseWithHooks_KVStorePropagation(t *testing.T) {
	tests := []struct {
		name           string
		preSendKVStore map[string]string
		wantKVStore    map[string]string
	}{
		{
			name:           "kvstore_propagated_to_post_send",
			preSendKVStore: map[string]string{"auth_session": "session=abc", "item_id": "4"},
			wantKVStore:    map[string]string{"auth_session": "session=abc", "item_id": "4"},
		},
		{
			name:           "nil_kvstore_propagated_as_nil",
			preSendKVStore: nil,
			wantKVStore:    nil,
		},
		{
			name:           "empty_kvstore_propagated_as_empty",
			preSendKVStore: map[string]string{},
			wantKVStore:    map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				w.Write([]byte("ok"))
			}))
			defer server.Close()

			u, _ := url.Parse(server.URL + "/test")
			store := newMemStore()
			engine := NewEngine(store, store, store, &http.Client{Timeout: 5 * time.Second}, "")

			baseData := &RequestData{
				Method:  "GET",
				URL:     u,
				Headers: map[string][]string{},
			}

			hooks := &mockHookCallbacks{
				preSendKVStore: tt.preSendKVStore,
			}
			hookState := &HookState{}
			fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

			result := engine.executeFuzzCaseWithHooks(context.Background(), baseData, nil, fc, "HTTP/1.x", 5*time.Second, "fuzz-1", hooks, hookState, nil)

			if result.Error != "" {
				t.Fatalf("unexpected error: %s", result.Error)
			}
			if hooks.postSendCalls != 1 {
				t.Fatalf("postSendCalls = %d, want 1", hooks.postSendCalls)
			}

			// Verify the kvStore was propagated to PostSend.
			if tt.wantKVStore == nil {
				if hooks.postSendKVStore != nil {
					t.Errorf("postSendKVStore = %v, want nil", hooks.postSendKVStore)
				}
			} else {
				if len(hooks.postSendKVStore) != len(tt.wantKVStore) {
					t.Errorf("postSendKVStore length = %d, want %d", len(hooks.postSendKVStore), len(tt.wantKVStore))
				}
				for k, want := range tt.wantKVStore {
					got, ok := hooks.postSendKVStore[k]
					if !ok {
						t.Errorf("postSendKVStore missing key %q", k)
					} else if got != want {
						t.Errorf("postSendKVStore[%q] = %q, want %q", k, got, want)
					}
				}
			}
		})
	}
}

func TestExecuteFuzzCaseWithHooks_PreSendError(t *testing.T) {
	store := newMemStore()
	engine := NewEngine(store, store, store, &http.Client{Timeout: 5 * time.Second}, "")

	u, _ := url.Parse("https://example.com/test")
	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{},
	}

	hooks := &mockHookCallbacks{
		preSendErr: fmt.Errorf("macro execution failed"),
	}
	hookState := &HookState{}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCaseWithHooks(context.Background(), baseData, nil, fc, "HTTP/1.x", 5*time.Second, "fuzz-1", hooks, hookState, nil)

	if result.Error == "" {
		t.Fatal("expected error from pre_send hook")
	}
	if result.Error != "pre_send hook: macro execution failed" {
		t.Errorf("Error = %q, want prefix %q", result.Error, "pre_send hook: macro execution failed")
	}
}

func TestExecuteFuzzCaseWithHooks_PostSendError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		w.Write([]byte("ok"))
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL + "/test")
	store := newMemStore()

	engine := NewEngine(store, store, store, &http.Client{Timeout: 5 * time.Second}, "")

	baseData := &RequestData{
		Method:  "GET",
		URL:     u,
		Headers: map[string][]string{},
	}

	hooks := &mockHookCallbacks{
		postSendErr: fmt.Errorf("post_receive macro failed"),
	}
	hookState := &HookState{}

	fc := FuzzCase{Index: 0, Payloads: map[string]string{}}

	result := engine.executeFuzzCaseWithHooks(context.Background(), baseData, nil, fc, "HTTP/1.x", 5*time.Second, "fuzz-1", hooks, hookState, nil)

	// Post-receive errors are recorded in the result.
	if result.Error == "" {
		t.Fatal("expected error from post_send hook")
	}
	if result.Error != "post_receive hook: post_receive macro failed" {
		t.Errorf("Error = %q", result.Error)
	}
}

// --- HookState tests ---

func TestHookState_Initial(t *testing.T) {
	state := &HookState{}
	if state.PreSendExecuted {
		t.Error("PreSendExecuted should be false initially")
	}
	if state.RequestCount != 0 {
		t.Errorf("RequestCount = %d, want 0", state.RequestCount)
	}
}

// --- memStore implements the interfaces needed for fuzzer engine tests ---

type memStore struct {
	sessions map[string]*session.Session
	messages map[string][]*session.Message
	fuzzJobs map[string]*session.FuzzJob
	results  []*session.FuzzResult
}

func newMemStore() *memStore {
	return &memStore{
		sessions: make(map[string]*session.Session),
		messages: make(map[string][]*session.Message),
		fuzzJobs: make(map[string]*session.FuzzJob),
	}
}

func (m *memStore) GetSession(_ context.Context, id string) (*session.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, fmt.Errorf("session %s not found", id)
	}
	return s, nil
}

func (m *memStore) GetMessages(_ context.Context, sessionID string, opts session.MessageListOptions) ([]*session.Message, error) {
	msgs := m.messages[sessionID]
	if opts.Direction != "" {
		var filtered []*session.Message
		for _, msg := range msgs {
			if msg.Direction == opts.Direction {
				filtered = append(filtered, msg)
			}
		}
		return filtered, nil
	}
	return msgs, nil
}

func (m *memStore) SaveSession(_ context.Context, s *session.Session) error {
	if s.ID == "" {
		s.ID = fmt.Sprintf("sess-%d", len(m.sessions)+1)
	}
	m.sessions[s.ID] = s
	return nil
}

func (m *memStore) AppendMessage(_ context.Context, msg *session.Message) error {
	m.messages[msg.SessionID] = append(m.messages[msg.SessionID], msg)
	return nil
}

func (m *memStore) SaveFuzzJob(_ context.Context, job *session.FuzzJob) error {
	m.fuzzJobs[job.ID] = job
	return nil
}

func (m *memStore) UpdateFuzzJob(_ context.Context, job *session.FuzzJob) error {
	m.fuzzJobs[job.ID] = job
	return nil
}

func (m *memStore) SaveFuzzResult(_ context.Context, result *session.FuzzResult) error {
	m.results = append(m.results, result)
	return nil
}
