package intercept

import (
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"
)

func TestNewQueue(t *testing.T) {
	q := NewQueue()
	if q == nil {
		t.Fatal("NewQueue returned nil")
	}
	if q.Len() != 0 {
		t.Errorf("new queue should be empty, got %d items", q.Len())
	}
	if q.Timeout() != DefaultInterceptTimeout {
		t.Errorf("expected default timeout %v, got %v", DefaultInterceptTimeout, q.Timeout())
	}
	if q.TimeoutBehaviorValue() != TimeoutAutoRelease {
		t.Errorf("expected default behavior %q, got %q", TimeoutAutoRelease, q.TimeoutBehaviorValue())
	}
}

func TestQueue_EnqueueAndGet(t *testing.T) {
	q := NewQueue()
	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{"Content-Type": []string{"application/json"}}
	body := []byte(`{"key":"value"}`)
	matchedRules := []string{"rule-1", "rule-2"}

	id, actionCh := q.Enqueue("POST", u, headers, body, matchedRules)

	if id == "" {
		t.Fatal("Enqueue returned empty ID")
	}
	if actionCh == nil {
		t.Fatal("Enqueue returned nil action channel")
	}
	if q.Len() != 1 {
		t.Errorf("expected 1 item in queue, got %d", q.Len())
	}

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if item.ID != id {
		t.Errorf("expected ID %q, got %q", id, item.ID)
	}
	if item.Method != "POST" {
		t.Errorf("expected method POST, got %q", item.Method)
	}
	if item.URL.String() != u.String() {
		t.Errorf("expected URL %q, got %q", u.String(), item.URL.String())
	}
	if item.Headers.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type header, got %q", item.Headers.Get("Content-Type"))
	}
	if string(item.Body) != `{"key":"value"}` {
		t.Errorf("expected body %q, got %q", `{"key":"value"}`, string(item.Body))
	}
	if len(item.MatchedRules) != 2 || item.MatchedRules[0] != "rule-1" {
		t.Errorf("unexpected matched rules: %v", item.MatchedRules)
	}
}

func TestQueue_EnqueueDeepCopies(t *testing.T) {
	q := NewQueue()
	u, _ := url.Parse("http://example.com/test")
	headers := http.Header{"X-Test": []string{"original"}}
	body := []byte("original")
	rules := []string{"rule-1"}

	id, _ := q.Enqueue("GET", u, headers, body, rules)

	// Modify originals after enqueue.
	headers.Set("X-Test", "modified")
	body[0] = 'X'
	rules[0] = "modified"
	u.Path = "/modified"

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	// Verify the enqueued item has the original values.
	if item.Headers.Get("X-Test") != "original" {
		t.Errorf("headers should be deep-copied, got %q", item.Headers.Get("X-Test"))
	}
	if string(item.Body) != "original" {
		t.Errorf("body should be deep-copied, got %q", string(item.Body))
	}
	if item.MatchedRules[0] != "rule-1" {
		t.Errorf("rules should be deep-copied, got %q", item.MatchedRules[0])
	}
	if item.URL.Path != "/test" {
		t.Errorf("URL should be deep-copied, got %q", item.URL.Path)
	}
}

func TestQueue_EnqueueNilValues(t *testing.T) {
	q := NewQueue()

	id, actionCh := q.Enqueue("GET", nil, nil, nil, nil)

	if id == "" {
		t.Fatal("Enqueue returned empty ID")
	}
	if actionCh == nil {
		t.Fatal("Enqueue returned nil action channel")
	}

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if item.URL != nil {
		t.Errorf("expected nil URL, got %v", item.URL)
	}
	if item.Headers == nil {
		t.Error("expected non-nil empty headers")
	}
	if item.Body != nil {
		t.Errorf("expected nil body, got %v", item.Body)
	}
	if item.MatchedRules != nil {
		t.Errorf("expected nil matched rules, got %v", item.MatchedRules)
	}
}

func TestQueue_GetNotFound(t *testing.T) {
	q := NewQueue()

	_, err := q.Get("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestQueue_List(t *testing.T) {
	q := NewQueue()

	// Empty queue returns nil.
	items := q.List()
	if items != nil {
		t.Errorf("expected nil for empty queue, got %v", items)
	}

	// Add items.
	id1, _ := q.Enqueue("GET", nil, nil, nil, nil)
	id2, _ := q.Enqueue("POST", nil, nil, nil, nil)

	items = q.List()
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}

	ids := map[string]bool{}
	for _, item := range items {
		ids[item.ID] = true
	}
	if !ids[id1] || !ids[id2] {
		t.Errorf("List should contain both IDs: got %v", ids)
	}
}

func TestQueue_Respond(t *testing.T) {
	q := NewQueue()
	id, actionCh := q.Enqueue("GET", nil, nil, nil, nil)

	// Respond in a goroutine.
	go func() {
		err := q.Respond(id, InterceptAction{Type: ActionRelease})
		if err != nil {
			t.Errorf("Respond returned error: %v", err)
		}
	}()

	// Wait for action.
	select {
	case action := <-actionCh:
		if action.Type != ActionRelease {
			t.Errorf("expected ActionRelease, got %v", action.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action")
	}

	// Item should be removed from queue.
	if q.Len() != 0 {
		t.Errorf("expected 0 items after respond, got %d", q.Len())
	}
}

func TestQueue_RespondNotFound(t *testing.T) {
	q := NewQueue()
	err := q.Respond("nonexistent", InterceptAction{Type: ActionRelease})
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestQueue_RespondModifyAndForward(t *testing.T) {
	q := NewQueue()
	id, actionCh := q.Enqueue("GET", nil, nil, nil, nil)

	overrideBody := "new body"
	action := InterceptAction{
		Type:            ActionModifyAndForward,
		OverrideMethod:  "POST",
		OverrideURL:     "http://other.com/api",
		OverrideHeaders: map[string]string{"X-New": "value"},
		OverrideBody:    &overrideBody,
	}

	go func() {
		if err := q.Respond(id, action); err != nil {
			t.Errorf("Respond returned error: %v", err)
		}
	}()

	select {
	case received := <-actionCh:
		if received.Type != ActionModifyAndForward {
			t.Errorf("expected ActionModifyAndForward, got %v", received.Type)
		}
		if received.OverrideMethod != "POST" {
			t.Errorf("expected method POST, got %q", received.OverrideMethod)
		}
		if *received.OverrideBody != "new body" {
			t.Errorf("expected body %q, got %q", "new body", *received.OverrideBody)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action")
	}
}

func TestQueue_RespondDrop(t *testing.T) {
	q := NewQueue()
	id, actionCh := q.Enqueue("GET", nil, nil, nil, nil)

	go func() {
		if err := q.Respond(id, InterceptAction{Type: ActionDrop}); err != nil {
			t.Errorf("Respond returned error: %v", err)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != ActionDrop {
			t.Errorf("expected ActionDrop, got %v", action.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action")
	}
}

func TestQueue_Remove(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)
	q.Remove(id)

	if q.Len() != 0 {
		t.Errorf("expected 0 items after remove, got %d", q.Len())
	}

	// Remove nonexistent is a no-op.
	q.Remove("nonexistent")
}

func TestQueue_Clear(t *testing.T) {
	q := NewQueue()
	q.Enqueue("GET", nil, nil, nil, nil)
	q.Enqueue("POST", nil, nil, nil, nil)
	q.Clear()

	if q.Len() != 0 {
		t.Errorf("expected 0 items after clear, got %d", q.Len())
	}
}

func TestQueue_SetTimeout(t *testing.T) {
	q := NewQueue()
	q.SetTimeout(30 * time.Second)
	if q.Timeout() != 30*time.Second {
		t.Errorf("expected 30s timeout, got %v", q.Timeout())
	}
}

func TestQueue_SetTimeoutBehavior(t *testing.T) {
	q := NewQueue()
	q.SetTimeoutBehavior(TimeoutAutoDrop)
	if q.TimeoutBehaviorValue() != TimeoutAutoDrop {
		t.Errorf("expected auto_drop, got %q", q.TimeoutBehaviorValue())
	}
}

func TestQueue_ConcurrentAccess(t *testing.T) {
	q := NewQueue()
	var wg sync.WaitGroup
	const n = 100

	// Concurrent enqueues.
	ids := make([]string, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			id, _ := q.Enqueue("GET", nil, nil, nil, nil)
			ids[idx] = id
		}(i)
	}
	wg.Wait()

	if q.Len() != n {
		t.Errorf("expected %d items, got %d", n, q.Len())
	}

	// Concurrent responds.
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			q.Respond(ids[idx], InterceptAction{Type: ActionRelease})
		}(i)
	}
	wg.Wait()

	if q.Len() != 0 {
		t.Errorf("expected 0 items after responds, got %d", q.Len())
	}
}

func TestQueue_UniqueIDs(t *testing.T) {
	q := NewQueue()
	ids := make(map[string]bool)
	const n = 100

	for i := 0; i < n; i++ {
		id, _ := q.Enqueue("GET", nil, nil, nil, nil)
		if ids[id] {
			t.Fatalf("duplicate ID: %s", id)
		}
		ids[id] = true
	}
}

func TestQueue_TimestampSet(t *testing.T) {
	q := NewQueue()
	before := time.Now()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)
	after := time.Now()

	item, _ := q.Get(id)
	if item.Timestamp.Before(before) || item.Timestamp.After(after) {
		t.Errorf("timestamp %v should be between %v and %v", item.Timestamp, before, after)
	}
}
