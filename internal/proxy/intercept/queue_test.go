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

func TestQueue_DefaultMaxItems(t *testing.T) {
	q := NewQueue()
	if q.MaxItems() != DefaultMaxQueueItems {
		t.Errorf("expected default max items %d, got %d", DefaultMaxQueueItems, q.MaxItems())
	}
}

func TestQueue_SetMaxItems(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(50)
	if q.MaxItems() != 50 {
		t.Errorf("expected max items 50, got %d", q.MaxItems())
	}
}

func TestQueue_MaxItemsAutoRelease(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(3)

	// Fill the queue to capacity.
	for i := 0; i < 3; i++ {
		id, _ := q.Enqueue("GET", nil, nil, nil, nil)
		if id == "" {
			t.Fatalf("enqueue %d returned empty ID", i)
		}
	}
	if q.Len() != 3 {
		t.Fatalf("expected 3 items, got %d", q.Len())
	}

	// The 4th enqueue should auto-release: the channel should immediately
	// provide an ActionRelease, and the item should NOT be in the queue.
	id4, actionCh := q.Enqueue("POST", nil, nil, nil, nil)
	if id4 == "" {
		t.Fatal("enqueue returned empty ID for overflow item")
	}

	select {
	case action := <-actionCh:
		if action.Type != ActionRelease {
			t.Errorf("expected ActionRelease for overflow item, got %v", action.Type)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for auto-release action on overflow item")
	}

	// Queue size should still be 3 (the overflow item is not added).
	if q.Len() != 3 {
		t.Errorf("expected 3 items (overflow not added), got %d", q.Len())
	}

	// The overflow item should not be findable in the queue.
	_, err := q.Get(id4)
	if err == nil {
		t.Error("overflow item should not be in the queue")
	}
}

func TestQueue_MaxItemsZeroMeansUnlimited(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(0)

	// Should be able to enqueue many items without auto-release.
	const n = 200
	for i := 0; i < n; i++ {
		q.Enqueue("GET", nil, nil, nil, nil)
	}
	if q.Len() != n {
		t.Errorf("expected %d items with unlimited queue, got %d", n, q.Len())
	}
}

func TestQueue_MaxItemsResumesAfterRemoval(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(2)

	id1, _ := q.Enqueue("GET", nil, nil, nil, nil)
	q.Enqueue("GET", nil, nil, nil, nil)

	// Queue is full. Remove one item.
	q.Remove(id1)

	// Should be able to enqueue again.
	id3, _ := q.Enqueue("GET", nil, nil, nil, nil)
	if q.Len() != 2 {
		t.Errorf("expected 2 items after remove + enqueue, got %d", q.Len())
	}

	// Verify the new item is in the queue.
	_, err := q.Get(id3)
	if err != nil {
		t.Errorf("new item should be in queue: %v", err)
	}
}

func TestQueue_SetRawBytes(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	rawBytes := []byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")
	if err := q.SetRawBytes(id, rawBytes); err != nil {
		t.Fatalf("SetRawBytes returned error: %v", err)
	}

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if string(item.RawBytes) != string(rawBytes) {
		t.Errorf("expected raw bytes %q, got %q", rawBytes, item.RawBytes)
	}
}

func TestQueue_SetRawBytes_DeepCopy(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	rawBytes := []byte("original raw bytes")
	if err := q.SetRawBytes(id, rawBytes); err != nil {
		t.Fatalf("SetRawBytes returned error: %v", err)
	}

	// Modify the original after setting.
	rawBytes[0] = 'X'

	item, _ := q.Get(id)
	if item.RawBytes[0] != 'o' {
		t.Error("SetRawBytes should deep-copy the raw bytes")
	}
}

func TestQueue_SetRawBytes_NotFound(t *testing.T) {
	q := NewQueue()
	err := q.SetRawBytes("nonexistent", []byte("data"))
	if err == nil {
		t.Fatal("expected error for nonexistent ID")
	}
}

func TestQueue_SetRawBytes_Nil(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	if err := q.SetRawBytes(id, nil); err != nil {
		t.Fatalf("SetRawBytes with nil returned error: %v", err)
	}

	item, _ := q.Get(id)
	if item.RawBytes != nil {
		t.Errorf("expected nil raw bytes, got %v", item.RawBytes)
	}
}

func TestQueue_SetRawBytes_Empty(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	if err := q.SetRawBytes(id, []byte{}); err != nil {
		t.Fatalf("SetRawBytes with empty returned error: %v", err)
	}

	item, _ := q.Get(id)
	if item.RawBytes != nil {
		t.Errorf("expected nil raw bytes for empty input, got %v", item.RawBytes)
	}
}

func TestQueue_SetRawBytes_ExceedsMaxSize(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	oversized := make([]byte, MaxRawBytesSize+1)
	err := q.SetRawBytes(id, oversized)
	if err == nil {
		t.Fatal("expected error for oversized raw bytes")
	}

	// Verify the item's raw bytes were not set.
	item, _ := q.Get(id)
	if item.RawBytes != nil {
		t.Error("raw bytes should not be set when exceeding max size")
	}
}

func TestInterceptAction_IsRawMode(t *testing.T) {
	tests := []struct {
		name string
		mode ReleaseMode
		want bool
	}{
		{name: "raw", mode: ModeRaw, want: true},
		{name: "structured", mode: ModeStructured, want: false},
		{name: "empty", mode: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := InterceptAction{Mode: tt.mode}
			if got := a.IsRawMode(); got != tt.want {
				t.Errorf("IsRawMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestInterceptAction_EffectiveMode(t *testing.T) {
	tests := []struct {
		name string
		mode ReleaseMode
		want ReleaseMode
	}{
		{name: "raw", mode: ModeRaw, want: ModeRaw},
		{name: "structured", mode: ModeStructured, want: ModeStructured},
		{name: "empty defaults to structured", mode: "", want: ModeStructured},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := InterceptAction{Mode: tt.mode}
			if got := a.EffectiveMode(); got != tt.want {
				t.Errorf("EffectiveMode() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestValidateRawOverride(t *testing.T) {
	tests := []struct {
		name    string
		size    int
		wantErr bool
	}{
		{name: "empty", size: 0, wantErr: false},
		{name: "small", size: 1024, wantErr: false},
		{name: "at limit", size: MaxRawBytesSize, wantErr: false},
		{name: "over limit", size: MaxRawBytesSize + 1, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := make([]byte, tt.size)
			err := ValidateRawOverride(data)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateRawOverride() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestQueue_RespondWithRawMode(t *testing.T) {
	q := NewQueue()
	id, actionCh := q.Enqueue("GET", nil, nil, nil, nil)

	rawOverride := []byte("raw data to send")
	action := InterceptAction{
		Type:        ActionModifyAndForward,
		Mode:        ModeRaw,
		RawOverride: rawOverride,
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
		if !received.IsRawMode() {
			t.Error("expected raw mode")
		}
		if string(received.RawOverride) != "raw data to send" {
			t.Errorf("expected raw override %q, got %q", "raw data to send", received.RawOverride)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action")
	}
}

func TestQueue_MaxItemsConcurrent(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(10)

	var wg sync.WaitGroup
	const goroutines = 50
	autoReleased := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, actionCh := q.Enqueue("GET", nil, nil, nil, nil)
			// Check if the action is immediately available (auto-released).
			select {
			case action := <-actionCh:
				autoReleased <- (action.Type == ActionRelease)
			default:
				autoReleased <- false
			}
		}()
	}
	wg.Wait()
	close(autoReleased)

	// Count auto-released items.
	released := 0
	for wasReleased := range autoReleased {
		if wasReleased {
			released++
		}
	}

	// At least (goroutines - maxItems) should have been auto-released.
	if released < goroutines-10 {
		t.Errorf("expected at least %d auto-released items, got %d", goroutines-10, released)
	}

	// Queue should not exceed maxItems.
	if q.Len() > 10 {
		t.Errorf("queue size %d exceeds maxItems 10", q.Len())
	}
}
