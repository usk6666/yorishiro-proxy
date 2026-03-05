package intercept

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestQueue_EnqueueResponse(t *testing.T) {
	q := NewQueue()
	reqURL, _ := url.Parse("http://example.com/api")
	headers := http.Header{"Content-Type": []string{"text/html"}}
	body := []byte("<html>hello</html>")
	matchedRules := []string{"rule-resp-1"}

	id, actionCh := q.EnqueueResponse("GET", reqURL, 200, headers, body, matchedRules)

	if id == "" {
		t.Fatal("EnqueueResponse returned empty ID")
	}
	if actionCh == nil {
		t.Fatal("EnqueueResponse returned nil action channel")
	}
	if q.Len() != 1 {
		t.Errorf("expected 1 item in queue, got %d", q.Len())
	}

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if item.Phase != PhaseResponse {
		t.Errorf("expected phase %q, got %q", PhaseResponse, item.Phase)
	}
	if item.Method != "GET" {
		t.Errorf("expected method GET, got %q", item.Method)
	}
	if item.URL.String() != reqURL.String() {
		t.Errorf("expected URL %q, got %q", reqURL.String(), item.URL.String())
	}
	if item.StatusCode != 200 {
		t.Errorf("expected status code 200, got %d", item.StatusCode)
	}
	if item.Headers.Get("Content-Type") != "text/html" {
		t.Errorf("expected Content-Type text/html, got %q", item.Headers.Get("Content-Type"))
	}
	if string(item.Body) != "<html>hello</html>" {
		t.Errorf("expected body %q, got %q", "<html>hello</html>", string(item.Body))
	}
	if len(item.MatchedRules) != 1 || item.MatchedRules[0] != "rule-resp-1" {
		t.Errorf("unexpected matched rules: %v", item.MatchedRules)
	}
}

func TestQueue_EnqueueResponse_DeepCopies(t *testing.T) {
	q := NewQueue()
	reqURL, _ := url.Parse("http://example.com/test")
	headers := http.Header{"X-Test": []string{"original"}}
	body := []byte("original")
	rules := []string{"rule-1"}

	id, _ := q.EnqueueResponse("GET", reqURL, 200, headers, body, rules)

	// Modify originals after enqueue.
	headers.Set("X-Test", "modified")
	body[0] = 'X'
	rules[0] = "modified"
	reqURL.Path = "/modified"

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

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

func TestQueue_EnqueueResponse_NilValues(t *testing.T) {
	q := NewQueue()

	id, actionCh := q.EnqueueResponse("GET", nil, 404, nil, nil, nil)

	if id == "" {
		t.Fatal("EnqueueResponse returned empty ID")
	}
	if actionCh == nil {
		t.Fatal("EnqueueResponse returned nil action channel")
	}

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if item.Phase != PhaseResponse {
		t.Errorf("expected phase %q, got %q", PhaseResponse, item.Phase)
	}
	if item.StatusCode != 404 {
		t.Errorf("expected status code 404, got %d", item.StatusCode)
	}
	if item.URL != nil {
		t.Errorf("expected nil URL, got %v", item.URL)
	}
}

func TestQueue_EnqueueResponse_MaxItemsAutoRelease(t *testing.T) {
	q := NewQueue()
	q.SetMaxItems(2)

	// Fill the queue.
	q.EnqueueResponse("GET", nil, 200, nil, nil, nil)
	q.EnqueueResponse("POST", nil, 201, nil, nil, nil)

	if q.Len() != 2 {
		t.Fatalf("expected 2 items, got %d", q.Len())
	}

	// The 3rd enqueue should auto-release.
	id3, actionCh := q.EnqueueResponse("PUT", nil, 500, nil, nil, nil)
	if id3 == "" {
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

	// Queue size should still be 2.
	if q.Len() != 2 {
		t.Errorf("expected 2 items (overflow not added), got %d", q.Len())
	}
}

func TestQueue_EnqueueResponse_Respond(t *testing.T) {
	q := NewQueue()
	id, actionCh := q.EnqueueResponse("GET", nil, 200, nil, nil, nil)

	overrideBody := "modified body"
	go func() {
		err := q.Respond(id, InterceptAction{
			Type:                 ActionModifyAndForward,
			OverrideStatus:       403,
			OverrideResponseBody: &overrideBody,
		})
		if err != nil {
			t.Errorf("Respond returned error: %v", err)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != ActionModifyAndForward {
			t.Errorf("expected ActionModifyAndForward, got %v", action.Type)
		}
		if action.OverrideStatus != 403 {
			t.Errorf("expected override status 403, got %d", action.OverrideStatus)
		}
		if *action.OverrideResponseBody != "modified body" {
			t.Errorf("expected body %q, got %q", "modified body", *action.OverrideResponseBody)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for action")
	}
}

func TestQueue_Enqueue_HasPhaseRequest(t *testing.T) {
	q := NewQueue()
	id, _ := q.Enqueue("GET", nil, nil, nil, nil)

	item, err := q.Get(id)
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}
	if item.Phase != PhaseRequest {
		t.Errorf("expected phase %q for Enqueue, got %q", PhaseRequest, item.Phase)
	}
}

func TestQueue_MixedRequestAndResponse(t *testing.T) {
	q := NewQueue()

	reqID, _ := q.Enqueue("POST", nil, nil, nil, nil)
	respID, _ := q.EnqueueResponse("POST", nil, 200, nil, nil, nil)

	if q.Len() != 2 {
		t.Fatalf("expected 2 items, got %d", q.Len())
	}

	reqItem, err := q.Get(reqID)
	if err != nil {
		t.Fatalf("Get request returned error: %v", err)
	}
	if reqItem.Phase != PhaseRequest {
		t.Errorf("expected request phase, got %q", reqItem.Phase)
	}

	respItem, err := q.Get(respID)
	if err != nil {
		t.Fatalf("Get response returned error: %v", err)
	}
	if respItem.Phase != PhaseResponse {
		t.Errorf("expected response phase, got %q", respItem.Phase)
	}
}
