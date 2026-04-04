package pipeline

import (
	"context"
	"fmt"
	"net/url"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// newTestEngine creates an Engine with a single enabled request rule matching all URLs.
func newTestEngine(t *testing.T, direction intercept.Direction) *intercept.Engine {
	t.Helper()
	e := intercept.NewEngine()
	if err := e.AddRule(intercept.Rule{
		ID:        "test-rule",
		Enabled:   true,
		Direction: direction,
	}); err != nil {
		t.Fatalf("AddRule: %v", err)
	}
	return e
}

// respondAsync sends an action to the queue item after a short delay.
func respondAsync(t *testing.T, q *intercept.Queue, action intercept.InterceptAction) {
	t.Helper()
	go func() {
		// Wait for the item to appear in the queue.
		for i := 0; i < 100; i++ {
			items := q.List()
			if len(items) > 0 {
				if err := q.Respond(items[0].ID, action); err != nil {
					t.Errorf("Respond: %v", err)
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Errorf("timed out waiting for queue item")
	}()
}

func TestInterceptStep_NilEngine_Continue(t *testing.T) {
	step := NewInterceptStep(nil, intercept.NewQueue())
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/api"},
	}
	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}
}

func TestInterceptStep_NilQueue_Continue(t *testing.T) {
	step := NewInterceptStep(intercept.NewEngine(), nil)
	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/api"},
	}
	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}
}

func TestInterceptStep_NoRuleMatch_Continue(t *testing.T) {
	engine := intercept.NewEngine()
	// Add a rule that won't match.
	engine.AddRule(intercept.Rule{
		ID:        "narrow-rule",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: "^/never-match$",
		},
	})
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/api/test"},
	}
	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue for no rule match, got %v", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("expected empty queue, got %d items", queue.Len())
	}
}

func TestInterceptStep_Send_Release_Continue(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "POST",
		URL:       &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
		Headers:   []exchange.KeyValue{{Name: "Content-Type", Value: "application/json"}},
		Body:      []byte(`{"key":"value"}`),
	}

	respondAsync(t, queue, intercept.InterceptAction{Type: intercept.ActionRelease})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue after release, got %v", result.Action)
	}
}

func TestInterceptStep_Send_Drop(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/secret"},
	}

	respondAsync(t, queue, intercept.InterceptAction{Type: intercept.ActionDrop})

	result := step.Process(context.Background(), ex)
	if result.Action != Drop {
		t.Errorf("expected Drop, got %v", result.Action)
	}
}

func TestInterceptStep_Send_ModifyAndForward_InPlace(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Scheme: "http", Host: "example.com", Path: "/api"},
		Headers: []exchange.KeyValue{
			{Name: "Authorization", Value: "Bearer old-token"},
			{Name: "Accept", Value: "text/html"},
		},
		Body: []byte("original"),
	}

	newBody := "modified body"
	respondAsync(t, queue, intercept.InterceptAction{
		Type:            intercept.ActionModifyAndForward,
		OverrideMethod:  "POST",
		OverrideURL:     "http://other.com/new",
		OverrideHeaders: map[string]string{"Authorization": "Bearer new-token"},
		AddHeaders:      map[string]string{"X-Added": "yes"},
		RemoveHeaders:   []string{"Accept"},
		OverrideBody:    &newBody,
	})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue after modify, got %v", result.Action)
	}

	// Verify in-place modifications.
	if ex.Method != "POST" {
		t.Errorf("expected method POST, got %q", ex.Method)
	}
	if ex.URL == nil || ex.URL.Host != "other.com" || ex.URL.Path != "/new" {
		t.Errorf("expected URL http://other.com/new, got %v", ex.URL)
	}
	if string(ex.Body) != "modified body" {
		t.Errorf("expected body %q, got %q", "modified body", string(ex.Body))
	}

	// Check headers: Authorization should be overridden, Accept removed, X-Added added.
	authFound := false
	acceptFound := false
	addedFound := false
	for _, h := range ex.Headers {
		switch h.Name {
		case "Authorization":
			authFound = true
			if h.Value != "Bearer new-token" {
				t.Errorf("expected Authorization %q, got %q", "Bearer new-token", h.Value)
			}
		case "Accept":
			acceptFound = true
		case "X-Added":
			addedFound = true
			if h.Value != "yes" {
				t.Errorf("expected X-Added %q, got %q", "yes", h.Value)
			}
		}
	}
	if !authFound {
		t.Error("Authorization header not found after override")
	}
	if acceptFound {
		t.Error("Accept header should have been removed")
	}
	if !addedFound {
		t.Error("X-Added header not found after add")
	}
}

func TestInterceptStep_Receive_Release_Continue(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionResponse)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Headers:   []exchange.KeyValue{{Name: "Content-Type", Value: "text/html"}},
		Body:      []byte("<html>hello</html>"),
	}

	respondAsync(t, queue, intercept.InterceptAction{Type: intercept.ActionRelease})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue after release, got %v", result.Action)
	}
}

func TestInterceptStep_Receive_Drop(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionResponse)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Headers:   []exchange.KeyValue{{Name: "Content-Type", Value: "text/html"}},
	}

	respondAsync(t, queue, intercept.InterceptAction{Type: intercept.ActionDrop})

	result := step.Process(context.Background(), ex)
	if result.Action != Drop {
		t.Errorf("expected Drop, got %v", result.Action)
	}
}

func TestInterceptStep_Receive_ModifyAndForward(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionResponse)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Receive,
		Status:    200,
		Headers: []exchange.KeyValue{
			{Name: "Content-Type", Value: "text/html"},
			{Name: "X-Remove", Value: "gone"},
		},
		Body: []byte("original response"),
	}

	newBody := "modified response"
	respondAsync(t, queue, intercept.InterceptAction{
		Type:                    intercept.ActionModifyAndForward,
		OverrideStatus:          403,
		OverrideResponseHeaders: map[string]string{"Content-Type": "application/json"},
		AddResponseHeaders:      map[string]string{"X-Custom": "added"},
		RemoveResponseHeaders:   []string{"X-Remove"},
		OverrideResponseBody:    &newBody,
	})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue after modify, got %v", result.Action)
	}

	if ex.Status != 403 {
		t.Errorf("expected status 403, got %d", ex.Status)
	}
	if string(ex.Body) != "modified response" {
		t.Errorf("expected body %q, got %q", "modified response", string(ex.Body))
	}

	ctFound := false
	removeFound := false
	customFound := false
	for _, h := range ex.Headers {
		switch h.Name {
		case "Content-Type":
			ctFound = true
			if h.Value != "application/json" {
				t.Errorf("expected Content-Type %q, got %q", "application/json", h.Value)
			}
		case "X-Remove":
			removeFound = true
		case "X-Custom":
			customFound = true
		}
	}
	if !ctFound {
		t.Error("Content-Type not found")
	}
	if removeFound {
		t.Error("X-Remove should have been removed")
	}
	if !customFound {
		t.Error("X-Custom should have been added")
	}
}

func TestInterceptStep_Send_RawMode_ModifyAndForward(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/raw"},
		RawBytes:  []byte("original raw bytes"),
	}

	rawOverride := []byte("modified raw bytes")
	respondAsync(t, queue, intercept.InterceptAction{
		Type:        intercept.ActionModifyAndForward,
		Mode:        intercept.ModeRaw,
		RawOverride: rawOverride,
	})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue after raw modify, got %v", result.Action)
	}
	if string(ex.RawBytes) != "modified raw bytes" {
		t.Errorf("expected RawBytes %q, got %q", "modified raw bytes", string(ex.RawBytes))
	}
}

func TestInterceptStep_Timeout_AutoRelease(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/slow"},
	}

	// Do not respond -- let it timeout.
	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue (auto_release), got %v", result.Action)
	}
}

func TestInterceptStep_Timeout_AutoDrop(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	queue.SetTimeout(50 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/slow"},
	}

	result := step.Process(context.Background(), ex)
	if result.Action != Drop {
		t.Errorf("expected Drop (auto_drop), got %v", result.Action)
	}
}

func TestInterceptStep_ContextCancelled_Drop(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	queue.SetTimeout(5 * time.Second) // Long timeout.
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/cancel"},
	}

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel context after item is enqueued.
	go func() {
		for queue.Len() == 0 {
			time.Sleep(time.Millisecond)
		}
		cancel()
	}()

	result := step.Process(ctx, ex)
	if result.Action != Drop {
		t.Errorf("expected Drop on context cancel, got %v", result.Action)
	}
}

func TestInterceptStep_WithPipeline_Without(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	p := New(step)
	excluded := p.Without(step)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "GET",
		URL:       &url.URL{Path: "/macro"},
	}

	// The excluded pipeline should not block.
	outEx, action, _ := excluded.Run(context.Background(), ex)
	if action != Continue {
		t.Errorf("expected Continue from excluded pipeline, got %v", action)
	}
	if outEx != ex {
		t.Error("expected same exchange from excluded pipeline")
	}

	// The queue should be empty since the step was excluded.
	if queue.Len() != 0 {
		t.Errorf("expected empty queue after excluded pipeline, got %d", queue.Len())
	}
}

func TestInterceptStep_Send_BodyBase64Override(t *testing.T) {
	engine := newTestEngine(t, intercept.DirectionRequest)
	queue := intercept.NewQueue()
	step := NewInterceptStep(engine, queue)

	ex := &exchange.Exchange{
		Direction: exchange.Send,
		Method:    "POST",
		URL:       &url.URL{Path: "/api"},
		Body:      []byte("original"),
	}

	// "bW9kaWZpZWQ=" is base64 for "modified"
	b64Body := "bW9kaWZpZWQ="
	respondAsync(t, queue, intercept.InterceptAction{
		Type:               intercept.ActionModifyAndForward,
		OverrideBodyBase64: &b64Body,
	})

	result := step.Process(context.Background(), ex)
	if result.Action != Continue {
		t.Errorf("expected Continue, got %v", result.Action)
	}
	if string(ex.Body) != "modified" {
		t.Errorf("expected body %q, got %q", "modified", string(ex.Body))
	}
}

func TestApplyHeaderModifications(t *testing.T) {
	tests := []struct {
		name      string
		headers   []exchange.KeyValue
		overrides map[string]string
		adds      map[string]string
		removes   []string
		wantLen   int
		check     func([]exchange.KeyValue) error
	}{
		{
			name: "override existing header",
			headers: []exchange.KeyValue{
				{Name: "Content-Type", Value: "text/html"},
			},
			overrides: map[string]string{"content-type": "application/json"},
			wantLen:   1,
			check: func(h []exchange.KeyValue) error {
				if h[0].Value != "application/json" {
					return fmt.Errorf("expected application/json, got %q", h[0].Value)
				}
				// Preserve original case of the name.
				if h[0].Name != "Content-Type" {
					return fmt.Errorf("expected Content-Type (preserved case), got %q", h[0].Name)
				}
				return nil
			},
		},
		{
			name:      "override non-existing adds header",
			headers:   []exchange.KeyValue{},
			overrides: map[string]string{"X-New": "value"},
			wantLen:   1,
		},
		{
			name: "add header",
			headers: []exchange.KeyValue{
				{Name: "Existing", Value: "val"},
			},
			adds:    map[string]string{"Added": "new"},
			wantLen: 2,
		},
		{
			name: "remove header case-insensitive",
			headers: []exchange.KeyValue{
				{Name: "X-Remove-Me", Value: "gone"},
				{Name: "Keep", Value: "here"},
			},
			removes: []string{"x-remove-me"},
			wantLen: 1,
			check: func(h []exchange.KeyValue) error {
				if h[0].Name != "Keep" {
					return fmt.Errorf("expected Keep, got %q", h[0].Name)
				}
				return nil
			},
		},
		{
			name:    "nil headers stays nil-safe",
			headers: nil,
			adds:    map[string]string{"New": "val"},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := applyHeaderModifications(tt.headers, tt.overrides, tt.adds, tt.removes)
			if len(result) != tt.wantLen {
				t.Errorf("expected %d headers, got %d: %v", tt.wantLen, len(result), result)
			}
			if tt.check != nil {
				if err := tt.check(result); err != nil {
					t.Error(err)
				}
			}
		})
	}
}

// Use fmt.Errorf directly in check functions above.
