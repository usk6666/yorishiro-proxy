package mcp

import (
	"context"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/proxy/intercept"
)

// --- M3 Integration: Intercept ---

// TestM3_Intercept_EnqueueAndRelease verifies the lifecycle:
// enqueue a request into the intercept queue -> query the queue to see it -> release it.
func TestM3_Intercept_EnqueueAndRelease(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue a GET request with a matching rule ID.
	id, actionCh := queue.Enqueue("GET", nil, nil, nil, []string{"rule-auth"})

	// Verify the item appears in the intercept_queue query.
	qResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(query): %v", err)
	}
	if qResult.IsError {
		t.Fatalf("query intercept_queue returned error: %v", qResult.Content)
	}

	var qr queryInterceptQueueResult
	extractResult(t, qResult, &qr)
	if qr.Count != 1 {
		t.Fatalf("intercept_queue count = %d, want 1", qr.Count)
	}
	if qr.Items[0].ID != id {
		t.Errorf("queue item ID = %q, want %q", qr.Items[0].ID, id)
	}
	if qr.Items[0].Method != "GET" {
		t.Errorf("queue item method = %q, want GET", qr.Items[0].Method)
	}

	// Release the intercepted request.
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, callErr := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "execute",
			Arguments: mustMarshal(t, executeInput{
				Action: "release",
				Params: executeParams{
					InterceptID: id,
				},
			}),
		})
		if callErr != nil {
			t.Errorf("CallTool(release) error: %v", callErr)
			return
		}
		if result.IsError {
			t.Errorf("release returned error: %v", result.Content)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionRelease {
			t.Errorf("action.Type = %v, want ActionRelease", action.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for release action")
	}

	<-done
}

// TestM3_Intercept_ModifyAndForwardWithOverrides verifies that modify_and_forward
// passes overrides (method, URL, headers, body) through to the action channel.
func TestM3_Intercept_ModifyAndForwardWithOverrides(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.Enqueue("GET", nil, nil, nil, []string{"rule-api"})

	overrideBody := `{"injected":"payload"}`
	done := make(chan struct{})
	go func() {
		defer close(done)
		result, callErr := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "execute",
			Arguments: mustMarshal(t, executeInput{
				Action: "modify_and_forward",
				Params: executeParams{
					InterceptID:     id,
					OverrideMethod:  "PUT",
					OverrideURL:     "http://injected.example.com/api",
					OverrideHeaders: map[string]string{"X-Injected": "true", "Content-Type": "application/json"},
					OverrideBody:    &overrideBody,
				},
			}),
		})
		if callErr != nil {
			t.Errorf("CallTool error: %v", callErr)
			return
		}
		if result.IsError {
			t.Errorf("modify_and_forward returned error: %v", result.Content)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionModifyAndForward {
			t.Errorf("action.Type = %v, want ActionModifyAndForward", action.Type)
		}
		if action.OverrideMethod != "PUT" {
			t.Errorf("OverrideMethod = %q, want PUT", action.OverrideMethod)
		}
		if action.OverrideURL != "http://injected.example.com/api" {
			t.Errorf("OverrideURL = %q, want http://injected.example.com/api", action.OverrideURL)
		}
		if action.OverrideHeaders["X-Injected"] != "true" {
			t.Errorf("OverrideHeaders[X-Injected] = %q, want true", action.OverrideHeaders["X-Injected"])
		}
		if action.OverrideHeaders["Content-Type"] != "application/json" {
			t.Errorf("OverrideHeaders[Content-Type] = %q, want application/json", action.OverrideHeaders["Content-Type"])
		}
		if action.OverrideBody == nil || *action.OverrideBody != overrideBody {
			t.Error("OverrideBody does not match expected payload")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for modify_and_forward action")
	}

	<-done
}

// TestM3_Intercept_DropAction verifies that the drop action sends ActionDrop
// through the action channel so the proxy returns 502 to the client.
func TestM3_Intercept_DropAction(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	id, actionCh := queue.Enqueue("POST", nil, nil, []byte(`{"data":"secret"}`), []string{"rule-block"})

	done := make(chan struct{})
	go func() {
		defer close(done)
		result, callErr := cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "execute",
			Arguments: mustMarshal(t, executeInput{
				Action: "drop",
				Params: executeParams{
					InterceptID: id,
				},
			}),
		})
		if callErr != nil {
			t.Errorf("CallTool(drop) error: %v", callErr)
			return
		}
		if result.IsError {
			t.Errorf("drop returned error: %v", result.Content)
		}
	}()

	select {
	case action := <-actionCh:
		if action.Type != intercept.ActionDrop {
			t.Errorf("action.Type = %v, want ActionDrop", action.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for drop action")
	}

	<-done
}

// TestM3_Intercept_MultipleItemsInQueue verifies that multiple intercepted requests
// appear in the queue and can be acted upon independently.
func TestM3_Intercept_MultipleItemsInQueue(t *testing.T) {
	queue := intercept.NewQueue()
	cs := setupTestSessionWithInterceptQueue(t, queue)

	// Enqueue 3 requests.
	id1, actionCh1 := queue.Enqueue("GET", nil, nil, nil, []string{"rule-1"})
	id2, actionCh2 := queue.Enqueue("POST", nil, nil, []byte("body"), []string{"rule-2"})
	_, _ = queue.Enqueue("DELETE", nil, nil, nil, []string{"rule-3"})

	// Query the queue -- should have 3 items.
	qResult, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "query",
		Arguments: mustMarshal(t, queryInput{
			Resource: "intercept_queue",
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(query): %v", err)
	}
	var qr queryInterceptQueueResult
	extractResult(t, qResult, &qr)
	if qr.Count != 3 {
		t.Fatalf("queue count = %d, want 3", qr.Count)
	}

	// Release the first request.
	go func() {
		cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "execute",
			Arguments: mustMarshal(t, executeInput{
				Action: "release",
				Params: executeParams{InterceptID: id1},
			}),
		})
	}()
	select {
	case a := <-actionCh1:
		if a.Type != intercept.ActionRelease {
			t.Errorf("first action = %v, want ActionRelease", a.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out on first release")
	}

	// Drop the second request.
	go func() {
		cs.CallTool(context.Background(), &gomcp.CallToolParams{
			Name: "execute",
			Arguments: mustMarshal(t, executeInput{
				Action: "drop",
				Params: executeParams{InterceptID: id2},
			}),
		})
	}()
	select {
	case a := <-actionCh2:
		if a.Type != intercept.ActionDrop {
			t.Errorf("second action = %v, want ActionDrop", a.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out on second drop")
	}
}

// TestM3_Intercept_ConfigureInterceptRules verifies that intercept rules can be
// configured via the configure tool and verified via query config.
func TestM3_Intercept_ConfigureInterceptRules(t *testing.T) {
	engine := intercept.NewEngine()
	cs := setupInterceptTestSession(t, engine)

	// Add intercept rules via configure merge.
	result, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Add: []interceptRuleInput{
					{
						ID:        "rule-api",
						Enabled:   true,
						Direction: "request",
						Conditions: interceptConditionsInput{
							PathPattern: "/api/admin.*",
							Methods:     []string{"POST", "PUT", "DELETE"},
						},
					},
					{
						ID:        "rule-response",
						Enabled:   true,
						Direction: "response",
						Conditions: interceptConditionsInput{
							PathPattern: "/api/.*",
						},
					},
				},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure): %v", err)
	}
	if result.IsError {
		t.Fatalf("configure returned error: %v", result.Content)
	}

	var out configureResult
	configureUnmarshalResult(t, result, &out)

	if out.Status != "configured" {
		t.Errorf("status = %q, want configured", out.Status)
	}
	if out.InterceptRules == nil {
		t.Fatal("intercept_rules is nil")
	}
	if out.InterceptRules.TotalRules != 2 {
		t.Errorf("total_rules = %d, want 2", out.InterceptRules.TotalRules)
	}
	if out.InterceptRules.EnabledRules != 2 {
		t.Errorf("enabled_rules = %d, want 2", out.InterceptRules.EnabledRules)
	}

	// Verify the engine actually has the rules.
	if engine.Len() != 2 {
		t.Errorf("engine.Len() = %d, want 2", engine.Len())
	}

	// Disable one rule.
	result2, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Disable: []string{"rule-api"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure disable): %v", err)
	}
	if result2.IsError {
		t.Fatalf("configure disable returned error: %v", result2.Content)
	}

	var out2 configureResult
	configureUnmarshalResult(t, result2, &out2)
	if out2.InterceptRules.EnabledRules != 1 {
		t.Errorf("enabled_rules after disable = %d, want 1", out2.InterceptRules.EnabledRules)
	}

	// Remove a rule.
	result3, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "configure",
		Arguments: configureMarshal(t, configureInput{
			Operation: "merge",
			InterceptRules: &configureInterceptRules{
				Remove: []string{"rule-response"},
			},
		}),
	})
	if err != nil {
		t.Fatalf("CallTool(configure remove): %v", err)
	}
	if result3.IsError {
		t.Fatalf("configure remove returned error: %v", result3.Content)
	}

	var out3 configureResult
	configureUnmarshalResult(t, result3, &out3)
	if out3.InterceptRules.TotalRules != 1 {
		t.Errorf("total_rules after remove = %d, want 1", out3.InterceptRules.TotalRules)
	}
}
