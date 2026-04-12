package pipeline

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	httprules "github.com/usk6666/yorishiro-proxy/internal/rules/http"
)

func newTestInterceptEngine(rules ...httprules.InterceptRule) *httprules.InterceptEngine {
	e := httprules.NewInterceptEngine()
	e.SetRules(rules)
	return e
}

func newCatchAllRequestRule() httprules.InterceptRule {
	return httprules.InterceptRule{
		ID:        "catch-all",
		Enabled:   true,
		Direction: httprules.DirectionRequest,
	}
}

func newCatchAllResponseRule() httprules.InterceptRule {
	return httprules.InterceptRule{
		ID:        "catch-all-resp",
		Enabled:   true,
		Direction: httprules.DirectionResponse,
	}
}

func TestInterceptStep_Release(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		// Wait for the entry to appear in the queue.
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("Release: got action %v, want Continue", result.Action)
	}
	if result.Envelope != nil {
		t.Error("Release: expected nil Envelope in result")
	}
}

func TestInterceptStep_Drop(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Errorf("Drop: got action %v, want Drop", result.Action)
	}
}

func TestInterceptStep_ModifyAndForward(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/original",
		},
	}

	modifiedEnv := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/modified",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				action := &common.HoldAction{
					Type:     common.ActionModifyAndForward,
					Modified: modifiedEnv,
				}
				if err := queue.Release(entries[0].ID, action); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("ModifyAndForward: got action %v, want Continue", result.Action)
	}
	if result.Envelope == nil {
		t.Fatal("ModifyAndForward: expected non-nil Envelope in result")
	}
	msg, ok := result.Envelope.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatal("ModifyAndForward: expected HTTPMessage")
	}
	if msg.Path != "/modified" {
		t.Errorf("ModifyAndForward: path = %q, want /modified", msg.Path)
	}
}

func TestInterceptStep_NoMatch(t *testing.T) {
	// Rule only matches /api/ paths.
	engine := newTestInterceptEngine(httprules.InterceptRule{
		ID:          "api-only",
		Enabled:     true,
		Direction:   httprules.DirectionRequest,
		PathPattern: regexp.MustCompile(`^/api/`),
	})
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/web/index.html",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NoMatch: got action %v, want Continue", result.Action)
	}
	if queue.Len() != 0 {
		t.Errorf("NoMatch: queue should be empty, got %d items", queue.Len())
	}
}

func TestInterceptStep_RawMessage_PassThrough(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: []byte("hello")},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("RawMessage: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_NilEngine(t *testing.T) {
	queue := common.NewHoldQueue()
	step := NewInterceptStep(nil, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilEngine: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_NilQueue(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	step := NewInterceptStep(engine, nil, nil)

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("NilQueue: got action %v, want Continue", result.Action)
	}
}

func TestInterceptStep_ContextCancellation(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllRequestRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	ctx, cancel := context.WithCancel(context.Background())

	env := &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: "GET",
			Path:   "/",
		},
	}

	go func() {
		// Wait for the entry to appear, then cancel context.
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			if queue.Len() > 0 {
				cancel()
				return
			}
		}
		cancel()
	}()

	result := step.Process(ctx, env)
	if result.Action != Drop {
		t.Errorf("ContextCancellation: got action %v, want Drop", result.Action)
	}
}

func TestInterceptStep_ResponseMatch(t *testing.T) {
	engine := newTestInterceptEngine(newCatchAllResponseRule())
	queue := common.NewHoldQueue()
	step := NewInterceptStep(engine, queue, nil)

	env := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status:       200,
			StatusReason: "OK",
		},
	}

	go func() {
		for i := 0; i < 100; i++ {
			time.Sleep(time.Millisecond)
			entries := queue.List()
			if len(entries) > 0 {
				if err := queue.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
					t.Errorf("Release error: %v", err)
				}
				return
			}
		}
		t.Error("timed out waiting for held entry")
	}()

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("ResponseMatch: got action %v, want Continue", result.Action)
	}
}
