package pipeline

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1159: InterceptStep re-runs HostScopeStep / HTTPScopeStep against the
// envelope about to be forwarded when a hold is released (manual release,
// timeout auto-release, modify_and_forward). These tests use the real
// connector.TargetScope engine and the real scope Steps, so a deny installed
// while the envelope is held is observed through the same live CheckTarget
// the head-of-pipeline Steps consult.

const recheckTarget = "127.0.0.1:8080"

// recheckHTTPRequest builds a Send-direction HTTP/1.x request envelope in
// the shape the plain-HTTP forward proxy produces: Context.TargetHost is
// "host:port" (internal/connector/plain_http_stack.go) and the HTTPMessage
// carries scheme / authority / path from the request line.
func recheckHTTPRequest(path string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "stream-1",
		FlowID:    "flow-1",
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Context:   envelope.EnvelopeContext{TargetHost: recheckTarget},
		Message: &envelope.HTTPMessage{
			Method:    "GET",
			Scheme:    "http",
			Authority: recheckTarget,
			Path:      path,
		},
	}
}

// newRecheckStep returns an InterceptStep that holds every HTTP request /
// response and WS frame, with the scope re-check wired to the real Steps.
func newRecheckStep(t *testing.T, scope *connector.TargetScope, queue *common.HoldQueue, safety *SafetyStep) *InterceptStep {
	t.Helper()
	return NewInterceptStep(
		newTestInterceptEngine(newCatchAllRequestRule(), newCatchAllResponseRule()),
		newTestWSInterceptEngine(newCatchAllWSRule()),
		nil, nil, queue, safety, nil,
	).WithScopeRecheck(NewHostScopeStep(scope), NewHTTPScopeStep(scope))
}

// newAllowLoopbackScope returns a TargetScope whose Policy Layer allows
// only 127.0.0.1.
func newAllowLoopbackScope() *connector.TargetScope {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules([]connector.TargetRule{{Hostname: "127.0.0.1"}}, nil)
	return scope
}

// denyLoopback replaces the Policy Layer the way the SIGHUP reload does.
func denyLoopback(scope *connector.TargetScope) {
	scope.ReplacePolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}, connector.PolicyOrigin{})
}

// whileHeld waits for the first held entry, runs during, then applies action
// (a nil action leaves the entry to the queue's timeout).
func whileHeld(t *testing.T, queue *common.HoldQueue, during func(), action *common.HoldAction) {
	t.Helper()
	go func() {
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			entries := queue.List()
			if len(entries) > 0 {
				if during != nil {
					during()
				}
				if action != nil {
					if err := queue.Release(entries[0].ID, action); err != nil {
						t.Errorf("Release error: %v", err)
					}
				}
				return
			}
			time.Sleep(time.Millisecond)
		}
		t.Error("timed out waiting for held entry")
	}()
}

// assertTargetScope403 asserts the Result is the same synthetic 403 the
// head-of-pipeline scope Steps emit for a denied HTTP request.
func assertTargetScope403(t *testing.T, result Result) {
	t.Helper()
	if result.Action != Respond {
		t.Fatalf("Action = %v, want Respond (scope re-check must block the release)", result.Action)
	}
	if result.BlockedBy != BlockedByTargetScope {
		t.Errorf("BlockedBy = %q, want %q", result.BlockedBy, BlockedByTargetScope)
	}
	if result.Envelope != nil {
		t.Errorf("Envelope = non-nil, want nil on a blocked release")
	}
	if result.Response == nil {
		t.Fatal("Response = nil, want synthetic 403 envelope")
	}
	resp, ok := result.Response.Message.(*envelope.HTTPMessage)
	if !ok {
		t.Fatalf("Response.Message = %T, want *HTTPMessage", result.Response.Message)
	}
	if resp.Status != 403 {
		t.Errorf("Response status = %d, want 403", resp.Status)
	}
	var body struct {
		BlockedBy string `json:"blocked_by"`
	}
	if err := json.Unmarshal(resp.Body, &body); err != nil {
		t.Fatalf("Response body %q is not JSON: %v", resp.Body, err)
	}
	if body.BlockedBy != BlockedByTargetScope {
		t.Errorf("Response body blocked_by = %q, want %q", body.BlockedBy, BlockedByTargetScope)
	}
}

func TestInterceptStep_ScopeRecheck_ReleaseAfterDenyBlocked(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	whileHeld(t, queue, func() { denyLoopback(scope) }, &common.HoldAction{Type: common.ActionRelease})

	assertTargetScope403(t, step.Process(context.Background(), recheckHTTPRequest("/")))
}

func TestInterceptStep_ScopeRecheck_AgentDenyDuringHoldBlocked(t *testing.T) {
	scope := connector.NewTargetScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	whileHeld(t, queue, func() {
		if err := scope.SetAgentRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1"}}); err != nil {
			t.Errorf("SetAgentRules: %v", err)
		}
	}, &common.HoldAction{Type: common.ActionRelease})

	assertTargetScope403(t, step.Process(context.Background(), recheckHTTPRequest("/")))
}

func TestInterceptStep_ScopeRecheck_TimeoutAutoReleaseBlocked(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	queue.SetTimeout(50 * time.Millisecond) // default behavior: auto_release
	step := newRecheckStep(t, scope, queue, nil)

	whileHeld(t, queue, func() { denyLoopback(scope) }, nil)

	assertTargetScope403(t, step.Process(context.Background(), recheckHTTPRequest("/")))
}

func TestInterceptStep_ScopeRecheck_ModifyAndForwardToDeniedTarget(t *testing.T) {
	tests := []struct {
		name   string
		denies []connector.TargetRule
		modify func(*envelope.HTTPMessage)
	}{
		{
			name:   "path rewritten into denied prefix",
			denies: []connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}},
			modify: func(m *envelope.HTTPMessage) { m.Path = "/admin/users" },
		},
		{
			name:   "authority rewritten to denied host",
			denies: []connector.TargetRule{{Hostname: "denied.example"}},
			modify: func(m *envelope.HTTPMessage) { m.Authority = "denied.example:8080" },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scope := connector.NewTargetScope()
			scope.SetPolicyRules(nil, tt.denies)
			queue := common.NewHoldQueue()
			step := newRecheckStep(t, scope, queue, nil)

			held := recheckHTTPRequest("/public")
			modified := held.Clone()
			tt.modify(modified.Message.(*envelope.HTTPMessage))

			whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

			assertTargetScope403(t, step.Process(context.Background(), held))
		})
	}
}

// The scope re-check runs before the safety re-check (Pipeline order:
// Scope → Safety), so a modified envelope violating both is attributed to
// target_scope.
func TestInterceptStep_ScopeRecheck_RunsBeforeSafetyRecheck(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}})
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, newDestructiveSQLSafetyStep(t))

	held := recheckHTTPRequest("/public")
	modified := held.Clone()
	hm := modified.Message.(*envelope.HTTPMessage)
	hm.Method = "POST"
	hm.Path = "/admin/query"
	hm.Body = []byte("DROP TABLE users;")

	whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

	assertTargetScope403(t, step.Process(context.Background(), held))
}

func TestInterceptStep_ScopeRecheck_WSFrameReleaseAfterDenyDropped(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-ws",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Context:   envelope.EnvelopeContext{TargetHost: recheckTarget},
		Message:   &envelope.WSMessage{Opcode: envelope.WSText, Fin: true, Payload: []byte("hi")},
	}

	whileHeld(t, queue, func() { denyLoopback(scope) }, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), env)
	if result.Action != Drop {
		t.Fatalf("Action = %v, want Drop (non-HTTP scope deny)", result.Action)
	}
	if result.BlockedBy != BlockedByTargetScope {
		t.Errorf("BlockedBy = %q, want %q", result.BlockedBy, BlockedByTargetScope)
	}
}

// Guards: the re-check must not change what an allowed release, an
// allowed modify_and_forward, or a Receive-direction release does.
func TestInterceptStep_ScopeRecheck_AllowedReleasePasses(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), recheckHTTPRequest("/"))
	if result.Action != Continue || result.Envelope != nil {
		t.Errorf("Result = %+v, want Continue with nil Envelope", result)
	}
}

func TestInterceptStep_ScopeRecheck_AllowedModifyAndForwardPasses(t *testing.T) {
	scope := connector.NewTargetScope()
	scope.SetPolicyRules(nil, []connector.TargetRule{{Hostname: "127.0.0.1", PathPrefix: "/admin"}})
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	held := recheckHTTPRequest("/public")
	modified := held.Clone()
	modified.Message.(*envelope.HTTPMessage).Path = "/public/other"

	whileHeld(t, queue, nil, &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified})

	result := step.Process(context.Background(), held)
	if result.Action != Continue {
		t.Fatalf("Action = %v, want Continue", result.Action)
	}
	if result.Envelope != modified {
		t.Errorf("Envelope = %p, want the modified envelope %p", result.Envelope, modified)
	}
}

func TestInterceptStep_ScopeRecheck_ReceiveReleasePasses(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := newRecheckStep(t, scope, queue, nil)

	env := &envelope.Envelope{
		StreamID:  "stream-1",
		Sequence:  1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Context:   envelope.EnvelopeContext{TargetHost: recheckTarget},
		Message:   &envelope.HTTPMessage{Status: 200, StatusReason: "OK"},
	}

	whileHeld(t, queue, func() { denyLoopback(scope) }, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), env)
	if result.Action != Continue {
		t.Errorf("Action = %v, want Continue (scope Steps are Send-only)", result.Action)
	}
}

// Without WithScopeRecheck (or with nil Steps) the release keeps its
// pre-USK-1159 behavior.
func TestInterceptStep_ScopeRecheck_NilStepsNoop(t *testing.T) {
	scope := newAllowLoopbackScope()
	queue := common.NewHoldQueue()
	step := NewInterceptStep(newTestInterceptEngine(newCatchAllRequestRule()), nil, nil, nil, queue, nil, nil).
		WithScopeRecheck(nil, nil)

	whileHeld(t, queue, func() { denyLoopback(scope) }, &common.HoldAction{Type: common.ActionRelease})

	result := step.Process(context.Background(), recheckHTTPRequest("/"))
	if result.Action != Continue {
		t.Errorf("Action = %v, want Continue", result.Action)
	}
}
