//go:build e2e

package ws

import (
	"context"
	"regexp"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// TestIntegration_InterceptEngine_HoldQueue_ReleaseModified exercises the
// full intercept flow: a frame matches an InterceptEngine rule, the
// matched IDs are handed to HoldQueue.Hold, an external action releases
// the entry with a modified envelope, and the caller receives the
// modified payload back.
//
// This mirrors the way InterceptStep (USK-648) will wire the engines
// to the HoldQueue.
func TestIntegration_InterceptEngine_HoldQueue_ReleaseModified(t *testing.T) {
	intercept := NewInterceptEngine()
	intercept.SetRules([]InterceptRule{{
		ID:             "ws-intercept-secret",
		Enabled:        true,
		Direction:      DirectionBoth,
		PayloadPattern: regexp.MustCompile(`secret`),
	}})

	q := common.NewHoldQueue()
	q.SetTimeout(2 * time.Second)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: []byte(`{"k":"secret"}`),
	}
	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
		Context: envelope.EnvelopeContext{
			TargetHost:  "example.com:443",
			UpgradePath: "/ws",
		},
	}

	matched := intercept.Match(env, msg)
	if len(matched) == 0 {
		t.Fatal("expected intercept match")
	}

	type holdResult struct {
		action *common.HoldAction
		err    error
	}
	results := make(chan holdResult, 1)
	go func() {
		action, err := q.Hold(context.Background(), env, matched)
		results <- holdResult{action: action, err: err}
	}()

	// Wait for entry to appear.
	deadline := time.Now().Add(time.Second)
	for q.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("HoldQueue never received entry")
		}
		time.Sleep(time.Millisecond)
	}

	// Build a modified envelope (simulate what InterceptStep + an MCP tool
	// would do): mutate the payload bytes.
	modEnv := env.Clone()
	modMsg := modEnv.Message.(*envelope.WSMessage)
	modMsg.Payload = []byte(`{"k":"REDACTED"}`)

	entries := q.List()
	if len(entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(entries))
	}
	if len(entries[0].MatchedRules) != 1 || entries[0].MatchedRules[0] != "ws-intercept-secret" {
		t.Errorf("MatchedRules = %v, want [ws-intercept-secret]", entries[0].MatchedRules)
	}

	if err := q.Release(entries[0].ID, &common.HoldAction{
		Type:     common.ActionModifyAndForward,
		Modified: modEnv,
	}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	res := <-results
	if res.err != nil {
		t.Fatalf("Hold returned err: %v", res.err)
	}
	if res.action.Type != common.ActionModifyAndForward {
		t.Errorf("action type = %v, want ModifyAndForward", res.action.Type)
	}
	if res.action.Modified == nil {
		t.Fatal("Modified envelope is nil")
	}
	gotMsg := res.action.Modified.Message.(*envelope.WSMessage)
	if string(gotMsg.Payload) != `{"k":"REDACTED"}` {
		t.Errorf("Modified payload = %q", string(gotMsg.Payload))
	}
}

// TestIntegration_InterceptEngine_HoldQueue_ReleaseDrop verifies the
// release-with-Drop path returns ActionDrop to the caller — the same
// signal InterceptStep will use to discard a frame at the layer boundary.
func TestIntegration_InterceptEngine_HoldQueue_ReleaseDrop(t *testing.T) {
	intercept := NewInterceptEngine()
	intercept.SetRules([]InterceptRule{{
		ID:           "ws-drop-binary",
		Enabled:      true,
		Direction:    DirectionBoth,
		OpcodeFilter: []envelope.WSOpcode{envelope.WSBinary},
	}})

	q := common.NewHoldQueue()
	q.SetTimeout(2 * time.Second)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSBinary,
		Fin:     true,
		Payload: []byte{0x00, 0x01, 0x02},
	}
	env := &envelope.Envelope{
		StreamID:  "s1",
		FlowID:    "f1",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolWebSocket,
		Message:   msg,
		Context:   envelope.EnvelopeContext{TargetHost: "example.com"},
	}

	matched := intercept.Match(env, msg)
	if len(matched) != 1 {
		t.Fatalf("expected match, got %v", matched)
	}

	type holdResult struct {
		action *common.HoldAction
		err    error
	}
	results := make(chan holdResult, 1)
	go func() {
		action, err := q.Hold(context.Background(), env, matched)
		results <- holdResult{action: action, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for q.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("HoldQueue never received entry")
		}
		time.Sleep(time.Millisecond)
	}

	entries := q.List()
	if err := q.Release(entries[0].ID, &common.HoldAction{Type: common.ActionDrop}); err != nil {
		t.Fatalf("Release: %v", err)
	}

	res := <-results
	if res.err != nil {
		t.Fatalf("Hold err: %v", res.err)
	}
	if res.action.Type != common.ActionDrop {
		t.Errorf("action type = %v, want Drop", res.action.Type)
	}
}

// TestIntegration_TransformEngine_AppliesAfterInterceptRelease shows the
// composition the Step layer will use: an InterceptEngine match → Hold →
// Release with the released envelope passed through TransformEngine, which
// applies its own rules in priority order before the frame leaves the
// pipeline.
func TestIntegration_TransformEngine_AppliesAfterInterceptRelease(t *testing.T) {
	intercept := NewInterceptEngine()
	intercept.SetRules([]InterceptRule{{
		ID:             "i1",
		Enabled:        true,
		Direction:      DirectionBoth,
		PayloadPattern: regexp.MustCompile(`token`),
	}})
	transform := NewTransformEngine()
	tr, err := CompileTransformRule("t1", 0, DirectionBoth, "", "", nil,
		TransformReplacePayload, `token=[A-Za-z0-9]+`, "token=[REDACTED]",
		0, false, 0, "")
	if err != nil {
		t.Fatal(err)
	}
	transform.SetRules([]TransformRule{*tr})

	q := common.NewHoldQueue()
	q.SetTimeout(2 * time.Second)

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Fin:     true,
		Payload: []byte(`token=abc123def`),
	}
	env := &envelope.Envelope{
		StreamID: "s1", FlowID: "f1",
		Direction: envelope.Send, Protocol: envelope.ProtocolWebSocket,
		Message: msg,
		Context: envelope.EnvelopeContext{TargetHost: "api.example.com"},
	}

	matched := intercept.Match(env, msg)
	if len(matched) == 0 {
		t.Fatal("intercept did not match")
	}

	type holdResult struct {
		action *common.HoldAction
		err    error
	}
	results := make(chan holdResult, 1)
	go func() {
		action, err := q.Hold(context.Background(), env, matched)
		results <- holdResult{action: action, err: err}
	}()

	deadline := time.Now().Add(time.Second)
	for q.Len() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("HoldQueue never received entry")
		}
		time.Sleep(time.Millisecond)
	}
	entries := q.List()
	if err := q.Release(entries[0].ID, &common.HoldAction{Type: common.ActionRelease}); err != nil {
		t.Fatalf("Release: %v", err)
	}
	res := <-results
	if res.err != nil {
		t.Fatalf("Hold err: %v", res.err)
	}
	if res.action.Type != common.ActionRelease {
		t.Fatalf("action type = %v", res.action.Type)
	}

	// Now run the transform engine over the original message (the
	// release path forwards as-is; the Step layer would feed it into
	// Transform next).
	if !transform.Transform(context.Background(), env, msg) {
		t.Fatal("Transform reported no modification")
	}
	if string(msg.Payload) != "token=[REDACTED]" {
		t.Errorf("Payload = %q", msg.Payload)
	}
}

// TestIntegration_SafetyEngine_BlocksMatchingFrame verifies the same
// flow for SafetyEngine: a payload that matches a safety rule produces a
// non-nil Violation, mirroring what SafetyStep will inspect to block the
// frame at the layer boundary.
func TestIntegration_SafetyEngine_BlocksMatchingFrame(t *testing.T) {
	safety := NewSafetyEngine()
	pat, _ := common.CompilePattern(`(?i)password=`)
	safety.AddRule(common.CompiledRule{
		ID:      "ws:safety-password",
		Name:    "password=",
		Pattern: pat,
		Targets: []common.Target{TargetPayload},
	})

	msg := &envelope.WSMessage{
		Opcode:  envelope.WSText,
		Payload: []byte(`{"login":"x","password=hunter2"}`),
	}
	v := safety.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("expected violation")
	}
	if v.RuleID != "ws:safety-password" {
		t.Errorf("RuleID = %q", v.RuleID)
	}

	// Negative case: clean payload produces no violation.
	clean := &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("hello")}
	if v := safety.CheckInput(context.Background(), clean); v != nil {
		t.Errorf("unexpected violation on clean payload: %+v", v)
	}
}
