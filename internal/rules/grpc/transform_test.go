package grpc

import (
	"context"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func TestTransformEngine_AddMetadata(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformAddMetadata, "X-Trace-Id", "abc", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	env.Raw = []byte("preexisting")
	if !e.TransformStart(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if metadataGet(msg.Metadata, "x-trace-id") != "abc" {
		t.Errorf("metadata[x-trace-id] = %q", metadataGet(msg.Metadata, "x-trace-id"))
	}
	// Casing must be preserved verbatim.
	if msg.Metadata[0].Name != "X-Trace-Id" {
		t.Errorf("Name = %q, want X-Trace-Id (verbatim casing)", msg.Metadata[0].Name)
	}
	// env.Raw must be cleared so Send re-encodes.
	if env.Raw != nil {
		t.Errorf("env.Raw should be cleared after metadata mutation; got %q", env.Raw)
	}
}

func TestTransformEngine_SetMetadata(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformSetMetadata, "Authorization", "Bearer new", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	metadata := []envelope.KeyValue{
		{Name: "authorization", Value: "Bearer old"},
		{Name: "AUTHORIZATION", Value: "Bearer older"},
	}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	if !e.TransformStart(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	// All case-insensitive matches deleted, then a single fresh entry added.
	count := 0
	for _, kv := range msg.Metadata {
		if metadataGet([]envelope.KeyValue{kv}, "authorization") != "" {
			count++
			if kv.Value != "Bearer new" {
				t.Errorf("auth value = %q, want Bearer new", kv.Value)
			}
		}
	}
	if count != 1 {
		t.Errorf("expected 1 authorization entry, got %d", count)
	}
}

func TestTransformEngine_RemoveMetadata_AllCaseInsensitive(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformRemoveMetadata, "X-Custom", "", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	metadata := []envelope.KeyValue{
		{Name: "x-custom", Value: "1"},
		{Name: "X-Custom", Value: "2"},
		{Name: "X-CUSTOM", Value: "3"},
		{Name: "Other", Value: "keep"},
	}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	if !e.TransformStart(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	for _, kv := range msg.Metadata {
		if metadataGet([]envelope.KeyValue{kv}, "x-custom") != "" {
			t.Errorf("x-custom should be removed but found %v", kv)
		}
	}
	if len(msg.Metadata) != 1 || msg.Metadata[0].Name != "Other" {
		t.Errorf("expected only Other to remain, got %v", msg.Metadata)
	}
}

func TestTransformEngine_AddMetadata_CRLFRejected(t *testing.T) {
	e := NewTransformEngine()
	// Inject CRLF in name.
	rule1, _ := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformAddMetadata, "X-Bad\r\nEvil", "v", "", "", 0, "")
	// Inject CRLF in value.
	rule2, _ := CompileTransformRule("r2", 1, DirectionSend, "", "",
		TransformAddMetadata, "X-Ok", "v\rsmuggle", "", "", 0, "")
	e.SetRules([]TransformRule{*rule1, *rule2})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	if e.TransformStart(context.Background(), env, msg) {
		t.Error("CRLF mutation must be rejected for both rules")
	}
	if len(msg.Metadata) != 0 {
		t.Errorf("metadata should remain empty; got %v", msg.Metadata)
	}
}

func TestTransformEngine_SetMetadata_CRLFRejected(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformSetMetadata, "X-Bad", "v\nx", "", "", 0, "")
	e.SetRules([]TransformRule{*rule})

	metadata := []envelope.KeyValue{{Name: "X-Bad", Value: "old"}}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	if e.TransformStart(context.Background(), env, msg) {
		t.Error("CRLF in SetMetadata must be rejected")
	}
	// Original must remain untouched (delete-then-add was guarded).
	if len(msg.Metadata) != 1 || msg.Metadata[0].Value != "old" {
		t.Errorf("metadata must be untouched on CRLF reject; got %v", msg.Metadata)
	}
}

func TestTransformEngine_RemoveMetadata_CRLFRejected(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformRemoveMetadata, "X-Bad\r\nEvil", "", "", "", 0, "")
	e.SetRules([]TransformRule{*rule})

	metadata := []envelope.KeyValue{
		{Name: "X-Bad", Value: "v"},
		{Name: "Other", Value: "keep"},
	}
	env, msg := makeStartEnv(envelope.Send, "svc", "M", metadata)
	if e.TransformStart(context.Background(), env, msg) {
		t.Error("CRLF in RemoveMetadata name must be rejected")
	}
	// Original metadata must be untouched on reject.
	if len(msg.Metadata) != 2 {
		t.Errorf("metadata must be untouched on CRLF reject; got %v", msg.Metadata)
	}
}

func TestTransformEngine_ReplacePayload_CommitAndClearRaw(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformReplacePayload, "", "", `secret\d+`, "[REDACTED]", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	original := []byte("contains secret123 inside")
	env, msg := makeDataEnv(envelope.Send, "svc", "M", original)
	env.Raw = []byte{0x00, 0x00, 0x00, 0x00, 25, 'a'} // pretend wire LPM
	originalWireLength := msg.WireLength

	if !e.TransformData(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if string(msg.Payload) != "contains [REDACTED] inside" {
		t.Errorf("payload = %q", msg.Payload)
	}
	// env.Raw must be cleared so the GRPCLayer.Send re-encodes the LPM.
	if env.Raw != nil {
		t.Errorf("env.Raw should be cleared after ReplacePayload; got %v", env.Raw)
	}
	// Regression: WireLength must remain at the last wire-observed value.
	if msg.WireLength != originalWireLength {
		t.Errorf("WireLength = %d, want %d (verbatim per action contract)", msg.WireLength, originalWireLength)
	}
}

func TestTransformEngine_ReplacePayload_NoMatch(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, "", "",
		TransformReplacePayload, "", "", `nothing-matches`, "X", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	original := []byte("untouched payload")
	env, msg := makeDataEnv(envelope.Send, "svc", "M", original)
	env.Raw = []byte("wire-bytes")

	if e.TransformData(context.Background(), env, msg) {
		t.Error("expected no modification on no-match")
	}
	if string(msg.Payload) != "untouched payload" {
		t.Errorf("payload mutated unexpectedly: %q", msg.Payload)
	}
	if string(env.Raw) != "wire-bytes" {
		t.Errorf("env.Raw must be left intact when no rule mutates; got %q", env.Raw)
	}
}

func TestTransformEngine_SetStatus(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionReceive, "", "",
		TransformSetStatus, "", "", "", "", 13 /* INTERNAL */, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	env, msg := makeEndEnv(envelope.Receive, 0, "OK")
	env.Raw = []byte("trailers")

	if !e.TransformEnd(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if msg.Status != 13 {
		t.Errorf("Status = %d, want 13", msg.Status)
	}
	if env.Raw != nil {
		t.Error("env.Raw should be cleared after End mutation")
	}
}

func TestTransformEngine_SetStatus_AcceptsAnyValue(t *testing.T) {
	// Per design review: no enum validation; any uint32 accepted.
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionReceive, "", "",
		TransformSetStatus, "", "", "", "", 9999, "")
	e.SetRules([]TransformRule{*rule})

	env, msg := makeEndEnv(envelope.Receive, 0, "")
	if !e.TransformEnd(context.Background(), env, msg) {
		t.Fatal("expected modification with non-canonical status")
	}
	if msg.Status != 9999 {
		t.Errorf("Status = %d, want 9999", msg.Status)
	}
}

func TestTransformEngine_SetStatusMessage(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionReceive, "", "",
		TransformSetStatusMessage, "", "", "", "", 0, "synthesized")
	e.SetRules([]TransformRule{*rule})

	env, msg := makeEndEnv(envelope.Receive, 0, "")
	if !e.TransformEnd(context.Background(), env, msg) {
		t.Fatal("expected modification")
	}
	if msg.Message != "synthesized" {
		t.Errorf("Message = %q, want synthesized", msg.Message)
	}
}

func TestTransformEngine_PriorityOrder(t *testing.T) {
	e := NewTransformEngine()
	rule1, _ := CompileTransformRule("r1", 10, DirectionSend, "", "",
		TransformAddMetadata, "X-Order", "second", "", "", 0, "")
	rule2, _ := CompileTransformRule("r2", 1, DirectionSend, "", "",
		TransformAddMetadata, "X-Order", "first", "", "", 0, "")
	e.SetRules([]TransformRule{*rule1, *rule2})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	e.TransformStart(context.Background(), env, msg)

	if len(msg.Metadata) != 2 {
		t.Fatalf("expected 2 entries, got %d", len(msg.Metadata))
	}
	if msg.Metadata[0].Value != "first" || msg.Metadata[1].Value != "second" {
		t.Errorf("priority order broken: %v", msg.Metadata)
	}
}

func TestTransformEngine_DirectionFilter(t *testing.T) {
	e := NewTransformEngine()
	rule, _ := CompileTransformRule("r1", 0, DirectionReceive, "", "",
		TransformAddMetadata, "X-Match", "yes", "", "", 0, "")
	e.SetRules([]TransformRule{*rule})

	env, msg := makeStartEnv(envelope.Send, "svc", "M", nil)
	if e.TransformStart(context.Background(), env, msg) {
		t.Error("send envelope must not match a receive-only rule")
	}
}

func TestTransformEngine_ServiceMethodGate(t *testing.T) {
	e := NewTransformEngine()
	rule, err := CompileTransformRule("r1", 0, DirectionSend, `^example\.`, `^Send`,
		TransformAddMetadata, "X", "y", "", "", 0, "")
	if err != nil {
		t.Fatal(err)
	}
	e.SetRules([]TransformRule{*rule})

	// Match.
	env, msg := makeStartEnv(envelope.Send, "example.Greeter", "SendGreeting", nil)
	if !e.TransformStart(context.Background(), env, msg) {
		t.Error("expected match")
	}
	// Service mismatch.
	env2, msg2 := makeStartEnv(envelope.Send, "other.Service", "SendGreeting", nil)
	if e.TransformStart(context.Background(), env2, msg2) {
		t.Error("service mismatch should not modify")
	}
	// Method mismatch.
	env3, msg3 := makeStartEnv(envelope.Send, "example.Greeter", "ReceiveX", nil)
	if e.TransformStart(context.Background(), env3, msg3) {
		t.Error("method mismatch should not modify")
	}
}

func TestTransformEngine_StartActionsIgnoreOnDataEnd(t *testing.T) {
	e := NewTransformEngine()
	// AddMetadata is Start-only; no-op on Data/End.
	rule, _ := CompileTransformRule("r1", 0, DirectionBoth, "", "",
		TransformAddMetadata, "X-Should-Not-Apply", "v", "", "", 0, "")
	e.SetRules([]TransformRule{*rule})

	envD, msgD := makeDataEnv(envelope.Send, "svc", "M", []byte("payload"))
	if e.TransformData(context.Background(), envD, msgD) {
		t.Error("AddMetadata must not apply on Data")
	}
	envE, msgE := makeEndEnv(envelope.Receive, 0, "OK")
	if e.TransformEnd(context.Background(), envE, msgE) {
		t.Error("AddMetadata must not apply on End")
	}
}
