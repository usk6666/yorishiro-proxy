package sse

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

func newTransformRule(id string, action TransformActionType, mutate func(*TransformRule)) *TransformRule {
	r, err := CompileTransformRule(id, 0, "", "", "", "", nil, nil, nil,
		action, "", "", "", "", "", "", "", 0)
	if err != nil {
		panic(err)
	}
	if mutate != nil {
		mutate(r)
	}
	return r
}

func TestTransformEngine_SetData(t *testing.T) {
	e := NewTransformEngine()
	r, err := CompileTransformRule("r1", 0, "", "", "", "", nil, nil, nil,
		TransformSetData, "", "", "replaced", "", "", "", "", 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	msg := &envelope.SSEMessage{Data: "original"}
	res := e.Transform(context.Background(), sseEnvelope(msg), msg)
	if !res.Modified || res.Drop {
		t.Fatalf("res = %+v", res)
	}
	if msg.Data != "replaced" {
		t.Errorf("data = %q, want %q", msg.Data, "replaced")
	}
}

func TestTransformEngine_ReplaceData_Global(t *testing.T) {
	e := NewTransformEngine()
	r, err := CompileTransformRule("r1", 0, "", "", "", "", nil, nil, nil,
		TransformReplaceData, "", "", "", "", "", "foo", "BAR", 0)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}
	e.AddRule(*r)

	msg := &envelope.SSEMessage{Data: "foo foo foo"}
	res := e.Transform(context.Background(), sseEnvelope(msg), msg)
	if !res.Modified {
		t.Fatalf("res = %+v", res)
	}
	if msg.Data != "BAR BAR BAR" {
		t.Errorf("data = %q, want %q", msg.Data, "BAR BAR BAR")
	}
}

func TestTransformEngine_PrependAppend_NoAutoNewline(t *testing.T) {
	e := NewTransformEngine()
	r1, _ := CompileTransformRule("p", 0, "", "", "", "", nil, nil, nil,
		TransformPrependData, "", "", "", "PRE-", "", "", "", 0)
	r2, _ := CompileTransformRule("a", 1, "", "", "", "", nil, nil, nil,
		TransformAppendData, "", "", "", "", "-POST", "", "", 0)
	e.AddRule(*r1)
	e.AddRule(*r2)

	msg := &envelope.SSEMessage{Data: "body"}
	_ = e.Transform(context.Background(), sseEnvelope(msg), msg)
	if msg.Data != "PRE-body-POST" {
		t.Errorf("data = %q", msg.Data)
	}
	// Prepend/append CRLF guards reject `\n` at compile time (CWE-113).
	if _, err := CompileTransformRule("p2", 0, "", "", "", "", nil, nil, nil,
		TransformPrependData, "", "", "", "PRE\n", "", "", "", 0); err == nil {
		t.Error("expected compile error for prepend_data with LF")
	}
}

func TestTransformEngine_SetRetry_Clear(t *testing.T) {
	e := NewTransformEngine()
	r1, _ := CompileTransformRule("set", 0, "", "", "", "", nil, nil, nil,
		TransformSetRetry, "", "", "", "", "", "", "", 2500)
	r2, _ := CompileTransformRule("clear", 1, "", "", "", "", nil, nil, nil,
		TransformSetRetry, "", "", "", "", "", "", "", 0)

	msg := &envelope.SSEMessage{Retry: 0}
	e.AddRule(*r1)
	_ = e.Transform(context.Background(), sseEnvelope(msg), msg)
	if msg.Retry != 2500*time.Millisecond {
		t.Errorf("retry = %v, want 2500ms", msg.Retry)
	}
	e.SetRules([]TransformRule{*r2})
	_ = e.Transform(context.Background(), sseEnvelope(msg), msg)
	if msg.Retry != 0 {
		t.Errorf("retry should be cleared, got %v", msg.Retry)
	}
}

func TestTransformEngine_Drop(t *testing.T) {
	e := NewTransformEngine()
	r, _ := CompileTransformRule("drop", 0, "", "", "", "", nil, nil, nil,
		TransformDrop, "", "", "", "", "", "", "", 0)
	e.AddRule(*r)

	msg := &envelope.SSEMessage{Data: "x"}
	res := e.Transform(context.Background(), sseEnvelope(msg), msg)
	if !res.Drop {
		t.Errorf("expected drop, got %+v", res)
	}
	if res.DropRuleID != "drop" {
		t.Errorf("DropRuleID = %q", res.DropRuleID)
	}
}

func TestTransformEngine_Priority_LastWritesWin(t *testing.T) {
	e := NewTransformEngine()
	// Priority 0 (first) sets "first"; priority 10 (last) sets "last".
	// last-wins is the natural fallout of ordered application.
	r1, _ := CompileTransformRule("r1", 0, "", "", "", "", nil, nil, nil,
		TransformSetData, "", "", "first", "", "", "", "", 0)
	r2, _ := CompileTransformRule("r2", 10, "", "", "", "", nil, nil, nil,
		TransformSetData, "", "", "last", "", "", "", "", 0)
	e.AddRule(*r2) // add out of order to exercise sort
	e.AddRule(*r1)

	msg := &envelope.SSEMessage{Data: "x"}
	_ = e.Transform(context.Background(), sseEnvelope(msg), msg)
	if msg.Data != "last" {
		t.Errorf("data = %q, want last", msg.Data)
	}
}

func TestTransformEngine_CRLFGuards(t *testing.T) {
	cases := []struct {
		name   string
		action TransformActionType
		mutate func(*TransformRule)
		want   string
	}{
		{"set_event CR", TransformSetEvent, func(r *TransformRule) { r.SetEventValue = "x\r" }, "set_event"},
		{"set_event LF", TransformSetEvent, func(r *TransformRule) { r.SetEventValue = "x\n" }, "set_event"},
		{"set_id LF", TransformSetID, func(r *TransformRule) { r.SetIDValue = "x\n" }, "set_id"},
		{"prepend LF", TransformPrependData, func(r *TransformRule) { r.PrependDataValue = "x\n" }, "prepend_data"},
		{"append CR", TransformAppendData, func(r *TransformRule) { r.AppendDataValue = "x\r" }, "append_data"},
		{"set_data CR", TransformSetData, func(r *TransformRule) { r.SetDataValue = "x\r" }, "set_data"},
		{"replace_data LF replacement", TransformReplaceData, func(r *TransformRule) { r.ReplaceDataWith = "x\n" }, "replace_data"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Call the validator directly because we can't reach it through CompileTransformRule
			// for SetEvent/etc without a non-empty value; round-trip via Compile.
			//
			// CompileTransformRule embeds the value, then runs validateActionForCRLF.
			rule := &TransformRule{ActionType: tc.action}
			tc.mutate(rule)
			if err := validateActionForCRLF(tc.action, rule); err == nil {
				t.Errorf("expected error for %s; got nil", tc.name)
			} else if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not mention %q", err.Error(), tc.want)
			}
		})
	}
}

func TestTransformEngine_SetData_AllowsLF(t *testing.T) {
	// Multi-line data is legal per RFC 8895 — one `data:` line per
	// '\n'-split chunk. Compile must accept the value.
	if _, err := CompileTransformRule("r1", 0, "", "", "", "", nil, nil, nil,
		TransformSetData, "", "", "line1\nline2", "", "", "", "", 0); err != nil {
		t.Fatalf("compile: %v", err)
	}
}

func TestTransformEngine_ReplaceData_RequiresPattern(t *testing.T) {
	if _, err := CompileTransformRule("r1", 0, "", "", "", "", nil, nil, nil,
		TransformReplaceData, "", "", "", "", "", "", "X", 0); err == nil {
		t.Fatal("expected error for replace_data with empty pattern")
	}
}

func TestTransformEngine_DirectionSendRejected(t *testing.T) {
	if _, err := CompileTransformRule("r1", 0, "send", "", "", "", nil, nil, nil,
		TransformSetData, "", "", "x", "", "", "", "", 0); err == nil {
		t.Fatal("expected error for direction=send")
	}
}

func TestTransformEngine_NilEnv(t *testing.T) {
	e := NewTransformEngine()
	r := newTransformRule("r", TransformSetEvent, func(r *TransformRule) { r.SetEventValue = "x" })
	e.AddRule(*r)
	// nil msg / env must not panic.
	res := e.Transform(context.Background(), nil, nil)
	if res.Drop || res.Modified {
		t.Errorf("nil inputs produced action: %+v", res)
	}
}
