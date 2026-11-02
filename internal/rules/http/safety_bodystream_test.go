package http

import (
	"context"
	"io"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// nopBodySource is a BodyStream source that is never read.
type nopBodySource struct{}

func (nopBodySource) Read([]byte) (int, error)         { return 0, io.EOF }
func (nopBodySource) Finish(error) envelope.BodyResult { return envelope.BodyResult{} }

// streamedRequest is a request head whose body is a BodyStream.
func streamedRequest(path string) *envelope.HTTPMessage {
	return &envelope.HTTPMessage{
		Method:     "POST",
		Path:       path,
		Headers:    []envelope.KeyValue{{Name: "Content-Length", Value: "100"}},
		BodyStream: envelope.NewBodyStream(nopBodySource{}),
	}
}

// TestSafetyEngine_BodyTargetFailsClosedOnStreamedBody (USK-1414 T16, R16):
// a body-target rule evaluated on a request whose body is streamed — a
// rule added after the head was parsed — blocks it: the engine cannot see
// the body, and streaming never exempts a request from the Input Filter.
func TestSafetyEngine_BodyTargetFailsClosedOnStreamedBody(t *testing.T) {
	e := NewSafetyEngine()
	if err := e.LoadPreset("destructive-sql"); err != nil {
		t.Fatalf("LoadPreset: %v", err)
	}
	msg := streamedRequest("/upload")

	v := e.CheckInput(context.Background(), msg)
	if v == nil {
		t.Fatal("CheckInput passed a streamed body under a body-target rule; want a fail-closed violation")
	}
	if v.Target != "body" {
		t.Errorf("violation target = %q, want body", v.Target)
	}
	if all := e.CheckInputAll(context.Background(), msg); len(all) == 0 {
		t.Error("CheckInputAll returned no violation for a streamed body under a body-target rule")
	}
	if done := msg.BodyStream.Done(); isClosed(done) {
		t.Error("the engine ended the body stream; it must not read or close it")
	}
}

// TestSafetyEngine_StreamedBodyWithoutBodyRulePasses: without a body-target
// rule a streamed request is judged on its head alone.
func TestSafetyEngine_StreamedBodyWithoutBodyRulePasses(t *testing.T) {
	e := NewSafetyEngine()
	e.AddRule(common.CompiledRule{
		ID:      "url-only",
		Name:    "url only",
		Pattern: regexp.MustCompile(`/admin`),
		Targets: []common.Target{common.TargetURL},
	})
	if v := e.CheckInput(context.Background(), streamedRequest("/ok")); v != nil {
		t.Errorf("CheckInput = %+v, want nil", v)
	}
	if v := e.CheckInput(context.Background(), streamedRequest("/admin")); v == nil || v.Target != "url" {
		t.Errorf("CheckInput(/admin) = %+v, want the url violation", v)
	}
}

func isClosed(ch <-chan struct{}) bool {
	select {
	case <-ch:
		return true
	default:
		return false
	}
}
