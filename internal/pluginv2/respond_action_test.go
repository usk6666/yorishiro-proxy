package pluginv2

import (
	"strings"
	"testing"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// callBuiltin invokes a Starlark Builtin from Go test code with positional
// args (kwargs unsupported here for brevity).
func callBuiltin(t *testing.T, b *starlark.Builtin, args ...starlark.Value) (starlark.Value, error) {
	t.Helper()
	thread := &starlark.Thread{Name: "test"}
	return starlark.Call(thread, b, starlark.Tuple(args), nil)
}

func TestRespond_HTTPMinimal(t *testing.T) {
	mod := newActionModule()
	respond, ok := mod.Members["RESPOND"].(*starlark.Builtin)
	if !ok {
		t.Fatalf("RESPOND not a Builtin: %T", mod.Members["RESPOND"])
	}
	v, err := callBuiltin(t, respond, starlark.MakeInt(404))
	if err != nil {
		t.Fatalf("RESPOND(404) err = %v", err)
	}
	r, ok := v.(*RespondAction)
	if !ok {
		t.Fatalf("not *RespondAction: %T", v)
	}
	if r.HTTPResponse == nil {
		t.Fatal("HTTPResponse nil")
	}
	if r.HTTPResponse.StatusCode != 404 {
		t.Errorf("StatusCode = %d, want 404", r.HTTPResponse.StatusCode)
	}
	if r.HTTPResponse.Body != nil {
		t.Errorf("Body = %v, want nil", r.HTTPResponse.Body)
	}
}

func TestRespond_HTTPWithHeadersAndBody(t *testing.T) {
	mod := newActionModule()
	respond := mod.Members["RESPOND"].(*starlark.Builtin)

	headers := starlark.NewList([]starlark.Value{
		starlark.Tuple{starlark.String("content-type"), starlark.String("text/plain")},
		starlark.Tuple{starlark.String("X-Trace"), starlark.String("abc")},
	})
	v, err := callBuiltin(t, respond, starlark.MakeInt(200), headers, starlark.Bytes("hello"))
	if err != nil {
		t.Fatalf("RESPOND(...) err = %v", err)
	}
	r := v.(*RespondAction)
	if got, want := len(r.HTTPResponse.Headers), 2; got != want {
		t.Fatalf("len Headers = %d, want %d", got, want)
	}
	if r.HTTPResponse.Headers[0] != (envelope.KeyValue{Name: "content-type", Value: "text/plain"}) {
		t.Errorf("Headers[0] = %+v", r.HTTPResponse.Headers[0])
	}
	if r.HTTPResponse.Headers[1] != (envelope.KeyValue{Name: "X-Trace", Value: "abc"}) {
		t.Errorf("Headers[1] preserved case incorrectly: %+v", r.HTTPResponse.Headers[1])
	}
	if string(r.HTTPResponse.Body) != "hello" {
		t.Errorf("Body = %q, want %q", string(r.HTTPResponse.Body), "hello")
	}
}

func TestRespond_HTTPInvalidStatus(t *testing.T) {
	mod := newActionModule()
	respond := mod.Members["RESPOND"].(*starlark.Builtin)
	if _, err := callBuiltin(t, respond, starlark.MakeInt(99)); err == nil {
		t.Error("expected error for status_code=99")
	}
	if _, err := callBuiltin(t, respond, starlark.MakeInt(1000)); err == nil {
		t.Error("expected error for status_code=1000")
	}
}

func TestRespond_HeadersValueTypeRejected(t *testing.T) {
	mod := newActionModule()
	respond := mod.Members["RESPOND"].(*starlark.Builtin)

	bad := starlark.NewList([]starlark.Value{
		starlark.Tuple{starlark.String("name"), starlark.MakeInt(1)},
	})
	_, err := callBuiltin(t, respond, starlark.MakeInt(200), bad)
	if err == nil || !strings.Contains(err.Error(), "value must be string") {
		t.Errorf("expected value-must-be-string error, got %v", err)
	}
}

func TestRespond_StringBodyAccepted(t *testing.T) {
	mod := newActionModule()
	respond := mod.Members["RESPOND"].(*starlark.Builtin)
	v, err := callBuiltin(t, respond, starlark.MakeInt(200), starlark.None, starlark.String("plain"))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	r := v.(*RespondAction)
	if string(r.HTTPResponse.Body) != "plain" {
		t.Errorf("Body = %q", string(r.HTTPResponse.Body))
	}
}

func TestRespondGRPC_Minimal(t *testing.T) {
	mod := newActionModule()
	respondGRPC := mod.Members["RESPOND_GRPC"].(*starlark.Builtin)
	v, err := callBuiltin(t, respondGRPC, starlark.MakeInt(7))
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	r := v.(*RespondAction)
	if r.GRPCResponse == nil {
		t.Fatal("GRPCResponse nil")
	}
	if r.GRPCResponse.Status != 7 {
		t.Errorf("Status = %d, want 7", r.GRPCResponse.Status)
	}
}

func TestRespondGRPC_WithMessageAndTrailers(t *testing.T) {
	mod := newActionModule()
	respondGRPC := mod.Members["RESPOND_GRPC"].(*starlark.Builtin)

	trailers := starlark.NewList([]starlark.Value{
		starlark.Tuple{starlark.String("grpc-message"), starlark.String("denied")},
	})
	v, err := callBuiltin(t, respondGRPC, starlark.MakeInt(7), starlark.String("denied"), trailers)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	r := v.(*RespondAction)
	if r.GRPCResponse.Message != "denied" {
		t.Errorf("Message = %q", r.GRPCResponse.Message)
	}
	if len(r.GRPCResponse.Trailers) != 1 {
		t.Errorf("Trailers len = %d", len(r.GRPCResponse.Trailers))
	}
}

func TestRespond_TypeContract(t *testing.T) {
	r := &RespondAction{HTTPResponse: &HTTPRespondPayload{StatusCode: 200}}
	if r.Type() != "respond" {
		t.Errorf("Type = %q", r.Type())
	}
	if !bool(r.Truth()) {
		t.Error("Truth should be true")
	}
	if _, err := r.Hash(); err == nil {
		t.Error("Hash should error")
	}
	r.Freeze() // no panic
}
