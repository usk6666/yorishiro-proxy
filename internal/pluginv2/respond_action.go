package pluginv2

import (
	"fmt"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// RespondAction is the typed Starlark value produced by `action.RESPOND(...)`
// or `action.RESPOND_GRPC(...)`. The dispatcher type-checks it as the signal
// for ActionRespond and reads the per-shape payload directly — no string-key
// dict that could rot under typos.
//
// Exactly one of HTTPResponse or GRPCResponse is non-nil.
type RespondAction struct {
	HTTPResponse *HTTPRespondPayload
	GRPCResponse *GRPCRespondPayload
}

// HTTPRespondPayload is the body of action.RESPOND(...). It maps directly to
// an *envelope.HTTPMessage at envelope-synthesis time in the pipeline package.
type HTTPRespondPayload struct {
	StatusCode int
	Headers    []envelope.KeyValue
	Body       []byte
}

// GRPCRespondPayload is the body of action.RESPOND_GRPC(...). It maps to an
// *envelope.GRPCEndMessage; native gRPC trailer-HEADERS are HPACK-rendered
// by the gRPC Layer's Send so the synthesized envelope's Raw stays nil.
type GRPCRespondPayload struct {
	Status   uint32
	Message  string
	Trailers []envelope.KeyValue
}

// String / Type / Freeze / Truth / Hash satisfy starlark.Value.

func (r *RespondAction) String() string {
	switch {
	case r == nil:
		return "respond(<nil>)"
	case r.HTTPResponse != nil:
		return fmt.Sprintf("respond(http status=%d)", r.HTTPResponse.StatusCode)
	case r.GRPCResponse != nil:
		return fmt.Sprintf("respond(grpc status=%d)", r.GRPCResponse.Status)
	default:
		return "respond(<empty>)"
	}
}

func (r *RespondAction) Type() string         { return "respond" }
func (r *RespondAction) Freeze()              {}
func (r *RespondAction) Truth() starlark.Bool { return starlark.True }
func (r *RespondAction) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: respond")
}

// builtinRespond implements `action.RESPOND(status_code, headers=[], body=b"")`.
func builtinRespond(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		statusCode int
		headersV   starlark.Value = starlark.None
		bodyV      starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"status_code", &statusCode,
		"headers?", &headersV,
		"body?", &bodyV,
	); err != nil {
		return nil, err
	}
	if statusCode < 100 || statusCode > 999 {
		return nil, fmt.Errorf("%s: status_code must be in [100, 999], got %d", fn.Name(), statusCode)
	}
	headers, err := starlarkPairsToKVs(headersV)
	if err != nil {
		return nil, fmt.Errorf("%s: headers: %w", fn.Name(), err)
	}
	body, err := starlarkValueToBytes(bodyV)
	if err != nil {
		return nil, fmt.Errorf("%s: body: %w", fn.Name(), err)
	}
	return &RespondAction{HTTPResponse: &HTTPRespondPayload{
		StatusCode: statusCode,
		Headers:    headers,
		Body:       body,
	}}, nil
}

// builtinRespondGRPC implements `action.RESPOND_GRPC(status, message="", trailers=[])`.
func builtinRespondGRPC(_ *starlark.Thread, fn *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var (
		status    int
		message   starlark.String
		trailersV starlark.Value = starlark.None
	)
	if err := starlark.UnpackArgs(fn.Name(), args, kwargs,
		"status", &status,
		"message?", &message,
		"trailers?", &trailersV,
	); err != nil {
		return nil, err
	}
	if status < 0 || status > 0xFFFFFFFF {
		return nil, fmt.Errorf("%s: status must fit in uint32, got %d", fn.Name(), status)
	}
	trailers, err := starlarkPairsToKVs(trailersV)
	if err != nil {
		return nil, fmt.Errorf("%s: trailers: %w", fn.Name(), err)
	}
	return &RespondAction{GRPCResponse: &GRPCRespondPayload{
		Status:   uint32(status),
		Message:  string(message),
		Trailers: trailers,
	}}, nil
}

// starlarkPairsToKVs converts a Starlark sequence of (name, value) 2-tuples
// to []envelope.KeyValue, preserving order. None / empty input → nil.
func starlarkPairsToKVs(v starlark.Value) ([]envelope.KeyValue, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	iter, ok := v.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("expected sequence of (name, value) tuples, got %s", v.Type())
	}
	it := iter.Iterate()
	defer it.Done()
	var out []envelope.KeyValue
	var elem starlark.Value
	for it.Next(&elem) {
		tup, ok := elem.(starlark.Tuple)
		if !ok || tup.Len() != 2 {
			return nil, fmt.Errorf("expected 2-tuple, got %s", elem.Type())
		}
		name, ok := tup[0].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("name must be string, got %s", tup[0].Type())
		}
		val, ok := tup[1].(starlark.String)
		if !ok {
			return nil, fmt.Errorf("value must be string, got %s", tup[1].Type())
		}
		out = append(out, envelope.KeyValue{Name: string(name), Value: string(val)})
	}
	return out, nil
}

// starlarkValueToBytes converts None / starlark.Bytes / starlark.String to
// []byte. Other types are an error.
func starlarkValueToBytes(v starlark.Value) ([]byte, error) {
	if v == nil || v == starlark.None {
		return nil, nil
	}
	switch x := v.(type) {
	case starlark.Bytes:
		return []byte(x), nil
	case starlark.String:
		return []byte(x), nil
	default:
		return nil, fmt.Errorf("expected bytes or string, got %s", v.Type())
	}
}
