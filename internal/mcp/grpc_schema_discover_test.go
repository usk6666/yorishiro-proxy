// Package mcp grpc_schema_discover_test.go covers the grpc_schema MCP
// tool's action=discover surface (USK-928). The tests use the exported
// protoschema.SetReflectionDialForTest seam to plug a synthetic
// reflection server into the discover code path — exercising the full
// MCP handler (validation, scope, rate limit, budget, persist, list)
// without standing up a real gRPC server.
package mcp

import (
	"context"
	"errors"
	"strings"
	"testing"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	v1 "google.golang.org/grpc/reflection/grpc_reflection_v1"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// fakeMCPReflectionChannel is a paired implementation of
// protoschema.ReflectionStreamChannel. Like the internal fake, it
// services Send envelopes by queueing the matching response shape on
// Next.
type fakeMCPReflectionChannel struct {
	t        *testing.T
	service  string
	services []string
	files    map[string][][]byte
	mode     string
	pending  []*envelope.Envelope
	reqIdx   int
}

func (c *fakeMCPReflectionChannel) Send(_ context.Context, env *envelope.Envelope) error {
	switch m := env.Message.(type) {
	case *envelope.GRPCStartMessage:
		return nil
	case *envelope.GRPCDataMessage:
		if m.Payload == nil && m.WireLength == 0 && m.EndStream {
			return nil
		}
		c.reqIdx++
		if c.mode == "unimplemented" {
			c.pending = append(c.pending, &envelope.Envelope{
				Direction: envelope.Receive,
				Protocol:  envelope.ProtocolGRPC,
				Message: &envelope.GRPCEndMessage{
					Status:  12, // UNIMPLEMENTED
					Message: "not implemented",
				},
			})
			return nil
		}
		req := &v1.ServerReflectionRequest{}
		if err := proto.Unmarshal(m.Payload, req); err != nil {
			return err
		}
		switch r := req.MessageRequest.(type) {
		case *v1.ServerReflectionRequest_ListServices:
			c.queueListServices()
		case *v1.ServerReflectionRequest_FileContainingSymbol:
			c.queueFileDescriptor(r.FileContainingSymbol)
		}
	case *envelope.GRPCEndMessage:
		// no-op
	}
	return nil
}

func (c *fakeMCPReflectionChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if len(c.pending) == 0 {
		return nil, errors.New("no pending envelopes")
	}
	env := c.pending[0]
	c.pending = c.pending[1:]
	return env, nil
}

func (c *fakeMCPReflectionChannel) queueListServices() {
	respSvcs := make([]*v1.ServiceResponse, 0, len(c.services))
	for _, s := range c.services {
		respSvcs = append(respSvcs, &v1.ServiceResponse{Name: s})
	}
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_ListServicesResponse{
			ListServicesResponse: &v1.ListServiceResponse{Service: respSvcs},
		},
	}
	c.queueResp(resp)
}

func (c *fakeMCPReflectionChannel) queueFileDescriptor(svc string) {
	files, ok := c.files[svc]
	if !ok {
		c.queueErrorResp(5, "unknown symbol "+svc)
		return
	}
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_FileDescriptorResponse{
			FileDescriptorResponse: &v1.FileDescriptorResponse{FileDescriptorProto: files},
		},
	}
	c.queueResp(resp)
}

func (c *fakeMCPReflectionChannel) queueErrorResp(code int32, msg string) {
	resp := &v1.ServerReflectionResponse{
		MessageResponse: &v1.ServerReflectionResponse_ErrorResponse{
			ErrorResponse: &v1.ErrorResponse{ErrorCode: code, ErrorMessage: msg},
		},
	}
	c.queueResp(resp)
}

func (c *fakeMCPReflectionChannel) queueResp(resp *v1.ServerReflectionResponse) {
	payload, err := proto.Marshal(resp)
	if err != nil {
		c.t.Fatalf("marshal response: %v", err)
	}
	c.pending = append(c.pending, &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
	})
}

// mcpReflectionFileDescriptor returns a marshaled FileDescriptorProto
// describing a single service+method. Mirrors the helper used by the
// protoschema tests.
func mcpReflectionFileDescriptor(t *testing.T, packageName, fileName, serviceName, methodName, inputMsg, outputMsg string) []byte {
	t.Helper()
	syntax := "proto3"
	str := func(s string) *string { return &s }
	fd := &descriptorpb.FileDescriptorProto{
		Name:    &fileName,
		Package: &packageName,
		Syntax:  &syntax,
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: &inputMsg},
			{Name: &outputMsg},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{
			{
				Name: &serviceName,
				Method: []*descriptorpb.MethodDescriptorProto{
					{
						Name:       &methodName,
						InputType:  str("." + packageName + "." + inputMsg),
						OutputType: str("." + packageName + "." + outputMsg),
					},
				},
			},
		},
	}
	raw, err := proto.Marshal(fd)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// TestGRPCSchemaDiscover_Happy verifies the full action=discover MCP
// path: synthetic reflection server → MCP handler → SaveGRPCSchema +
// Register tail → list reports the discovered service with
// source_label="reflection://...".
func TestGRPCSchemaDiscover_Happy(t *testing.T) {
	greeterFD := mcpReflectionFileDescriptor(t, "demo", "demo/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")

	restore := protoschema.SetReflectionDialForTest(func(service string) protoschema.ReflectionStreamChannel {
		return &fakeMCPReflectionChannel{
			t:        t,
			service:  service,
			services: []string{"demo.Greeter"},
			files: map[string][][]byte{
				"demo.Greeter": {greeterFD},
			},
		}
	})
	defer restore()

	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "discover",
		"params": map[string]any{
			"target_addr": "127.0.0.1:9000",
			"scheme":      "http",
		},
	})
	if result.IsError {
		t.Fatalf("discover error: %v", extractTextContent(result))
	}

	var out grpcSchemaDiscoverResult
	unmarshalExecuteResult(t, result, &out)
	if len(out.Discovered) != 1 || out.Discovered[0].Service != "demo.Greeter" {
		t.Fatalf("Discovered = %+v, want [demo.Greeter]", out.Discovered)
	}
	if out.Target != "127.0.0.1:9000" {
		t.Errorf("Target = %q, want 127.0.0.1:9000", out.Target)
	}
	if out.ReflectionVersion != "v1" {
		t.Errorf("ReflectionVersion = %q, want v1", out.ReflectionVersion)
	}
	if out.Discovered[0].SourceLabel != "reflection://127.0.0.1:9000" {
		t.Errorf("SourceLabel = %q, want reflection://127.0.0.1:9000", out.Discovered[0].SourceLabel)
	}

	// Verify list also surfaces the discovered entry with the same label.
	listResult := callGRPCSchema(t, cs, map[string]any{"action": "list"})
	var listOut grpcSchemaListResult
	unmarshalExecuteResult(t, listResult, &listOut)
	if len(listOut.Schemas) != 1 || listOut.Schemas[0].Service != "demo.Greeter" {
		t.Fatalf("after discover, list = %+v", listOut.Schemas)
	}
	if listOut.Schemas[0].SourceLabel != "reflection://127.0.0.1:9000" {
		t.Errorf("list SourceLabel = %q, want reflection://127.0.0.1:9000", listOut.Schemas[0].SourceLabel)
	}
}

// TestGRPCSchemaDiscover_MissingTargetAddr verifies that target_addr is
// required.
func TestGRPCSchemaDiscover_MissingTargetAddr(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "discover",
		"params": map[string]any{},
	})
	if !result.IsError {
		t.Fatal("expected error when target_addr is missing")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "target_addr") {
		t.Errorf("error must mention target_addr: %q", msg)
	}
}

// TestGRPCSchemaDiscover_CRLFGuard verifies that CR/LF in target_addr
// is rejected before any network egress.
func TestGRPCSchemaDiscover_CRLFGuard(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "discover",
		"params": map[string]any{
			"target_addr": "127.0.0.1:9000\r\nX-Injected: 1",
		},
	})
	if !result.IsError {
		t.Fatal("expected CRLF rejection")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "CR/LF") {
		t.Errorf("error must mention CR/LF: %q", msg)
	}
}

// TestGRPCSchemaDiscover_TargetScope verifies that an out-of-scope
// target_addr is rejected by the target scope check before any
// network egress.
func TestGRPCSchemaDiscover_TargetScope(t *testing.T) {
	t.Parallel()
	// Set a scope rule that does not include our target host.
	ts := connector.NewTargetScope()
	_ = ts.SetAgentRules([]connector.TargetRule{
		{Hostname: "allowed.example.com"},
	}, nil)

	store := newTestStore(t)
	s := newServer(context.Background(), nil, store, nil, WithTargetScope(ts))

	_, err := s.handleGRPCSchemaDiscover(context.Background(), grpcSchemaToolParams{
		TargetAddr: "blocked.example.com:9000",
		Scheme:     "http",
	})
	if err == nil {
		t.Fatal("expected target scope rejection")
	}
	if !strings.Contains(err.Error(), "scope") {
		t.Errorf("error must mention scope: %v", err)
	}
}

// TestGRPCSchemaDiscover_RejectsCrossActionFields verifies that supplying
// descriptor_set_b64 / proto_paths under action=discover is rejected.
func TestGRPCSchemaDiscover_RejectsCrossActionFields(t *testing.T) {
	t.Parallel()
	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "discover",
		"params": map[string]any{
			"target_addr":        "127.0.0.1:9000",
			"descriptor_set_b64": "Cg==",
		},
	})
	if !result.IsError {
		t.Fatal("expected error when descriptor_set_b64 is set under action=discover")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "descriptor_set_b64") {
		t.Errorf("error must mention descriptor_set_b64: %q", msg)
	}
}

// TestGRPCSchemaDiscover_UnimplementedReturnsRemediationHint verifies
// that a target that lacks reflection support surfaces the verbatim
// "enable reflection" hint.
func TestGRPCSchemaDiscover_UnimplementedReturnsRemediationHint(t *testing.T) {
	restore := protoschema.SetReflectionDialForTest(func(service string) protoschema.ReflectionStreamChannel {
		return &fakeMCPReflectionChannel{
			t:       t,
			service: service,
			mode:    "unimplemented",
		}
	})
	defer restore()

	store := newTestStore(t)
	cs := setupGRPCSchemaTestSession(t, store)

	result := callGRPCSchema(t, cs, map[string]any{
		"action": "discover",
		"params": map[string]any{
			"target_addr": "127.0.0.1:9000",
			"scheme":      "http",
		},
	})
	if !result.IsError {
		t.Fatal("expected error when both v1 and v1alpha return UNIMPLEMENTED")
	}
	msg := extractTextContent(result)
	if !strings.Contains(msg, "does not implement gRPC reflection") {
		t.Errorf("error must include the canonical message: %q", msg)
	}
	if !strings.Contains(msg, "reflection.Register(s)") {
		t.Errorf("error must include enable-reflection hint: %q", msg)
	}
}
