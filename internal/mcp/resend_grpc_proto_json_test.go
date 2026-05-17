// Package mcp resend_grpc_proto_json_test.go covers the proto-json
// body_encoding wiring on the resend_grpc tool (USK-923):
//
//   - validateResendGRPCMessagesShape accepts "proto-json" alongside
//     the existing values.
//   - populateResendGRPCMessages routes proto-json payloads through
//     protoschema.Encode against the registered schema.
//   - Missing schema for the resend's (service, method) hard-errors
//     with the canonical message pointing at grpc_schema register.
//   - DiscardUnknown is in effect (typo'd JSON keys do not hard-error).
//   - Mixed encodings in a single messages[] array work per-message.
package mcp

import (
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
)

// loadSchemaIntoServer registers the test fixture schema directly into
// the Server's in-memory Registry. The fixture is the same descriptor
// set used by the protoschema unit tests.
func loadSchemaIntoServer(t *testing.T, s *Server) {
	t.Helper()
	specs, err := protoschema.LoadFileDescriptorSet(embeddedTestDescBytes, nil)
	if err != nil {
		t.Fatalf("LoadFileDescriptorSet: %v", err)
	}
	s.grpcSchemaRegistry().Register(specs)
}

func TestValidateResendGRPCMessagesShape_AcceptsProtoJSON(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: `{"f_string":"hi"}`, BodyEncoding: "proto-json"},
		},
	}
	if err := validateResendGRPCMessagesShape(input); err != nil {
		t.Errorf("validateResendGRPCMessagesShape: %v", err)
	}
}

func TestPopulateResendGRPCMessages_ProtoJSON_Happy(t *testing.T) {
	t.Parallel()
	s := newServer(t.Context(), nil, newTestStore(t), nil)
	loadSchemaIntoServer(t, s)

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: `{"f_string":"hello","f_int32":42}`, BodyEncoding: "proto-json"},
		},
	}
	plan := &resendGRPCPlan{
		service: "usk.test.Greeter",
		method:  "SayHello",
	}
	if err := s.populateResendGRPCMessages(input, plan); err != nil {
		t.Fatalf("populateResendGRPCMessages: %v", err)
	}
	if len(plan.messages) != 1 || len(plan.messages[0].payload) == 0 {
		t.Fatalf("plan.messages = %+v", plan.messages)
	}
	// The wire payload must round-trip back through protoschema.Decode
	// using the registered descriptor.
	spec := s.grpcSchemaRegistry().LookupMethod("usk.test.Greeter", "SayHello")
	js, err := protoschema.Decode(plan.messages[0].payload, spec.InputDesc)
	if err != nil {
		t.Fatalf("round-trip Decode: %v", err)
	}
	if !strings.Contains(js, `"hello"`) {
		t.Errorf("round-trip lost field: %s", js)
	}
}

func TestPopulateResendGRPCMessages_ProtoJSON_NoSchemaRegistered(t *testing.T) {
	t.Parallel()
	s := newServer(t.Context(), nil, newTestStore(t), nil)
	// No schema registered.

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: `{"f_string":"hi"}`, BodyEncoding: "proto-json"},
		},
	}
	plan := &resendGRPCPlan{
		service: "no.such.Service",
		method:  "Method",
	}
	err := s.populateResendGRPCMessages(input, plan)
	if err == nil {
		t.Fatal("expected hard error when no schema is registered")
	}
	msg := err.Error()
	if !strings.Contains(msg, "grpc_schema") {
		t.Errorf("error must point at grpc_schema tool: %q", msg)
	}
	if !strings.Contains(msg, "no.such.Service") {
		t.Errorf("error must mention the missing service: %q", msg)
	}
}

func TestPopulateResendGRPCMessages_ProtoJSON_TypeMismatch(t *testing.T) {
	t.Parallel()
	s := newServer(t.Context(), nil, newTestStore(t), nil)
	loadSchemaIntoServer(t, s)

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			// String for int32 — protojson rejects.
			{Payload: `{"f_int32":"not-a-number"}`, BodyEncoding: "proto-json"},
		},
	}
	plan := &resendGRPCPlan{
		service: "usk.test.Greeter",
		method:  "SayHello",
	}
	err := s.populateResendGRPCMessages(input, plan)
	if err == nil {
		t.Fatal("expected error for type mismatch")
	}
	if !strings.Contains(err.Error(), "messages[0]") {
		t.Errorf("error must reference message index: %q", err.Error())
	}
}

func TestPopulateResendGRPCMessages_ProtoJSON_DiscardUnknownKeys(t *testing.T) {
	t.Parallel()
	s := newServer(t.Context(), nil, newTestStore(t), nil)
	loadSchemaIntoServer(t, s)

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			// f_typo is not in the schema; DiscardUnknown silently drops.
			{Payload: `{"f_string":"hi","f_typo":"ignored"}`, BodyEncoding: "proto-json"},
		},
	}
	plan := &resendGRPCPlan{
		service: "usk.test.Greeter",
		method:  "SayHello",
	}
	if err := s.populateResendGRPCMessages(input, plan); err != nil {
		t.Errorf("DiscardUnknown should ignore unknown keys: %v", err)
	}
}

func TestPopulateResendGRPCMessages_MixedEncodings(t *testing.T) {
	t.Parallel()
	s := newServer(t.Context(), nil, newTestStore(t), nil)
	loadSchemaIntoServer(t, s)

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: `{"f_string":"a"}`, BodyEncoding: "proto-json"},
			{Payload: `{"0001:0000:String":"b"}`, BodyEncoding: "proto-schemaless-json"},
			{Payload: "raw", BodyEncoding: "text"},
		},
	}
	plan := &resendGRPCPlan{
		service: "usk.test.Greeter",
		method:  "SayHello",
	}
	if err := s.populateResendGRPCMessages(input, plan); err != nil {
		t.Fatalf("populateResendGRPCMessages: %v", err)
	}
	if len(plan.messages) != 3 {
		t.Fatalf("plan.messages len = %d, want 3", len(plan.messages))
	}
	if string(plan.messages[2].payload) != "raw" {
		t.Errorf("text encoding mangled: %q", plan.messages[2].payload)
	}
}
