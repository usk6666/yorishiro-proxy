// Package mcp resend_grpc_proto_schemaless_test.go covers the
// proto-schemaless-json body_encoding wiring on the resend_grpc tool
// (USK-922). The unit tier asserts:
//
//   - validateResendGRPCMessagesShape accepts "proto-schemaless-json"
//     alongside "text" and "base64".
//   - validateResendGRPCMessagesShape continues to reject unknown values
//     with an explicit allowlist error.
//   - populateResendGRPCMessages routes the JSON payload through
//     internal/encoding/protobuf.Encode and recovers the original proto
//     wire bytes (round-trip).
//   - Invalid JSON surfaces "messages[i]: invalid proto-schemaless-json: ..."
//     so the AI agent can correlate the offending message index.
//   - The size cap is enforced AFTER encoding (a small JSON producing
//     oversize proto bytes is rejected).
package mcp

import (
	"bytes"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
)

// TestValidateResendGRPCMessagesShape_AcceptsProtoSchemalessJSON asserts
// the validator allowlist includes the new encoding.
func TestValidateResendGRPCMessagesShape_AcceptsProtoSchemalessJSON(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: `{"0001:0000:String":"hi"}`, BodyEncoding: "proto-schemaless-json"},
		},
	}
	if err := validateResendGRPCMessagesShape(input); err != nil {
		t.Fatalf("validateResendGRPCMessagesShape: %v", err)
	}
}

// TestValidateResendGRPCMessagesShape_RejectsUnknownEncoding pins the
// allowlist error wording — the error must enumerate the three accepted
// values so AI agents can self-correct.
func TestValidateResendGRPCMessagesShape_RejectsUnknownEncoding(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: "x", BodyEncoding: "json"},
		},
	}
	err := validateResendGRPCMessagesShape(input)
	if err == nil {
		t.Fatal("expected error for unknown body_encoding, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "proto-schemaless-json") {
		t.Errorf("error must enumerate proto-schemaless-json in allowlist: %q", msg)
	}
	if !strings.Contains(msg, "text") || !strings.Contains(msg, "base64") {
		t.Errorf("error must enumerate text and base64 in allowlist: %q", msg)
	}
}

// TestPopulateResendGRPCMessages_ProtoSchemalessJSON_Roundtrip asserts the
// happy-path: a valid JSON payload round-trips to the same proto wire
// bytes the standalone protobuf.Encode would emit.
func TestPopulateResendGRPCMessages_ProtoSchemalessJSON_Roundtrip(t *testing.T) {
	t.Parallel()
	payload := `{"0001:0000:String":"hi from resend"}`
	wantBytes, err := protobuf.Encode(payload)
	if err != nil {
		t.Fatalf("standalone protobuf.Encode: %v", err)
	}

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: payload, BodyEncoding: "proto-schemaless-json"},
		},
	}
	plan := &resendGRPCPlan{}
	srv := &Server{}
	if err := srv.populateResendGRPCMessages(input, plan); err != nil {
		t.Fatalf("populateResendGRPCMessages: %v", err)
	}
	if len(plan.messages) != 1 {
		t.Fatalf("plan.messages len = %d, want 1", len(plan.messages))
	}
	if !bytes.Equal(plan.messages[0].payload, wantBytes) {
		t.Errorf("encoded payload diverges from protobuf.Encode\n got: %x\nwant: %x",
			plan.messages[0].payload, wantBytes)
	}
}

// TestPopulateResendGRPCMessages_ProtoSchemalessJSON_InvalidJSON asserts
// invalid JSON surfaces the standard error shape so AI agents can correlate
// the failure to a specific message index.
func TestPopulateResendGRPCMessages_ProtoSchemalessJSON_InvalidJSON(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: "not-a-json", BodyEncoding: "proto-schemaless-json"},
		},
	}
	plan := &resendGRPCPlan{}
	srv := &Server{}
	err := srv.populateResendGRPCMessages(input, plan)
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
	msg := err.Error()
	if !strings.Contains(msg, "messages[0]:") {
		t.Errorf("error must reference messages[0] index, got: %q", msg)
	}
	if !strings.Contains(msg, "invalid proto-schemaless-json") {
		t.Errorf("error must mention invalid proto-schemaless-json, got: %q", msg)
	}
}

// TestPopulateResendGRPCMessages_ProtoSchemalessJSON_SizeCapEnforced
// asserts the maxResendGRPCPayload cap fires on the POST-encode byte
// length (JSON-amplification guard). A JSON payload that encodes to
// exactly maxResendGRPCPayload+1 must be rejected.
func TestPopulateResendGRPCMessages_ProtoSchemalessJSON_SizeCapEnforced(t *testing.T) {
	t.Parallel()
	// Build a String field whose value byte length pushes the encoded
	// proto size past the cap by 1. Tag byte 0x0a + varint length + value
	// bytes, where the varint length itself takes 4 bytes for a value
	// near 16 MiB. We make the inner string len = maxResendGRPCPayload
	// so the total wire size is len + varint(len) + 1 > cap.
	const valueLen = maxResendGRPCPayload
	bigValue := strings.Repeat("A", valueLen)
	payload := `{"0001:0000:String":"` + bigValue + `"}`

	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: payload, BodyEncoding: "proto-schemaless-json"},
		},
	}
	plan := &resendGRPCPlan{}
	srv := &Server{}
	err := srv.populateResendGRPCMessages(input, plan)
	if err == nil {
		t.Fatal("expected payload-too-large error, got nil")
	}
	if !strings.Contains(err.Error(), "payload too large") {
		t.Errorf("error must mention payload too large, got: %q", err.Error())
	}
}

// TestPopulateResendGRPCMessages_ProtoSchemalessJSON_RequiresEncodingForCompressed
// asserts the compressed=true precondition still applies to the new
// encoding path.
func TestPopulateResendGRPCMessages_ProtoSchemalessJSON_RequiresEncodingForCompressed(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{
				Payload:      `{"0001:0000:String":"hi"}`,
				BodyEncoding: "proto-schemaless-json",
				Compressed:   true,
			},
		},
	}
	plan := &resendGRPCPlan{}
	srv := &Server{}
	err := srv.populateResendGRPCMessages(input, plan)
	if err == nil {
		t.Fatal("expected error for compressed=true without encoding, got nil")
	}
	if !strings.Contains(err.Error(), "compressed=true requires encoding") {
		t.Errorf("error must mention encoding requirement, got: %q", err.Error())
	}
}

// TestPopulateResendGRPCMessages_TextEncoding_StillWorks regression guard:
// the new dispatch must not break the text/base64 paths.
func TestPopulateResendGRPCMessages_TextEncoding_StillWorks(t *testing.T) {
	t.Parallel()
	input := &resendGRPCInput{
		Messages: []resendGRPCData{
			{Payload: "hello", BodyEncoding: "text"},
		},
	}
	plan := &resendGRPCPlan{}
	srv := &Server{}
	if err := srv.populateResendGRPCMessages(input, plan); err != nil {
		t.Fatalf("populateResendGRPCMessages: %v", err)
	}
	if string(plan.messages[0].payload) != "hello" {
		t.Errorf("text passthrough broken: got %q", plan.messages[0].payload)
	}
}
