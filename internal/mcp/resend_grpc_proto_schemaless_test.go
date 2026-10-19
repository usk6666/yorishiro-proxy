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

// setMaxResendGRPCPayloadForTest lowers maxResendGRPCPayload for the
// duration of t and restores it via t.Cleanup. Callers must NOT call
// t.Parallel(): the cap is a package var read by every resend/fuzz gRPC
// populate call.
func setMaxResendGRPCPayloadForTest(t *testing.T, n int) {
	t.Helper()
	prev := maxResendGRPCPayload
	maxResendGRPCPayload = n
	t.Cleanup(func() { maxResendGRPCPayload = prev })
}

// TestPopulateResendGRPCMessages_ProtoSchemalessJSON_SizeCapEnforced
// asserts the maxResendGRPCPayload cap fires on the POST-encode byte
// length (JSON-amplification guard) at the exact boundary: a payload
// that encodes to exactly the cap is accepted, one that encodes to cap+1
// is rejected. The accept case's JSON text is itself longer than the
// cap, so a check on the pre-encode JSON length would wrongly reject it.
//
// The cap is lowered to 1 KiB so the boundary is crossed without
// building 16 MiB fixtures (USK-1205). Not parallel: it overrides a
// package var.
func TestPopulateResendGRPCMessages_ProtoSchemalessJSON_SizeCapEnforced(t *testing.T) {
	const testCap = 1024
	setMaxResendGRPCPayloadForTest(t, testCap)

	jsonWithString := func(n int) string {
		return `{"0001:0000:String":"` + strings.Repeat("A", n) + `"}`
	}
	populate := func(payload string) (*resendGRPCPlan, error) {
		input := &resendGRPCInput{
			Messages: []resendGRPCData{
				{Payload: payload, BodyEncoding: "proto-schemaless-json"},
			},
		}
		plan := &resendGRPCPlan{}
		srv := &Server{}
		return plan, srv.populateResendGRPCMessages(input, plan)
	}

	// Measure the encoder's framing overhead (tag + length varint) from a
	// successful populate instead of hand-computing it. A 512-byte value
	// uses the same 2-byte length varint as the ~1 KiB values below.
	const probeLen = 512
	probePlan, err := populate(jsonWithString(probeLen))
	if err != nil {
		t.Fatalf("probe populate: %v", err)
	}
	overhead := len(probePlan.messages[0].payload) - probeLen
	if overhead <= 0 {
		t.Fatalf("probe: encoded length %d not larger than value length %d", len(probePlan.messages[0].payload), probeLen)
	}

	t.Run("encoded size == cap is accepted", func(t *testing.T) {
		payload := jsonWithString(testCap - overhead)
		if len(payload) <= testCap {
			t.Fatalf("precondition: JSON length %d must exceed cap %d so only a post-encode check accepts it", len(payload), testCap)
		}
		plan, err := populate(payload)
		if err != nil {
			t.Fatalf("populate at exactly cap: %v", err)
		}
		if got := len(plan.messages[0].payload); got != testCap {
			t.Fatalf("encoded length = %d, want exactly cap %d", got, testCap)
		}
	})

	t.Run("encoded size == cap+1 is rejected", func(t *testing.T) {
		_, err := populate(jsonWithString(testCap - overhead + 1))
		if err == nil {
			t.Fatal("expected payload-too-large error, got nil")
		}
		if want := "messages[0]: payload too large: 1025 > 1024"; err.Error() != want {
			t.Errorf("error = %q, want %q", err.Error(), want)
		}
	})
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
