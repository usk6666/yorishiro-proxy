// Package mcp fuzz_grpc_proto_schemaless_test.go covers the
// proto-schemaless-json JSON-path positions added by USK-925 — the
// validation surface, the per-key value encoder, and the per-variant
// commit pass. The integration suite (fuzz_grpc_integration_test.go,
// e2e tag) exercises the end-to-end wire effect; this file is the unit
// tier and avoids the gRPC server.
package mcp

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protobuf"
)

// TestIsValidFuzzGRPCPath_AcceptsJSONPath asserts the shape-layer
// validator recognises the new path family. parseProtoKeyParts /
// per-key checks happen in validateFuzzGRPCPositionAgainstPlan and are
// covered by the table tests below.
func TestIsValidFuzzGRPCPath_AcceptsJSONPath(t *testing.T) {
	t.Parallel()
	cases := []struct {
		path string
		ok   bool
	}{
		{"messages[0].payload.0001:0000:String", true},
		{"messages[12].payload.000a:0003:embedded message", true}, // shape OK; deeper validator rejects type
		{"messages[0].payload.", false},                           // empty key
		{"messages[0].payload", true},                             // bytes-level — still valid
		{"service", true},
		{"metadata[0].value", true},
		{"nope", false},
	}
	for _, tc := range cases {
		got := isValidFuzzGRPCPath(tc.path)
		if got != tc.ok {
			t.Errorf("isValidFuzzGRPCPath(%q) = %v, want %v", tc.path, got, tc.ok)
		}
	}
}

// TestValidateFuzzGRPCPositionAgainstPlan_JSONPathHappyPath asserts that
// every prerequisite (proto-schemaless source on the targeted message,
// parseable key, supported wire type, key present in source) lining up
// produces no error.
func TestValidateFuzzGRPCPositionAgainstPlan_JSONPathHappyPath(t *testing.T) {
	t.Parallel()
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				bodyEncoding: "proto-schemaless-json",
				jsonPayload:  `{"0001:0000:String":"hi"}`,
			},
		},
	}
	pos := fuzzGRPCPosition{
		Path:     "messages[0].payload.0001:0000:String",
		Payloads: []string{"hi", "bye"},
	}
	if err := validateFuzzGRPCPositionAgainstPlan(0, pos, plan); err != nil {
		t.Fatalf("happy path: %v", err)
	}
}

// TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsNonSchemaless
// pins the body_encoding gate. A JSON-path position against a base64
// message has no source JSON to mutate, so it must be rejected before
// any iterator runs.
func TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsNonSchemaless(t *testing.T) {
	t.Parallel()
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{bodyEncoding: "base64"}, // no jsonPayload
		},
	}
	pos := fuzzGRPCPosition{
		Path:     "messages[0].payload.0001:0000:String",
		Payloads: []string{"x"},
	}
	err := validateFuzzGRPCPositionAgainstPlan(0, pos, plan)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "proto-schemaless-json") {
		t.Errorf("error must name the required body_encoding: %q", err)
	}
}

// TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsUnsupportedWireType
// pins the v1 type allowlist — composite types (`repeated`, `embedded
// message`) are out of scope until structured payload iterators land.
func TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsUnsupportedWireType(t *testing.T) {
	t.Parallel()
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				bodyEncoding: "proto-schemaless-json",
				jsonPayload:  `{"0001:0000:embedded message":{"0002:0000:Varint":1}}`,
			},
		},
	}
	pos := fuzzGRPCPosition{
		Path:     "messages[0].payload.0001:0000:embedded message",
		Payloads: []string{"x"},
	}
	err := validateFuzzGRPCPositionAgainstPlan(0, pos, plan)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "embedded message") || !strings.Contains(err.Error(), "supported") {
		t.Errorf("error must name the unsupported type and list supported ones: %q", err)
	}
}

// TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsMissingKey
// pins the no-silent-noop rule: if the iterator targets a key the
// source JSON doesn't carry, the AI agent must learn at validation
// time, not by inspecting unchanged wire bytes.
func TestValidateFuzzGRPCPositionAgainstPlan_JSONPathRejectsMissingKey(t *testing.T) {
	t.Parallel()
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				bodyEncoding: "proto-schemaless-json",
				jsonPayload:  `{"0001:0000:String":"hi"}`,
			},
		},
	}
	pos := fuzzGRPCPosition{
		Path:     "messages[0].payload.0002:0001:Varint",
		Payloads: []string{"42"},
	}
	err := validateFuzzGRPCPositionAgainstPlan(0, pos, plan)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !strings.Contains(err.Error(), "not present") {
		t.Errorf("error must signal the missing key: %q", err)
	}
}

// TestValidateFuzzGRPCMessagePathConflicts_RejectsByteAndJSONSameMessage
// asserts a single message cannot be addressed by both a bytes-level
// position and a JSON-path position — the bytes form would silently
// clobber the JSON mutation result during the commit pass.
func TestValidateFuzzGRPCMessagePathConflicts_RejectsByteAndJSONSameMessage(t *testing.T) {
	t.Parallel()
	err := validateFuzzGRPCMessagePathConflicts([]fuzzGRPCPosition{
		{Path: "messages[0].payload", Payloads: []string{"raw"}},
		{Path: "messages[0].payload.0001:0000:String", Payloads: []string{"x"}},
	})
	if err == nil {
		t.Fatal("expected conflict error, got nil")
	}
	if !strings.Contains(err.Error(), "cannot combine") {
		t.Errorf("error must explain the conflict: %q", err)
	}
}

// TestValidateFuzzGRPCMessagePathConflicts_AllowsBytesAndJSONOnDifferentMessages
// pins that the conflict gate is per-message — independent N's are fine.
func TestValidateFuzzGRPCMessagePathConflicts_AllowsBytesAndJSONOnDifferentMessages(t *testing.T) {
	t.Parallel()
	err := validateFuzzGRPCMessagePathConflicts([]fuzzGRPCPosition{
		{Path: "messages[0].payload", Payloads: []string{"raw"}},
		{Path: "messages[1].payload.0001:0000:String", Payloads: []string{"x"}},
	})
	if err != nil {
		t.Errorf("expected no conflict across distinct messages: %v", err)
	}
}

// TestEncodeFuzzGRPCJSONFieldValue_PerWireType covers the value-encoder
// translation table — each supported wire type accepts the payload form
// documented in help_fuzz_grpc.md.
func TestEncodeFuzzGRPCJSONFieldValue_PerWireType(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		key     string
		payload string
		want    string
		errCt   string
	}{
		{"String_text", "0001:0000:String", "alice", `"alice"`, ""},
		{"String_with_quotes", "0001:0000:String", `a"b`, `"a\"b"`, ""},
		{"Varint_signed_negative", "0001:0000:Varint", "-1", `-1`, ""},
		{"Varint_uint64_max", "0001:0000:Varint", "18446744073709551615", `18446744073709551615`, ""},
		{"Varint_bad", "0001:0000:Varint", "not-a-number", "", "invalid integer"},
		{"32-bit_ok", "0001:0000:32-bit", "4294967295", `4294967295`, ""},
		{"32-bit_overflow", "0001:0000:32-bit", "4294967296", "", "invalid 32-bit"},
		{"64-bit_signed", "0001:0000:64-bit", "-9223372036854775808", `-9223372036854775808`, ""},
		{"bytes_ok", "0001:0000:bytes", "de:ad:be:ef", `"de:ad:be:ef"`, ""},
		{"bytes_empty", "0001:0000:bytes", "", `""`, ""},
		{"bytes_bad_hex", "0001:0000:bytes", "zz", "", "invalid bytes payload"},
		{"unsupported_type", "0001:0000:repeated", "1", "", "unsupported proto wire type"},
		{"bad_key", "bad", "x", "", "invalid proto field key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := encodeFuzzGRPCJSONFieldValue(tc.key, tc.payload)
			if tc.errCt != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got %q", tc.errCt, got)
				}
				if !strings.Contains(err.Error(), tc.errCt) {
					t.Fatalf("error %q must contain %q", err, tc.errCt)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %s, want %s", got, tc.want)
			}
		})
	}
}

// TestCommitFuzzGRPCJSONMutations_RoundTrip pins the per-variant commit
// behaviour: a mutation against a single proto field rewrites
// plan.messages[idx].payload to the proto bytes the standalone Encode
// would emit for the same merged JSON tree.
func TestCommitFuzzGRPCJSONMutations_RoundTrip(t *testing.T) {
	t.Parallel()
	src := `{"0001:0000:String":"original","0002:0001:Varint":1}`
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				bodyEncoding: "proto-schemaless-json",
				jsonPayload:  src,
			},
		},
	}
	muts := map[int]map[string]json.RawMessage{
		0: {
			"0001:0000:String": json.RawMessage(`"mutated"`),
			"0002:0001:Varint": json.RawMessage(`42`),
		},
	}
	if err := commitFuzzGRPCJSONMutations(plan, muts); err != nil {
		t.Fatalf("commit: %v", err)
	}
	want, err := protobuf.Encode(`{"0001:0000:String":"mutated","0002:0001:Varint":42}`)
	if err != nil {
		t.Fatalf("standalone Encode: %v", err)
	}
	if got := plan.messages[0].payload; string(got) != string(want) {
		t.Errorf("payload diverges from standalone Encode\n got: %x\nwant: %x", got, want)
	}
}

// TestCommitFuzzGRPCJSONMutations_NoopOnEmpty asserts the commit pass
// is a no-op when no positions targeted any message — important so
// non-JSON-path runs don't accidentally re-encode messages that may
// have been base64-decoded into binary bytes the proto-schemaless
// parser would heuristic-type into something else.
func TestCommitFuzzGRPCJSONMutations_NoopOnEmpty(t *testing.T) {
	t.Parallel()
	originalBytes := []byte{0x12, 0x03, 'h', 'i'}
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				payload:      append([]byte(nil), originalBytes...),
				bodyEncoding: "base64",
				// jsonPayload intentionally empty
			},
		},
	}
	if err := commitFuzzGRPCJSONMutations(plan, nil); err != nil {
		t.Fatalf("nil mutations: %v", err)
	}
	if string(plan.messages[0].payload) != string(originalBytes) {
		t.Errorf("payload mutated despite empty mutations: got %x, want %x", plan.messages[0].payload, originalBytes)
	}
}

// TestApplyFuzzGRPCPosition_JSONPathQueuesMutation pins that the
// JSON-path branch in applyFuzzGRPCPosition does NOT mutate
// plan.messages[idx].payload directly — it stages the mutation on the
// jsonMuts map for the commit pass to fold in.
func TestApplyFuzzGRPCPosition_JSONPathQueuesMutation(t *testing.T) {
	t.Parallel()
	originalBytes := []byte{0x0a, 0x05, 'a', 'l', 'i', 'c', 'e'}
	plan := &resendGRPCPlan{
		messages: []resendGRPCDataPlan{
			{
				payload:      append([]byte(nil), originalBytes...),
				bodyEncoding: "proto-schemaless-json",
				jsonPayload:  `{"0001:0000:String":"alice"}`,
			},
		},
	}
	jsonMuts := map[int]map[string]json.RawMessage{}
	if err := applyFuzzGRPCPosition(plan, "messages[0].payload.0001:0000:String", "bob", jsonMuts); err != nil {
		t.Fatalf("apply: %v", err)
	}
	// Bytes payload is unchanged at this point — commit pass owns the
	// rewrite.
	if string(plan.messages[0].payload) != string(originalBytes) {
		t.Errorf("apply mutated payload prematurely: got %x, want %x", plan.messages[0].payload, originalBytes)
	}
	got, ok := jsonMuts[0]["0001:0000:String"]
	if !ok {
		t.Fatal("apply did not stage the JSON mutation")
	}
	if string(got) != `"bob"` {
		t.Errorf("queued value = %s, want %q", got, `"bob"`)
	}
}
