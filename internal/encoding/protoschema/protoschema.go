// Package protoschema provides schema-aware protobuf wire format codec
// using protoreflect.DynamicMessage + protojson, plus a process-global
// Registry indexed by (service, method).
//
// This is the schema-aware counterpart to the schemaless codec in
// internal/encoding/protobuf. Use protoschema when the operator has
// registered a precompiled FileDescriptorSet for a service; otherwise
// fall back to the schemaless codec.
//
// MITM principle compliance:
//   - The schema-aware JSON is purely a derived view at the MCP transport
//     boundary; the wire bytes (Envelope.Raw, Flow.Body) are never mutated.
//   - protojson.Marshal drops unknown fields, so a decode→edit→encode
//     round-trip via Encode is LOSSY for any field not in the registered
//     schema. Callers must surface this caveat (help_grpc_schema.md +
//     a non-fatal warning on resend when the source flow had unknowns).
//   - Attacker-controlled descriptor bytes are bounded by
//     MaxDescriptorSetBytes (16 MiB) before any protoreflect call, and
//     every protoreflect entry point is wrapped in defer-recover so a
//     panic from malformed input surfaces as a returned error rather
//     than crashing the proxy.
package protoschema

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Decode parses raw proto wire bytes against the supplied message
// descriptor and returns a JSON string produced by protojson. The output
// uses the original .proto field names (UseProtoNames=true) and omits
// unpopulated fields.
//
// On wire-format parse failure (proto.Unmarshal error), Decode returns
// ("", err). Callers that want schemaless fallback inspect the error and
// re-run the schemaless codec on the same raw bytes.
//
// Unknown wire fields (not present in the schema) are preserved on the
// DynamicMessage and survive a proto.Marshal round-trip, but
// protojson.Marshal drops them — this is the documented lossy edge.
func Decode(raw []byte, desc protoreflect.MessageDescriptor) (string, error) {
	if desc == nil {
		return "", errors.New("protoschema decode: message descriptor is nil")
	}
	jsonStr, err := decodeSafe(raw, desc)
	if err != nil {
		return "", fmt.Errorf("protoschema decode: %w", err)
	}
	return jsonStr, nil
}

// decodeSafe runs the protoreflect entry points under a defer-recover so
// any panic from malformed input surfaces as a returned error (MITM
// principle 5). google.golang.org/protobuf is generally panic-safe but
// dynamicpb on adversarial descriptors has historically had a small
// surface of panics; the wrapper is defensive.
func decodeSafe(raw []byte, desc protoreflect.MessageDescriptor) (jsonStr string, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during decode: %v", r)
		}
	}()
	msg := dynamicpb.NewMessage(desc)
	if perr := proto.Unmarshal(raw, msg); perr != nil {
		return "", fmt.Errorf("unmarshal wire bytes: %w", perr)
	}
	jsonBytes, perr := (protojson.MarshalOptions{
		UseProtoNames:   true,
		EmitUnpopulated: false,
		Indent:          "  ",
	}).Marshal(msg)
	if perr != nil {
		return "", fmt.Errorf("marshal to JSON: %w", perr)
	}
	return string(jsonBytes), nil
}

// Encode converts a JSON string into proto wire bytes via
// DynamicMessage + protojson.UnmarshalOptions{DiscardUnknown: true}.
//
// DiscardUnknown=true means JSON keys not present in the schema are
// silently ignored — AI-typoed field names produce a message with the
// typo'd field absent rather than a hard error. Type mismatches
// (string for int32, etc.) still hard-error.
//
// The returned bytes are deterministic per the dynamicpb implementation
// detail (proto.Marshal does NOT guarantee deterministic output by
// default, but for callers that pin field order via JSON input this is
// good enough for round-trip correctness tests).
func Encode(jsonStr string, desc protoreflect.MessageDescriptor) ([]byte, error) {
	if desc == nil {
		return nil, errors.New("protoschema encode: message descriptor is nil")
	}
	out, err := encodeSafe(jsonStr, desc)
	if err != nil {
		return nil, fmt.Errorf("protoschema encode: %w", err)
	}
	return out, nil
}

// encodeSafe runs the protoreflect entry points under a defer-recover so
// any panic from malformed JSON or adversarial schema surfaces as a
// returned error (MITM principle 5).
func encodeSafe(jsonStr string, desc protoreflect.MessageDescriptor) (out []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic during encode: %v", r)
		}
	}()
	msg := dynamicpb.NewMessage(desc)
	if perr := (protojson.UnmarshalOptions{
		DiscardUnknown: true,
	}).Unmarshal([]byte(jsonStr), msg); perr != nil {
		return nil, fmt.Errorf("unmarshal JSON: %w", perr)
	}
	wire, perr := proto.Marshal(msg)
	if perr != nil {
		return nil, fmt.Errorf("marshal to wire bytes: %w", perr)
	}
	return wire, nil
}

// HasUnknownFields reports whether decoding raw against desc produces a
// DynamicMessage with non-empty UnknownFields(). Used by the resend
// path's lossy-round-trip warning — the source flow's bytes are inspected
// before encoding the user-supplied JSON so the warning is non-fatal but
// visible.
//
// Returns false on any parse error: a malformed wire is a separate
// failure mode handled by the resend path's hard-error branch.
func HasUnknownFields(raw []byte, desc protoreflect.MessageDescriptor) bool {
	if desc == nil {
		return false
	}
	has, _ := hasUnknownFieldsSafe(raw, desc)
	return has
}

func hasUnknownFieldsSafe(raw []byte, desc protoreflect.MessageDescriptor) (has bool, err error) {
	defer func() {
		if r := recover(); r != nil {
			has = false
			err = fmt.Errorf("panic during unknown-field probe: %v", r)
		}
	}()
	msg := dynamicpb.NewMessage(desc)
	if perr := proto.Unmarshal(raw, msg); perr != nil {
		return false, perr
	}
	return len(msg.GetUnknown()) > 0, nil
}
