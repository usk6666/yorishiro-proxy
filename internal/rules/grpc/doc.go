// Package grpc provides gRPC-specific rule engines for intercept,
// transform, and safety filtering. Each engine operates on the gRPC
// envelope message types (GRPCStartMessage, GRPCDataMessage,
// GRPCEndMessage) and follows RFC-001 sections 3.2.3, 3.5.2, 3.6, and
// 9.2.
//
// The package mirrors the API shape of internal/rules/http but adapts
// to gRPC realities:
//
//   - InterceptEngine exposes MatchStart / MatchData / MatchEnd which
//     return matched rule IDs (the InterceptStep — USK-648, future —
//     wires those IDs into common.HoldQueue).
//   - TransformEngine exposes TransformStart / TransformData /
//     TransformEnd. Supported actions are AddMetadata, SetMetadata,
//     RemoveMetadata, ReplacePayload, SetStatus, SetStatusMessage.
//   - SafetyEngine.CheckInput type-switches on the gRPC message type
//     and evaluates against gRPC-local Targets (metadata, payload,
//     service, method) plus the existing common.TargetBody for preset
//     reuse (TargetBody maps to the gRPC payload).
//
// MITM principles enforced by this package:
//
//   - Wire fidelity: metadata casing and order are preserved
//     verbatim. Lookups by name are case-insensitive (mirrors HTTP/2
//     semantics) but mutations preserve the casing the rule supplies.
//     RemoveMetadata removes ALL case-insensitive matches.
//   - No CRLF in metadata: AddMetadata / SetMetadata reject names or
//     values containing CR or LF (CWE-113 defense in depth, even
//     though HPACK will typically reject these at the codec layer).
//   - WireLength is left verbatim after ReplacePayload. The action
//     mutates GRPCDataMessage.Payload and clears Envelope.Raw so the
//     downstream Layer re-encodes a fresh wire frame from the
//     post-mutation Payload. The original WireLength remains as the
//     last wire-observed value for diagnostic purposes.
//   - The engine does NOT call HoldQueue itself. It returns the
//     matched rule IDs only; InterceptStep owns the Hold/Release
//     contract.
//
// Direction filtering: InterceptRule and TransformRule each carry a
// package-local RuleDirection ("send" / "receive" / "both") translated
// from envelope.Direction at match time. Mirroring rules/http keeps
// config round-trip behavior consistent across protocols.
package grpc
