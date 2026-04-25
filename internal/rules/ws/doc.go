// Package ws provides WebSocket-specific rule engines for intercept,
// transform, and safety filtering. Each engine operates on
// envelope.WSMessage and follows RFC-001 sections 3.5.2 and 3.6.
//
// # Engines
//
// InterceptEngine matches WebSocket frames against configurable rules and
// returns matched rule IDs for the HoldQueue. WS has no Send/Receive
// asymmetry like HTTP request/response, so a single Match(env, msg) method
// covers both directions and the rule's Direction field gates evaluation.
//
// TransformEngine applies WS-specific actions (ReplacePayload, SetOpcode,
// SetFin, SetClose) in priority order. Rules are sorted ascending by
// Priority — lower values applied first.
//
// SafetyEngine evaluates rules against WS-local Targets ("payload" and
// "opcode") and returns the first violation (or all violations via
// CheckInputAll).
//
// # MITM principles
//
//   - Mask / Masked: NEVER touched by the rule API surface. There is no
//     field on TransformRule and no action that exposes the masking key.
//     WSLayer regenerates Mask on Send (USK-642).
//   - Compressed flag: rules see the decompressed Payload; the engine
//     NEVER flips the Compressed bit. WSLayer.Send (USK-642) re-compresses
//     when Compressed is true.
//   - ReplacePayload operates on decompressed bytes and does not touch
//     Compressed. After payload modification, per-message-deflate
//     context-takeover desync is an accepted MITM consequence (attacker
//     knob, not an engine-side mitigation).
//   - ReplacePayload on a control frame (Close/Ping/Pong) operates on the
//     Payload bytes verbatim — for Close frames this stomps the encoded
//     CloseCode/CloseReason. Use SetClose for structured Close edits;
//     ReplacePayload is the raw-edit path.
//   - SetOpcode / SetFin / SetClose perform NO semantic validation.
//     Arbitrary bytes / bools are allowed. Wire-level desync (e.g.
//     marking a continuation frame as Fin without a preceding fragmented
//     start) is an accepted attacker knob.
//   - Continuation frames match literally on Opcode=WSContinuation. The
//     engine does NOT track per-stream first-fragment type; an
//     OpcodeFilter of [WSText] does NOT match a WSContinuation frame even
//     if the original stream began with a Text frame. Operators must list
//     WSContinuation explicitly when they need to inspect continuations.
//   - TargetPayload size: bounded by WSLayer's maxFramePayloadSize
//     (16 MiB). The engine does not enforce its own cap.
//
// # Match field sources
//
//   - HostPattern matches EnvelopeContext.TargetHost (port-stripped).
//   - PathPattern matches EnvelopeContext.UpgradePath, populated by
//     WSLayer when it consumes the HTTP/1.1 Upgrade or HTTP/2 CONNECT-
//     :protocol handshake (USK-642). Empty for unrelated envelopes.
//   - OpcodeFilter matches WSMessage.Opcode literally (no continuation
//     resolution). Empty filter matches all opcodes.
//   - PayloadPattern matches WSMessage.Payload (decompressed bytes).
//
// # OpcodeFilter pre-bail
//
// matchesRule enforces evaluation order:
// Direction → Enabled → Opcode → Host → Path → Payload.
// The Opcode check MUST short-circuit BEFORE any *regexp.Regexp.MatchString
// call so that a Text-only rule with a heavy payload regex does not pay
// regex cost on every Binary frame. This is the explicit precedence
// approved in the USK-647 design review.
//
// # Targets
//
// SafetyEngine evaluates each compiled rule's Targets list. WS-local
// targets are declared in safety.go as common.Target-typed constants:
//
//   - TargetPayload — full decompressed payload bytes
//   - TargetOpcode  — numeric opcode rendered as "0xN" (e.g. "0x1" for Text)
//
// HTTP presets are NOT auto-loaded into the WS SafetyEngine. Operators
// who want payload regex rules should add them with explicit
// Targets: []common.Target{TargetPayload}.
package ws
