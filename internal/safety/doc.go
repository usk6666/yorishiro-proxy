// Package safety provides the SafetyFilter Engine that operates on the MCP
// control plane.
//
// # Role
//
// This package is the MCP-plane output filter (PII redaction, body / header
// masking) and input filter (block decisions made on already-recorded data
// at MCP-call time). It is consumed by tools under internal/mcp/ — for
// example query (response masking before returning recorded flows to the
// caller), security (configuration introspection), and resend / fuzz
// (input validation against rules at submit time).
//
// # Wire fidelity
//
// Per RFC-001 Principle 1 (Wire fidelity), Envelope.Raw and recorded body
// bytes in flow.Store MUST contain the exact wire-observed bytes. Output
// masking is applied only at the moment data is returned over the MCP
// transport — never before recording. Callers obtain the original wire
// bytes from flow.Store and run them through Engine.FilterOutput /
// FilterOutputHeaders right before serializing the MCP response.
//
// # Boundary with the live data path
//
// This package MUST NOT be imported from data-path packages
// (internal/connector, internal/layer, internal/pipeline, internal/pluginv2,
// internal/flow). Live-path block / drop decisions are the responsibility
// of the per-protocol engines under internal/rules/{http,ws,grpc}, which
// are wired into the pipeline via internal/pipeline/safety_step.go and are
// expressly forbidden from mutating Envelope.Raw or message bodies.
//
// As a Policy Layer, configuration is immutable at runtime — changes
// require a proxy restart so that AI agents cannot disable filters
// in-flight.
//
// # Relation to the live-wire Input Filter
//
// This package is the Output Filter half of SafetyFilter — it protects
// the AI agent from receiving sensitive bytes (LLM training-data leakage
// prevention, enterprise LLM Input Security Policy compliance). The
// Input Filter half lives in internal/rules/{http,ws,grpc}/safety.go and
// is orchestrated by internal/pipeline/safety_step.go — Send-direction
// only, blocks destructive payloads bound for the upstream server. The
// two engines share preset definitions (internal/rules/common/preset.go)
// but operate at different layers (MCP plane vs live wire) and serve
// different threat models. See RFC-001 §3.7 (docs/rfc/envelope.md) for
// the full role split and the design decisions behind it (USK-702 /
// USK-894).
package safety
