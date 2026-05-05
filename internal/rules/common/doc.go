// Package common provides shared primitives for protocol-specific rule engines.
//
// This includes:
//   - HoldQueue: a blocking queue for held envelopes awaiting external action
//   - CompilePattern/CompileHeaderMatch: rule compilation utilities with safety limits
//   - Preset patterns: destructive SQL, OS command, PII detection patterns
//
// Protocol-specific engines (rules/http/, rules/ws/, rules/grpc/, etc.)
// consume these primitives and implement their own matching logic. Those
// engines are part of the live data path and per RFC-001 Principle 1
// (Wire fidelity) MUST NOT mutate Envelope.Raw or message bodies — they
// only report Violations that drive block / drop decisions.
//
// Output masking (PII redaction at MCP response time) is intentionally NOT
// part of this package or the rules/* engines. It lives in internal/safety,
// which operates on the MCP control plane and runs against already-recorded
// wire bytes. Any future mask-style rule belongs there, not here.
package common
