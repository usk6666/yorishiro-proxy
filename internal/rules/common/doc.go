// Package common provides shared primitives for protocol-specific rule engines.
//
// This includes:
//   - HoldQueue: a blocking queue for held envelopes awaiting external action
//   - CompilePattern/CompileHeaderMatch: rule compilation utilities with safety limits
//   - Preset patterns: destructive SQL, OS command, PII detection patterns
//
// Protocol-specific engines (rules/http/, rules/ws/, etc.) consume these
// primitives and implement their own matching logic.
package common
