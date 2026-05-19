// Package config grpc_schema.go declares the GRPCSchemaConfig nested
// substruct (USK-926). The struct is mounted under ProxyConfig.GRPCSchema
// and configures runtime knobs for the `grpc_schema` MCP tool's
// host-protoc invocation path (source="file"). See
// internal/encoding/protoschema/protoc_runner.go for the consumer.
//
// The "no bundled protoc" stance (USK-923 user preference) means this
// substruct is OPTIONAL — a config that omits "grpc_schema" entirely
// keeps the default protoc binary lookup ("protoc" on PATH) and is
// indistinguishable from one with an empty struct.
package config

import (
	"fmt"
	"os"
	"strings"
)

// GRPCSchemaConfig holds runtime knobs for the grpc_schema MCP tool.
//
// Currently a single field — ProtocBinary — but kept as a substruct so
// future register-tool knobs (e.g. additional source modes, cache
// settings) can land here without restructuring ProxyConfig. Mirrors
// the WebSocket / GRPC / SSE / SafetyFilter substruct convention.
type GRPCSchemaConfig struct {
	// ProtocBinary is the path to (or bare name of) the protoc binary
	// invoked when grpc_schema register is called with source="file".
	// Empty (or omitted) selects the default "protoc" and relies on the
	// host PATH. Validation rejects an all-whitespace value but does
	// NOT call exec.LookPath at config load — the binary may be
	// installed by a later step, and config validation must be
	// hermetic (USK-926 Resolved #27).
	ProtocBinary string `json:"protoc_binary,omitempty"`
}

// DefaultProtocBinary is the bare-name fallback when neither the env
// var nor the config supplies a protoc path. exec.LookPath resolves
// this against $PATH at invocation time.
const DefaultProtocBinary = "protoc"

// ProtocBinaryEnvVar is the environment variable name consulted by
// ResolveProtocBinary. Project house style is YP_* uppercase (see
// internal/mcpserver/server.go EnvVarMap); the Issue text's
// "yorishiro_proxy_protoc" lowercase form is intentionally rejected.
const ProtocBinaryEnvVar = "YP_PROTOC_BINARY"

// Validate enforces the syntactic invariants on GRPCSchemaConfig. An
// empty ProtocBinary (the "use default" case) is accepted; a value
// that trims to empty is rejected because that indicates a config
// authoring error (the user supplied something but it is meaningless).
//
// exec.LookPath is intentionally NOT called here — the binary may be
// installed by a later step and config validation must be hermetic
// (Resolved #27).
func (c *GRPCSchemaConfig) Validate() error {
	if c == nil {
		return nil
	}
	if c.ProtocBinary != "" && strings.TrimSpace(c.ProtocBinary) == "" {
		return fmt.Errorf("grpc_schema.protoc_binary must not be whitespace-only")
	}
	return nil
}

// ResolveProtocBinary returns the protoc binary name (or path) to
// invoke. Precedence (Resolved #6):
//
//  1. YP_PROTOC_BINARY environment variable (when set and non-empty)
//  2. ProxyConfig.GRPCSchema.ProtocBinary (when set and non-empty)
//  3. DefaultProtocBinary ("protoc")
//
// os.LookupEnv is consulted at invocation time (not init time) so a
// parent setup step that mutates PATH or the env var affects the
// resolution as expected.
//
// There is intentionally NO per-MCP-call override. Allowing the
// grpc_schema MCP tool to specify an arbitrary host binary would let
// any MCP caller pivot the protoc subprocess into an arbitrary code-
// execution gadget — a clear control-plane regression. Operators who
// need a different binary set it in the config file or in the env
// var; both of those surfaces are server-side authoritative.
func ResolveProtocBinary(c *ProxyConfig) string {
	if v, ok := os.LookupEnv(ProtocBinaryEnvVar); ok {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	if c != nil && c.GRPCSchema != nil {
		if v := strings.TrimSpace(c.GRPCSchema.ProtocBinary); v != "" {
			return v
		}
	}
	return DefaultProtocBinary
}
