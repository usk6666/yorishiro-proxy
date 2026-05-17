// Package mcp grpc_schema_tool.go implements the schema-aware gRPC .proto
// schema management tool (USK-923).
//
// The tool is a single MCP entry with an `action` discriminator
// (register / list / unregister / clear), mirroring the macro / manage /
// intercept multi-action pattern. Persistent storage lives in the
// grpc_schemas SQLite table via flow.SchemaStore; the in-memory
// protoschema.Registry on Server.grpcSchemas is rehydrated from the
// table at first use so registrations survive process restart.
//
// register accepts source="descriptor_set" only — a precompiled
// FileDescriptorSet binary (base64-encoded). source="file" / proto_paths
// is rejected at the schema boundary with a pointer to protoc
// --include_imports (D1 deferred to a follow-up Issue).
package mcp

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// grpcSchemaToolInput is the typed input for the grpc_schema tool.
type grpcSchemaToolInput struct {
	// Action is the schema action to perform.
	// Available actions: register, list, unregister, clear.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params grpcSchemaToolParams `json:"params,omitempty"`
}

// grpcSchemaToolParams is the union of all grpc_schema action parameters.
// Only the fields relevant to the specified action are read.
type grpcSchemaToolParams struct {
	// Source is the descriptor input shape. USK-923 accepts
	// "descriptor_set" only; "file" is rejected with a pointer to
	// protoc --include_imports.
	Source string `json:"source,omitempty" jsonschema:"input shape; only 'descriptor_set' is currently supported"`
	// DescriptorSetB64 is the base64-encoded FileDescriptorSet payload.
	// Required when action=register and source=descriptor_set. Capped at
	// 16 MiB after base64 decode.
	DescriptorSetB64 string `json:"descriptor_set_b64,omitempty" jsonschema:"base64-encoded FileDescriptorSet bytes (max 16 MiB decoded). Generate via protoc --include_imports --descriptor_set_out=<file> <protos>"`
	// ServiceFilter optionally restricts which services from the
	// FileDescriptorSet are registered. Empty means "register all
	// services found in the descriptor".
	ServiceFilter []string `json:"service_filter,omitempty" jsonschema:"optional fully-qualified service names to register; empty means register every service in the descriptor"`
	// SourceLabel is a free-form diagnostic label (filename hint,
	// version tag, etc.) preserved in the list output.
	SourceLabel string `json:"source_label,omitempty" jsonschema:"free-form label preserved in list output (e.g. filename or version tag)"`
	// Service is the fully-qualified service name. Required for
	// action=unregister.
	Service string `json:"service,omitempty" jsonschema:"fully-qualified service name (required for unregister)"`
	// ProtoPaths is rejected for USK-923; surfaced on the schema so AI
	// agents see a clear error message instead of a silently ignored
	// field. Reserved for a follow-up Issue (D1 deferred).
	ProtoPaths []string `json:"proto_paths,omitempty" jsonschema:"reserved for source='file' (deferred to a follow-up Issue); the field is rejected when populated"`
}

// availableGRPCSchemaActions enumerates valid action names for the
// grpc_schema tool's error message.
var availableGRPCSchemaActions = []string{"register", "list", "unregister", "clear"}

// registerGRPCSchema wires the grpc_schema MCP tool.
func (s *Server) registerGRPCSchema() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "grpc_schema",
		Description: "Manage .proto schemas for schema-aware gRPC decode (query) and encode (resend_grpc). " +
			"Actions: 'register' (upsert a service from a precompiled FileDescriptorSet base64 payload — " +
			"generate via `protoc --include_imports --descriptor_set_out=<file> <protos>`, max 16 MiB decoded), " +
			"'list' (registered services + methods), 'unregister' (remove a service by name), 'clear' (remove all). " +
			"Once a schema is registered, query messages decodes matching gRPC Data bodies as protojson with real " +
			"field names (body_decoded_encoding=\"proto-json\") and resend_grpc accepts body_encoding=\"proto-json\". " +
			"Schemaless fallback always applies when no schema matches. See yorishiro://help/grpc_schema.",
	}, s.handleGRPCSchemaTool)
}

// handleGRPCSchemaTool routes the grpc_schema invocation to the matching
// action handler.
func (s *Server) handleGRPCSchemaTool(ctx context.Context, _ *gomcp.CallToolRequest, input grpcSchemaToolInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "grpc_schema",
		"action", input.Action,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "grpc_schema",
			"action", input.Action,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	switch input.Action {
	case "":
		return nil, nil, fmt.Errorf("action is required: available actions are %s", strings.Join(availableGRPCSchemaActions, ", "))
	case "register":
		res, err := s.handleGRPCSchemaRegister(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	case "list":
		res, err := s.handleGRPCSchemaList(ctx)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	case "unregister":
		res, err := s.handleGRPCSchemaUnregister(ctx, input.Params)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	case "clear":
		res, err := s.handleGRPCSchemaClear(ctx)
		if err != nil {
			return nil, nil, err
		}
		return nil, res, nil
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %s", input.Action, strings.Join(availableGRPCSchemaActions, ", "))
	}
}

// grpcSchemaRegisterResult is the structured output of the register action.
type grpcSchemaRegisterResult struct {
	Registered []grpcSchemaServiceEntry `json:"registered"`
}

// grpcSchemaListResult is the structured output of the list action.
type grpcSchemaListResult struct {
	Schemas []grpcSchemaServiceEntry `json:"schemas"`
}

// grpcSchemaUnregisterResult is the structured output of the unregister action.
type grpcSchemaUnregisterResult struct {
	Service      string `json:"service"`
	Unregistered bool   `json:"unregistered"`
}

// grpcSchemaClearResult is the structured output of the clear action.
type grpcSchemaClearResult struct {
	Cleared int64 `json:"cleared"`
}

// grpcSchemaServiceEntry is one service in the register / list output.
type grpcSchemaServiceEntry struct {
	Service      string                  `json:"service"`
	Methods      []grpcSchemaMethodEntry `json:"methods"`
	SourceLabel  string                  `json:"source_label,omitempty"`
	RegisteredAt string                  `json:"registered_at,omitempty"`
}

// grpcSchemaMethodEntry is one method in a service entry.
type grpcSchemaMethodEntry struct {
	Name   string `json:"name"`
	Input  string `json:"input"`
	Output string `json:"output"`
}

// handleGRPCSchemaRegister parses the descriptor_set_b64 payload, filters
// by service_filter, persists the result via SchemaStore, and updates the
// in-memory Registry.
func (s *Server) handleGRPCSchemaRegister(ctx context.Context, params grpcSchemaToolParams) (*grpcSchemaRegisterResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	if err := validateGRPCSchemaRegisterInput(params); err != nil {
		return nil, err
	}

	// Pre-decode size cap on the base64 input itself (USK-923 review S-1,
	// CWE-770). Base64 encodes 3 bytes into 4 chars; cap the encoded
	// length at the equivalent of MaxDescriptorSetBytes + a small slack
	// (padding, newlines) so a pathological input cannot allocate
	// gigabytes during DecodeString before the post-decode cap fires.
	maxEncodedLen := protoschema.MaxDescriptorSetBytes*4/3 + 64
	if len(params.DescriptorSetB64) > maxEncodedLen {
		return nil, fmt.Errorf("descriptor_set_b64 length %d exceeds maximum encoded size %d (decoded cap is %d bytes)", len(params.DescriptorSetB64), maxEncodedLen, protoschema.MaxDescriptorSetBytes)
	}

	raw, err := base64.StdEncoding.DecodeString(params.DescriptorSetB64)
	if err != nil {
		return nil, fmt.Errorf("decode descriptor_set_b64: %w", err)
	}
	if len(raw) > protoschema.MaxDescriptorSetBytes {
		return nil, fmt.Errorf("descriptor_set size %d exceeds maximum %d bytes after base64 decode", len(raw), protoschema.MaxDescriptorSetBytes)
	}

	specs, err := protoschema.LoadFileDescriptorSet(raw, params.ServiceFilter)
	if err != nil {
		return nil, err
	}

	// Persist before updating the in-memory registry: if the SQLite write
	// fails partway through, the registry stays consistent with disk.
	for _, spec := range specs {
		if perr := s.flowStore.store.SaveGRPCSchema(ctx, spec.Service, raw, params.SourceLabel); perr != nil {
			return nil, fmt.Errorf("save schema for service %q: %w", spec.Service, perr)
		}
		if params.SourceLabel != "" {
			spec.SourceLabel = params.SourceLabel
		}
	}

	s.grpcSchemaRegistry().Register(specs)

	result := &grpcSchemaRegisterResult{
		Registered: make([]grpcSchemaServiceEntry, 0, len(specs)),
	}
	for _, spec := range specs {
		result.Registered = append(result.Registered, serviceSpecToEntry(spec))
	}
	return result, nil
}

// validateGRPCSchemaRegisterInput enforces the source allowlist and the
// presence of descriptor_set_b64. The "file" source / proto_paths fields
// are rejected with a clear pointer to protoc --include_imports.
func validateGRPCSchemaRegisterInput(params grpcSchemaToolParams) error {
	if len(params.ProtoPaths) > 0 {
		return fmt.Errorf("proto_paths is reserved for a deferred follow-up Issue; run `protoc --include_imports --descriptor_set_out=<file> <protos>` and pass the base64-encoded result as descriptor_set_b64 (see help_grpc_schema for details)")
	}
	if params.Source != "" && params.Source != "descriptor_set" {
		if params.Source == "file" {
			return fmt.Errorf("source=\"file\" is not yet supported; run `protoc --include_imports --descriptor_set_out=<file> <protos>` and pass the base64-encoded result as descriptor_set_b64 (see help_grpc_schema for details)")
		}
		return fmt.Errorf("source %q is not supported; use source=\"descriptor_set\"", params.Source)
	}
	if params.DescriptorSetB64 == "" {
		return fmt.Errorf("descriptor_set_b64 is required for action=register (generate via `protoc --include_imports --descriptor_set_out=<file> <protos>` and base64-encode the result)")
	}
	return nil
}

// handleGRPCSchemaList returns every registered service ordered by service
// name. Reads from the in-memory Registry — kept in sync with the
// SchemaStore via lazy rehydrate on first use.
func (s *Server) handleGRPCSchemaList(ctx context.Context) (*grpcSchemaListResult, error) {
	if err := s.ensureGRPCSchemaRehydrated(ctx); err != nil {
		return nil, err
	}
	specs := s.grpcSchemaRegistry().ListServices()
	out := &grpcSchemaListResult{
		Schemas: make([]grpcSchemaServiceEntry, 0, len(specs)),
	}
	for _, spec := range specs {
		out.Schemas = append(out.Schemas, serviceSpecToEntry(spec))
	}
	return out, nil
}

// handleGRPCSchemaUnregister removes a service from both the Registry and
// the SchemaStore.
func (s *Server) handleGRPCSchemaUnregister(ctx context.Context, params grpcSchemaToolParams) (*grpcSchemaUnregisterResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	if params.Service == "" {
		return nil, fmt.Errorf("service is required for action=unregister")
	}
	if err := s.ensureGRPCSchemaRehydrated(ctx); err != nil {
		return nil, err
	}

	// SchemaStore.DeleteGRPCSchema returns an error when not found —
	// translate to unregistered=false rather than propagating.
	dbErr := s.flowStore.store.DeleteGRPCSchema(ctx, params.Service)
	regOK := s.grpcSchemaRegistry().Unregister(params.Service)

	if dbErr != nil {
		// Treat "not found" as a non-error so the result accurately
		// reports the absence rather than the operation failing.
		if !strings.Contains(dbErr.Error(), "not found") {
			return nil, fmt.Errorf("delete schema for service %q: %w", params.Service, dbErr)
		}
	}
	return &grpcSchemaUnregisterResult{
		Service:      params.Service,
		Unregistered: regOK || dbErr == nil,
	}, nil
}

// handleGRPCSchemaClear empties both the Registry and the SchemaStore.
func (s *Server) handleGRPCSchemaClear(ctx context.Context) (*grpcSchemaClearResult, error) {
	if s.flowStore.store == nil {
		return nil, fmt.Errorf("flow store is not initialized")
	}
	deleted, err := s.flowStore.store.ClearGRPCSchemas(ctx)
	if err != nil {
		return nil, fmt.Errorf("clear schemas: %w", err)
	}
	s.grpcSchemaRegistry().Clear()
	return &grpcSchemaClearResult{Cleared: deleted}, nil
}

// ensureGRPCSchemaRehydrated lazily loads every entry from SchemaStore
// into the in-memory Registry on first use. Subsequent calls re-load on
// every invocation so a list / unregister after an external DB write (or
// a different Server instance in tests) sees fresh state. Cost is one
// SELECT * scan; acceptable for the schema list size (handful of entries
// for the typical operator).
func (s *Server) ensureGRPCSchemaRehydrated(ctx context.Context) error {
	if s.flowStore.store == nil {
		return nil
	}
	records, err := s.flowStore.store.ListGRPCSchemas(ctx)
	if err != nil {
		return fmt.Errorf("list schemas: %w", err)
	}
	if len(records) == 0 {
		// No entries in DB; nothing to rehydrate. We intentionally do
		// NOT clear the in-memory Registry here — that would race with
		// concurrent test setup that registers schemas via the Registry
		// directly. The Registry stays the canonical view; rehydrate
		// only ADDS entries observed in DB.
		return nil
	}
	// Load each record independently. handleGRPCSchemaRegister persists
	// the SAME descriptor_set bytes once per service inside the set, so
	// the earlier byte-keyed cache (one-payload→one-service) lost every
	// sibling service after restart. Each rec carries its own service
	// filter; the per-record cost is one protodesc.NewFiles call on
	// rehydrate (operator-side, infrequent).
	all := make([]*protoschema.ServiceSpec, 0, len(records))
	var groupErr error
	for _, rec := range records {
		specs, perr := protoschema.LoadFileDescriptorSet(rec.DescriptorSet, []string{rec.Service})
		if perr != nil {
			// One malformed entry must not poison the rest — surface
			// the first error to the caller but continue gathering
			// the rest of the table.
			if groupErr == nil {
				groupErr = fmt.Errorf("rehydrate schema for service %q: %w", rec.Service, perr)
			}
			continue
		}
		applyRehydrateLabel(specs, rec)
		all = append(all, specs...)
	}
	if len(all) > 0 {
		s.grpcSchemaRegistry().Register(all)
	}
	return groupErr
}

// applyRehydrateLabel copies SourceLabel + RegisteredAt from the record
// onto the matching ServiceSpec in specs (in place). The Registry was
// built with a fresh RegisteredAt timestamp inside LoadFileDescriptorSet;
// we overwrite it with the original DB value so list output reflects the
// wall-clock at the first register call rather than the rehydrate call.
func applyRehydrateLabel(specs []*protoschema.ServiceSpec, rec *flow.GRPCSchemaRecord) {
	for _, sp := range specs {
		if sp.Service == rec.Service {
			sp.SourceLabel = rec.SourceLabel
			if !rec.RegisteredAt.IsZero() {
				sp.RegisteredAt = rec.RegisteredAt
			}
		}
	}
}

// serviceSpecToEntry projects a protoschema.ServiceSpec onto the MCP
// result entry shape.
func serviceSpecToEntry(spec *protoschema.ServiceSpec) grpcSchemaServiceEntry {
	entry := grpcSchemaServiceEntry{
		Service:     spec.Service,
		SourceLabel: spec.SourceLabel,
	}
	if !spec.RegisteredAt.IsZero() {
		entry.RegisteredAt = spec.RegisteredAt.UTC().Format(time.RFC3339Nano)
	}
	entry.Methods = make([]grpcSchemaMethodEntry, 0, len(spec.Methods))
	for _, m := range spec.Methods {
		entry.Methods = append(entry.Methods, grpcSchemaMethodEntry{
			Name:   m.Name,
			Input:  m.Input,
			Output: m.Output,
		})
	}
	return entry
}
