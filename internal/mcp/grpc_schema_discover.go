// Package mcp grpc_schema_discover.go implements the discover action of
// the grpc_schema MCP tool (USK-928).
//
// discover probes a target server's gRPC reflection endpoint
// (`grpc.reflection.v1.ServerReflection/ServerReflectionInfo` with a
// v1alpha fallback), enumerates every exposed service, fetches each
// service's FileContainingSymbol descriptor, deduplicates the file
// descriptors by filename, and registers the assembled FileDescriptorSet
// via the existing protoschema Registry + SchemaStore tail.
//
// Sibling pattern — the persistence path matches register's tail bit
// for bit: SaveGRPCSchema per service first, then a single
// Registry.Register call. Source label is `reflection://<target_addr>`
// so `list` distinguishes reflection-sourced entries from
// descriptor_set / file ones.
//
// Defense layers (matching resend_grpc — Resolved #17, #19):
//   - CRLF guards on target_addr / scheme / metadata
//   - Target Scope on the canonical URL AND target address
//   - Rate limit on the host (without port)
//   - Budget gate via a synthetic GRPCStartMessage envelope passed
//     through pipeline.NewBudgetStep
//
// Reflection chatter is NOT persisted as a Flow — schema management is
// control-plane and the registered service's source_label already records
// "we discovered from here" (Resolved #28 / U1).
package mcp

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/encoding/protoschema"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// grpcSchemaDiscoverResult is the structured output of action=discover.
//
// Discovered carries the same shape as register's Registered[] and
// list's Schemas[]. ReflectionVersion records which reflection service
// variant (v1 or v1alpha) the upstream answered on — informational, to
// help operators identify partly-upgraded reflection servers.
type grpcSchemaDiscoverResult struct {
	Discovered        []grpcSchemaServiceEntry `json:"discovered"`
	Target            string                   `json:"target"`
	ReflectionVersion string                   `json:"reflection_version,omitempty"`
}

// maxDiscoverTimeoutMs is the cap applied to user-supplied timeout_ms
// values. Mirrors protoschema.MaxDiscoverTimeout in milliseconds.
const maxDiscoverTimeoutMs = 300000

// handleGRPCSchemaDiscover is the action=discover handler. It performs
// every check on the resend_grpc dial path (CRLF / scope / rate / budget)
// before invoking protoschema.Discover, then runs the discovered
// descriptor set through the same Registry.Register + SchemaStore tail
// as register.
func (s *Server) handleGRPCSchemaDiscover(ctx context.Context, params grpcSchemaToolParams) (*grpcSchemaDiscoverResult, error) {
	if s.flowStore.store == nil {
		return nil, errors.New("flow store is not initialized")
	}
	if err := validateGRPCSchemaDiscoverInput(params); err != nil {
		return nil, err
	}

	scheme, canonicalURL := buildGRPCSchemaDiscoverCanonical(params)
	if err := s.checkGRPCSchemaDiscoverGates(ctx, scheme, canonicalURL, params); err != nil {
		return nil, err
	}

	timeout := resolveGRPCSchemaDiscoverTimeout(params)
	rtCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	if err := s.applyGRPCSchemaDiscoverRateAndBudget(rtCtx, canonicalURL, params); err != nil {
		return nil, err
	}

	discoverRes, err := protoschema.Discover(rtCtx, protoschema.DiscoverOptions{
		TargetAddr:    params.TargetAddr,
		Scheme:        scheme,
		Transport:     s.connector.tlsTransport,
		Metadata:      headerKVsToKeyValues(params.Metadata),
		ServiceFilter: params.ServiceFilter,
		Timeout:       timeout,
	})
	if err != nil {
		return nil, fmt.Errorf("grpc_schema discover: %w", err)
	}

	sourceLabel := "reflection://" + params.TargetAddr
	if err := s.persistDiscoveredServices(rtCtx, discoverRes, sourceLabel); err != nil {
		return nil, err
	}

	out := &grpcSchemaDiscoverResult{
		Target:            params.TargetAddr,
		ReflectionVersion: discoverRes.ReflectionVersion,
		Discovered:        make([]grpcSchemaServiceEntry, 0, len(discoverRes.Services)),
	}
	for _, spec := range discoverRes.Services {
		out.Discovered = append(out.Discovered, serviceSpecToEntry(spec))
	}

	slog.InfoContext(ctx, "grpc_schema discover complete",
		"target", params.TargetAddr,
		"reflection_version", discoverRes.ReflectionVersion,
		"services_discovered", len(discoverRes.Services),
		"descriptor_set_bytes", len(discoverRes.AssembledRawDescriptorSet),
	)
	return out, nil
}

// buildGRPCSchemaDiscoverCanonical returns the resolved scheme + the
// canonical reflection URL used for scope and rate-limit checks.
func buildGRPCSchemaDiscoverCanonical(params grpcSchemaToolParams) (string, *url.URL) {
	scheme := strings.ToLower(strings.TrimSpace(params.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	canonicalURL := &url.URL{
		Scheme: scheme,
		Host:   params.TargetAddr,
		Path:   "/" + protoschema.ReflectionV1Service + "/" + protoschema.ReflectionMethod,
	}
	return scheme, canonicalURL
}

// checkGRPCSchemaDiscoverGates runs Target Scope on both the canonical
// URL and the target address. Mirrors checkResendGRPCScope.
func (s *Server) checkGRPCSchemaDiscoverGates(_ context.Context, scheme string, canonicalURL *url.URL, params grpcSchemaToolParams) error {
	if err := s.checkTargetScopeURL(canonicalURL); err != nil {
		return fmt.Errorf("grpc_schema discover: %w", err)
	}
	if err := s.checkTargetScopeAddr(scheme, params.TargetAddr); err != nil {
		return fmt.Errorf("grpc_schema discover: %w", err)
	}
	return nil
}

// resolveGRPCSchemaDiscoverTimeout maps the user-supplied timeout_ms
// (or its absence) to a clamped time.Duration.
func resolveGRPCSchemaDiscoverTimeout(params grpcSchemaToolParams) time.Duration {
	if params.TimeoutMs == nil || *params.TimeoutMs <= 0 {
		return protoschema.DefaultDiscoverTimeout
	}
	ms := *params.TimeoutMs
	if ms > maxDiscoverTimeoutMs {
		ms = maxDiscoverTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// applyGRPCSchemaDiscoverRateAndBudget runs the rate limiter then the
// budget gate, returning the appropriate error if either trips.
func (s *Server) applyGRPCSchemaDiscoverRateAndBudget(ctx context.Context, canonicalURL *url.URL, params grpcSchemaToolParams) error {
	rateLimitHost, _, splitErr := net.SplitHostPort(params.TargetAddr)
	if splitErr != nil {
		rateLimitHost = params.TargetAddr
	}
	if err := s.waitRateLimit(ctx, rateLimitHost); err != nil {
		return fmt.Errorf("grpc_schema discover: %w", err)
	}
	return s.applyGRPCSchemaDiscoverBudget(ctx, canonicalURL, params)
}

// persistDiscoveredServices writes each discovered ServiceSpec via
// SaveGRPCSchema (all-or-nothing — Resolved #24) and finally calls
// Registry.Register once.
func (s *Server) persistDiscoveredServices(ctx context.Context, discoverRes *protoschema.DiscoverResult, sourceLabel string) error {
	for _, spec := range discoverRes.Services {
		if perr := s.flowStore.store.SaveGRPCSchema(ctx, spec.Service, discoverRes.AssembledRawDescriptorSet, sourceLabel); perr != nil {
			return fmt.Errorf("grpc_schema discover: save schema for service %q: %w", spec.Service, perr)
		}
		spec.SourceLabel = sourceLabel
	}
	s.grpcSchemaRegistry().Register(discoverRes.Services)
	return nil
}

// validateGRPCSchemaDiscoverInput enforces the discover-specific
// preconditions: target_addr required, scheme is http/https when set,
// no CRLF in target_addr/scheme/metadata. Cross-action params that
// would silently be ignored under action=discover (descriptor_set_b64,
// proto_paths, import_paths, service) are also rejected so the AI
// agent doesn't accidentally combine modes.
func validateGRPCSchemaDiscoverInput(params grpcSchemaToolParams) error {
	if strings.TrimSpace(params.TargetAddr) == "" {
		return errors.New("target_addr is required for action=discover")
	}
	if err := validateGRPCSchemaNoCRLF("target_addr", params.TargetAddr); err != nil {
		return err
	}
	if err := validateGRPCSchemaNoCRLF("scheme", params.Scheme); err != nil {
		return err
	}
	scheme := strings.ToLower(strings.TrimSpace(params.Scheme))
	switch scheme {
	case "", "http", "https":
	default:
		return fmt.Errorf("unsupported scheme %q: only http and https are allowed", params.Scheme)
	}
	if err := validateHeaderKVList(params.Metadata, "metadata"); err != nil {
		return err
	}
	if params.TimeoutMs != nil {
		if *params.TimeoutMs <= 0 {
			return fmt.Errorf("timeout_ms must be positive (got %d)", *params.TimeoutMs)
		}
	}
	if params.DescriptorSetB64 != "" {
		return errors.New("descriptor_set_b64 is only valid with action=register source=\"descriptor_set\"")
	}
	if len(params.ProtoPaths) > 0 {
		return errors.New("proto_paths is only valid with action=register source=\"file\"")
	}
	if len(params.ImportPaths) > 0 {
		return errors.New("import_paths is only valid with action=register source=\"file\"")
	}
	if params.Service != "" {
		return errors.New("service is only valid with action=unregister")
	}
	if params.Source != "" {
		return fmt.Errorf("source %q is only valid with action=register (use action=discover to fetch from reflection)", params.Source)
	}
	return nil
}

// validateGRPCSchemaNoCRLF rejects CR/LF in user-supplied URL components
// per the same hygiene applied by validateResendGRPCNoCRLF.
func validateGRPCSchemaNoCRLF(field, v string) error {
	if strings.ContainsAny(v, "\r\n") {
		return fmt.Errorf("%s contains CR/LF characters", field)
	}
	return nil
}

// applyGRPCSchemaDiscoverBudget runs a synthetic Send-side
// GRPCStartMessage envelope through pipeline.NewBudgetStep so the
// discover call participates in the agent-wide budget accounting on
// par with the resend / fuzz path. On Drop we synthesise an audit
// Stream + return errBudgetExhausted (the canonical shape every
// resend handler emits).
func (s *Server) applyGRPCSchemaDiscoverBudget(ctx context.Context, canonicalURL *url.URL, params grpcSchemaToolParams) error {
	if s.misc.budgetManager == nil {
		return nil
	}
	streamID := uuid.NewString()
	connID := uuid.NewString()
	startEnv := &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service:     protoschema.ReflectionV1Service,
			Method:      protoschema.ReflectionMethod,
			Authority:   params.TargetAddr,
			Scheme:      canonicalURL.Scheme,
			Path:        canonicalURL.Path,
			Metadata:    headerKVsToKeyValues(params.Metadata),
			ContentType: "application/grpc+proto",
		},
		Context: envelope.EnvelopeContext{ConnID: connID},
	}
	step := pipeline.NewBudgetStep(s.misc.budgetManager)
	pipe := pipeline.New(step)
	post, action, _, blockedBy := pipe.RunWithBlockedBy(ctx, startEnv)
	if action == pipeline.Drop {
		if blockedBy == pipeline.BlockedByBudget {
			recordBudgetBlockedStream(ctx, s.flowStore.store, post, streamID, flow.OriginResend)
			return errBudgetExhausted
		}
		return errors.New("grpc_schema discover: synthetic envelope dropped by pipeline")
	}
	return nil
}
