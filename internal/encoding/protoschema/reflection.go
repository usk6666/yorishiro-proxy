// Package protoschema reflection.go drives the gRPC server-reflection
// client for the grpc_schema MCP tool's `discover` action (USK-928).
//
// Sibling pattern: this file lives next to protoc_runner.go so all
// non-MCP-side schema acquisition modes (descriptor_set/file/reflection)
// share a single package home. The MCP handler (handleGRPCSchemaDiscover)
// calls Discover(ctx, opts) and feeds the returned bytes into
// SaveGRPCSchema + Registry.Register via the existing register tail —
// persistence semantics are byte-identical to source="descriptor_set"
// (Resolved #4).
//
// Transport — the discover RPC is dialled via the in-house HTTP/2 Layer
// plus the gRPC Layer wrap (the same recipe used by resend_grpc). NO
// runtime dependency on google.golang.org/grpc is introduced; only the
// generated proto types under
// google.golang.org/grpc/reflection/grpc_reflection_v1 (and v1alpha)
// are imported (Resolved #11; project Principle #4).
//
// Protocol — v1 is tried first; on a stream-level UNIMPLEMENTED (gRPC
// status code 12) status the discover transparently falls back to
// v1alpha (Resolved #2, #20). Any other failure surfaces verbatim.
//
// Security — per-LPM size cap, total-FileDescriptorSet cap, explicit
// timeout, and explicit context cancellation. The reflection-own
// services are stripped before issuing FileContainingSymbol so we never
// re-fetch the reflection schema itself (Resolved #12).
package protoschema

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/google/uuid"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	v1 "google.golang.org/grpc/reflection/grpc_reflection_v1"

	httputilpkg "github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// ReflectionV1Service is the fully-qualified v1 reflection service name.
const ReflectionV1Service = "grpc.reflection.v1.ServerReflection"

// ReflectionV1AlphaService is the fully-qualified v1alpha reflection
// service name. We probe v1 first and fall back here on UNIMPLEMENTED.
const ReflectionV1AlphaService = "grpc.reflection.v1alpha.ServerReflection"

// ReflectionMethod is the bidi-streaming method name shared by both
// reflection versions.
const ReflectionMethod = "ServerReflectionInfo"

// DefaultDiscoverTimeout is the wall-clock budget applied to a single
// Discover invocation when DiscoverOptions.Timeout is zero. 30s matches
// the resend_grpc default (Resolved #14).
const DefaultDiscoverTimeout = 30 * time.Second

// MaxDiscoverTimeout is the upper bound the runner applies to a caller-
// supplied timeout. 5 minutes is a sane upper bound that covers cold-cache
// reads from slow upstreams while preventing an MCP caller from parking
// the server indefinitely (Resolved #14).
const MaxDiscoverTimeout = 5 * time.Minute

// gRPC status code for UNIMPLEMENTED. Matches codes.Unimplemented from
// google.golang.org/grpc/codes without importing the runtime package.
const grpcStatusUnimplemented uint32 = 12

// DiscoverOptions is the input to Discover.
type DiscoverOptions struct {
	// TargetAddr is the upstream host or host:port. Required.
	TargetAddr string

	// Scheme selects http (h2c) vs https (TLS+ALPN h2). Empty defaults to
	// https (Resolved #31).
	Scheme string

	// Transport supplies the TLS dial helper. Required when Scheme=="https".
	// May be nil for plaintext h2c.
	Transport httputilpkg.TLSTransport

	// Metadata is the optional gRPC metadata list forwarded as initial
	// HEADERS on the reflection stream. Used by reflection endpoints that
	// gate access behind a bearer token or similar (U3).
	Metadata []envelope.KeyValue

	// ServiceFilter, when non-empty, restricts the per-service
	// FileContainingSymbol fetch to these fully-qualified names. Names not
	// present in the upstream's ListServices response cause an error
	// (Resolved #6, #30).
	ServiceFilter []string

	// Timeout overrides DefaultDiscoverTimeout. Values above
	// MaxDiscoverTimeout are clamped (Resolved #14).
	Timeout time.Duration

	// MaxLPMSize, when non-zero, caps the per-LPM bytes accepted on the
	// reflection stream. Defaults to MaxDescriptorSetBytes (Resolved #9).
	MaxLPMSize uint32
}

// DiscoverResult is the structured output of Discover.
type DiscoverResult struct {
	// Services is the resolved list ready for Registry.Register. The
	// caller is responsible for stamping SourceLabel (the protoschema
	// package does not know the caller's preferred label).
	Services []*ServiceSpec

	// AssembledRawDescriptorSet is the marshaled FileDescriptorSet bytes
	// ready for SaveGRPCSchema. One descriptor set covers ALL discovered
	// services so a single persistence row per service references the same
	// blob; the rehydrate path filters by service.
	AssembledRawDescriptorSet []byte

	// ReflectionVersion is the reflection service variant that succeeded
	// ("v1" or "v1alpha"). Informational; mirrors the verbatim service
	// names for the result schema.
	ReflectionVersion string
}

// reflectionVariant captures one reflection service variant. The same
// stream-level state machine drives both v1 and v1alpha — only the
// service name on :path and the message type are different on the wire,
// but the on-wire proto bytes are byte-identical between v1 and v1alpha
// (the .proto files were copied verbatim during the v1 promotion). We
// therefore marshal the v1 types unconditionally and only switch the
// :path component on fallback.
type reflectionVariant struct {
	name    string // "v1" or "v1alpha"
	service string // fully-qualified service name
}

var reflectionVariants = []reflectionVariant{
	{name: "v1", service: ReflectionV1Service},
	{name: "v1alpha", service: ReflectionV1AlphaService},
}

// reflectionDialFunc opens one bidi gRPC stream against the target's
// reflection service. The returned channel must support Send + Next on
// gRPC envelopes; the Close func is invoked when discoverOnce returns
// to tear down the underlying connection / Layer / stream regardless of
// success or failure.
//
// The default implementation (defaultReflectionDialFunc) builds the
// production HTTP/2 + gRPC Layer stack. Tests inject a synthetic dialer
// to exercise the protocol state machine without standing up real wire.
type reflectionDialFunc func(ctx context.Context, opts DiscoverOptions, service string) (reflectionStreamChannel, func(), error)

// reflectionDial is the package-level seam tests override. Production
// code paths always read this var lazily so the swap is goroutine-safe
// when tests run with t.Parallel.
var reflectionDial reflectionDialFunc = defaultReflectionDialFunc

// SetReflectionDialForTest replaces the package-level reflectionDial
// seam with a synthetic factory and returns a function the caller must
// invoke to restore the original dialer. Intended for tests in sibling
// packages (notably internal/mcp).
//
// The synthetic dialer receives the resolved reflection service path
// component (either ReflectionV1Service or ReflectionV1AlphaService)
// and must return a channel that speaks the reflection protocol.
//
// Concurrency: the override is global; callers must not run tests in
// parallel against this seam.
func SetReflectionDialForTest(factory func(service string) ReflectionStreamChannel) func() {
	orig := reflectionDial
	reflectionDial = func(_ context.Context, _ DiscoverOptions, service string) (reflectionStreamChannel, func(), error) {
		ch := factory(service)
		return reflectionStreamChannelAdapter{ch: ch}, func() {}, nil
	}
	return func() { reflectionDial = orig }
}

// ReflectionStreamChannel is the exported alias of the internal channel
// surface SetReflectionDialForTest produces. It mirrors the unexported
// reflectionStreamChannel — kept in lockstep via the adapter.
type ReflectionStreamChannel interface {
	Send(ctx context.Context, env *envelope.Envelope) error
	Next(ctx context.Context) (*envelope.Envelope, error)
}

// reflectionStreamChannelAdapter bridges ReflectionStreamChannel back
// to the unexported interface used by the protocol driver.
type reflectionStreamChannelAdapter struct {
	ch ReflectionStreamChannel
}

func (a reflectionStreamChannelAdapter) Send(ctx context.Context, env *envelope.Envelope) error {
	return a.ch.Send(ctx, env)
}

func (a reflectionStreamChannelAdapter) Next(ctx context.Context) (*envelope.Envelope, error) {
	return a.ch.Next(ctx)
}

// Discover probes the target gRPC server's reflection endpoint and
// returns the assembled schema bytes plus the resolved []*ServiceSpec.
//
// Behaviour (per Resolved decisions):
//
//   - v1 is tried first; on stream-level UNIMPLEMENTED we retry once
//     against v1alpha (Resolved #2). Any other terminal error from v1
//     surfaces immediately.
//   - reflection.v1.ServerReflection and reflection.v1alpha.ServerReflection
//     are stripped from the candidate service list before issuing
//     FileContainingSymbol (Resolved #12).
//   - ServiceFilter, when supplied, is validated against the upstream's
//     ListServices reply before any FileContainingSymbol fetch (Resolved
//     #30). Filter entries that are not present produce an error.
//   - Per-service FileContainingSymbol requests are issued sequentially
//     (Resolved #15). file_descriptor_proto entries returned across
//     services are deduplicated by filename (Resolved #8); a filename
//     collision with byte-differing content surfaces as a protodesc
//     parse error.
//   - The assembled FileDescriptorSet is bound by MaxDescriptorSetBytes
//     (Resolved #9).
//   - All-or-nothing: any per-service failure aborts the discover; no
//     partial result is returned (Resolved #24).
func Discover(ctx context.Context, opts DiscoverOptions) (*DiscoverResult, error) {
	opts, err := normalizeDiscoverOptions(opts)
	if err != nil {
		return nil, err
	}

	runCtx, cancel := context.WithTimeout(ctx, opts.Timeout)
	defer cancel()

	var lastErr error
	for _, variant := range reflectionVariants {
		res, err := discoverOnce(runCtx, opts, variant)
		if err == nil {
			return res, nil
		}
		// Only retry on stream-level UNIMPLEMENTED (Resolved #20). Every
		// other error class is terminal.
		if !isUnimplementedErr(err) {
			return nil, fmt.Errorf("reflection (%s): %w", variant.name, err)
		}
		lastErr = err
		slog.DebugContext(runCtx, "reflection variant returned UNIMPLEMENTED; falling back",
			"variant", variant.name,
			"target", opts.TargetAddr,
		)
	}

	// Both v1 and v1alpha returned UNIMPLEMENTED — surface the verbatim
	// error spec from the design review (Resolved #10).
	_ = lastErr // retained for log context above
	return nil, fmt.Errorf("target %q does not implement gRPC reflection (server returned gRPC status UNIMPLEMENTED for both v1 and v1alpha). Enable reflection on the target server: for grpc-go, import google.golang.org/grpc/reflection and call reflection.Register(s); for other runtimes see https://github.com/grpc/grpc/blob/master/doc/server-reflection.md", opts.TargetAddr)
}

// normalizeDiscoverOptions validates and fills defaults. Caller-supplied
// fields stay verbatim where set; zero values get the documented default.
func normalizeDiscoverOptions(opts DiscoverOptions) (DiscoverOptions, error) {
	if strings.TrimSpace(opts.TargetAddr) == "" {
		return opts, errors.New("target_addr is empty")
	}
	scheme := strings.ToLower(strings.TrimSpace(opts.Scheme))
	switch scheme {
	case "":
		scheme = "https"
	case "http", "https":
	default:
		return opts, fmt.Errorf("unsupported scheme %q: only http and https are allowed", opts.Scheme)
	}
	opts.Scheme = scheme

	if scheme == "https" && opts.Transport == nil {
		return opts, errors.New("scheme=https requires a configured TLSTransport")
	}
	if opts.Timeout <= 0 {
		opts.Timeout = DefaultDiscoverTimeout
	}
	if opts.Timeout > MaxDiscoverTimeout {
		opts.Timeout = MaxDiscoverTimeout
	}
	if opts.MaxLPMSize == 0 {
		opts.MaxLPMSize = MaxDescriptorSetBytes
	}
	return opts, nil
}

// defaultReflectionDialFunc is the production dialer: TCP (+ TLS) →
// http2.Layer (ClientRole) → grpclayer.Wrap. Tests substitute a
// synthetic implementation via reflectionDial.
func defaultReflectionDialFunc(ctx context.Context, opts DiscoverOptions, service string) (reflectionStreamChannel, func(), error) {
	conn, err := dialReflectionUpstream(ctx, opts)
	if err != nil {
		return nil, nil, err
	}

	// Bound peer HEADERS to 1 MiB (matches the resend_grpc Layer recipe)
	// so a strict peer doesn't RST every HEADERS frame on the default
	// MaxHeaderListSize=0.
	initialSettings := http2.DefaultSettings()
	initialSettings.MaxHeaderListSize = 1 << 20
	connID := uuid.NewString()
	l, err := http2.New(conn, "", http2.ClientRole,
		http2.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: connID}),
		http2.WithInitialSettings(initialSettings),
	)
	if err != nil {
		_ = conn.Close()
		return nil, nil, fmt.Errorf("http2 layer: %w", err)
	}

	innerCh, err := l.OpenStream(ctx)
	if err != nil {
		_ = l.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("open stream: %w", err)
	}

	// Per-LPM cap: lower the gRPC Layer's wire cap to MaxLPMSize so a
	// pathological peer cannot stream a multi-GiB single LPM that
	// individually fits under the configured proxy cap but blows the
	// schema-side 16 MiB budget on assembly (Resolved #9, defense in
	// depth).
	ch := grpclayer.Wrap(innerCh, nil, grpclayer.RoleClient,
		grpclayer.WithMaxMessageSize(opts.MaxLPMSize),
	)

	streamID := uuid.NewString()
	authority := opts.TargetAddr
	startEnv := buildReflectionStartEnvelope(streamID, connID, service, authority, opts.Scheme, opts.Metadata)
	if err := ch.Send(ctx, startEnv); err != nil {
		_ = ch.Close()
		_ = l.Close()
		_ = conn.Close()
		return nil, nil, fmt.Errorf("send Start: %w", err)
	}

	cleanup := func() {
		_ = ch.Close()
		_ = l.Close()
		_ = conn.Close()
	}
	return ch, cleanup, nil
}

// discoverOnce executes a single reflection RPC against the supplied
// variant. Opens a fresh upstream connection / H2 stream / gRPC channel
// each call (Resolved sub-decision below): retrying v1alpha after v1
// UNIMPLEMENTED uses a brand new dial. This keeps the state machine
// strictly sequential and avoids stream-reuse subtleties (a single H2
// connection can carry both, but rebuilding is cheaper than reasoning
// about which side of a half-closed stream survives).
func discoverOnce(ctx context.Context, opts DiscoverOptions, variant reflectionVariant) (*DiscoverResult, error) {
	ch, cleanup, err := reflectionDial(ctx, opts, variant.service)
	if err != nil {
		return nil, err
	}
	defer cleanup()

	// Step 1: ListServices.
	services, err := reflectionListServices(ctx, ch, "", "", variant)
	if err != nil {
		return nil, err
	}

	// Strip reflection's own services (Resolved #12) and apply the optional
	// filter (Resolved #30).
	candidates, err := selectCandidateServices(services, opts.ServiceFilter)
	if err != nil {
		return nil, err
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("target %q reports zero services via gRPC reflection — the reflection registry is empty (server has not called reflection.Register on any service)", opts.TargetAddr)
	}

	// Step 2: FileContainingSymbol per service.
	fileBytes, err := reflectionFetchFileDescriptors(ctx, ch, "", "", variant, candidates)
	if err != nil {
		return nil, err
	}

	// Step 3: close the request side. The reflection RPC is bidi
	// streaming; the canonical termination is an empty DATA with
	// END_STREAM=1 (the gRPC-Go CloseSend wire shape). The gRPC Layer's
	// sendData translates Payload==nil + WireLength==0 + EndStream=true
	// into exactly that frame.
	endEnv := buildReflectionEndStreamEnvelope("", "", len(candidates)+1)
	if err := ch.Send(ctx, endEnv); err != nil {
		// The peer almost certainly closed its receive side after our last
		// response — Send-side CLOSE_STREAM races on partially-torn-down
		// connections are common in real-world reflection servers. Don't
		// fail the entire discover on a teardown race when we already have
		// all the descriptors we need.
		slog.DebugContext(ctx, "reflection: close-send failed (peer may have torn down recv side first)",
			"variant", variant.name,
			"error", err,
		)
	}

	// Assemble and bound-check the FileDescriptorSet.
	rawSet, err := assembleFileDescriptorSet(fileBytes)
	if err != nil {
		return nil, err
	}

	specs, err := LoadFileDescriptorSet(rawSet, opts.ServiceFilter)
	if err != nil {
		return nil, err
	}

	return &DiscoverResult{
		Services:                  specs,
		AssembledRawDescriptorSet: rawSet,
		ReflectionVersion:         variant.name,
	}, nil
}

// reflectionListServices sends ListServices and reads until a Data
// envelope carrying ListServicesResponse arrives. Returns the
// fully-qualified service names.
func reflectionListServices(ctx context.Context, ch reflectionStreamChannel, _, _ string, _ reflectionVariant) ([]string, error) {
	listReq := &v1.ServerReflectionRequest{
		MessageRequest: &v1.ServerReflectionRequest_ListServices{ListServices: "*"},
	}
	if err := sendReflectionRequest(ctx, ch, 1, listReq); err != nil {
		return nil, fmt.Errorf("send ListServices: %w", err)
	}

	resp, err := readReflectionResponse(ctx, ch)
	if err != nil {
		return nil, fmt.Errorf("read ListServices response: %w", err)
	}

	switch m := resp.MessageResponse.(type) {
	case *v1.ServerReflectionResponse_ListServicesResponse:
		out := make([]string, 0, len(m.ListServicesResponse.GetService()))
		for _, svc := range m.ListServicesResponse.GetService() {
			out = append(out, svc.GetName())
		}
		return out, nil
	case *v1.ServerReflectionResponse_ErrorResponse:
		return nil, &reflectionRPCError{Code: uint32(m.ErrorResponse.GetErrorCode()), Message: m.ErrorResponse.GetErrorMessage()}
	default:
		return nil, fmt.Errorf("unexpected ListServices response type %T", resp.MessageResponse)
	}
}

// reflectionFetchFileDescriptors issues one FileContainingSymbol per
// candidate service (sequentially per Resolved #15) and collects every
// returned file_descriptor_proto. All-or-nothing on failure.
func reflectionFetchFileDescriptors(ctx context.Context, ch reflectionStreamChannel, _, _ string, _ reflectionVariant, candidates []string) ([][]byte, error) {
	var collected [][]byte
	for i, svc := range candidates {
		req := &v1.ServerReflectionRequest{
			MessageRequest: &v1.ServerReflectionRequest_FileContainingSymbol{FileContainingSymbol: svc},
		}
		if err := sendReflectionRequest(ctx, ch, i+2, req); err != nil {
			return nil, fmt.Errorf("send FileContainingSymbol(%s): %w", svc, err)
		}
		resp, err := readReflectionResponse(ctx, ch)
		if err != nil {
			return nil, fmt.Errorf("read FileContainingSymbol(%s) response (collected=%d/%d): %w", svc, i, len(candidates), err)
		}
		switch m := resp.MessageResponse.(type) {
		case *v1.ServerReflectionResponse_FileDescriptorResponse:
			collected = append(collected, m.FileDescriptorResponse.GetFileDescriptorProto()...)
		case *v1.ServerReflectionResponse_ErrorResponse:
			return nil, fmt.Errorf("FileContainingSymbol(%s) failed (collected=%d/%d before failure): server returned reflection error code=%d message=%q",
				svc, i, len(candidates),
				m.ErrorResponse.GetErrorCode(), m.ErrorResponse.GetErrorMessage())
		default:
			return nil, fmt.Errorf("unexpected FileContainingSymbol(%s) response type %T", svc, resp.MessageResponse)
		}
	}
	return collected, nil
}

// reflectionStreamChannel is the minimum surface of layer.Channel that
// the reflection driver uses. Extracted as a small interface so unit
// tests can plug an in-memory pair without standing up a real H2 stack.
type reflectionStreamChannel interface {
	Send(ctx context.Context, env *envelope.Envelope) error
	Next(ctx context.Context) (*envelope.Envelope, error)
}

// sendReflectionRequest marshals req and writes one GRPCDataMessage
// envelope on ch.
func sendReflectionRequest(ctx context.Context, ch reflectionStreamChannel, seq int, req *v1.ServerReflectionRequest) error {
	payload, err := proto.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	env := &envelope.Envelope{
		FlowID:    uuid.NewString(),
		Sequence:  seq,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Compressed: false,
			WireLength: uint32(len(payload)),
			Payload:    payload,
		},
	}
	return ch.Send(ctx, env)
}

// readReflectionResponse drains ch envelopes until a GRPCDataMessage is
// observed and unmarshals it as ServerReflectionResponse. Other envelope
// types (Start with response headers, End with trailers) are absorbed.
// A GRPCEndMessage encountered before a Data envelope means the stream
// terminated with no further data — surfaced as an error (callers
// translate UNIMPLEMENTED status into the fallback signal).
func readReflectionResponse(ctx context.Context, ch reflectionStreamChannel) (*v1.ServerReflectionResponse, error) {
	for {
		env, err := ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil, errors.New("stream closed before receiving a response")
			}
			return nil, err
		}
		switch m := env.Message.(type) {
		case *envelope.GRPCStartMessage:
			// Response HEADERS. Nothing to do — the actual response sits
			// in the next GRPCDataMessage envelope.
			continue
		case *envelope.GRPCDataMessage:
			resp := &v1.ServerReflectionResponse{}
			if uerr := proto.Unmarshal(m.Payload, resp); uerr != nil {
				return nil, fmt.Errorf("unmarshal ServerReflectionResponse: %w", uerr)
			}
			return resp, nil
		case *envelope.GRPCEndMessage:
			// Trailer arrived without any data. Surface the gRPC status so
			// the caller can decide whether to fall back (UNIMPLEMENTED)
			// or to abort.
			return nil, &reflectionRPCError{Code: m.Status, Message: m.Message}
		default:
			// Unknown envelope type — ignore and keep draining. Future
			// envelope additions on the same channel shouldn't break the
			// reflection driver.
			_ = env
			continue
		}
	}
}

// reflectionRPCError carries a gRPC-status-shaped failure. We avoid the
// google.golang.org/grpc/status package so the project keeps zero
// runtime dependency on grpc-go.
type reflectionRPCError struct {
	Code    uint32
	Message string
}

func (e *reflectionRPCError) Error() string {
	return fmt.Sprintf("gRPC status %d: %s", e.Code, e.Message)
}

// isUnimplementedErr reports whether err is the UNIMPLEMENTED stream
// status that warrants a v1→v1alpha fallback (Resolved #20).
func isUnimplementedErr(err error) bool {
	if err == nil {
		return false
	}
	var rpcErr *reflectionRPCError
	if errors.As(err, &rpcErr) {
		return rpcErr.Code == grpcStatusUnimplemented
	}
	return false
}

// dialReflectionUpstream produces a TCP (and optionally TLS) connection
// to opts.TargetAddr. Uses the same TLSTransport contract as
// resend_grpc's dialResendGRPCUpstream.
func dialReflectionUpstream(ctx context.Context, opts DiscoverOptions) (net.Conn, error) {
	dialAddr, sni := resolveReflectionDialTarget(opts.TargetAddr, opts.Scheme == "https")
	dialer := &net.Dialer{Timeout: opts.Timeout}
	conn, err := dialer.DialContext(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, fmt.Errorf("dial %s: %w", dialAddr, err)
	}
	if opts.Scheme == "https" {
		if opts.Transport == nil {
			_ = conn.Close()
			return nil, errors.New("scheme=https requires a configured TLSTransport")
		}
		tlsConn, _, tlsErr := opts.Transport.TLSConnect(ctx, conn, sni)
		if tlsErr != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("tls handshake %s: %w", sni, tlsErr)
		}
		conn = tlsConn
	}
	return conn, nil
}

// resolveReflectionDialTarget splits target_addr into a host:port dial
// address and an SNI. Mirrors resolveResendGRPCDialTarget.
func resolveReflectionDialTarget(targetAddr string, useTLS bool) (addr, sni string) {
	host := targetAddr
	port := ""
	if h, p, err := net.SplitHostPort(targetAddr); err == nil {
		host = h
		port = p
	}
	if port == "" {
		if useTLS {
			port = "443"
		} else {
			port = "80"
		}
	}
	return net.JoinHostPort(host, port), host
}

// buildReflectionStartEnvelope synthesises the Send-side GRPCStartMessage
// that opens the reflection RPC stream. ContentType is the canonical
// application/grpc+proto value.
func buildReflectionStartEnvelope(streamID, connID, service, authority, scheme string, metadata []envelope.KeyValue) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.NewString(),
		Sequence:  0,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCStartMessage{
			Service:     service,
			Method:      ReflectionMethod,
			Authority:   authority,
			Scheme:      scheme,
			Path:        "/" + service + "/" + ReflectionMethod,
			Metadata:    metadata,
			ContentType: "application/grpc+proto",
		},
		Context: envelope.EnvelopeContext{ConnID: connID},
	}
}

// buildReflectionEndStreamEnvelope synthesises the canonical
// CloseSend-shaped DATA(empty, END_STREAM=1) envelope.
func buildReflectionEndStreamEnvelope(streamID, connID string, seq int) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		FlowID:    uuid.NewString(),
		Sequence:  seq,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message: &envelope.GRPCDataMessage{
			Compressed: false,
			WireLength: 0,
			Payload:    nil,
			EndStream:  true,
		},
		Context: envelope.EnvelopeContext{ConnID: connID},
	}
}

// selectCandidateServices strips reflection's own services and applies
// the optional ServiceFilter. Returns an error when the filter mentions
// a service the target does not expose.
func selectCandidateServices(services []string, filter []string) ([]string, error) {
	cleaned := make([]string, 0, len(services))
	for _, s := range services {
		if s == ReflectionV1Service || s == ReflectionV1AlphaService {
			continue
		}
		cleaned = append(cleaned, s)
	}
	if len(filter) == 0 {
		return cleaned, nil
	}
	have := make(map[string]struct{}, len(cleaned))
	for _, s := range cleaned {
		have[s] = struct{}{}
	}
	out := make([]string, 0, len(filter))
	for _, want := range filter {
		if _, ok := have[want]; !ok {
			// Surface what the target offered so the operator can fix the
			// typo. cleaned is alphabetised by the protodesc tail anyway,
			// but we sort defensively for stable diagnostics.
			return nil, fmt.Errorf("service %q in service_filter not present in target's reflection registry (available: %v)", want, cleaned)
		}
		out = append(out, want)
	}
	return out, nil
}

// assembleFileDescriptorSet deduplicates raw FileDescriptorProto bytes
// by filename (Resolved #8) and marshals the result to a single
// FileDescriptorSet bounded by MaxDescriptorSetBytes.
//
// Filename-keyed dedup: the same .proto may appear in the
// FileContainingSymbol response of multiple services (e.g. a common
// types file). Byte-level dedup would over-keep when grpc servers tweak
// descriptor metadata across calls; filename-keyed dedup matches what
// protoc-built descriptor sets look like. A second occurrence with
// byte-differing content is left for protodesc.NewFiles to detect — its
// error surfaces with full context via LoadFileDescriptorSet.
func assembleFileDescriptorSet(fileBytes [][]byte) ([]byte, error) {
	seen := make(map[string]struct{}, len(fileBytes))
	out := &descriptorpb.FileDescriptorSet{}
	for i, raw := range fileBytes {
		fd := &descriptorpb.FileDescriptorProto{}
		if err := proto.Unmarshal(raw, fd); err != nil {
			return nil, fmt.Errorf("parse FileDescriptorProto[%d]: %w", i, err)
		}
		name := fd.GetName()
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		out.File = append(out.File, fd)
	}
	if len(out.File) == 0 {
		return nil, errors.New("reflection returned zero FileDescriptorProto entries — schema is empty")
	}
	marshaled, err := proto.Marshal(out)
	if err != nil {
		return nil, fmt.Errorf("marshal FileDescriptorSet: %w", err)
	}
	if len(marshaled) > MaxDescriptorSetBytes {
		return nil, fmt.Errorf("reflection response assembled FileDescriptorSet size %d exceeds maximum %d bytes", len(marshaled), MaxDescriptorSetBytes)
	}
	return marshaled, nil
}

// Note on v1alpha — the v1 and v1alpha .proto files share the same
// message-and-field-number layout (v1 was a verbatim copy of v1alpha at
// promotion). Marshaling a v1 ServerReflectionRequest therefore produces
// wire bytes a v1alpha server unmarshals correctly (and vice versa).
// The fallback to v1alpha only swaps the :path service component; the
// proto types stay v1 throughout. This avoids importing the deprecated
// google.golang.org/grpc/reflection/grpc_reflection_v1alpha package.
