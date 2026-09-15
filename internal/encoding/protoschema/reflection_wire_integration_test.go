//go:build e2e

// reflection_wire_integration_test.go drives protoschema.Discover end to
// end through defaultReflectionDialFunc — the real TCP dial /
// http2.New(ClientRole) / OpenStream / grpclayer.Wrap /
// buildReflectionStartEnvelope path — against a live grpc-go reflection
// server (USK-1054).
//
// Why this file exists: every other test in this package installs a
// synthetic dialer over the package-level reflectionDial seam, so the
// production dialer had never executed under test. The USK-1051
// `:authority` omission existed on this code path too and CI could not
// see it. assertProductionDialer below makes that structurally
// impossible to regress back into.
//
// Tier — plain `//go:build e2e` (merge-gate smoke), deviating from the
// CLAUDE.md default of `e2e && !e2e_smoke`: a well-formed `:authority` is
// a hard precondition for every outbound gRPC dial against grpc-go
// >= 1.83.2, it sits one line away from regression, and the existing
// merge-gate wire guard (internal/layer/grpc/grpc_integration_test.go)
// covers only the MITM relay path — none of the three synthetic
// producers (resend / fuzz / reflection discover) had merge-gate wire
// coverage.
//
// e2e Subsystem Verification Checklist applicability — the rows covered
// here are Communication success, Raw bytes / wire fidelity (via the h2c
// byte tap in TestDiscover_RealWire_H2C_RequestPseudoHeadersOnTheWire)
// and Error paths in both of its senses: the protocol error path, where
// the dial succeeds and the server answers with a real UNIMPLEMENTED
// status driving the v1 -> v1alpha fallback (Test C), and the transport
// error path, where the dial itself fails inside
// defaultReflectionDialFunc / dialReflectionUpstream (Test D). Stream
// recording, Flow recording, State transitions, Plugin hook firing,
// Variant recording and MCP `query` retrieval are N/A by design:
// grpc_schema discover is a control-plane outbound dial that runs no
// Record or Plugin Pipeline step and persists no Flow — its only
// Pipeline is a lone pipeline.NewBudgetStep applied in
// internal/mcp/grpc_schema_discover.go, and the reflection chatter is
// deliberately not recorded (USK-928 Resolved #28 / U1).

package protoschema

import (
	"bytes"
	"context"
	"crypto/tls"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/reflection"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/types/descriptorpb"

	v1grpc "google.golang.org/grpc/reflection/grpc_reflection_v1"
	v1alphagrpc "google.golang.org/grpc/reflection/grpc_reflection_v1alpha"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// reflectionWireTimeout is the explicit DiscoverOptions.Timeout used by
// every test below. A hang must fail the test, not park the tier.
const reflectionWireTimeout = 10 * time.Second

// -----------------------------------------------------------------------------
// Harness
// -----------------------------------------------------------------------------

// staticServiceInfo is a minimal reflection.ServiceInfoProvider backed by
// a fixed service-name list. It lets the reflection server advertise
// synthetic services without registering a real handler for each, and it
// keeps protoregistry.GlobalFiles untouched.
type staticServiceInfo []string

// GetServiceInfo implements reflection.ServiceInfoProvider. The
// reflection server only reads the map keys.
func (s staticServiceInfo) GetServiceInfo() map[string]grpc.ServiceInfo {
	out := make(map[string]grpc.ServiceInfo, len(s))
	for _, name := range s {
		out[name] = grpc.ServiceInfo{}
	}
	return out
}

// reflectionCallObserver records what the upstream actually saw on the
// ServerReflectionInfo stream. grpc-go owns the reflection handler, so a
// grpc.StreamInterceptor is the only instrumentation seam available.
type reflectionCallObserver struct {
	mu         sync.Mutex
	md         metadata.MD
	fullMethod string
	calls      int
}

// intercept captures the incoming metadata and the resolved full method
// before delegating to grpc-go's reflection handler.
func (o *reflectionCallObserver) intercept(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	md, _ := metadata.FromIncomingContext(ss.Context())
	o.mu.Lock()
	o.md = md.Copy()
	o.fullMethod = info.FullMethod
	o.calls++
	o.mu.Unlock()
	return handler(srv, ss)
}

// snapshot returns a copy of the observed state. Safe to call after the
// RPC has completed; the interceptor runs on grpc-go's own goroutines.
func (o *reflectionCallObserver) snapshot() (metadata.MD, string, int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.md.Copy(), o.fullMethod, o.calls
}

// reflectionUpstreamOptions configures startReflectionUpstream.
type reflectionUpstreamOptions struct {
	// useTLS terminates the listener with TLS + ALPN h2 using a
	// freshly-generated CA and a "localhost" leaf.
	useTLS bool
	// registerV1 / registerV1Alpha select which reflection service
	// variants get a handler. Registering only v1alpha makes grpc-go
	// answer the v1 probe with a genuine UNIMPLEMENTED on the wire.
	registerV1      bool
	registerV1Alpha bool
	// advertised is the service-name list ListServices returns.
	advertised []string
	// files is the descriptor pool FileContainingSymbol resolves against.
	files []*descriptorpb.FileDescriptorProto
	// listener, when non-nil, is served instead of a fresh
	// 127.0.0.1:0 listener. Used by the h2c wire-tap test.
	listener net.Listener
}

// startReflectionUpstream stands up a real grpc-go server exposing the
// server-reflection service over the requested transport and returns the
// bound port plus the call observer.
//
// The server uses grpc-go's default proto codec on purpose: the sibling
// resend/fuzz harnesses install a raw []byte codec via
// grpc.ForceServerCodec, which is server-wide and would break the
// reflection service's own protobuf marshalling.
func startReflectionUpstream(t *testing.T, opts reflectionUpstreamOptions) (port string, obs *reflectionCallObserver) {
	t.Helper()

	resolver, err := protodesc.NewFiles(&descriptorpb.FileDescriptorSet{File: opts.files})
	if err != nil {
		t.Fatalf("protodesc.NewFiles: %v", err)
	}

	obs = &reflectionCallObserver{}
	serverOpts := []grpc.ServerOption{grpc.StreamInterceptor(obs.intercept)}
	if opts.useTLS {
		serverOpts = append(serverOpts, grpc.Creds(credentials.NewTLS(reflectionUpstreamTLSConfig(t))))
	}
	gs := grpc.NewServer(serverOpts...)

	svcOpts := reflection.ServerOptions{
		Services:           staticServiceInfo(opts.advertised),
		DescriptorResolver: resolver,
	}
	if opts.registerV1 {
		v1grpc.RegisterServerReflectionServer(gs, reflection.NewServerV1(svcOpts))
	}
	if opts.registerV1Alpha {
		// reflection.NewServer returns the v1alpha-shaped adapter.
		v1alphagrpc.RegisterServerReflectionServer(gs, reflection.NewServer(svcOpts))
	}

	ln := opts.listener
	if ln == nil {
		// Bind 127.0.0.1 while the caller targets "localhost:<port>":
		// an :authority derived from the socket rather than from the
		// caller's TargetAddr would read "127.0.0.1:<port>", so the
		// assertions below can tell the two apart. SNI still resolves to
		// "localhost", matching the issued leaf.
		var lerr error
		ln, lerr = net.Listen("tcp", "127.0.0.1:0")
		if lerr != nil {
			t.Fatalf("listen: %v", lerr)
		}
	}
	_, port, err = net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatalf("split listen addr %q: %v", ln.Addr().String(), err)
	}

	go func() { _ = gs.Serve(ln) }()
	// t.Cleanup rather than defer: teardown must run after Discover and
	// its Layer goroutines have finished inside the test body.
	t.Cleanup(func() {
		gs.GracefulStop()
		_ = ln.Close()
	})
	return port, obs
}

// reflectionUpstreamTLSConfig issues a fresh CA + "localhost" leaf and
// returns a server TLS config advertising ALPN h2.
func reflectionUpstreamTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	leaf, err := cert.NewIssuer(ca).GetCertificate("localhost")
	if err != nil {
		t.Fatalf("issue localhost leaf: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
}

// assertProductionDialer fails unless the package-level reflectionDial
// seam still points at defaultReflectionDialFunc.
//
// This is the direct answer to USK-1054: without it, an unrelated future
// test could install a fake dialer (the seam is global and this package
// has helpers that do exactly that) and every assertion in this file
// would keep passing while covering nothing.
func assertProductionDialer(t *testing.T) {
	t.Helper()
	got := reflect.ValueOf(reflectionDial).Pointer()
	want := reflect.ValueOf(defaultReflectionDialFunc).Pointer()
	if got != want {
		t.Fatalf("reflectionDial seam is not defaultReflectionDialFunc (got %#x, want %#x): this test must drive the real dial path", got, want)
	}
}

// newGreeterFileDescriptor materialises the shared synthetic descriptor
// used by every test below, reusing the untagged reflection_test.go
// fixture verbatim.
func newGreeterFileDescriptor(t *testing.T) *descriptorpb.FileDescriptorProto {
	t.Helper()
	raw := buildTestFileDescriptorProto(t,
		"usk1054", "usk1054/greeter.proto", "Greeter", "SayHello", "HelloRequest", "HelloResponse")
	fd := &descriptorpb.FileDescriptorProto{}
	if err := proto.Unmarshal(raw, fd); err != nil {
		t.Fatalf("unmarshal fixture FileDescriptorProto: %v", err)
	}
	return fd
}

// assertGreeterDiscovered validates the assembled schema content the
// real reflection server produced.
func assertGreeterDiscovered(t *testing.T, res *DiscoverResult, wantVersion string) {
	t.Helper()
	if res == nil {
		t.Fatal("Discover returned a nil result")
	}
	if res.ReflectionVersion != wantVersion {
		t.Errorf("ReflectionVersion = %q, want %q", res.ReflectionVersion, wantVersion)
	}
	if len(res.Services) != 1 {
		t.Fatalf("len(Services) = %d, want 1: %+v", len(res.Services), res.Services)
	}
	svc := res.Services[0]
	if svc.Service != "usk1054.Greeter" {
		t.Errorf("Services[0].Service = %q, want %q", svc.Service, "usk1054.Greeter")
	}
	if len(svc.Methods) != 1 {
		t.Fatalf("len(Services[0].Methods) = %d, want 1: %+v", len(svc.Methods), svc.Methods)
	}
	m := svc.Methods[0]
	if m.Name != "SayHello" {
		t.Errorf("method Name = %q, want %q", m.Name, "SayHello")
	}
	if m.Input != "usk1054.HelloRequest" {
		t.Errorf("method Input = %q, want %q", m.Input, "usk1054.HelloRequest")
	}
	if m.Output != "usk1054.HelloResponse" {
		t.Errorf("method Output = %q, want %q", m.Output, "usk1054.HelloResponse")
	}

	if len(res.AssembledRawDescriptorSet) == 0 {
		t.Fatal("AssembledRawDescriptorSet is empty")
	}
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(res.AssembledRawDescriptorSet, fds); err != nil {
		t.Fatalf("unmarshal AssembledRawDescriptorSet: %v", err)
	}
	if len(fds.GetFile()) != 1 {
		t.Fatalf("AssembledRawDescriptorSet has %d files, want 1", len(fds.GetFile()))
	}
	if got := fds.GetFile()[0].GetName(); got != "usk1054/greeter.proto" {
		t.Errorf("assembled file name = %q, want %q", got, "usk1054/greeter.proto")
	}
}

// assertSingleMetadataValue asserts md[key] holds exactly one value
// equal to want, byte for byte (no case folding, no normalisation).
func assertSingleMetadataValue(t *testing.T, md metadata.MD, key, want string) {
	t.Helper()
	got := md.Get(key)
	if len(got) != 1 {
		t.Fatalf("upstream metadata %q = %v, want exactly one value (%q)", key, got, want)
	}
	if got[0] != want {
		t.Errorf("upstream metadata %q = %q, want %q", key, got[0], want)
	}
}

// -----------------------------------------------------------------------------
// Test A — https happy path through the production dialer
// -----------------------------------------------------------------------------

// TestDiscover_RealWire_HTTPS_AuthorityAndSchema drives the whole
// production dial path over TLS+ALPN h2 and pins what the upstream
// actually observed.
//
// The :authority assertion is the USK-1051 guard: buildReflectionStartEnvelope
// sets Context{ConnID} only, so any Send-side derivation of :authority from
// Envelope.Context.TargetHost yields the empty string and grpc-go >= 1.83.2
// early-aborts the stream with codes.Internal "no host or :authority header
// present".
func TestDiscover_RealWire_HTTPS_AuthorityAndSchema(t *testing.T) {
	port, obs := startReflectionUpstream(t, reflectionUpstreamOptions{
		useTLS:     true,
		registerV1: true,
		advertised: []string{"usk1054.Greeter"},
		files:      []*descriptorpb.FileDescriptorProto{newGreeterFileDescriptor(t)},
	})
	targetAddr := net.JoinHostPort("localhost", port)

	assertProductionDialer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: targetAddr,
		Scheme:     "https",
		Transport:  &transport.StandardTransport{InsecureSkipVerify: true},
		Timeout:    reflectionWireTimeout,
	})
	if err != nil {
		t.Fatalf("Discover over TLS: %v", err)
	}
	assertGreeterDiscovered(t, res, "v1")

	md, fullMethod, calls := obs.snapshot()
	if calls != 1 {
		t.Fatalf("upstream saw %d reflection streams, want 1", calls)
	}
	if want := "/" + ReflectionV1Service + "/" + ReflectionMethod; fullMethod != want {
		t.Errorf("upstream FullMethod = %q, want %q", fullMethod, want)
	}
	// Verbatim: the listener bound 127.0.0.1:<port>, so "localhost:<port>"
	// can only come from the caller-supplied TargetAddr.
	assertSingleMetadataValue(t, md, ":authority", targetAddr)
	assertSingleMetadataValue(t, md, "content-type", "application/grpc+proto")
}

// -----------------------------------------------------------------------------
// Test B — h2c + client-side byte tap
// -----------------------------------------------------------------------------

// wireRecorder accumulates the client -> server byte stream. grpc-go
// reads on its own goroutines, so every access is mutex-guarded.
type wireRecorder struct {
	mu  sync.Mutex
	buf []byte
}

func (r *wireRecorder) append(b []byte) {
	r.mu.Lock()
	r.buf = append(r.buf, b...)
	r.mu.Unlock()
}

func (r *wireRecorder) snapshot() []byte {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]byte(nil), r.buf...)
}

// teeListener wraps every accepted connection in a teeConn.
type teeListener struct {
	net.Listener
	rec *wireRecorder
}

func (l *teeListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return &teeConn{Conn: c, rec: l.rec}, nil
}

// teeConn records everything the server reads, i.e. the raw client ->
// server byte stream.
type teeConn struct {
	net.Conn
	rec *wireRecorder
}

func (c *teeConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rec.append(p[:n])
	}
	return n, err
}

// firstRequestHeaderFields replays the recorded client -> server byte
// stream and returns the ordered HPACK header fields of the first
// HEADERS frame on stream 1.
func firstRequestHeaderFields(t *testing.T, raw []byte) []hpack.HeaderField {
	t.Helper()
	if len(raw) < len(http2.ClientPreface) {
		t.Fatalf("recorded client stream is %d bytes, shorter than the %d-byte HTTP/2 client preface", len(raw), len(http2.ClientPreface))
	}
	if got := string(raw[:len(http2.ClientPreface)]); got != http2.ClientPreface {
		t.Fatalf("recorded client stream does not open with the HTTP/2 client preface: %q", got)
	}
	rd := frame.NewReader(bytes.NewReader(raw[len(http2.ClientPreface):]))
	dec := hpack.NewDecoder(4096)
	for {
		f, err := rd.ReadFrame()
		if err != nil {
			t.Fatalf("no HEADERS frame for stream 1 in the %d recorded bytes: %v", len(raw), err)
		}
		if f.Header.Type != frame.TypeHeaders || f.Header.StreamID != 1 {
			continue
		}
		if !f.Header.Flags.Has(frame.FlagEndHeaders) {
			t.Fatalf("stream-1 HEADERS lacks END_HEADERS (flags=%#x); this tap does not reassemble CONTINUATION", uint8(f.Header.Flags))
		}
		if f.Header.Flags.Has(frame.FlagPadded) || f.Header.Flags.Has(frame.FlagPriority) {
			t.Fatalf("stream-1 HEADERS carries PADDED/PRIORITY (flags=%#x); this tap decodes the payload directly", uint8(f.Header.Flags))
		}
		fields, derr := dec.Decode(f.Payload)
		if derr != nil {
			t.Fatalf("hpack decode of the stream-1 HEADERS payload: %v", derr)
		}
		return fields
	}
}

// formatHeaderFields renders an ordered field list for failure output.
func formatHeaderFields(fields []hpack.HeaderField) string {
	var b strings.Builder
	for i, f := range fields {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(f.Name)
		b.WriteString(": ")
		b.WriteString(f.Value)
	}
	return b.String()
}

// TestDiscover_RealWire_H2C_RequestPseudoHeadersOnTheWire pins the exact
// ordered HPACK header block the production dialer emits.
//
// grpc-go discards :scheme, :method and te before building metadata
// (internal/transport/http_util.go isReservedHeader + the explicit case
// list in http2_server.operateHeaders), so :scheme is invisible to Test
// A's interceptor and an h2c RPC that lies ":scheme: https" on the wire
// still succeeds. Only this tap catches a regression of schemeForStart.
func TestDiscover_RealWire_H2C_RequestPseudoHeadersOnTheWire(t *testing.T) {
	base, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	// startReflectionUpstream registers its own Close for whatever
	// listener it is handed, but only after two t.Fatalf-capable steps
	// (protodesc.NewFiles, net.SplitHostPort). Register teardown here, at
	// the point of acquisition, so a Fatal in either cannot leak the
	// socket for the life of the test binary. The resulting double Close
	// on the happy path is harmless — net.TCPListener.Close is idempotent
	// and the second call's ErrClosed is discarded — so do not "tidy"
	// this back into a leak.
	t.Cleanup(func() { _ = base.Close() })
	rec := &wireRecorder{}
	port, obs := startReflectionUpstream(t, reflectionUpstreamOptions{
		registerV1: true,
		advertised: []string{"usk1054.Greeter"},
		files:      []*descriptorpb.FileDescriptorProto{newGreeterFileDescriptor(t)},
		listener:   &teeListener{Listener: base, rec: rec},
	})
	targetAddr := net.JoinHostPort("localhost", port)

	assertProductionDialer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: targetAddr,
		Scheme:     "http",
		Timeout:    reflectionWireTimeout,
	})
	if err != nil {
		t.Fatalf("Discover over h2c: %v", err)
	}
	assertGreeterDiscovered(t, res, "v1")

	md, _, calls := obs.snapshot()
	if calls != 1 {
		t.Fatalf("upstream saw %d reflection streams, want 1", calls)
	}
	assertSingleMetadataValue(t, md, ":authority", targetAddr)

	// Ordered wire assertion. The HTTP/2 Layer emits the default
	// (Chrome-shaped) pseudo-header order :method :scheme :authority
	// :path, followed by the gRPC Layer's conventional
	// content-type then te.
	fields := firstRequestHeaderFields(t, rec.snapshot())
	want := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: targetAddr},
		{Name: ":path", Value: "/" + ReflectionV1Service + "/" + ReflectionMethod},
		{Name: "content-type", Value: "application/grpc+proto"},
		{Name: "te", Value: "trailers"},
	}
	if len(fields) != len(want) {
		t.Fatalf("stream-1 HEADERS carried %d fields, want %d\n got: %s\nwant: %s",
			len(fields), len(want), formatHeaderFields(fields), formatHeaderFields(want))
	}
	for i := range want {
		if fields[i].Name != want[i].Name || fields[i].Value != want[i].Value {
			t.Errorf("stream-1 HEADERS field[%d] = %q: %q, want %q: %q\n got: %s\nwant: %s",
				i, fields[i].Name, fields[i].Value, want[i].Name, want[i].Value,
				formatHeaderFields(fields), formatHeaderFields(want))
		}
	}
}

// -----------------------------------------------------------------------------
// Test C — real-wire v1 -> v1alpha fallback
// -----------------------------------------------------------------------------

// TestDiscover_RealWire_FallsBackToV1AlphaOnUnimplemented exercises the
// one branch of Discover's variant loop that had never run against a real
// server: only the v1alpha reflection service is registered, so grpc-go
// answers the v1 probe with a genuine trailers-only UNIMPLEMENTED
// (gRPC status 12) and Discover must transparently retry on v1alpha.
func TestDiscover_RealWire_FallsBackToV1AlphaOnUnimplemented(t *testing.T) {
	port, obs := startReflectionUpstream(t, reflectionUpstreamOptions{
		registerV1Alpha: true,
		advertised:      []string{"usk1054.Greeter"},
		files:           []*descriptorpb.FileDescriptorProto{newGreeterFileDescriptor(t)},
	})
	targetAddr := net.JoinHostPort("localhost", port)

	assertProductionDialer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: targetAddr,
		Scheme:     "http",
		Timeout:    reflectionWireTimeout,
	})
	if err != nil {
		t.Fatalf("Discover with only v1alpha registered: %v", err)
	}
	assertGreeterDiscovered(t, res, "v1alpha")

	md, fullMethod, calls := obs.snapshot()
	// The v1 probe never reaches a handler (no service registered), so
	// the interceptor fires exactly once — on the v1alpha retry.
	if calls != 1 {
		t.Fatalf("upstream saw %d intercepted reflection streams, want 1 (v1alpha only)", calls)
	}
	if want := "/" + ReflectionV1AlphaService + "/" + ReflectionMethod; fullMethod != want {
		t.Errorf("upstream FullMethod = %q, want %q", fullMethod, want)
	}
	assertSingleMetadataValue(t, md, ":authority", targetAddr)
}

// -----------------------------------------------------------------------------
// Test D — production dialer, transport error path
// -----------------------------------------------------------------------------

// TestDiscover_RealWire_DialFailureSurfacesTransportError covers the one
// error class Tests A-C structurally cannot reach: a *transport* failure
// raised inside defaultReflectionDialFunc / dialReflectionUpstream. Test
// C's UNIMPLEMENTED fallback is a *protocol* error — the dial succeeded
// and the server answered — so without this test every transport wrap in
// the production dialer (`dial %s: %w`, `http2 layer: %w`,
// `open stream: %w`, `send Start: %w`, `tls handshake %s: %w`) is text no
// test has ever executed, and a dial error could start being swallowed
// or mangled without CI noticing.
//
// The target is a loopback port bound only long enough to learn its
// number and then released, so connect() is refused immediately rather
// than hanging. No hardcoded port: a fixed number could legitimately be
// in use on a developer box.
func TestDiscover_RealWire_DialFailureSurfacesTransportError(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen to reserve an unbound port: %v", err)
	}
	targetAddr := probe.Addr().String()
	if cerr := probe.Close(); cerr != nil {
		t.Fatalf("close the probe listener %s: %v", targetAddr, cerr)
	}

	assertProductionDialer(t)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Deliberately shorter than reflectionWireTimeout: this value also
	// becomes net.Dialer.Timeout, and on a host that blackholes rather
	// than refuses the connect it is the only thing between this test and
	// a full-length stall of the merge gate.
	res, err := Discover(ctx, DiscoverOptions{
		TargetAddr: targetAddr,
		Scheme:     "http",
		Timeout:    2 * time.Second,
	})
	if err == nil {
		t.Fatalf("Discover against the released port %s returned no error (res = %+v)", targetAddr, res)
	}
	if res != nil {
		t.Errorf("Discover returned a non-nil result alongside an error: %+v", res)
	}

	// Discriminating, but deliberately not on the errno text: the
	// "connect: connection refused" tail is OS-specific. What is pinned
	// here are the two wraps this codebase owns — dialReflectionUpstream's
	// `dial <addr>: ` and Discover's variant wrap, which must name v1
	// because a dial error surfaces on the very first iteration.
	wantPrefix := "reflection (v1): dial " + targetAddr + ": "
	if got := err.Error(); !strings.HasPrefix(got, wantPrefix) {
		t.Errorf("Discover error = %q, want prefix %q", got, wantPrefix)
	}
	// isUnimplementedErr is false for a transport error, so the variant
	// loop must return immediately. Were it ever to fall through, the
	// surfaced error would name v1alpha — either as the second variant's
	// wrap or inside the both-variants "does not implement gRPC
	// reflection" message.
	if strings.Contains(err.Error(), "v1alpha") {
		t.Errorf("Discover fell back to v1alpha on a transport error: %v", err)
	}
}
