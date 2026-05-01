//go:build e2e

package mcp

// fuzz_grpc_integration_test.go — RFC-001 N8 acceptance gate for the
// fuzz_grpc MCP tool (USK-679).
//
// The suite drives real gRPC RPCs directly against a TLS-enabled
// grpc-go upstream — no MITM proxy is in the loop. The MCP server is
// configured with a TLSTransport that skips verification (the upstream
// uses a per-test self-signed cert), and the fuzz_grpc handler dials
// the upstream over TLS+ALPN h2 once per variant.
//
// Acceptance criteria (USK-679):
//   AC#1: N variant generation + per-variant fuzz Store recording
//   AC#2: Each variant is an independent stream (fresh streamID, fresh
//         connection, fresh ConnID)
//   AC#3: PluginStepPost fires per Start + per Data envelope per variant;
//         End is observation-only (PhaseSupportNone in surface table)
//   AC#4: Legacy `fuzz` tool unaffected (parallel coexistence)

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"go.starlark.net/starlark"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	// Force-register the gzip compressor on the gRPC server.
	_ "google.golang.org/grpc/encoding/gzip"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// ---------------------------------------------------------------------------
// Raw codec — round-trips []byte payloads without protobuf marshalling.
// Mirrors the helper in resend_grpc_integration_test.go but must be
// re-declared here because that file lives in the same package and
// re-using its codec name would cause RegisterCodec to panic on init.
// ---------------------------------------------------------------------------

const fuzzGRPCRawCodecName = "raw_fuzz_grpc"

type fuzzGRPCRawCodec struct{}

func (fuzzGRPCRawCodec) Name() string { return fuzzGRPCRawCodecName }

func (fuzzGRPCRawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("fuzzGRPCRawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (fuzzGRPCRawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("fuzzGRPCRawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}

func init() {
	encoding.RegisterCodec(fuzzGRPCRawCodec{})
}

// ---------------------------------------------------------------------------
// Hand-rolled gRPC service descriptor — yorishiro.test.FuzzEcho with a
// unary method. Captures every observed request so tests can assert
// per-variant payload / metadata reached the upstream.
// ---------------------------------------------------------------------------

const (
	fuzzGRPCServiceName = "yorishiro.test.FuzzEcho"
	fuzzGRPCMethodUnary = "Unary"
)

type fuzzGRPCObservedRequest struct {
	Payload  []byte
	Metadata metadata.MD
	FullPath string
}

type fuzzGRPCEchoServer struct {
	mu       sync.Mutex
	observed []fuzzGRPCObservedRequest
	respond  func(req []byte) (resp []byte, st *status.Status)
}

func (s *fuzzGRPCEchoServer) capture(ctx context.Context, full string, req []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := fuzzGRPCObservedRequest{
		Payload:  append([]byte(nil), req...),
		FullPath: full,
	}
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		entry.Metadata = md.Copy()
	}
	s.observed = append(s.observed, entry)
}

func (s *fuzzGRPCEchoServer) snapshot() []fuzzGRPCObservedRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]fuzzGRPCObservedRequest, len(s.observed))
	copy(out, s.observed)
	return out
}

type fuzzGRPCEchoHandler interface{}

var fuzzGRPCEchoServiceDesc = grpc.ServiceDesc{
	ServiceName: fuzzGRPCServiceName,
	HandlerType: (*fuzzGRPCEchoHandler)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: fuzzGRPCMethodUnary,
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				h := srv.(*fuzzGRPCEchoServer)
				full := "/" + fuzzGRPCServiceName + "/" + fuzzGRPCMethodUnary
				h.capture(ctx, full, req)
				h.mu.Lock()
				respond := h.respond
				h.mu.Unlock()
				if respond != nil {
					resp, st := respond(req)
					if st != nil {
						return nil, st.Err()
					}
					return &resp, nil
				}
				resp := append([]byte(nil), req...)
				resp = append(resp, []byte("|echo")...)
				return &resp, nil
			},
		},
	},
	Metadata: "yorishiro.test.FuzzEcho",
}

// ---------------------------------------------------------------------------
// Upstream gRPC server — TLS with ALPN h2.
// ---------------------------------------------------------------------------

func startFuzzGRPCUpstream(t *testing.T, srv *fuzzGRPCEchoServer) (addr string, shutdown func()) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)
	leaf, err := issuer.GetCertificate("localhost")
	if err != nil {
		t.Fatalf("issue cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
	creds := credentials.NewTLS(tlsCfg)

	gs := grpc.NewServer(grpc.Creds(creds), grpc.ForceServerCodec(fuzzGRPCRawCodec{}))
	gs.RegisterService(&fuzzGRPCEchoServiceDesc, srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	return ln.Addr().String(), func() {
		gs.GracefulStop()
		_ = ln.Close()
	}
}

// ---------------------------------------------------------------------------
// MCP test session helpers.
// ---------------------------------------------------------------------------

// fuzzGRPCHookCallable wraps a Go counter increment in a Starlark
// Callable so it can be registered on the pluginv2 Engine.
func fuzzGRPCHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// fuzzGRPCSessionCounters bundles the atomic counters returned by
// setupFuzzGRPCSession so callers don't have to juggle four pointers.
type fuzzGRPCSessionCounters struct {
	preStart  int32
	postStart int32
	preData   int32
	postData  int32
}

// setupFuzzGRPCSession spins up an MCP server pre-wired with a fresh
// flow store, an InsecureSkipVerify TLSTransport, and a pluginv2.Engine
// that pre-registers pre/post counter hooks for ("grpc","on_start") and
// ("grpc","on_data"). Returns the client session, the live flow store,
// and the counters bundle.
func setupFuzzGRPCSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *fuzzGRPCSessionCounters) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	c := &fuzzGRPCSessionCounters{}
	for _, h := range []pluginv2.Hook{
		{
			Protocol:   pluginv2.ProtoGRPC,
			Event:      pluginv2.EventOnStart,
			Phase:      pluginv2.PhasePrePipeline,
			PluginName: "fuzz-grpc-pre-start",
			Fn: fuzzGRPCHookCallable("pre-start", func() {
				atomic.AddInt32(&c.preStart, 1)
			}),
		},
		{
			Protocol:   pluginv2.ProtoGRPC,
			Event:      pluginv2.EventOnStart,
			Phase:      pluginv2.PhasePostPipeline,
			PluginName: "fuzz-grpc-post-start",
			Fn: fuzzGRPCHookCallable("post-start", func() {
				atomic.AddInt32(&c.postStart, 1)
			}),
		},
		{
			Protocol:   pluginv2.ProtoGRPC,
			Event:      pluginv2.EventOnData,
			Phase:      pluginv2.PhasePrePipeline,
			PluginName: "fuzz-grpc-pre-data",
			Fn: fuzzGRPCHookCallable("pre-data", func() {
				atomic.AddInt32(&c.preData, 1)
			}),
		},
		{
			Protocol:   pluginv2.ProtoGRPC,
			Event:      pluginv2.EventOnData,
			Phase:      pluginv2.PhasePostPipeline,
			PluginName: "fuzz-grpc-post-data",
			Fn: fuzzGRPCHookCallable("post-data", func() {
				atomic.AddInt32(&c.postData, 1)
			}),
		},
	} {
		engine.Registry().Register(h)
	}

	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil,
		WithPluginv2Engine(engine),
		WithTLSTransport(&httputil.StandardTransport{InsecureSkipVerify: true}),
	)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "fuzz-grpc-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, c
}

// callFuzzGRPC issues the fuzz_grpc tool with the supplied input and
// returns the parsed structured result. Test fails on transport errors
// or IsError responses.
func callFuzzGRPC(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *fuzzGRPCResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "fuzz_grpc",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool fuzz_grpc: %v", err)
	}
	if res.IsError {
		var msg strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*gomcp.TextContent); ok {
				msg.WriteString(tc.Text)
				msg.WriteString("\n")
			}
		}
		t.Fatalf("tool returned error: %s", msg.String())
	}
	if res.StructuredContent == nil {
		t.Fatal("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	var out fuzzGRPCResult
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode structured content: %v", err)
	}
	return &out
}

// ---------------------------------------------------------------------------
// AC#1 + AC#2 + AC#3 — N variant generation + independent streams +
// PluginStepPost firing per Start + per Data envelope.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_PayloadPositionGeneratesVariants(t *testing.T) {
	cs, store, c := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	payloads := []string{"alpha", "beta", "gamma", "delta"}
	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": payloads},
		},
		"timeout_ms": 10000,
	})

	if result.TotalVariants != len(payloads) {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, len(payloads))
	}
	if result.CompletedVariants != len(payloads) {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, len(payloads))
	}
	if len(result.Variants) != len(payloads) {
		t.Fatalf("len(Variants) = %d, want %d", len(result.Variants), len(payloads))
	}

	// AC#2: Each variant must have its own Stream row, with distinct StreamIDs.
	seenStreamIDs := map[string]bool{}
	for i, row := range result.Variants {
		if row.StreamID == "" {
			t.Errorf("variants[%d].StreamID is empty", i)
		}
		if seenStreamIDs[row.StreamID] {
			t.Errorf("variants[%d].StreamID = %q is duplicated — variants must be independent streams", i, row.StreamID)
		}
		seenStreamIDs[row.StreamID] = true
		if row.Status != 0 {
			t.Errorf("variants[%d].Status = %d, want 0 (OK)", i, row.Status)
		}
		if row.Error != "" {
			t.Errorf("variants[%d].Error = %q, want empty", i, row.Error)
		}
		s, err := store.GetStream(context.Background(), row.StreamID)
		if err != nil || s == nil {
			t.Errorf("variants[%d]: GetStream(%s) err=%v", i, row.StreamID, err)
		}
	}

	// AC#1: Upstream observed each fuzzed payload exactly once.
	observed := upstream.snapshot()
	if len(observed) != len(payloads) {
		t.Fatalf("upstream observed %d requests, want %d", len(observed), len(payloads))
	}
	seenPayloads := map[string]bool{}
	for _, o := range observed {
		seenPayloads[string(o.Payload)] = true
	}
	for _, p := range payloads {
		if !seenPayloads[p] {
			t.Errorf("upstream did not see payload %q", p)
		}
	}

	// AC#3: PluginStepPost fires per Start (1 send + 1 receive = 2) +
	// per Data (1 send + 1 receive = 2) per variant. Pre never fires
	// (resend bypass per RFC §9.3 D1).
	wantPostStart := int32(2 * len(payloads))
	wantPostData := int32(2 * len(payloads))
	if got := atomic.LoadInt32(&c.postStart); got != wantPostStart {
		t.Errorf("on_start post hook fired %d times, want %d (1 send + 1 receive per variant)", got, wantPostStart)
	}
	if got := atomic.LoadInt32(&c.postData); got != wantPostData {
		t.Errorf("on_data post hook fired %d times, want %d (1 send + 1 receive per variant)", got, wantPostData)
	}
	if got := atomic.LoadInt32(&c.preStart); got != 0 {
		t.Errorf("on_start pre hook fired %d times, want 0 (PluginStepPre bypassed)", got)
	}
	if got := atomic.LoadInt32(&c.preData); got != 0 {
		t.Errorf("on_data pre hook fired %d times, want 0 (PluginStepPre bypassed)", got)
	}
}

// ---------------------------------------------------------------------------
// Position path: metadata[N].value mutation reaches the upstream.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_MetadataValuePosition(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	values := []string{"alpha-md", "beta-md", "gamma-md"}
	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"metadata": []map[string]any{
			{"name": "x-fuzz-marker", "value": "ORIGINAL"},
		},
		"messages": []map[string]any{
			{"payload": "p"},
		},
		"positions": []map[string]any{
			{"path": "metadata[0].value", "payloads": values},
		},
		"timeout_ms": 10000,
	})
	if result.CompletedVariants != len(values) {
		t.Fatalf("CompletedVariants = %d, want %d", result.CompletedVariants, len(values))
	}

	observed := upstream.snapshot()
	seen := map[string]bool{}
	for _, o := range observed {
		if got := o.Metadata.Get("x-fuzz-marker"); len(got) > 0 {
			seen[got[0]] = true
		}
	}
	for _, v := range values {
		if !seen[v] {
			t.Errorf("upstream did not see x-fuzz-marker=%q (saw %v)", v, seen)
		}
	}
	if seen["ORIGINAL"] {
		t.Error("upstream saw x-fuzz-marker=ORIGINAL — base metadata leaked into a variant")
	}
}

// ---------------------------------------------------------------------------
// Cartesian product across two positions (service × messages[0].payload).
// ---------------------------------------------------------------------------

func TestFuzzGRPC_TwoPositionCartesian(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	upstream.respond = func(req []byte) ([]byte, *status.Status) {
		// Simulate "service unknown" for Wrong service mutation by relying
		// on the test harness service name; the descriptor is registered
		// only for fuzzGRPCServiceName, so any other name surfaces as
		// Unimplemented from grpc-go's mux. The handler captures BEFORE
		// the framework rejects, so capture covers all calls that reach
		// the registered handler. For this test, we keep service
		// constant and only fuzz the payload — see Note below.
		resp := append([]byte(nil), req...)
		resp = append(resp, []byte("|cart")...)
		return resp, nil
	}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	// We fuzz two positions: messages[0].payload (3 values) and
	// metadata[0].value (2 values). Total = 6 variants.
	payloads := []string{"x1", "x2", "x3"}
	mdValues := []string{"a", "b"}
	expectedTotal := len(payloads) * len(mdValues)

	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"metadata": []map[string]any{
			{"name": "x-fuzz-mode", "value": "ORIG"},
		},
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": payloads},
			{"path": "metadata[0].value", "payloads": mdValues},
		},
		"timeout_ms": 10000,
	})
	if result.TotalVariants != expectedTotal {
		t.Errorf("TotalVariants = %d, want %d", result.TotalVariants, expectedTotal)
	}
	if result.CompletedVariants != expectedTotal {
		t.Errorf("CompletedVariants = %d, want %d", result.CompletedVariants, expectedTotal)
	}
	observed := upstream.snapshot()
	if len(observed) != expectedTotal {
		t.Fatalf("upstream hits = %d, want %d", len(observed), expectedTotal)
	}

	// Every (payload, mdValue) pair must have hit the upstream.
	pairs := map[string]bool{}
	for _, o := range observed {
		md := ""
		if got := o.Metadata.Get("x-fuzz-mode"); len(got) > 0 {
			md = got[0]
		}
		pairs[fmt.Sprintf("%s|%s", string(o.Payload), md)] = true
	}
	for _, pl := range payloads {
		for _, mv := range mdValues {
			key := fmt.Sprintf("%s|%s", pl, mv)
			if !pairs[key] {
				t.Errorf("missing variant pair %q", key)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Validation: empty positions rejected.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsEmptyPositions(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty positions; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: invalid path syntax rejected.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsInvalidPath(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				// scheme is intentionally not a fuzz position; reject.
				{"path": "scheme", "payloads": []string{"http"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for invalid path; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: out-of-range index rejected at plan time.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsOutOfRangeMessageIndex(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				// Only 1 message present (index 0); index 5 is out of range.
				{"path": "messages[5].payload", "payloads": []string{"y"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for out-of-range index; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: variant count cap enforced at validate time.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsExcessiveVariantCount(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	bigList := make([]string, 100)
	for i := range bigList {
		bigList[i] = fmt.Sprintf("p%d", i)
	}
	// 2 positions × 100 × 100 = 10000 → exceeds 1000 cap.
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				{"path": "messages[0].payload", "payloads": bigList},
				{"path": "method", "payloads": bigList},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for excessive variant count; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: empty payloads in a position rejected.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsEmptyPayloads(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				{"path": "messages[0].payload", "payloads": []string{}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty payloads; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Validation: per-payload decoded size cap (CWE-770 — mirrors fuzz_http).
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsExcessivePayloadSize(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	bigPayload := strings.Repeat("A", 2<<20) // 2 MiB > 1 MiB cap
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				{"path": "messages[0].payload", "payloads": []string{bigPayload}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for oversized payload; got %+v", res)
	}
	var msg strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			msg.WriteString(tc.Text)
		}
	}
	if !strings.Contains(msg.String(), "exceeds") {
		t.Errorf("error message %q does not mention size cap", msg.String())
	}
}

// ---------------------------------------------------------------------------
// stop_on_non_ok aborts remaining variants when an upstream returns
// non-OK gRPC status.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_StopOnNonOKAbortsRemaining(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	upstream.respond = func(req []byte) ([]byte, *status.Status) {
		if string(req) == "BOOM" {
			return nil, status.New(codes.FailedPrecondition, "intentional test failure")
		}
		resp := append([]byte(nil), req...)
		resp = append(resp, []byte("|ok")...)
		return resp, nil
	}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	// Position 0 = messages[0].payload. Variants iterate position 0 in
	// order: ok1, BOOM, ok2. The second variant returns FailedPrecondition,
	// stop_on_non_ok aborts the third.
	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"ok1", "BOOM", "ok2"}},
		},
		"stop_on_non_ok": true,
		"timeout_ms":     10000,
	})
	if result.CompletedVariants != 2 {
		t.Errorf("CompletedVariants = %d, want 2 (first OK, second non-OK aborted)", result.CompletedVariants)
	}
	if result.StoppedReason == "" {
		t.Error("StoppedReason is empty; want a stop_on_non_ok reason")
	}
	if len(result.Variants) != 2 {
		t.Fatalf("len(Variants) = %d, want 2", len(result.Variants))
	}
	if result.Variants[1].Status != uint32(codes.FailedPrecondition) {
		t.Errorf("variants[1].Status = %d, want %d (FailedPrecondition)", result.Variants[1].Status, codes.FailedPrecondition)
	}
}

// ---------------------------------------------------------------------------
// Tag application — every variant Stream gets the tag.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_TagAppliedToEachVariantStream(t *testing.T) {
	cs, store, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{"v1", "v2"}},
		},
		"tag":        "fuzz-grpc-tag-7",
		"timeout_ms": 10000,
	})
	if result.CompletedVariants != 2 {
		t.Fatalf("CompletedVariants = %d, want 2", result.CompletedVariants)
	}

	// The tag UpdateStream side-effect is best-effort and ordered after
	// pipeline.Run; poll briefly to avoid a flake.
	deadline := time.Now().Add(2 * time.Second)
	for i, row := range result.Variants {
		var stream *flow.Stream
		for time.Now().Before(deadline) {
			s, err := store.GetStream(context.Background(), row.StreamID)
			if err == nil && s != nil && s.Tags["tag"] == "fuzz-grpc-tag-7" {
				stream = s
				break
			}
			time.Sleep(20 * time.Millisecond)
		}
		if stream == nil {
			t.Fatalf("variants[%d]: tag did not propagate to stream %s within deadline", i, row.StreamID)
		}
	}
}

// ---------------------------------------------------------------------------
// Wire-fidelity: payload CRLF / NUL / control chars pass through verbatim
// (MITM principle). Position payloads bypass the base CRLF guard by
// design — see fuzz_grpc_helpers.go file-level docstring.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_PayloadCRLFPassesThrough(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	upstream := &fuzzGRPCEchoServer{}
	addr, shutdown := startFuzzGRPCUpstream(t, upstream)
	defer shutdown()

	// A payload containing CR/LF reaches the upstream verbatim (gRPC
	// payloads are opaque bytes, not parsed by HTTP/2 framing for CRLF).
	smuggling := "begin\r\ninjected\nend"
	result := callFuzzGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     fuzzGRPCServiceName,
		"method":      fuzzGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"positions": []map[string]any{
			{"path": "messages[0].payload", "payloads": []string{smuggling}},
		},
		"timeout_ms": 10000,
	})
	if result.CompletedVariants != 1 {
		t.Fatalf("CompletedVariants = %d, want 1", result.CompletedVariants)
	}
	observed := upstream.snapshot()
	if len(observed) != 1 {
		t.Fatalf("upstream hits = %d, want 1", len(observed))
	}
	if string(observed[0].Payload) != smuggling {
		t.Errorf("upstream payload = %q, want %q (CR/LF must pass through verbatim)", observed[0].Payload, smuggling)
	}
}

// ---------------------------------------------------------------------------
// Validation: base CRLF guard inherited from resend_grpc still rejects
// CR/LF in user-supplied URL/RPC components.
// ---------------------------------------------------------------------------

func TestFuzzGRPC_RejectsCRLFInBaseFields(t *testing.T) {
	cs, _, _ := setupFuzzGRPCSession(t)
	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "fuzz_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc\r\nInjected",
			"method":      "M",
			"messages": []map[string]any{
				{"payload": "x"},
			},
			"positions": []map[string]any{
				{"path": "messages[0].payload", "payloads": []string{"y"}},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for CRLF in service field; got %+v", res)
	}
}

// status import keeps the linter happy on platforms where codes is
// referenced only inside conditionals.
var _ = status.Code
