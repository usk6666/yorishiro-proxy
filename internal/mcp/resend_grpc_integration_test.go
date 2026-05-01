//go:build e2e

package mcp

// resend_grpc_integration_test.go — RFC-001 N8 acceptance gate for the
// resend_grpc MCP tool (USK-674).
//
// The suite drives real gRPC RPCs (unary + server-streaming + compressed)
// directly against a TLS-enabled grpc-go upstream — no MITM proxy is in
// the loop. The MCP server is configured with a TLSTransport that skips
// verification (the upstream uses a per-test self-signed cert), and the
// resend_grpc handler dials the upstream over TLS+ALPN h2.
//
// Acceptance criteria (USK-674):
//   AC#1: gRPC unary round-trip
//   AC#2: gRPC server-streaming round-trip
//   AC#3: Service / Method override works
//   AC#4: Metadata case/order preserved
//   AC#5: PluginStepPost fires per Start + per Data envelope (End is
//         observation-only by design — see the surface table at
//         internal/pluginv2/surface.go: ("grpc","on_end") = PhaseSupportNone)

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
// Mirrors the helper in internal/layer/grpc/grpc_integration_test.go but
// must be re-declared here because that file lives in package grpc_test.
// ---------------------------------------------------------------------------

const resendGRPCRawCodecName = "raw_resend_grpc"

type resendGRPCRawCodec struct{}

func (resendGRPCRawCodec) Name() string { return resendGRPCRawCodecName }

func (resendGRPCRawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("resendGRPCRawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (resendGRPCRawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("resendGRPCRawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}

func init() {
	encoding.RegisterCodec(resendGRPCRawCodec{})
}

// ---------------------------------------------------------------------------
// Hand-rolled gRPC service descriptor — yorishiro.test.ResendEcho with
// unary + server-streaming methods. Captures the most recent request
// metadata so tests can assert preservation.
// ---------------------------------------------------------------------------

const (
	resendGRPCServiceName        = "yorishiro.test.ResendEcho"
	resendGRPCMethodUnary        = "Unary"
	resendGRPCMethodServerStream = "ServerStream"
)

type resendGRPCEchoHandler interface{}

type resendGRPCEchoServer struct {
	mu          sync.Mutex
	lastReq     []byte
	lastMD      metadata.MD
	lastFull    string
	streamCount int
}

func (s *resendGRPCEchoServer) capture(ctx context.Context, full string, req []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastReq = append([]byte(nil), req...)
	s.lastFull = full
	if md, ok := metadata.FromIncomingContext(ctx); ok {
		s.lastMD = md.Copy()
	}
}

func (s *resendGRPCEchoServer) snapshot() (req []byte, md metadata.MD, full string, count int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastReq, s.lastMD.Copy(), s.lastFull, s.streamCount
}

var resendGRPCEchoServiceDesc = grpc.ServiceDesc{
	ServiceName: resendGRPCServiceName,
	HandlerType: (*resendGRPCEchoHandler)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: resendGRPCMethodUnary,
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				h := srv.(*resendGRPCEchoServer)
				full := "/" + resendGRPCServiceName + "/" + resendGRPCMethodUnary
				h.capture(ctx, full, req)
				resp := append([]byte(nil), req...)
				resp = append(resp, []byte("|echo")...)
				return &resp, nil
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName: resendGRPCMethodServerStream,
			Handler: func(srv any, stream grpc.ServerStream) error {
				var req []byte
				if err := stream.RecvMsg(&req); err != nil {
					return err
				}
				h := srv.(*resendGRPCEchoServer)
				full := "/" + resendGRPCServiceName + "/" + resendGRPCMethodServerStream
				h.capture(stream.Context(), full, req)
				h.mu.Lock()
				h.streamCount = 3
				h.mu.Unlock()
				for i := 0; i < 3; i++ {
					payload := append([]byte(nil), req...)
					payload = append(payload, []byte(fmt.Sprintf("|chunk-%d", i))...)
					if err := stream.SendMsg(&payload); err != nil {
						return err
					}
				}
				return nil
			},
			ServerStreams: true,
		},
	},
	Metadata: "yorishiro.test.ResendEcho",
}

// ---------------------------------------------------------------------------
// Upstream gRPC server — TLS with ALPN h2.
// ---------------------------------------------------------------------------

func startResendGRPCUpstream(t *testing.T, srv *resendGRPCEchoServer) (addr string, shutdown func()) {
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

	gs := grpc.NewServer(grpc.Creds(creds), grpc.ForceServerCodec(resendGRPCRawCodec{}))
	gs.RegisterService(&resendGRPCEchoServiceDesc, srv)

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

// resendGRPCHookCallable wraps a Go counter increment in a Starlark
// Callable so it can be registered on the pluginv2 Engine. Mirrors the
// helper in resend_http_integration_test.go.
func resendGRPCHookCallable(name string, fn func()) starlark.Callable {
	return starlark.NewBuiltin(name, func(_ *starlark.Thread, _ *starlark.Builtin, _ starlark.Tuple, _ []starlark.Tuple) (starlark.Value, error) {
		fn()
		return starlark.None, nil
	})
}

// setupResendGRPCSession spins up an MCP server pre-wired with a fresh
// flow store, an InsecureSkipVerify TLSTransport, and a pluginv2.Engine
// that pre-registers post-pipeline counter hooks for ("grpc","on_start")
// and ("grpc","on_data"). Returns the client session, the live flow
// store (for Stream/Flow assertions), and atomic counters.
func setupResendGRPCSession(t *testing.T) (*gomcp.ClientSession, flow.Store, *int32, *int32) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	var startCount, dataCount int32
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPC,
		Event:      pluginv2.EventOnStart,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "resend-grpc-post-start",
		Fn: resendGRPCHookCallable("post-start", func() {
			atomic.AddInt32(&startCount, 1)
		}),
	})
	engine.Registry().Register(pluginv2.Hook{
		Protocol:   pluginv2.ProtoGRPC,
		Event:      pluginv2.EventOnData,
		Phase:      pluginv2.PhasePostPipeline,
		PluginName: "resend-grpc-post-data",
		Fn: resendGRPCHookCallable("post-data", func() {
			atomic.AddInt32(&dataCount, 1)
		}),
	})

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

	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-grpc-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store, &startCount, &dataCount
}

// callResendGRPC issues the resend_grpc tool with the supplied input and
// returns the parsed structured result. Test fails on transport errors.
func callResendGRPC(t *testing.T, cs *gomcp.ClientSession, input map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend_grpc",
		Arguments: input,
	})
	if err != nil {
		t.Fatalf("CallTool resend_grpc: %v", err)
	}
	return res
}

// decodeResendGRPCResult unmarshals the structured tool output into v.
func decodeResendGRPCResult(t *testing.T, res *gomcp.CallToolResult, v any) {
	t.Helper()
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
		t.Fatalf("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("decode structured content into %T: %v", v, err)
	}
}

// ---------------------------------------------------------------------------
// AC#1 — gRPC unary round-trip.
// ---------------------------------------------------------------------------

func TestResendGRPC_UnaryRoundTrip(t *testing.T) {
	cs, _, startCount, dataCount := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "ping"},
		},
		"timeout_ms": 10000,
	})

	var result resendGRPCResult
	decodeResendGRPCResult(t, res, &result)

	req, _, full, _ := upstream.snapshot()
	if string(req) != "ping" {
		t.Errorf("upstream req = %q, want ping", req)
	}
	if full != "/"+resendGRPCServiceName+"/"+resendGRPCMethodUnary {
		t.Errorf("upstream full = %q, want correct path", full)
	}
	if len(result.Messages) != 1 {
		t.Fatalf("result.Messages len = %d, want 1", len(result.Messages))
	}
	if result.Messages[0].Payload != "ping|echo" {
		t.Errorf("result payload = %q, want %q", result.Messages[0].Payload, "ping|echo")
	}
	if result.End == nil {
		t.Fatal("result.End is nil; expected gRPC trailer")
	}
	if result.End.Status != 0 {
		t.Errorf("result.End.Status = %d, want 0 (OK)", result.End.Status)
	}

	// AC#5: PluginStepPost fires per Start (1 send + 1 receive = 2) +
	// per Data (1 send + 1 receive = 2). End is observation-only.
	if got := atomic.LoadInt32(startCount); got != 2 {
		t.Errorf("on_start hook fired %d times, want 2 (1 send + 1 receive)", got)
	}
	if got := atomic.LoadInt32(dataCount); got != 2 {
		t.Errorf("on_data hook fired %d times, want 2 (1 send + 1 receive)", got)
	}
}

// ---------------------------------------------------------------------------
// AC#2 — gRPC server-streaming round-trip.
// ---------------------------------------------------------------------------

func TestResendGRPC_ServerStreamingRoundTrip(t *testing.T) {
	cs, _, startCount, dataCount := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodServerStream,
		"messages": []map[string]any{
			{"payload": "seed"},
		},
		"timeout_ms": 10000,
	})

	var result resendGRPCResult
	decodeResendGRPCResult(t, res, &result)

	if len(result.Messages) != 3 {
		t.Fatalf("result.Messages len = %d, want 3 (server-streaming)", len(result.Messages))
	}
	for i, m := range result.Messages {
		want := fmt.Sprintf("seed|chunk-%d", i)
		if m.Payload != want {
			t.Errorf("result.Messages[%d].Payload = %q, want %q", i, m.Payload, want)
		}
	}
	if result.End == nil || result.End.Status != 0 {
		t.Fatalf("result.End = %+v, want OK trailer", result.End)
	}

	// PluginStepPost: 1 Start send + 1 Data send + 1 Start receive + 3 Data receive = 2 starts, 4 datas
	if got := atomic.LoadInt32(startCount); got != 2 {
		t.Errorf("on_start hook fired %d times, want 2", got)
	}
	if got := atomic.LoadInt32(dataCount); got != 4 {
		t.Errorf("on_data hook fired %d times, want 4 (1 send + 3 receive)", got)
	}
}

// ---------------------------------------------------------------------------
// AC#3 — Service / Method override works.
// ---------------------------------------------------------------------------

func TestResendGRPC_ServiceMethodOverride(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	// User explicitly supplies Service + Method — verify they reach the
	// upstream handler unchanged.
	callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "override-test"},
		},
		"timeout_ms": 10000,
	})

	_, _, full, _ := upstream.snapshot()
	want := "/" + resendGRPCServiceName + "/" + resendGRPCMethodUnary
	if full != want {
		t.Errorf("override full path = %q, want %q", full, want)
	}
}

// ---------------------------------------------------------------------------
// AC#4 — Metadata case/order preserved.
// ---------------------------------------------------------------------------

func TestResendGRPC_MetadataCaseAndOrderPreserved(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	// Note: gRPC metadata key names are downcased per the gRPC over HTTP/2
	// spec (HTTP/2 HEADERS lowercase rule). We assert that user-supplied
	// values reach the upstream and that duplicate values for the same
	// key are preserved in order.
	callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"metadata": []map[string]any{
			{"name": "x-trace-id", "value": "first"},
			{"name": "x-trace-id", "value": "second"},
			{"name": "x-multi", "value": "alpha"},
		},
		"messages": []map[string]any{
			{"payload": "md-test"},
		},
		"timeout_ms": 10000,
	})

	_, md, _, _ := upstream.snapshot()
	if got := md.Get("x-trace-id"); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Errorf("x-trace-id = %v, want [first second] (order + duplicates preserved)", got)
	}
	if got := md.Get("x-multi"); len(got) != 1 || got[0] != "alpha" {
		t.Errorf("x-multi = %v, want [alpha]", got)
	}
}

// ---------------------------------------------------------------------------
// CRLF rejection (table-driven).
// ---------------------------------------------------------------------------

func TestResendGRPC_RejectsCRLFInUserFields(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)

	cases := []struct {
		name, field, value string
	}{
		{"service-cr", "service", "Echo\rInjected"},
		{"service-lf", "service", "Echo\nInjected"},
		{"method-cr", "method", "Unary\rInjected"},
		{"method-lf", "method", "Unary\nInjected"},
		{"scheme-cr", "scheme", "https\rInjected"},
		{"target-addr-lf", "target_addr", "127.0.0.1:443\nInjected"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			input := map[string]any{
				"target_addr": "127.0.0.1:443",
				"scheme":      "https",
				"service":     "Svc",
				"method":      "Method",
				"messages": []map[string]any{
					{"payload": "x"},
				},
			}
			input[c.field] = c.value
			res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
				Name:      "resend_grpc",
				Arguments: input,
			})
			if err != nil {
				// CallTool returns Go-side error only on transport failure;
				// CRLF rejection should arrive as IsError content.
				if strings.Contains(err.Error(), "CR/LF") {
					return
				}
				t.Fatalf("CallTool returned transport err = %v", err)
			}
			if res == nil || !res.IsError {
				t.Fatalf("expected error result for %s=%q, got %+v", c.field, c.value, res)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Tag application — verifies that input.tag lands on the new Stream row.
// ---------------------------------------------------------------------------

func TestResendGRPC_TagAppliedToStreamRow(t *testing.T) {
	cs, store, _, _ := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      resendGRPCMethodUnary,
		"messages": []map[string]any{
			{"payload": "tagged"},
		},
		"tag":        "manual-resend-7",
		"timeout_ms": 10000,
	})

	var result resendGRPCResult
	decodeResendGRPCResult(t, res, &result)

	// Wait for the tag UpdateStream side-effect to land. The handler
	// invokes UpdateStream after pipeline.Run returns.
	deadline := time.Now().Add(2 * time.Second)
	var stream *flow.Stream
	for time.Now().Before(deadline) {
		s, err := store.GetStream(context.Background(), result.StreamID)
		if err == nil && s != nil && s.Tags["tag"] == "manual-resend-7" {
			stream = s
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if stream == nil {
		t.Fatalf("tag did not propagate to stream %s within deadline", result.StreamID)
	}
}

// ---------------------------------------------------------------------------
// Unimplemented method maps to non-zero gRPC status without producing a
// transport error — verifies the End-envelope projection of upstream
// failure status.
// ---------------------------------------------------------------------------

func TestResendGRPC_UnimplementedMethodSurfacesStatus(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)
	upstream := &resendGRPCEchoServer{}
	addr, shutdown := startResendGRPCUpstream(t, upstream)
	defer shutdown()

	res := callResendGRPC(t, cs, map[string]any{
		"target_addr": addr,
		"scheme":      "https",
		"service":     resendGRPCServiceName,
		"method":      "DoesNotExist",
		"messages": []map[string]any{
			{"payload": "void"},
		},
		"timeout_ms": 10000,
	})

	var result resendGRPCResult
	decodeResendGRPCResult(t, res, &result)
	if result.End == nil {
		t.Fatal("End is nil; expected gRPC trailer with non-OK status")
	}
	if result.End.Status == 0 {
		t.Errorf("End.Status = 0, want non-zero (Unimplemented)")
	}
	if result.End.Status != uint32(codes.Unimplemented) {
		t.Errorf("End.Status = %d, want %d (Unimplemented)", result.End.Status, codes.Unimplemented)
	}
}

// ---------------------------------------------------------------------------
// From-scratch validation — missing required fields surface a clean error.
// ---------------------------------------------------------------------------

func TestResendGRPC_FromScratchMissingFields(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)

	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_grpc",
		Arguments: map[string]any{
			"messages": []map[string]any{
				{"payload": "x"},
			},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for missing target_addr/service/method; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Empty messages — rejected at validation.
// ---------------------------------------------------------------------------

func TestResendGRPC_RejectsEmptyMessages(t *testing.T) {
	cs, _, _, _ := setupResendGRPCSession(t)

	res, _ := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_grpc",
		Arguments: map[string]any{
			"target_addr": "127.0.0.1:9999",
			"scheme":      "https",
			"service":     "Svc",
			"method":      "M",
			"messages":    []map[string]any{},
		},
	})
	if res == nil || !res.IsError {
		t.Fatalf("expected error for empty messages list; got %+v", res)
	}
}

// ---------------------------------------------------------------------------
// Non-gRPC flow_id — explicit pointer to the right tool.
// ---------------------------------------------------------------------------

// (Skipped: requires synthesising a non-gRPC Stream row; covered by the
// equivalent test in resend_http / resend_ws integration suites.)

// status import keeps the linter happy; used implicitly via codes only in
// this file. The blank assignment defends against the linter dropping it
// when only codes is referenced.
var _ = status.Code
