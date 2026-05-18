//go:build e2e && !e2e_smoke

// Package mcp resend_grpc_listener_capture_integration_test.go is the
// USK-920 acceptance gate: a listener-captured gRPC flow (via
// proxybuild.Manager + ForwardConfig.Protocol="grpc") must be replayable
// by resend_grpc using only {flow_id, messages}, with no manual overrides
// for target_addr / scheme / service / method.
//
// USK-922/923 follow-up: the test must also cover the
// body_encoding ∈ {"base64", "proto-schemaless-json", "proto-json (with
// schema)", "proto-json (without schema)"} matrix on the recovered
// listener-captured flow. The no-schema arm asserts the error string
// includes the recovered service / method so the operator sees the
// recovered identity rather than empty strings.
//
// Tagged `e2e && !e2e_smoke` per CLAUDE.md guidance: it spins up a full
// proxybuild Manager + grpc-go upstream, so it belongs in the nightly
// full tier rather than the per-PR merge gate.
package mcp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// ---------------------------------------------------------------------------
// Raw codec — round-trips []byte payloads without protobuf marshalling.
// Re-declared here under a unique name so the codec registration does not
// collide with the codec(s) registered by sibling integration tests in
// other packages.
// ---------------------------------------------------------------------------

const listenerCaptureRawCodecName = "raw_listener_capture"

type listenerCaptureRawCodec struct{}

func (listenerCaptureRawCodec) Name() string { return listenerCaptureRawCodecName }

func (listenerCaptureRawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("listenerCaptureRawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (listenerCaptureRawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("listenerCaptureRawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}

func init() {
	encoding.RegisterCodec(listenerCaptureRawCodec{})
}

// ---------------------------------------------------------------------------
// Upstream service — usk.test.Greeter / SayHello, raw-codec.
//
// We deliberately use the same service+method names as the protoschema
// test fixture so the registered FileDescriptorSet (used by the
// proto-json case) matches the wire :path.
// ---------------------------------------------------------------------------

const (
	listenerCaptureServiceName = "usk.test.Greeter"
	listenerCaptureMethodName  = "SayHello"
)

type listenerCaptureGreeterServer struct {
	mu      sync.Mutex
	lastReq []byte
	callCnt int
}

func (g *listenerCaptureGreeterServer) record(req []byte) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.lastReq = append([]byte(nil), req...)
	g.callCnt++
}

var listenerCaptureGreeterDesc = grpc.ServiceDesc{
	ServiceName: listenerCaptureServiceName,
	HandlerType: (*any)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: listenerCaptureMethodName,
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				h := srv.(*listenerCaptureGreeterServer)
				h.record(req)
				// Echo bytes back so the client's RecvMsg sees something.
				resp := append([]byte(nil), req...)
				return &resp, nil
			},
		},
	},
	Metadata: listenerCaptureServiceName,
}

// startH2CGreeterUpstream starts an h2c gRPC server on a random local
// port. Returns (addr, server-pointer, shutdown).
func startH2CGreeterUpstream(t *testing.T) (addr string, srv *listenerCaptureGreeterServer, shutdown func()) {
	t.Helper()
	srv = &listenerCaptureGreeterServer{}
	gs := grpc.NewServer(grpc.ForceServerCodec(listenerCaptureRawCodec{}))
	gs.RegisterService(&listenerCaptureGreeterDesc, srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	return ln.Addr().String(), srv, func() {
		gs.GracefulStop()
		_ = ln.Close()
	}
}

// ---------------------------------------------------------------------------
// proxybuild manager wiring — bound to the SQLite store backing the MCP
// session.
// ---------------------------------------------------------------------------

// startGRPCForwardListener constructs a proxybuild.Manager wired to
// `store` and brings up a TCP forward listener with
// ForwardConfig.Protocol="grpc" targeting `upstreamAddr` (h2c upstream).
// Returns the manager and the bound forward address.
func startGRPCForwardListener(t *testing.T, ctx context.Context, store flow.Store, upstreamAddr string) (
	mgr *proxybuild.Manager, fwdAddr string,
) {
	t.Helper()
	logger := testutil.DiscardLogger()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("ca.Generate: %v", err)
	}
	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
	factory := func(ctx context.Context, name, addr string) (*proxybuild.Stack, error) {
		return proxybuild.BuildLiveStack(ctx, proxybuild.Deps{
			Logger:       logger,
			ListenerName: name,
			ListenAddr:   addr,
			FlowStore:    store,
			BuildConfig:  buildCfg,
		})
	}
	m, err := proxybuild.NewManager(proxybuild.ManagerConfig{
		Logger:       logger,
		StackFactory: factory,
	})
	if err != nil {
		t.Fatalf("NewManager: %v", err)
	}
	if err := m.Start(ctx, "127.0.0.1:0"); err != nil {
		t.Fatalf("manager.Start: %v", err)
	}
	if err := m.StartTCPForwards(ctx, proxybuild.TCPForwardParams{
		Forwards: map[string]*config.ForwardConfig{
			"0": {Target: upstreamAddr, Protocol: "grpc"},
		},
	}); err != nil {
		t.Fatalf("StartTCPForwards: %v", err)
	}
	addrs := m.TCPForwardAddrs()
	fwdAddr = addrs["0"]
	if fwdAddr == "" {
		t.Fatalf("TCPForwardAddrs missing port 0: %v", addrs)
	}
	return m, fwdAddr
}

// ---------------------------------------------------------------------------
// MCP session wiring (shares the SQLite store with proxybuild).
// ---------------------------------------------------------------------------

// setupListenerCaptureMCPSession creates an MCP client session backed by
// `store`. InsecureSkipVerify is enabled on the TLSTransport for parity
// with the rest of the resend_grpc suite (the resend in our test paths
// dials over plaintext h2c, but the option is harmless).
func setupListenerCaptureMCPSession(t *testing.T, store flow.Store) *gomcp.ClientSession {
	t.Helper()
	ctx := context.Background()
	s := newServer(ctx, nil, store, nil,
		WithTLSTransport(&transport.StandardTransport{InsecureSkipVerify: true}),
	)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "listener-capture-resend-grpc-test",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

// registerListenerCaptureSchema registers the embedded test fixture
// FileDescriptorSet into the running MCP server's grpc_schema registry
// for the proto-json arms.
func registerListenerCaptureSchema(t *testing.T, cs *gomcp.ClientSession) {
	t.Helper()
	b64 := base64.StdEncoding.EncodeToString(embeddedTestDescBytes)
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "grpc_schema",
		Arguments: map[string]any{
			"action": "register",
			"params": map[string]any{
				"source":             "descriptor_set",
				"descriptor_set_b64": b64,
			},
		},
	})
	if err != nil {
		t.Fatalf("grpc_schema register: %v", err)
	}
	if res.IsError {
		t.Fatalf("grpc_schema register error: %v", res.Content)
	}
}

// ---------------------------------------------------------------------------
// Helpers — driving the captured RPC + locating the recorded flow.
// ---------------------------------------------------------------------------

// driveOneRPCThroughForward dials the forward port over h2c and invokes
// SayHello with `payload` as the raw-codec body. The upstream echoes it
// back; we wait for the request to land in `srv.lastReq` before
// returning.
func driveOneRPCThroughForward(t *testing.T, ctx context.Context, fwdAddr string, srv *listenerCaptureGreeterServer, payload []byte) {
	t.Helper()
	cc, err := grpc.NewClient(fwdAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(listenerCaptureRawCodec{})),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer cc.Close()

	full := "/" + listenerCaptureServiceName + "/" + listenerCaptureMethodName
	req := payload
	var resp []byte
	if err := cc.Invoke(ctx, full, &req, &resp); err != nil {
		t.Fatalf("Invoke %s: %v", full, err)
	}
	if string(resp) != string(payload) {
		t.Errorf("upstream echo = %q, want %q", resp, payload)
	}
	// Sanity check upstream captured something.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		srv.mu.Lock()
		c := srv.callCnt
		srv.mu.Unlock()
		if c > 0 {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("upstream never observed the RPC call")
}

// waitForListenerCapturedGRPCFlow polls the store until a Send-direction
// flow tagged grpc_event=start with grpc_service / grpc_method matching
// our fixture is present, then returns its flow_id (which is also the
// stream_id — gRPC starts open a new stream).
func waitForListenerCapturedGRPCFlow(t *testing.T, store flow.Store) string {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "grpc"})
		if err == nil {
			for _, st := range streams {
				flows, ferr := store.GetFlows(ctx, st.ID, flow.FlowListOptions{Direction: "send"})
				if ferr != nil || len(flows) == 0 {
					continue
				}
				for _, fl := range flows {
					if fl.Metadata == nil {
						continue
					}
					if fl.Metadata["grpc_event"] != "start" {
						continue
					}
					if fl.Metadata["grpc_service"] != listenerCaptureServiceName {
						continue
					}
					if fl.Metadata["grpc_method"] != listenerCaptureMethodName {
						continue
					}
					return st.ID
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("never saw a listener-captured grpc Start flow with the expected service/method")
	return ""
}

// callResendGRPCWithStruct issues resend_grpc with the supplied map. The
// caller gets the raw result so it can branch on IsError vs a successful
// structured payload.
func callResendGRPCWithStruct(t *testing.T, cs *gomcp.ClientSession, args map[string]any) *gomcp.CallToolResult {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name:      "resend_grpc",
		Arguments: args,
	})
	if err != nil {
		t.Fatalf("CallTool resend_grpc: %v", err)
	}
	return res
}

// extractToolErrorText returns the concatenated TextContent of an
// IsError=true tool result.
func extractToolErrorText(res *gomcp.CallToolResult) string {
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*gomcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}

// decodeStructured unmarshals a non-error result's StructuredContent.
func decodeStructured(t *testing.T, res *gomcp.CallToolResult, v any) {
	t.Helper()
	if res.IsError {
		t.Fatalf("expected success, got error: %s", extractToolErrorText(res))
	}
	if res.StructuredContent == nil {
		t.Fatalf("expected structured content, got nil")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured: %v", err)
	}
	if err := json.Unmarshal(raw, v); err != nil {
		t.Fatalf("unmarshal structured: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

// TestResendGRPCListenerCapture_FlowIDAlone_Base64 is the canonical
// USK-920 acceptance gate: a listener-captured gRPC flow must resend with
// {flow_id, messages: [{payload, body_encoding:"base64"}]} and no manual
// overrides.
func TestResendGRPCListenerCapture_FlowIDAlone_Base64(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := newTestStore(t)
	upAddr, upSrv, upStop := startH2CGreeterUpstream(t)
	defer upStop()
	mgr, fwdAddr := startGRPCForwardListener(t, ctx, store, upAddr)
	defer mgr.StopAll(context.Background())

	driveOneRPCThroughForward(t, ctx, fwdAddr, upSrv, []byte("hello-listener"))
	flowID := waitForListenerCapturedGRPCFlow(t, store)

	cs := setupListenerCaptureMCPSession(t, store)

	// Recovery sanity: flow_id only, base64-encoded payload. The resend
	// must dial the same h2c upstream (scheme=http recovered) and the
	// service / method must come from the listener-captured Flow.URL.
	res := callResendGRPCWithStruct(t, cs, map[string]any{
		"flow_id": flowID,
		"messages": []map[string]any{
			{
				"payload":       base64.StdEncoding.EncodeToString([]byte("resend-listener")),
				"body_encoding": "base64",
			},
		},
		"timeout_ms": 10000,
	})
	var out resendGRPCResult
	decodeStructured(t, res, &out)
	if upSrv.callCnt < 2 {
		t.Errorf("upstream callCnt=%d, want >= 2 after resend", upSrv.callCnt)
	}
}

// TestResendGRPCListenerCapture_FlowIDAlone_ProtoSchemalessJSON exercises
// USK-922 addendum #1: body_encoding="proto-schemaless-json" must work
// flow_id-only on a listener-captured flow.
func TestResendGRPCListenerCapture_FlowIDAlone_ProtoSchemalessJSON(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := newTestStore(t)
	upAddr, upSrv, upStop := startH2CGreeterUpstream(t)
	defer upStop()
	mgr, fwdAddr := startGRPCForwardListener(t, ctx, store, upAddr)
	defer mgr.StopAll(context.Background())

	driveOneRPCThroughForward(t, ctx, fwdAddr, upSrv, []byte("\x0a\x05hello"))
	flowID := waitForListenerCapturedGRPCFlow(t, store)

	cs := setupListenerCaptureMCPSession(t, store)

	// proto-schemaless-json uses PacketProxy-style "FFFF:OOOO:Type" keys
	// (see internal/encoding/protobuf). Field 1 / ordinal 0 / String for
	// the f_string field on usk.test.HelloRequest. The upstream codec is
	// raw bytes so any well-formed proto payload round-trips.
	res := callResendGRPCWithStruct(t, cs, map[string]any{
		"flow_id": flowID,
		"messages": []map[string]any{
			{
				"payload":       `{"0001:0000:String":"resend-schemaless"}`,
				"body_encoding": "proto-schemaless-json",
			},
		},
		"timeout_ms": 10000,
	})
	var out resendGRPCResult
	decodeStructured(t, res, &out)
}

// TestResendGRPCListenerCapture_FlowIDAlone_ProtoJSON_WithSchema exercises
// USK-923 addendum #2: body_encoding="proto-json" with a registered
// schema must work flow_id-only.
func TestResendGRPCListenerCapture_FlowIDAlone_ProtoJSON_WithSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := newTestStore(t)
	upAddr, upSrv, upStop := startH2CGreeterUpstream(t)
	defer upStop()
	mgr, fwdAddr := startGRPCForwardListener(t, ctx, store, upAddr)
	defer mgr.StopAll(context.Background())

	driveOneRPCThroughForward(t, ctx, fwdAddr, upSrv, []byte("\x0a\x05hello"))
	flowID := waitForListenerCapturedGRPCFlow(t, store)

	cs := setupListenerCaptureMCPSession(t, store)
	registerListenerCaptureSchema(t, cs)

	res := callResendGRPCWithStruct(t, cs, map[string]any{
		"flow_id": flowID,
		"messages": []map[string]any{
			{
				"payload":       `{"f_string":"hello-proto-json","f_int32":42}`,
				"body_encoding": "proto-json",
			},
		},
		"timeout_ms": 10000,
	})
	var out resendGRPCResult
	decodeStructured(t, res, &out)
}

// TestResendGRPCListenerCapture_FlowIDAlone_ProtoJSON_NoSchema exercises
// USK-920 addendum #3: when body_encoding="proto-json" is used without a
// registered schema, the hard error must include the recovered service /
// method (not empty strings) so the operator can immediately call
// grpc_schema register with the right name.
func TestResendGRPCListenerCapture_FlowIDAlone_ProtoJSON_NoSchema(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	store := newTestStore(t)
	upAddr, upSrv, upStop := startH2CGreeterUpstream(t)
	defer upStop()
	mgr, fwdAddr := startGRPCForwardListener(t, ctx, store, upAddr)
	defer mgr.StopAll(context.Background())

	driveOneRPCThroughForward(t, ctx, fwdAddr, upSrv, []byte("\x0a\x05hello"))
	flowID := waitForListenerCapturedGRPCFlow(t, store)

	cs := setupListenerCaptureMCPSession(t, store)
	// NOTE: deliberately NOT calling registerListenerCaptureSchema.

	res := callResendGRPCWithStruct(t, cs, map[string]any{
		"flow_id": flowID,
		"messages": []map[string]any{
			{
				"payload":       `{"f_string":"no-schema"}`,
				"body_encoding": "proto-json",
			},
		},
		"timeout_ms": 10000,
	})
	if !res.IsError {
		t.Fatalf("expected error, got success: %+v", res.StructuredContent)
	}
	errText := extractToolErrorText(res)
	if !strings.Contains(errText, listenerCaptureServiceName) {
		t.Errorf("error text missing recovered service %q: %q", listenerCaptureServiceName, errText)
	}
	if !strings.Contains(errText, listenerCaptureMethodName) {
		t.Errorf("error text missing recovered method %q: %q", listenerCaptureMethodName, errText)
	}
}
