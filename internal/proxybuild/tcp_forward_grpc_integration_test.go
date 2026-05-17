//go:build e2e && !e2e_smoke

// Package proxybuild_test exhaustive tier — USK-914 gRPC over h2c forward
// proxy. Validates the ForwardConfig.Protocol="grpc" arm (h2c stack +
// per-stream content-type filter) round-trips unary / server-streaming /
// bidi RPCs and rejects non-gRPC streams.
//
// The harness duplicates the minimum-needed gRPC fixtures from
// internal/layer/grpc/grpc_integration_test.go (echoServer, rawCodec) so
// this file does not cross-package import an _test fixture.
package proxybuild_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/status"
)

// rawCodecName / rawCodec — duplicated from internal/layer/grpc/grpc_integration_test.go.
// Registers as "rawforward" so the codec name does not collide with the
// "raw" codec the source-of-truth fixture registers in its own test
// binary (Go test caches package binaries per build-tag set, but the
// safety belt is cheap).
const rawCodecName = "rawforward"

type rawCodec struct{}

func (rawCodec) Name() string { return rawCodecName }

func (rawCodec) Marshal(v any) ([]byte, error) {
	b, ok := v.(*[]byte)
	if !ok {
		return nil, fmt.Errorf("rawCodec: Marshal: want *[]byte, got %T", v)
	}
	if b == nil {
		return nil, nil
	}
	out := make([]byte, len(*b))
	copy(out, *b)
	return out, nil
}

func (rawCodec) Unmarshal(data []byte, v any) error {
	b, ok := v.(*[]byte)
	if !ok {
		return fmt.Errorf("rawCodec: Unmarshal: want *[]byte, got %T", v)
	}
	*b = make([]byte, len(data))
	copy(*b, data)
	return nil
}

func init() {
	encoding.RegisterCodec(rawCodec{})
}

// echoServer / echoServiceDesc — duplicated from
// internal/layer/grpc/grpc_integration_test.go. Implements Unary,
// ServerStream, and BidiStream (ClientStream omitted — not exercised
// here).
const (
	fwdEchoServiceName        = "yorishiro.forward.test.Echo"
	fwdEchoMethodUnary        = "Unary"
	fwdEchoMethodServerStream = "ServerStream"
	fwdEchoMethodBidiStream   = "BidiStream"
)

type echoHandler interface{}

type echoServer struct {
	unary        func(ctx context.Context, req []byte) ([]byte, error)
	serverStream func(req []byte, stream grpc.ServerStream) error
	bidiStream   func(stream grpc.ServerStream) error
}

var echoServiceDesc = grpc.ServiceDesc{
	ServiceName: fwdEchoServiceName,
	HandlerType: (*echoHandler)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: fwdEchoMethodUnary,
			Handler: func(srv any, ctx context.Context, dec func(any) error, _ grpc.UnaryServerInterceptor) (any, error) {
				var req []byte
				if err := dec(&req); err != nil {
					return nil, err
				}
				h := srv.(*echoServer)
				if h.unary == nil {
					return nil, status.Error(codes.Unimplemented, "Unary not set")
				}
				resp, err := h.unary(ctx, req)
				if err != nil {
					return nil, err
				}
				return &resp, nil
			},
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName: fwdEchoMethodServerStream,
			Handler: func(srv any, stream grpc.ServerStream) error {
				var req []byte
				if err := stream.RecvMsg(&req); err != nil {
					return err
				}
				h := srv.(*echoServer)
				if h.serverStream == nil {
					return status.Error(codes.Unimplemented, "ServerStream not set")
				}
				return h.serverStream(req, stream)
			},
			ServerStreams: true,
		},
		{
			StreamName:    fwdEchoMethodBidiStream,
			ServerStreams: true,
			ClientStreams: true,
			Handler: func(srv any, stream grpc.ServerStream) error {
				h := srv.(*echoServer)
				if h.bidiStream == nil {
					return status.Error(codes.Unimplemented, "BidiStream not set")
				}
				return h.bidiStream(stream)
			},
		},
	},
	Metadata: "yorishiro.forward.test.Echo",
}

func fwdEchoFullMethod(method string) string {
	return "/" + fwdEchoServiceName + "/" + method
}

// startH2CGRPCUpstream starts a gRPC server speaking h2c (cleartext).
// Returns (addr, shutdown).
func startH2CGRPCUpstream(t *testing.T, srv *echoServer) (addr string, shutdown func()) {
	t.Helper()
	gs := grpc.NewServer(grpc.ForceServerCodec(rawCodec{}))
	gs.RegisterService(&echoServiceDesc, srv)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = gs.Serve(ln) }()
	return ln.Addr().String(), func() {
		gs.GracefulStop()
		_ = ln.Close()
	}
}

// dialGRPCViaForward opens a gRPC client connection that targets the
// forward listener directly (h2c, no TLS, no CONNECT). The proxy is
// transparent — the gRPC client sees the forward port as a normal h2c
// endpoint and the proxy hands the streams to the upstream gRPC server.
func dialGRPCViaForward(t *testing.T, fwdAddr string) *grpc.ClientConn {
	t.Helper()
	cc, err := grpc.NewClient(fwdAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(rawCodec{})),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	return cc
}

// TestProxybuild_TCPForward_GRPC_UnaryRoundtrip exercises a unary RPC via
// the gRPC forward listener: client sends echo:hello → server replies
// echo:hello → flows are recorded with Protocol=grpc.
func TestProxybuild_TCPForward_GRPC_UnaryRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := &echoServer{
		unary: func(_ context.Context, req []byte) ([]byte, error) {
			out := append([]byte("echo:"), req...)
			return out, nil
		},
	}
	upAddr, upStop := startH2CGRPCUpstream(t, srv)
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "grpc")
	defer mgr.StopAll(context.Background())

	cc := dialGRPCViaForward(t, fwdAddr)
	defer cc.Close()

	req := []byte("hello-usk-914-grpc")
	var resp []byte
	if err := cc.Invoke(ctx, fwdEchoFullMethod(fwdEchoMethodUnary), &req, &resp); err != nil {
		t.Fatalf("Invoke Unary: %v", err)
	}
	if want := []byte("echo:hello-usk-914-grpc"); string(resp) != string(want) {
		t.Errorf("Unary resp=%q want %q", resp, want)
	}

	// Wait for recordings to settle.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasGRPCStream(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasGRPCStream(store) {
		t.Errorf("expected at least one Stream with Protocol=grpc, got %+v", store.Streams())
	}
}

// TestProxybuild_TCPForward_GRPC_ServerStreaming exercises the
// server-streaming RPC variant (1 request → N responses).
func TestProxybuild_TCPForward_GRPC_ServerStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const n = 3
	srv := &echoServer{
		serverStream: func(req []byte, stream grpc.ServerStream) error {
			for i := 0; i < n; i++ {
				msg := append([]byte(fmt.Sprintf("%d:", i)), req...)
				if err := stream.SendMsg(&msg); err != nil {
					return err
				}
			}
			return nil
		},
	}
	upAddr, upStop := startH2CGRPCUpstream(t, srv)
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "grpc")
	defer mgr.StopAll(context.Background())

	cc := dialGRPCViaForward(t, fwdAddr)
	defer cc.Close()

	desc := &grpc.StreamDesc{StreamName: fwdEchoMethodServerStream, ServerStreams: true}
	stream, err := cc.NewStream(ctx, desc, fwdEchoFullMethod(fwdEchoMethodServerStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}
	req := []byte("svr-stream")
	if err := stream.SendMsg(&req); err != nil {
		t.Fatalf("SendMsg: %v", err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatalf("CloseSend: %v", err)
	}
	var got [][]byte
	for {
		var msg []byte
		if rerr := stream.RecvMsg(&msg); rerr != nil {
			if errors.Is(rerr, io.EOF) {
				break
			}
			t.Fatalf("RecvMsg: %v", rerr)
		}
		got = append(got, msg)
	}
	if len(got) != n {
		t.Errorf("server-stream got %d messages, want %d", len(got), n)
	}
	for i, m := range got {
		want := fmt.Sprintf("%d:svr-stream", i)
		if string(m) != want {
			t.Errorf("msg %d = %q, want %q", i, m, want)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasGRPCStream(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasGRPCStream(store) {
		t.Errorf("expected at least one Stream with Protocol=grpc, got %+v", store.Streams())
	}
}

// TestProxybuild_TCPForward_GRPC_BidiStreaming exercises a bidi-streaming
// RPC: client sends 3 messages → server echoes each → client closes.
func TestProxybuild_TCPForward_GRPC_BidiStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	srv := &echoServer{
		bidiStream: func(stream grpc.ServerStream) error {
			for {
				var msg []byte
				if rerr := stream.RecvMsg(&msg); rerr != nil {
					if errors.Is(rerr, io.EOF) {
						return nil
					}
					return rerr
				}
				echo := append([]byte("bidi:"), msg...)
				if serr := stream.SendMsg(&echo); serr != nil {
					return serr
				}
			}
		},
	}
	upAddr, upStop := startH2CGRPCUpstream(t, srv)
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "grpc")
	defer mgr.StopAll(context.Background())

	cc := dialGRPCViaForward(t, fwdAddr)
	defer cc.Close()

	desc := &grpc.StreamDesc{StreamName: fwdEchoMethodBidiStream, ServerStreams: true, ClientStreams: true}
	stream, err := cc.NewStream(ctx, desc, fwdEchoFullMethod(fwdEchoMethodBidiStream))
	if err != nil {
		t.Fatalf("NewStream: %v", err)
	}

	send := [][]byte{[]byte("one"), []byte("two"), []byte("three")}
	var wg sync.WaitGroup
	wg.Add(1)
	var recvErr error
	got := make([][]byte, 0, len(send))
	go func() {
		defer wg.Done()
		for {
			var msg []byte
			if rerr := stream.RecvMsg(&msg); rerr != nil {
				if !errors.Is(rerr, io.EOF) {
					recvErr = rerr
				}
				return
			}
			got = append(got, msg)
		}
	}()

	for _, m := range send {
		mc := m // local copy for SendMsg's pointer arg
		if serr := stream.SendMsg(&mc); serr != nil {
			t.Fatalf("SendMsg: %v", serr)
		}
	}
	if cerr := stream.CloseSend(); cerr != nil {
		t.Fatalf("CloseSend: %v", cerr)
	}
	wg.Wait()
	if recvErr != nil {
		t.Fatalf("RecvMsg: %v", recvErr)
	}
	if len(got) != len(send) {
		t.Errorf("bidi got %d messages, want %d", len(got), len(send))
	}
	for i, m := range got {
		want := "bidi:" + string(send[i])
		if string(m) != want {
			t.Errorf("bidi msg %d = %q, want %q", i, m, want)
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasGRPCStream(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasGRPCStream(store) {
		t.Errorf("expected at least one Stream with Protocol=grpc, got %+v", store.Streams())
	}
}

// TestProxybuild_TCPForward_GRPC_FilterRejectsNonGRPC asserts the
// Protocol="grpc" content-type filter rejects a stream whose
// content-type is not application/grpc[+suffix]. The reject path records
// a state="error" Stream tagged with
// forward_protocol_mismatch=non_grpc_under_grpc_filter.
func TestProxybuild_TCPForward_GRPC_FilterRejectsNonGRPC(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream is the gRPC server (irrelevant — the request never reaches
	// it because the proxy rejects the stream at the filter).
	srv := &echoServer{}
	upAddr, upStop := startH2CGRPCUpstream(t, srv)
	defer upStop()

	mgr, fwdAddr, store := startH2ForwardListener(t, ctx, upAddr, "grpc")
	defer mgr.StopAll(context.Background())

	// Send a plain HTTP/2 (h2c) GET request — content-type will be empty
	// (or text/plain after stdlib defaults), which the filter rejects.
	var dialed []net.Conn
	var mu sync.Mutex
	cli := h2cForwardClient(fwdAddr, &dialed, &mu)
	req, _ := gohttp.NewRequestWithContext(ctx, "GET", "http://"+fwdAddr+"/not-grpc", nil)
	resp, err := cli.Do(req)
	if err == nil && resp != nil {
		// The proxy emitted RST_STREAM(REFUSED_STREAM); the stdlib h2
		// client surfaces that as an error on the response body read.
		_, rErr := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		// Either Do or body-read MUST surface an error — successful
		// response means the filter did not fire.
		if rErr == nil {
			t.Errorf("expected RST_STREAM error on non-gRPC stream, got status=%d body read OK", resp.StatusCode)
		}
	}
	// Drain conn handles so the test does not race the listener teardown.
	cli.CloseIdleConnections()
	mu.Lock()
	dialSnap := append([]net.Conn{}, dialed...)
	mu.Unlock()
	closeDialedConns(dialSnap)

	// Wait for the reject Stream to be recorded.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if hasForwardProtocolMismatch(store) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !hasForwardProtocolMismatch(store) {
		var dump []string
		for _, s := range store.Streams() {
			dump = append(dump, fmt.Sprintf("%s[%s tags=%v]", s.ID, s.State, s.Tags))
		}
		t.Errorf("expected a state=error Stream tagged forward_protocol_mismatch, got %v", dump)
	}
}

// hasGRPCStream reports whether any recorded Stream carries Protocol=grpc.
func hasGRPCStream(store *flowStoreCapture) bool {
	for _, st := range store.Streams() {
		if st.Protocol == "grpc" {
			return true
		}
	}
	return false
}

// hasForwardProtocolMismatch reports whether any recorded Stream is
// tagged with the gRPC-filter reject marker. The tag is appended via
// UpdateStream.AppendTags, so we also scan StreamUpdates as a fallback
// (the in-test flowStoreCapture does not merge AppendTags into Stream.Tags).
func hasForwardProtocolMismatch(store *flowStoreCapture) bool {
	for _, st := range store.Streams() {
		if v, ok := st.Tags["forward_protocol_mismatch"]; ok && v == "non_grpc_under_grpc_filter" {
			return true
		}
		for _, upd := range store.StreamUpdates(st.ID) {
			if upd.AppendTags == nil {
				continue
			}
			if v := upd.AppendTags["forward_protocol_mismatch"]; v == "non_grpc_under_grpc_filter" {
				return true
			}
		}
	}
	return false
}
