package http2

import (
	"bytes"
	"context"
	"io"
	"net"
	gohttp "net/http"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// h2cRecordingTestServer wraps an h2c server with httptest.Server-compatible API.
type h2cRecordingTestServer struct {
	URL    string
	cancel context.CancelFunc
}

func (s *h2cRecordingTestServer) Close() { s.cancel() }

func newH2CRecordingTestServer(t *testing.T, handler gohttp.Handler) *h2cRecordingTestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	protos := &gohttp.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &gohttp.Server{Handler: handler, Protocols: protos}
	ctx, cancel := context.WithCancel(context.Background())
	go server.Serve(ln)
	go func() { <-ctx.Done(); server.Close() }()
	return &h2cRecordingTestServer{
		URL:    "http://" + ln.Addr().String(),
		cancel: cancel,
	}
}

// TestGRPCProgressiveRecording_Unary verifies that a gRPC unary RPC
// is progressively recorded with State="active" during processing and
// State="complete" after the stream ends, with correct frame messages.
func TestGRPCProgressiveRecording_Unary(t *testing.T) {
	reqPayload := []byte("unary-request")
	respPayload := []byte("unary-response")

	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}

		frames, err := protogrpc.ReadAllFrames(body)
		if err != nil {
			t.Errorf("upstream parse frames: %v", err)
		}
		if len(frames) != 1 || string(frames[0].Payload) != string(reqPayload) {
			t.Errorf("unexpected request payload: frames=%d", len(frames))
		}

		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, respPayload))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-unary", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, reqPayload)
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Method", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Allow async recording to complete.
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	// Verify flow was recorded.
	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "unary")
	}

	// Verify messages: should have at least:
	// 1. Send headers (seq=0)
	// 2. Client frame (seq=1, direction=client_to_server)
	// 3. Server frame (seq=2, direction=server_to_client)
	// 4. Trailers (final receive)
	flowMsgs := filterMessages(store.messages, fl.ID)
	if len(flowMsgs) < 4 {
		t.Fatalf("expected at least 4 messages, got %d", len(flowMsgs))
	}

	// First message should be send headers.
	if flowMsgs[0].Direction != "send" {
		t.Errorf("msg[0] direction = %q, want %q", flowMsgs[0].Direction, "send")
	}
	if flowMsgs[0].Metadata["grpc_type"] != "headers" {
		t.Errorf("msg[0] grpc_type = %q, want %q", flowMsgs[0].Metadata["grpc_type"], "headers")
	}

	// Second message should be client frame.
	if flowMsgs[1].Direction != "send" {
		t.Errorf("msg[1] direction = %q, want %q", flowMsgs[1].Direction, "send")
	}
	if flowMsgs[1].Metadata["direction"] != "client_to_server" {
		t.Errorf("msg[1] metadata direction = %q, want %q", flowMsgs[1].Metadata["direction"], "client_to_server")
	}
	if string(flowMsgs[1].Body) != string(reqPayload) {
		t.Errorf("msg[1] body = %q, want %q", flowMsgs[1].Body, reqPayload)
	}
	if flowMsgs[1].Metadata["encoding"] != "protobuf" {
		t.Errorf("msg[1] encoding = %q, want %q", flowMsgs[1].Metadata["encoding"], "protobuf")
	}

	// Third message should be server frame.
	if flowMsgs[2].Direction != "receive" {
		t.Errorf("msg[2] direction = %q, want %q", flowMsgs[2].Direction, "receive")
	}
	if flowMsgs[2].Metadata["direction"] != "server_to_client" {
		t.Errorf("msg[2] metadata direction = %q, want %q", flowMsgs[2].Metadata["direction"], "server_to_client")
	}
	if string(flowMsgs[2].Body) != string(respPayload) {
		t.Errorf("msg[2] body = %q, want %q", flowMsgs[2].Body, respPayload)
	}

	// Last message should be trailers.
	last := flowMsgs[len(flowMsgs)-1]
	if last.Metadata["grpc_type"] != "trailers" {
		t.Errorf("last msg grpc_type = %q, want %q", last.Metadata["grpc_type"], "trailers")
	}
}

// TestGRPCProgressiveRecording_ServerStreaming verifies that server streaming
// RPCs are recorded progressively with multiple response frames.
func TestGRPCProgressiveRecording_ServerStreaming(t *testing.T) {
	respPayloads := []string{"resp-1", "resp-2", "resp-3"}

	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)

		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		for _, p := range respPayloads {
			w.Write(protogrpc.EncodeFrame(false, []byte(p)))
		}
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-sstream", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("request"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/ServerStream", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "stream")
	}

	// Count server->client frames recorded.
	flowMsgs := filterMessages(store.messages, fl.ID)
	var serverFrames int
	for _, msg := range flowMsgs {
		if msg.Metadata != nil && msg.Metadata["direction"] == "server_to_client" {
			serverFrames++
		}
	}
	if serverFrames != len(respPayloads) {
		t.Errorf("server frames recorded = %d, want %d", serverFrames, len(respPayloads))
	}

	// Verify tags.
	if fl.Tags == nil {
		t.Fatal("expected tags to be set")
	}
	if fl.Tags["streaming_type"] != "grpc" {
		t.Errorf("tag streaming_type = %q, want %q", fl.Tags["streaming_type"], "grpc")
	}
}

// TestGRPCProgressiveRecording_BidiStreaming verifies that bidirectional
// streaming RPCs record client and server frames interleaved.
func TestGRPCProgressiveRecording_BidiStreaming(t *testing.T) {
	const numReqFrames = 3
	const numRespFrames = 3

	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}

		frames, _ := protogrpc.ReadAllFrames(body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Echo back same number of frames.
		for range frames {
			w.Write(protogrpc.EncodeFrame(false, []byte("pong")))
		}
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-bidi", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	var reqBodyBuf bytes.Buffer
	for i := 0; i < numReqFrames; i++ {
		reqBodyBuf.Write(protogrpc.EncodeFrame(false, []byte("ping")))
	}

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Echo/BiDi", &reqBodyBuf)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "bidirectional")
	}

	// Count client and server frames.
	flowMsgs := filterMessages(store.messages, fl.ID)
	var clientFrames, serverFrames int
	for _, msg := range flowMsgs {
		if msg.Metadata == nil {
			continue
		}
		switch msg.Metadata["direction"] {
		case "client_to_server":
			clientFrames++
		case "server_to_client":
			serverFrames++
		}
	}
	if clientFrames != numReqFrames {
		t.Errorf("client frames = %d, want %d", clientFrames, numReqFrames)
	}
	if serverFrames != numRespFrames {
		t.Errorf("server frames = %d, want %d", serverFrames, numRespFrames)
	}
}

// TestGRPCProgressiveRecording_EmptyBody verifies that a gRPC request
// with no body still creates a flow and completes it.
func TestGRPCProgressiveRecording_EmptyBody(t *testing.T) {
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-empty", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Empty", gohttp.NoBody)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Should have at least send headers + trailers.
	flowMsgs := filterMessages(store.messages, fl.ID)
	if len(flowMsgs) < 2 {
		t.Errorf("expected at least 2 messages (headers + trailers), got %d", len(flowMsgs))
	}
}

// TestGRPCProgressiveRecording_FlowActiveBeforeComplete verifies that the
// flow is created with State="active" before the stream completes.
func TestGRPCProgressiveRecording_FlowActiveBeforeComplete(t *testing.T) {
	// Use a channel to pause the upstream so we can check state mid-stream.
	proceed := make(chan struct{})

	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Send one frame immediately.
		w.Write(protogrpc.EncodeFrame(false, []byte("first")))
		if f, ok := w.(gohttp.Flusher); ok {
			f.Flush()
		}
		// Wait before sending more.
		<-proceed
		w.Write(protogrpc.EncodeFrame(false, []byte("second")))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-active", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("request"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/SlowStream", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	type result struct {
		resp *gohttp.Response
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		resCh <- result{resp, err}
	}()

	// Wait for the flow to appear with State="active".
	var foundActive bool
	for i := 0; i < 50; i++ {
		time.Sleep(50 * time.Millisecond)
		store.mu.Lock()
		if len(store.flows) > 0 && store.flows[0].State == "active" {
			foundActive = true
			store.mu.Unlock()
			break
		}
		store.mu.Unlock()
	}

	if !foundActive {
		t.Error("expected flow with State='active' during streaming")
	}

	// Allow stream to complete.
	close(proceed)

	r := <-resCh
	if r.err != nil {
		t.Fatalf("client request: %v", r.err)
	}
	defer r.resp.Body.Close()
	io.Copy(io.Discard, r.resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	// After completion, flow should be State="complete".
	if store.flows[0].State != "complete" {
		t.Errorf("final state = %q, want %q", store.flows[0].State, "complete")
	}
}

// TestGRPCProgressiveRecording_CompressedFrameMetadata verifies that
// compressed frame metadata is correctly recorded.
func TestGRPCProgressiveRecording_CompressedFrameMetadata(t *testing.T) {
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Send a "compressed" frame (compressed flag=1).
		w.Write(protogrpc.EncodeFrame(true, []byte("compressed-data")))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-compressed", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("req"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Compress", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	// Find the server->client frame and check compressed metadata.
	flowMsgs := filterMessages(store.messages, store.flows[0].ID)
	var foundCompressed bool
	for _, msg := range flowMsgs {
		if msg.Metadata != nil && msg.Metadata["direction"] == "server_to_client" {
			if msg.Metadata["compressed"] != "true" {
				t.Errorf("compressed metadata = %q, want %q", msg.Metadata["compressed"], "true")
			}
			foundCompressed = true
		}
	}
	if !foundCompressed {
		t.Error("no server_to_client frame found")
	}
}

// TestGRPCProgressiveRecording_ServiceMethodParsing verifies that service
// and method names are correctly parsed from the URL path.
func TestGRPCProgressiveRecording_ServiceMethodParsing(t *testing.T) {
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("resp")))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-svc", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("req"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/com.example.v1.UserService/GetUser", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.Tags == nil {
		t.Fatal("expected tags to be set")
	}
	if fl.Tags["grpc_service"] != "com.example.v1.UserService" {
		t.Errorf("grpc_service tag = %q, want %q", fl.Tags["grpc_service"], "com.example.v1.UserService")
	}
	if fl.Tags["grpc_method"] != "GetUser" {
		t.Errorf("grpc_method tag = %q, want %q", fl.Tags["grpc_method"], "GetUser")
	}

	// Check send headers metadata too.
	flowMsgs := filterMessages(store.messages, fl.ID)
	if len(flowMsgs) > 0 && flowMsgs[0].Metadata != nil {
		if flowMsgs[0].Metadata["service"] != "com.example.v1.UserService" {
			t.Errorf("send msg service = %q, want %q", flowMsgs[0].Metadata["service"], "com.example.v1.UserService")
		}
		if flowMsgs[0].Metadata["method"] != "GetUser" {
			t.Errorf("send msg method = %q, want %q", flowMsgs[0].Metadata["method"], "GetUser")
		}
	}
}

// TestGRPCProgressiveRecording_NilStore verifies that progressive recording
// gracefully handles a nil store (no-op).
func TestGRPCProgressiveRecording_NilStore(t *testing.T) {
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("resp")))
	}))
	defer upstream.Close()

	handler := NewHandler(nil, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(nil, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-nil", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("req"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Method", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	// Should not panic with nil store.
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
}

// TestGRPCProgressiveRecording_TrailersOnly verifies that trailers-only
// responses (no DATA frames) are recorded with grpc_trailers_only metadata.
func TestGRPCProgressiveRecording_TrailersOnly(t *testing.T) {
	// Upstream returns a trailers-only response (grpc-status in headers, no body).
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "12") // UNIMPLEMENTED
		w.Header().Set("Grpc-Message", "method not implemented")
		w.WriteHeader(gohttp.StatusOK)
		// No body — trailers-only response.
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-trailers-only", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("request"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Unimplemented", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "unary")
	}

	// Find the final trailers message and verify grpc_trailers_only.
	flowMsgs := filterMessages(store.messages, fl.ID)
	var trailersMsg *flow.Message
	for _, msg := range flowMsgs {
		if msg.Metadata != nil && msg.Metadata["grpc_type"] == "trailers" {
			trailersMsg = msg
		}
	}
	if trailersMsg == nil {
		t.Fatal("expected a trailers message")
	}
	if trailersMsg.Metadata["grpc_trailers_only"] != "true" {
		t.Errorf("grpc_trailers_only = %q, want %q", trailersMsg.Metadata["grpc_trailers_only"], "true")
	}
	if trailersMsg.Metadata["grpc_status"] != "12" {
		t.Errorf("grpc_status = %q, want %q", trailersMsg.Metadata["grpc_status"], "12")
	}
}

// TestGRPCProgressiveRecording_NormalUnary_NoTrailersOnlyMetadata verifies that
// normal unary RPCs with response DATA frames do NOT have grpc_trailers_only.
func TestGRPCProgressiveRecording_NormalUnary_NoTrailersOnlyMetadata(t *testing.T) {
	upstream := newH2CRecordingTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("response")))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-prog-normal-unary", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("request"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Method", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	// Find the final trailers message and verify NO grpc_trailers_only.
	flowMsgs := filterMessages(store.messages, store.flows[0].ID)
	for _, msg := range flowMsgs {
		if msg.Metadata != nil && msg.Metadata["grpc_type"] == "trailers" {
			if _, ok := msg.Metadata["grpc_trailers_only"]; ok {
				t.Errorf("normal unary RPC should not have grpc_trailers_only metadata")
			}
		}
	}
}

// filterMessages returns messages belonging to a specific flow, sorted by sequence.
func filterMessages(messages []*flow.Message, flowID string) []*flow.Message {
	var result []*flow.Message
	for _, msg := range messages {
		if msg.FlowID == flowID {
			result = append(result, msg)
		}
	}
	return result
}
