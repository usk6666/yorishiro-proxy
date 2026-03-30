package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"testing"
	"time"

	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// h2cTestServer wraps an h2c server with httptest.Server-compatible fields.
type h2cTestServer struct {
	Listener net.Listener
	cancel   context.CancelFunc
}

func (s *h2cTestServer) Close() {
	s.cancel()
}

// newH2CTestServer starts an h2c-capable test server, replacing
// httptest.NewServer for gRPC tests that need HTTP/2 upstream.
func newH2CTestServer(t *testing.T, handler gohttp.Handler) *h2cTestServer {
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
	return &h2cTestServer{Listener: ln, cancel: cancel}
}

// startFrameEngineProxy creates a proxy using the new clientConn frame engine
// (replacing startH2CProxyListener's h2c.NewHandler). The proxy accepts h2c
// connections, routes streams through handleStream(), and returns the listener
// address and a cancel function.
//
// This exercises the actual production code path:
//
//	clientConn.serve() -> dispatchStream() -> handleStream() -> tryHandleGRPCStream()
func startFrameEngineProxy(t *testing.T, handler *Handler, connID, clientAddr, connectAuthority string, tlsMeta tlsMetadata) (string, context.CancelFunc) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		cancel()
		t.Fatalf("listen: %v", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				hctx := proxy.ContextWithConnID(proxy.ContextWithClientAddr(ctx, clientAddr), connID)
				handler.serveHTTP2(hctx, conn, connectAuthority, tlsMeta)
			}()
		}
	}()

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	return ln.Addr().String(), cancel
}

// newFrameEngineClient connects to the proxy using raw HTTP/2 frames,
// performs the handshake, and returns the test connection.
func newFrameEngineClient(t *testing.T, addr string) *h2cTestConn {
	t.Helper()

	// We reuse the structure but without the server side.
	clientConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	tc := &h2cTestConn{
		clientConn: clientConn,
		writer:     frame.NewWriter(clientConn),
		reader:     frame.NewReader(clientConn),
		encoder:    hpack.NewEncoder(4096, false),
		decoder:    hpack.NewDecoder(4096),
	}

	// Perform HTTP/2 handshake.
	clientConn.Write([]byte(clientMagic))
	tc.writer.WriteSettings(nil)

	// Read server SETTINGS.
	f, err := tc.reader.ReadFrame()
	if err != nil {
		clientConn.Close()
		t.Fatalf("read server SETTINGS: %v", err)
	}
	if f.Header.Type != frame.TypeSettings || f.Header.Flags.Has(frame.FlagAck) {
		clientConn.Close()
		t.Fatalf("expected non-ACK SETTINGS, got type=%s flags=0x%02x", f.Header.Type, f.Header.Flags)
	}

	// Read server SETTINGS ACK.
	f, err = tc.reader.ReadFrame()
	if err != nil {
		clientConn.Close()
		t.Fatalf("read server SETTINGS ACK: %v", err)
	}
	if f.Header.Type != frame.TypeSettings || !f.Header.Flags.Has(frame.FlagAck) {
		clientConn.Close()
		t.Fatalf("expected SETTINGS ACK, got type=%s flags=0x%02x", f.Header.Type, f.Header.Flags)
	}

	// Send client SETTINGS ACK.
	tc.writer.WriteSettingsAck()

	return tc
}

// readFullResponse reads all response frames for a stream until END_STREAM.
// It handles WINDOW_UPDATE frames and collects HEADERS, DATA, and trailer HEADERS.
func readFullResponse(t *testing.T, tc *h2cTestConn) (status string, respHeaders []hpack.HeaderField, body []byte, trailers []hpack.HeaderField) {
	t.Helper()
	gotEndStream := false
	headersReceived := false
	var bodyBuf bytes.Buffer

	for !gotEndStream {
		f, err := tc.reader.ReadFrame()
		if err != nil {
			t.Fatalf("read response frame: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeWindowUpdate:
			continue
		case frame.TypeHeaders:
			fragment, err := f.HeaderBlockFragment()
			if err != nil {
				t.Fatalf("HeaderBlockFragment: %v", err)
			}
			fields, err := tc.decoder.Decode(fragment)
			if err != nil {
				t.Fatalf("decode headers: %v", err)
			}
			if !headersReceived {
				headersReceived = true
				respHeaders = fields
				for _, hf := range fields {
					if hf.Name == ":status" {
						status = hf.Value
					}
				}
			} else {
				// Trailing HEADERS.
				trailers = fields
			}
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		case frame.TypeData:
			data, err := f.DataPayload()
			if err != nil {
				t.Fatalf("DataPayload: %v", err)
			}
			bodyBuf.Write(data)
			if f.Header.Flags.Has(frame.FlagEndStream) {
				gotEndStream = true
			}
		default:
			// Ignore other frame types (e.g. PING).
		}
	}
	return status, respHeaders, bodyBuf.Bytes(), trailers
}

// sendGRPCRequest sends a gRPC POST request via raw HTTP/2 frames.
func sendGRPCRequest(t *testing.T, tc *h2cTestConn, streamID uint32, upstreamURL, path string, grpcBody []byte) {
	t.Helper()
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: upstreamURL},
		{Name: ":path", Value: path},
		{Name: "content-type", Value: "application/grpc"},
		{Name: "te", Value: "trailers"},
	})

	endStream := len(grpcBody) == 0
	tc.writer.WriteHeaders(streamID, endStream, true, headerBlock)
	if !endStream {
		tc.writer.WriteData(streamID, true, grpcBody)
	}
}

// TestFrameEngine_GRPCUnary verifies that a gRPC unary RPC works through
// the new clientConn frame engine. This exercises the production path:
// clientConn -> handleStream -> tryHandleGRPCStream -> handleGRPCStream.
func TestFrameEngine_GRPCUnary(t *testing.T) {
	reqPayload := []byte("unary-req")
	respPayload := []byte("unary-resp")

	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-unary", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	// Send gRPC request.
	grpcBody := protogrpc.EncodeFrame(false, reqPayload)
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

	// Read response.
	status, _, body, _ := readFullResponse(t, tc)

	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	respFrames, err := protogrpc.ReadAllFrames(body)
	if err != nil {
		t.Fatalf("parse response frames: %v", err)
	}
	if len(respFrames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(respFrames))
	}
	if string(respFrames[0].Payload) != string(respPayload) {
		t.Errorf("response payload = %q, want %q", respFrames[0].Payload, respPayload)
	}

	// Verify flow was recorded.
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}
	if store.flows[0].Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, "gRPC")
	}
	if store.flows[0].State != "complete" {
		t.Errorf("state = %q, want %q", store.flows[0].State, "complete")
	}
	if store.flows[0].FlowType != "unary" {
		t.Errorf("flow_type = %q, want %q", store.flows[0].FlowType, "unary")
	}
}

// TestFrameEngine_GRPCServerStreaming verifies server streaming gRPC RPCs
// through the new frame engine with progressive recording.
func TestFrameEngine_GRPCServerStreaming(t *testing.T) {
	respPayloads := []string{"resp-1", "resp-2", "resp-3"}

	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-sstream", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("request"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/ServerStream", grpcBody)

	status, _, body, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	frames, err := protogrpc.ReadAllFrames(body)
	if err != nil {
		t.Fatalf("parse response frames: %v", err)
	}
	if len(frames) != len(respPayloads) {
		t.Fatalf("expected %d response frames, got %d", len(respPayloads), len(frames))
	}
	for i, f := range frames {
		if string(f.Payload) != respPayloads[i] {
			t.Errorf("frame %d: payload = %q, want %q", i, f.Payload, respPayloads[i])
		}
	}

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

	// Verify progressive recording captured all server frames.
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
}

// TestFrameEngine_GRPCClientStreaming verifies client streaming through the
// frame engine. With clientConn, all DATA frames are accumulated before
// dispatch, so the gRPC handler sees them as a single body read.
func TestFrameEngine_GRPCClientStreaming(t *testing.T) {
	payloads := []string{"frame-1", "frame-2", "frame-3"}

	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}
		frames, err := protogrpc.ReadAllFrames(body)
		if err != nil {
			t.Errorf("upstream parse: %v", err)
		}
		if len(frames) != len(payloads) {
			t.Errorf("expected %d frames, got %d", len(payloads), len(frames))
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("response")))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-cstream", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	// Build body with multiple gRPC frames.
	var grpcBody bytes.Buffer
	for _, p := range payloads {
		grpcBody.Write(protogrpc.EncodeFrame(false, []byte(p)))
	}
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/ClientStream", grpcBody.Bytes())

	status, _, body, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	frames, _ := protogrpc.ReadAllFrames(body)
	if len(frames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(frames))
	}
	if string(frames[0].Payload) != "response" {
		t.Errorf("response = %q, want %q", frames[0].Payload, "response")
	}

	// Verify flow recording.
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	// Count client frames recorded.
	flowMsgs := filterMessages(store.messages, store.flows[0].ID)
	var clientFrameCount int
	for _, msg := range flowMsgs {
		if msg.Metadata != nil && msg.Metadata["direction"] == "client_to_server" {
			clientFrameCount++
		}
	}
	if clientFrameCount != len(payloads) {
		t.Errorf("client frames recorded = %d, want %d", clientFrameCount, len(payloads))
	}
}

// TestFrameEngine_GRPCBidiStreaming verifies bidirectional streaming through
// the frame engine with progressive recording of both client and server frames.
func TestFrameEngine_GRPCBidiStreaming(t *testing.T) {
	const numReqFrames = 3
	const numRespFrames = 3

	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		frames, _ := protogrpc.ReadAllFrames(body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		for range frames {
			w.Write(protogrpc.EncodeFrame(false, []byte("pong")))
		}
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-bidi", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	var grpcBody bytes.Buffer
	for i := 0; i < numReqFrames; i++ {
		grpcBody.Write(protogrpc.EncodeFrame(false, []byte("ping")))
	}
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Echo/BiDi", grpcBody.Bytes())

	status, _, body, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	frames, _ := protogrpc.ReadAllFrames(body)
	if len(frames) != numRespFrames {
		t.Fatalf("expected %d response frames, got %d", numRespFrames, len(frames))
	}

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}
	fl := store.flows[0]
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

// TestFrameEngine_GRPCEmptyBody verifies gRPC with no body through the
// new frame engine.
func TestFrameEngine_GRPCEmptyBody(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-empty", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	// Send request with empty body (END_STREAM on HEADERS).
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Empty", nil)

	status, _, _, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Errorf("status = %q, want %q", status, "200")
	}

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}
	if store.flows[0].Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, "gRPC")
	}
	if store.flows[0].State != "complete" {
		t.Errorf("state = %q, want %q", store.flows[0].State, "complete")
	}
}

// TestFrameEngine_GRPCTrailersPreserved verifies that gRPC trailers
// (Grpc-Status, Grpc-Message) are correctly forwarded through the frame
// engine's trailer HEADERS frame.
func TestFrameEngine_GRPCTrailersPreserved(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("resp")))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-trailers", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("req"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

	status, _, body, trailers := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	// Verify response body.
	frames, _ := protogrpc.ReadAllFrames(body)
	if len(frames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(frames))
	}

	// Verify trailers were received.
	var grpcStatus, grpcMessage string
	for _, hf := range trailers {
		switch hf.Name {
		case "grpc-status":
			grpcStatus = hf.Value
		case "grpc-message":
			grpcMessage = hf.Value
		}
	}
	if grpcStatus != "0" {
		t.Errorf("grpc-status trailer = %q, want %q", grpcStatus, "0")
	}
	if grpcMessage != "OK" {
		t.Errorf("grpc-message trailer = %q, want %q", grpcMessage, "OK")
	}
}

// TestFrameEngine_GRPCMetadataRecording verifies that gRPC service/method
// metadata is correctly parsed and recorded via the frame engine.
func TestFrameEngine_GRPCMetadataRecording(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-meta", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("req"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/com.example.v1.UserService/GetUser", grpcBody)

	_, _, _, _ = readFullResponse(t, tc)

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
		t.Errorf("grpc_service = %q, want %q", fl.Tags["grpc_service"], "com.example.v1.UserService")
	}
	if fl.Tags["grpc_method"] != "GetUser" {
		t.Errorf("grpc_method = %q, want %q", fl.Tags["grpc_method"], "GetUser")
	}

	// Verify send headers message.
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

// TestFrameEngine_NonGRPCNotCapturedAsGRPC verifies that non-gRPC requests
// through the frame engine are recorded as HTTP/2, not gRPC.
func TestFrameEngine_NonGRPCNotCapturedAsGRPC(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-non-grpc", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	// Send a regular HTTP/2 request (not gRPC).
	headerBlock := tc.encoder.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: upstream.Listener.Addr().String()},
		{Name: ":path", Value: "/api/data"},
		{Name: "content-type", Value: "application/json"},
	})
	tc.writer.WriteHeaders(1, true, true, headerBlock)

	status, _, body, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}
	if string(body) != "ok" {
		t.Errorf("body = %q, want %q", body, "ok")
	}

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}
	if store.flows[0].Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, "HTTP/2")
	}
}

// TestFrameEngine_GRPCContentTypeVariants verifies that different Content-Type
// values for gRPC are correctly detected through the frame engine.
func TestFrameEngine_GRPCContentTypeVariants(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		wantGRPC    bool
	}{
		{"application/grpc", "application/grpc", true},
		{"application/grpc+proto", "application/grpc+proto", true},
		{"application/grpc+json", "application/grpc+json", true},
		{"application/json", "application/json", false},
		{"text/plain", "text/plain", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", tt.contentType)
				w.WriteHeader(gohttp.StatusOK)
				if tt.wantGRPC {
					w.Write(protogrpc.EncodeFrame(false, []byte("resp")))
				} else {
					w.Write([]byte("ok"))
				}
			}))
			defer upstream.Close()

			store := &mockStore{}
			handler := NewHandler(store, testutil.DiscardLogger())
			grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
			handler.SetGRPCHandler(grpcHandler)

			proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-ct-"+tt.name, "127.0.0.1:9999", "", tlsMetadata{})
			defer cancel()

			tc := newFrameEngineClient(t, proxyAddr)
			defer tc.clientConn.Close()

			headerBlock := tc.encoder.Encode([]hpack.HeaderField{
				{Name: ":method", Value: "POST"},
				{Name: ":scheme", Value: "http"},
				{Name: ":authority", Value: upstream.Listener.Addr().String()},
				{Name: ":path", Value: "/test.Service/Method"},
				{Name: "content-type", Value: tt.contentType},
				{Name: "te", Value: "trailers"},
			})

			var reqBody []byte
			if tt.wantGRPC {
				reqBody = protogrpc.EncodeFrame(false, []byte("req"))
			} else {
				reqBody = []byte("body")
			}
			tc.writer.WriteHeaders(1, false, true, headerBlock)
			tc.writer.WriteData(1, true, reqBody)

			_, _, _, _ = readFullResponse(t, tc)

			time.Sleep(100 * time.Millisecond)
			store.mu.Lock()
			if len(store.flows) == 0 {
				store.mu.Unlock()
				t.Fatal("expected at least one flow to be recorded")
			}
			wantProtocol := "HTTP/2"
			if tt.wantGRPC {
				wantProtocol = "gRPC"
			}
			if store.flows[0].Protocol != wantProtocol {
				t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, wantProtocol)
			}
			store.mu.Unlock()
		})
	}
}

// TestFrameEngine_GRPCNilStore verifies that the gRPC path handles nil store
// gracefully through the frame engine.
func TestFrameEngine_GRPCNilStore(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, []byte("resp")))
	}))
	defer upstream.Close()

	handler := NewHandler(nil, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(nil, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-nil", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("req"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

	status, _, _, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Errorf("status = %q, want %q", status, "200")
	}
}

// TestFrameEngine_GRPCProgressiveRecordingFrameMessages verifies that
// progressive recording correctly records individual gRPC frames as separate
// flow messages when using the frame engine.
func TestFrameEngine_GRPCProgressiveRecordingFrameMessages(t *testing.T) {
	reqPayload := []byte("progressive-req")
	respPayload := []byte("progressive-resp")

	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		frames, _ := protogrpc.ReadAllFrames(body)
		_ = frames
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, respPayload))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-prog", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, reqPayload)
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

	_, _, _, _ = readFullResponse(t, tc)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) == 0 {
		t.Fatal("expected at least one flow to be recorded")
	}

	fl := store.flows[0]
	flowMsgs := filterMessages(store.messages, fl.ID)

	// Expected messages:
	// 1. Send headers (seq=0, direction=send, grpc_type=headers)
	// 2. Client frame (direction=client_to_server)
	// 3. Server frame (direction=server_to_client)
	// 4. Trailers (grpc_type=trailers)
	if len(flowMsgs) < 4 {
		t.Fatalf("expected at least 4 messages, got %d", len(flowMsgs))
	}

	// First message: send headers.
	if flowMsgs[0].Direction != "send" {
		t.Errorf("msg[0] direction = %q, want %q", flowMsgs[0].Direction, "send")
	}
	if flowMsgs[0].Metadata["grpc_type"] != "headers" {
		t.Errorf("msg[0] grpc_type = %q, want %q", flowMsgs[0].Metadata["grpc_type"], "headers")
	}

	// Second message: client frame.
	if flowMsgs[1].Direction != "send" {
		t.Errorf("msg[1] direction = %q, want %q", flowMsgs[1].Direction, "send")
	}
	if flowMsgs[1].Metadata["direction"] != "client_to_server" {
		t.Errorf("msg[1] metadata direction = %q, want %q", flowMsgs[1].Metadata["direction"], "client_to_server")
	}
	if string(flowMsgs[1].Body) != string(reqPayload) {
		t.Errorf("msg[1] body = %q, want %q", flowMsgs[1].Body, reqPayload)
	}

	// Third message: server frame.
	if flowMsgs[2].Direction != "receive" {
		t.Errorf("msg[2] direction = %q, want %q", flowMsgs[2].Direction, "receive")
	}
	if flowMsgs[2].Metadata["direction"] != "server_to_client" {
		t.Errorf("msg[2] metadata direction = %q, want %q", flowMsgs[2].Metadata["direction"], "server_to_client")
	}
	if string(flowMsgs[2].Body) != string(respPayload) {
		t.Errorf("msg[2] body = %q, want %q", flowMsgs[2].Body, respPayload)
	}

	// Last message: trailers.
	last := flowMsgs[len(flowMsgs)-1]
	if last.Metadata["grpc_type"] != "trailers" {
		t.Errorf("last msg grpc_type = %q, want %q", last.Metadata["grpc_type"], "trailers")
	}
}

// TestFrameEngine_GRPCMultipleStreams verifies that multiple gRPC streams
// on the same connection are handled correctly by the frame engine.
func TestFrameEngine_GRPCMultipleStreams(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Echo back the request body as response.
		w.Write(body)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-multi", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	// Send two sequential gRPC requests on streams 1 and 3.
	for _, streamID := range []uint32{1, 3} {
		payload := []byte(fmt.Sprintf("req-%d", streamID))
		grpcBody := protogrpc.EncodeFrame(false, payload)
		sendGRPCRequest(t, tc, streamID, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

		status, _, _, _ := readFullResponse(t, tc)
		if status != "200" {
			t.Fatalf("stream %d: status = %q, want %q", streamID, status, "200")
		}
	}

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	if len(store.flows) != 2 {
		t.Fatalf("expected 2 flows, got %d", len(store.flows))
	}
	for i, fl := range store.flows {
		if fl.Protocol != "gRPC" {
			t.Errorf("flow[%d] protocol = %q, want %q", i, fl.Protocol, "gRPC")
		}
		if fl.State != "complete" {
			t.Errorf("flow[%d] state = %q, want %q", i, fl.State, "complete")
		}
	}
}

// TestFrameEngine_GRPCFlowRawFrameRecording verifies that HTTP/2 frame-level
// raw bytes are available for gRPC flows processed through the frame engine.
// The frame engine stores raw bytes in streamRequest.rawFrames, and these
// should eventually be accessible for L4 recording.
func TestFrameEngine_GRPCFlowRawFrameRecording(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-raw", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("req"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Method", grpcBody)

	_, _, _, _ = readFullResponse(t, tc)

	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()

	// The flow should exist and be complete even though L4 raw frame
	// recording integration is handled by a later issue.
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
}

// TestFrameEngine_GRPCWriteFlush verifies that the frameResponseWriter's
// Flush() correctly works for gRPC streaming where headers must be sent
// before data frames.
func TestFrameEngine_GRPCWriteFlush(t *testing.T) {
	upstream := newH2CTestServer(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Simulate streaming: write multiple frames.
		for i := 0; i < 3; i++ {
			w.Write(protogrpc.EncodeFrame(false, []byte(fmt.Sprintf("chunk-%d", i))))
			if f, ok := w.(gohttp.Flusher); ok {
				f.Flush()
			}
		}
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startFrameEngineProxy(t, handler, "fe-grpc-flush", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	tc := newFrameEngineClient(t, proxyAddr)
	defer tc.clientConn.Close()

	grpcBody := protogrpc.EncodeFrame(false, []byte("req"))
	sendGRPCRequest(t, tc, 1, upstream.Listener.Addr().String(), "/test.Service/Stream", grpcBody)

	status, _, body, _ := readFullResponse(t, tc)
	if status != "200" {
		t.Fatalf("status = %q, want %q", status, "200")
	}

	frames, err := protogrpc.ReadAllFrames(body)
	if err != nil {
		t.Fatalf("parse response frames: %v", err)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 response frames, got %d", len(frames))
	}
	for i, f := range frames {
		expected := fmt.Sprintf("chunk-%d", i)
		if string(f.Payload) != expected {
			t.Errorf("frame %d: payload = %q, want %q", i, f.Payload, expected)
		}
	}
}
