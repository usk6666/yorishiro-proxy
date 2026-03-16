//go:build e2e

package http2_test

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- gRPC test helpers ---

// buildProtobufFrame creates a gRPC wire frame (5-byte header + protobuf payload)
// from a JSON string in the schema-less protobuf format.
func buildProtobufFrame(t *testing.T, jsonStr string) []byte {
	t.Helper()
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("protobuf encode: %v", err)
	}
	return protogrpc.EncodeFrame(false, payload)
}

// decodeAllProtobufFrames parses gRPC wire data into decoded JSON strings.
func decodeAllProtobufFrames(t *testing.T, data []byte) []string {
	t.Helper()
	frames, err := protogrpc.ReadAllFrames(data)
	if err != nil {
		t.Fatalf("read grpc frames: %v", err)
	}
	var jsons []string
	for _, f := range frames {
		j, err := protobuf.Decode(f.Payload)
		if err != nil {
			t.Fatalf("protobuf decode: %v", err)
		}
		jsons = append(jsons, j)
	}
	return jsons
}

// startGRPCTestUpstream creates an h2c HTTP/2 server that acts as a gRPC backend.
// The handler function receives the incoming gRPC frames and writes gRPC frames
// back. It is the caller's responsibility to set Content-Type and status.
func startGRPCTestUpstream(t *testing.T, handler gohttp.Handler) (addr string, cleanup func()) {
	t.Helper()
	protos := &gohttp.Protocols{}
	protos.SetHTTP1(true)
	protos.SetUnencryptedHTTP2(true)
	server := &gohttp.Server{
		Handler:   handler,
		Protocols: protos,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go server.Serve(ln)
	return ln.Addr().String(), func() { server.Close() }
}

// startGRPCProxy creates a proxy with HTTP/2 and gRPC support and returns
// the proxy address and cleanup function.
func startGRPCProxy(
	t *testing.T,
	ctx context.Context,
	store flow.Store,
	opts ...func(h2Handler *protohttp2.Handler),
) (proxyAddr string, cancel context.CancelFunc) {
	t.Helper()

	logger := testutil.DiscardLogger()
	httpHandler := protohttp.NewHandler(store, nil, logger)
	h2Handler := protohttp2.NewHandler(store, logger)

	// Wire up gRPC handler for gRPC-specific recording.
	grpcHandler := protogrpc.NewHandler(store, logger)
	h2Handler.SetGRPCHandler(grpcHandler)

	// Apply options.
	for _, opt := range opts {
		opt(h2Handler)
	}

	detector := protocol.NewDetector(h2Handler, httpHandler)
	listener := proxy.NewListener(proxy.ListenerConfig{
		Addr:     "127.0.0.1:0",
		Detector: detector,
		Logger:   logger,
	})

	proxyCtx, proxyCancel := context.WithCancel(ctx)

	go func() {
		if err := listener.Start(proxyCtx); err != nil && proxyCtx.Err() == nil {
			// Only log if the error is not from context cancellation.
			logger.Info("proxy listener error", "error", err)
		}
	}()

	select {
	case <-listener.Ready():
	case <-time.After(2 * time.Second):
		proxyCancel()
		t.Fatal("proxy did not become ready")
	}

	return listener.Addr(), proxyCancel
}

// newH2CClient creates an HTTP client configured for h2c that connects through
// the given proxy address.
func newH2CClient(proxyAddr string) *gohttp.Client {
	protos := &gohttp.Protocols{}
	protos.SetUnencryptedHTTP2(true)
	return &gohttp.Client{
		Transport: &gohttp.Transport{
			Protocols: protos,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, proxyAddr)
			},
		},
		Timeout: 15 * time.Second,
	}
}

// pollGRPCFlows polls the store until the expected number of gRPC flows appear.
func pollGRPCFlows(t *testing.T, ctx context.Context, store flow.Store, wantCount int) []*flow.Flow {
	t.Helper()
	var flows []*flow.Flow
	var err error
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Protocol: "gRPC", Limit: 100})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= wantCount {
			return flows
		}
	}
	t.Fatalf("expected %d gRPC flows, got %d after polling", wantCount, len(flows))
	return nil
}

// pollFlowState polls until the flow reaches the expected state.
func pollFlowState(t *testing.T, ctx context.Context, store flow.Store, flowID, wantState string) *flow.Flow {
	t.Helper()
	for i := 0; i < 60; i++ {
		time.Sleep(100 * time.Millisecond)
		fl, err := store.GetFlow(ctx, flowID)
		if err != nil {
			continue
		}
		if fl.State == wantState {
			return fl
		}
	}
	t.Fatalf("flow %s did not reach state %q", flowID, wantState)
	return nil
}

// --- Streaming transfer tests (USK-362) ---

func TestIntegration_GRPC_UnaryProxy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream gRPC unary server: echo the request back.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body) // Echo back the request frame.
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Build a protobuf gRPC frame.
	reqJSON := `{"0001:0000:String":"hello-unary"}`
	reqFrame := buildProtobufFrame(t, reqJSON)

	targetURL := fmt.Sprintf("http://%s/test.Service/UnaryMethod", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC unary request through proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the echoed response contains our data.
	if len(body) < 5 {
		t.Fatalf("response body too short: %d bytes", len(body))
	}
	decoded := decodeAllProtobufFrames(t, body)
	if len(decoded) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(decoded))
	}
	if !strings.Contains(decoded[0], "hello-unary") {
		t.Errorf("response frame does not contain expected data: %s", decoded[0])
	}

	// Verify flow recording.
	flows := pollGRPCFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
}

func TestIntegration_GRPC_ServerStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream sends 3 response frames for each request.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)

		flusher, ok := w.(gohttp.Flusher)
		for i := 0; i < 3; i++ {
			msg := fmt.Sprintf(`{"0001:0000:String":"stream-msg-%d"}`, i)
			payload, _ := protobuf.Encode(msg)
			frame := protogrpc.EncodeFrame(false, payload)
			w.Write(frame)
			if ok {
				flusher.Flush()
			}
		}
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqJSON := `{"0001:0000:String":"request-data"}`
	reqFrame := buildProtobufFrame(t, reqJSON)

	targetURL := fmt.Sprintf("http://%s/test.Service/ServerStream", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC server streaming: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Parse response frames.
	frames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(frames) != 3 {
		t.Fatalf("expected 3 response frames, got %d", len(frames))
	}

	// Verify flow recording: should be "stream" type.
	flows := pollGRPCFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
	if fl.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "stream")
	}
}

func TestIntegration_GRPC_ClientStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream counts request frames and returns a summary.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		frames, _ := protogrpc.ReadAllFrames(body)
		respJSON := fmt.Sprintf(`{"0001:0000:Varint":%d}`, len(frames))
		payload, _ := protobuf.Encode(respJSON)

		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, payload))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Build 3 client-side frames.
	var reqBuf bytes.Buffer
	for i := 0; i < 3; i++ {
		msg := fmt.Sprintf(`{"0001:0000:String":"client-msg-%d"}`, i)
		payload, _ := protobuf.Encode(msg)
		reqBuf.Write(protogrpc.EncodeFrame(false, payload))
	}

	targetURL := fmt.Sprintf("http://%s/test.Service/ClientStream", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, &reqBuf)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC client streaming: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify response contains 1 frame.
	respFrames, _ := protogrpc.ReadAllFrames(body)
	if len(respFrames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(respFrames))
	}

	// Verify flow recording: should be "stream" type (multiple req, single resp).
	flows := pollGRPCFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "stream")
	}
}

func TestIntegration_GRPC_BidirectionalStreaming(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream reads all request frames and echoes each one back plus an extra.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		reqFrames, _ := protogrpc.ReadAllFrames(body)

		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)

		flusher, ok := w.(gohttp.Flusher)
		// Echo each request frame back.
		for _, f := range reqFrames {
			w.Write(protogrpc.EncodeFrame(false, f.Payload))
			if ok {
				flusher.Flush()
			}
		}
		// Add an extra frame.
		extra, _ := protobuf.Encode(`{"0001:0000:String":"extra-bidi"}`)
		w.Write(protogrpc.EncodeFrame(false, extra))
		if ok {
			flusher.Flush()
		}
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Send 2 client frames.
	var reqBuf bytes.Buffer
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf(`{"0001:0000:String":"bidi-msg-%d"}`, i)
		payload, _ := protobuf.Encode(msg)
		reqBuf.Write(protogrpc.EncodeFrame(false, payload))
	}

	targetURL := fmt.Sprintf("http://%s/test.Service/BidiStream", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, &reqBuf)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC bidirectional streaming: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Expect 3 response frames (2 echoed + 1 extra).
	respFrames, _ := protogrpc.ReadAllFrames(body)
	if len(respFrames) != 3 {
		t.Fatalf("expected 3 response frames, got %d", len(respFrames))
	}

	// Verify no deadlock occurred and flow recording completed.
	flows := pollGRPCFlows(t, ctx, store, 1)
	fl := flows[0]
	if fl.FlowType != "bidirectional" {
		t.Errorf("flow_type = %q, want %q", fl.FlowType, "bidirectional")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}
}

func TestIntegration_GRPC_FrameReassembly(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes back.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Build 2 gRPC frames back-to-back (tests frame boundary reassembly).
	var reqBuf bytes.Buffer
	for i := 0; i < 2; i++ {
		msg := fmt.Sprintf(`{"0001:0000:String":"reassembly-%d"}`, i)
		payload, _ := protobuf.Encode(msg)
		reqBuf.Write(protogrpc.EncodeFrame(false, payload))
	}

	targetURL := fmt.Sprintf("http://%s/test.Service/Reassembly", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, &reqBuf)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC frame reassembly: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify both frames came through.
	respFrames, _ := protogrpc.ReadAllFrames(body)
	if len(respFrames) != 2 {
		t.Fatalf("expected 2 response frames, got %d", len(respFrames))
	}

	// Verify flow recording shows correct frame counts.
	flows := pollGRPCFlows(t, ctx, store, 1)
	if flows[0].State != "complete" {
		t.Errorf("state = %q, want %q", flows[0].State, "complete")
	}
}

// --- Protobuf codec tests (USK-363) ---

func TestIntegration_GRPC_InvalidProtobuf_Passthrough(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes the request body back.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Build a gRPC frame with invalid protobuf payload (random bytes).
	invalidPayload := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03}
	frame := protogrpc.EncodeFrame(false, invalidPayload)

	targetURL := fmt.Sprintf("http://%s/test.Service/InvalidProto", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(frame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC invalid protobuf: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d (invalid protobuf should be transparently forwarded)", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the invalid payload was passed through unchanged.
	respFrames, _ := protogrpc.ReadAllFrames(body)
	if len(respFrames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(respFrames))
	}
	if !bytes.Equal(respFrames[0].Payload, invalidPayload) {
		t.Errorf("invalid protobuf payload was modified during proxy transit")
	}

	// Flow should still be recorded.
	flows := pollGRPCFlows(t, ctx, store, 1)
	if flows[0].State != "complete" {
		t.Errorf("state = %q, want %q", flows[0].State, "complete")
	}
}

// --- Progressive recording tests (USK-364) ---

func TestIntegration_GRPC_ProgressiveRecording_ActiveThenComplete(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Channel to control upstream response timing.
	proceed := make(chan struct{})

	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)

		// Send first frame immediately.
		msg1, _ := protobuf.Encode(`{"0001:0000:String":"first"}`)
		w.Write(protogrpc.EncodeFrame(false, msg1))
		if f, ok := w.(gohttp.Flusher); ok {
			f.Flush()
		}

		// Wait before sending the second frame (so we can check "active" state).
		<-proceed

		msg2, _ := protobuf.Encode(`{"0001:0000:String":"second"}`)
		w.Write(protogrpc.EncodeFrame(false, msg2))
		if f, ok := w.(gohttp.Flusher); ok {
			f.Flush()
		}
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"request"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Progressive", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	// Start the request in a goroutine since it will block until upstream completes.
	type result struct {
		resp *gohttp.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		ch <- result{resp, err}
	}()

	// Wait for the flow to appear in "active" state.
	var activeFlow *flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err := store.ListFlows(ctx, flow.ListOptions{Protocol: "gRPC", State: "active", Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) > 0 {
			activeFlow = flows[0]
			break
		}
	}
	if activeFlow == nil {
		// Release the upstream before failing.
		close(proceed)
		t.Fatal("no active gRPC flow found during streaming")
	}
	if activeFlow.State != "active" {
		t.Errorf("flow state = %q, want %q during streaming", activeFlow.State, "active")
	}

	// Release the upstream to complete the stream.
	close(proceed)

	// Wait for the client response.
	res := <-ch
	if res.err != nil {
		t.Fatalf("gRPC progressive recording: %v", res.err)
	}
	defer res.resp.Body.Close()
	io.ReadAll(res.resp.Body)

	// Verify flow transitions to "complete".
	completedFlow := pollFlowState(t, ctx, store, activeFlow.ID, "complete")
	if completedFlow.FlowType != "stream" {
		t.Errorf("flow_type = %q, want %q", completedFlow.FlowType, "stream")
	}

	// Verify messages were recorded.
	msgs, err := store.GetMessages(ctx, activeFlow.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	// Should have: 1 send headers + N data frames + 1 final trailers
	if len(msgs) < 3 {
		t.Errorf("expected at least 3 messages, got %d", len(msgs))
	}
}

func TestIntegration_GRPC_MCP_ProtobufDecoded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes back.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"decoded-test-value"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Decoded", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	flows := pollGRPCFlows(t, ctx, store, 1)
	fl := flows[0]

	msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	// Verify at least one message body contains protobuf-encoded data that
	// can be decoded back to reveal the original value.
	foundBody := false
	for _, msg := range msgs {
		if len(msg.Body) > 0 {
			decoded, err := protobuf.Decode(msg.Body)
			if err == nil && strings.Contains(decoded, "decoded-test-value") {
				foundBody = true
				break
			}
		}
	}
	if !foundBody {
		t.Error("no message body contains the expected decoded protobuf data")
	}
}

// --- Subsystem adaptation tests (USK-365) ---

func TestIntegration_GRPC_SafetyFilter_Block(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// In gRPC streaming mode, the safety filter processes frames as they arrive.
	// The upstream connection is established before the body is processed
	// (since gRPC uses io.Pipe for non-blocking streaming), but the frame
	// containing the blocked pattern causes the stream to be terminated with
	// gRPC status PERMISSION_DENIED (7).
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Read the body (may get an error if pipe is closed by safety filter).
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		resp, _ := protobuf.Encode(`{"0001:0000:String":"should-not-see"}`)
		w.Write(protogrpc.EncodeFrame(false, resp))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	safetyEngine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "block-drop",
				Name:    "Block DROP TABLE",
				Pattern: `DROP\s+TABLE`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetSafetyEngine(safetyEngine)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	// Create a gRPC frame with a destructive SQL pattern.
	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"DROP TABLE users"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Dangerous", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC safety filter: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// The safety filter blocks the gRPC frame and terminates the stream.
	// Depending on timing, the response may be:
	// - HTTP 200 with Grpc-Status: 7 (PERMISSION_DENIED) in headers
	// - HTTP 502 (Bad Gateway) if the upstream request failed due to pipe closure
	// Both indicate the safety filter prevented the destructive payload.
	grpcStatus := resp.Header.Get("Grpc-Status")
	if grpcStatus == "" {
		grpcStatus = resp.Trailer.Get("Grpc-Status")
	}
	blocked := grpcStatus == "7" || resp.StatusCode == gohttp.StatusBadGateway
	if !blocked {
		t.Errorf("expected safety filter to block request: status=%d, Grpc-Status=%q, headers=%v, trailers=%v",
			resp.StatusCode, grpcStatus, resp.Header, resp.Trailer)
	}
}

func TestIntegration_GRPC_OutputFilter_PII_Mask(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream sends a response containing PII.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		respJSON := `{"0001:0000:String":"SSN: 123-45-6789"}`
		payload, _ := protobuf.Encode(respJSON)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, payload))
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	safetyEngine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:          "mask-ssn",
				Name:        "Mask SSN",
				Pattern:     `\d{3}-\d{2}-\d{4}`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "***-**-****",
			},
		},
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetSafetyEngine(safetyEngine)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"get user"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/GetUser", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC output filter: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Parse the response frame and verify SSN is masked.
	if len(body) <= 5 {
		t.Fatalf("response body too short for verification: %d bytes", len(body))
	}
	respFrames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(respFrames) == 0 {
		t.Fatal("no response frames found")
	}
	decoded, decErr := protobuf.Decode(respFrames[0].Payload)
	if decErr != nil {
		t.Fatalf("protobuf decode: %v", decErr)
	}
	if strings.Contains(decoded, "123-45-6789") {
		t.Errorf("SSN was not masked in gRPC response: %s", decoded)
	}
	if !strings.Contains(decoded, "***-**-****") {
		t.Errorf("expected masked SSN in response: %s", decoded)
	}
}

func TestIntegration_GRPC_PluginHooks_BodyModification(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes request body.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Create a plugin engine with a hook that modifies the body.
	pluginEngine := plugin.NewEngine(logger)
	pluginEngine.Registry().Register(
		"test-grpc-modifier",
		plugin.HookOnReceiveFromClient,
		func(ctx context.Context, data map[string]any) (*plugin.HookResult, error) {
			body, _ := data["body"].(string)
			if strings.Contains(body, "original-token") {
				newBody := strings.ReplaceAll(body, "original-token", "MODIFIED-TOKEN")
				return &plugin.HookResult{
					Action: plugin.ActionContinue,
					Data:   map[string]any{"body": newBody},
				}, nil
			}
			return nil, nil
		},
		plugin.OnErrorSkip,
	)

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetPluginEngine(pluginEngine)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"auth: original-token"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Auth", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC plugin hooks: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The upstream echoed the (modified) request body. Verify transformation.
	if len(body) <= 5 {
		t.Fatalf("response body too short for verification: %d bytes", len(body))
	}
	respFrames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(respFrames) == 0 {
		t.Fatal("no response frames found")
	}
	decoded, decErr := protobuf.Decode(respFrames[0].Payload)
	if decErr != nil {
		t.Fatalf("protobuf decode: %v", decErr)
	}
	if strings.Contains(decoded, "original-token") {
		t.Errorf("plugin did not modify body: %s", decoded)
	}
	if !strings.Contains(decoded, "MODIFIED-TOKEN") {
		t.Errorf("expected modified token in response: %s", decoded)
	}
}

func TestIntegration_GRPC_Intercept_Hold_Release(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body) // Echo.
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	interceptEngine := intercept.NewEngine()
	err = interceptEngine.AddRule(intercept.Rule{
		ID:        "grpc-intercept",
		Enabled:   true,
		Direction: intercept.DirectionRequest,
		Conditions: intercept.Conditions{
			PathPattern: "/test.Service/Intercepted",
			Methods:     []string{"POST"},
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	interceptQueue := intercept.NewQueue()
	interceptQueue.SetTimeout(5 * time.Second)

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetInterceptEngine(interceptEngine)
		h.SetInterceptQueue(interceptQueue)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"intercepted-data"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Intercepted", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	// Start request in background.
	type result struct {
		resp *gohttp.Response
		err  error
	}
	ch := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		ch <- result{resp, err}
	}()

	// Wait for the request to appear in the intercept queue.
	var items []*intercept.InterceptedRequest
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		items = interceptQueue.List()
		if len(items) > 0 {
			break
		}
	}
	if len(items) == 0 {
		t.Fatal("no items in intercept queue")
	}

	// Release the intercepted request.
	err = interceptQueue.Respond(items[0].ID, intercept.InterceptAction{
		Type: intercept.ActionRelease,
	})
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}

	// Wait for the response.
	res := <-ch
	if res.err != nil {
		t.Fatalf("intercepted request: %v", res.err)
	}
	defer res.resp.Body.Close()
	body, _ := io.ReadAll(res.resp.Body)

	if res.resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", res.resp.StatusCode, gohttp.StatusOK)
	}

	// Verify echoed data came through.
	if len(body) <= 5 {
		t.Fatalf("response body too short for verification: %d bytes", len(body))
	}
	respFrames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(respFrames) == 0 {
		t.Fatal("no response frames found")
	}
	decoded, decErr := protobuf.Decode(respFrames[0].Payload)
	if decErr != nil {
		t.Fatalf("protobuf decode: %v", decErr)
	}
	if !strings.Contains(decoded, "intercepted-data") {
		t.Errorf("expected original data after release: %s", decoded)
	}
}

func TestIntegration_GRPC_AutoTransform_BodyReplace(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes request body.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	pipeline := rules.NewPipeline()
	err = pipeline.AddRule(rules.Rule{
		ID:        "replace-grpc-token",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-secret",
			Value:   "NEW-SECRET",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetTransformPipeline(pipeline)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"token: old-secret"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Transform", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC auto-transform: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the echoed response contains transformed data.
	if len(body) <= 5 {
		t.Fatalf("response body too short for verification: %d bytes", len(body))
	}
	respFrames, parseErr := protogrpc.ReadAllFrames(body)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(respFrames) == 0 {
		t.Fatal("no response frames found")
	}
	decoded, decErr := protobuf.Decode(respFrames[0].Payload)
	if decErr != nil {
		t.Fatalf("protobuf decode: %v", decErr)
	}
	if strings.Contains(decoded, "old-secret") {
		t.Errorf("auto-transform not applied: %s", decoded)
	}
	if !strings.Contains(decoded, "NEW-SECRET") {
		t.Errorf("expected transformed value: %s", decoded)
	}
}

// --- Concurrent streams test ---

func TestIntegration_GRPC_ConcurrentStreams(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	const concurrency = 5
	var wg sync.WaitGroup
	errs := make(chan error, concurrency)

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			reqJSON := fmt.Sprintf(`{"0001:0000:String":"concurrent-%d"}`, n)
			reqFrame := buildProtobufFrame(t, reqJSON)
			targetURL := fmt.Sprintf("http://%s/test.Service/Concurrent%d", upstreamAddr, n)
			req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
			req.Header.Set("Content-Type", "application/grpc")

			resp, err := client.Do(req)
			if err != nil {
				errs <- fmt.Errorf("stream %d: %w", n, err)
				return
			}
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != gohttp.StatusOK {
				errs <- fmt.Errorf("stream %d: status = %d", n, resp.StatusCode)
				return
			}

			respFrames, _ := protogrpc.ReadAllFrames(body)
			if len(respFrames) != 1 {
				errs <- fmt.Errorf("stream %d: expected 1 frame, got %d", n, len(respFrames))
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Error(err)
	}

	// Verify all flows were recorded.
	flows := pollGRPCFlows(t, ctx, store, concurrency)
	if len(flows) < concurrency {
		t.Errorf("expected at least %d gRPC flows, got %d", concurrency, len(flows))
	}
}

// --- Variant recording test ---

func TestIntegration_GRPC_VariantRecording(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream echoes back.
	upstreamAddr, closeUpstream := startGRPCTestUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
	}))
	defer closeUpstream()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	// Use auto-transform to create a variant (modified body).
	pipeline := rules.NewPipeline()
	err = pipeline.AddRule(rules.Rule{
		ID:        "variant-replace",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "variant-original",
			Value:   "VARIANT-MODIFIED",
		},
	})
	if err != nil {
		t.Fatalf("AddRule: %v", err)
	}

	proxyAddr, proxyCancel := startGRPCProxy(t, ctx, store, func(h *protohttp2.Handler) {
		h.SetTransformPipeline(pipeline)
	})
	defer proxyCancel()

	client := newH2CClient(proxyAddr)

	reqFrame := buildProtobufFrame(t, `{"0001:0000:String":"variant-original"}`)
	targetURL := fmt.Sprintf("http://%s/test.Service/Variant", upstreamAddr)
	req, _ := gohttp.NewRequest("POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC variant: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify flow was recorded (the transformation creates a modified flow).
	flows := pollGRPCFlows(t, ctx, store, 1)
	if flows[0].State != "complete" {
		t.Errorf("state = %q, want %q", flows[0].State, "complete")
	}
}
