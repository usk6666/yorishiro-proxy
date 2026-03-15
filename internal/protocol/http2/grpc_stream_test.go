package http2

import (
	"bytes"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestHandleGRPCStream_UnaryOverStreaming verifies that a gRPC unary RPC
// (single request frame, single response frame) works correctly through
// the streaming transport path.
func TestHandleGRPCStream_UnaryOverStreaming(t *testing.T) {
	reqPayload := []byte("unary-request")
	respPayload := []byte("unary-response")

	// Start upstream HTTP/1.1 server (sufficient for unary).
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read body: %v", err)
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}

		// Parse the gRPC frame from the request.
		frames, err := protogrpc.ReadAllFrames(body)
		if err != nil {
			t.Errorf("upstream parse frames: %v", err)
		}
		if len(frames) != 1 || string(frames[0].Payload) != string(reqPayload) {
			t.Errorf("unexpected request payload: frames=%d", len(frames))
		}

		// Send gRPC response.
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, respPayload))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-grpc", "127.0.0.1:9999", "", tlsMetadata{})
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

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
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
	time.Sleep(100 * time.Millisecond) // Allow async recording to complete.
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Error("expected at least one flow to be recorded")
		return
	}
	if store.flows[0].Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, "gRPC")
	}
}

// TestHandleGRPCStream_StreamingNoDeadlock verifies that gRPC streaming
// does not deadlock by sending multiple request frames through a pipe.
// The pipe-based body is streamed by the proxy without full buffering.
// This test uses an HTTP/1.1 upstream (sufficient to verify the proxy's
// streaming behavior on the client→proxy leg).
func TestHandleGRPCStream_StreamingNoDeadlock(t *testing.T) {
	const numFrames = 3

	// Upstream reads all request frames and echoes them in the response.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		// Echo all frames back.
		for _, f := range frames {
			w.Write(protogrpc.EncodeFrame(f.Compressed, f.Payload))
		}
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-stream", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	// Use a pipe for the client body to control frame timing.
	// This simulates streaming: frames are written one at a time.
	bodyPR, bodyPW := io.Pipe()

	client := newH2CClientForAddr(proxyAddr)

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Echo/Stream", bodyPR)
	req.Header.Set("Content-Type", "application/grpc")

	// Start request in background.
	type result struct {
		resp *gohttp.Response
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := client.Do(req)
		resCh <- result{resp, err}
	}()

	// Write frames one at a time through the pipe — this exercises
	// the streaming path and would deadlock with full buffering if
	// the upstream waited for the response before sending more.
	for i := 0; i < numFrames; i++ {
		payload := []byte("ping")
		frame := protogrpc.EncodeFrame(false, payload)
		if _, err := bodyPW.Write(frame); err != nil {
			t.Fatalf("write frame %d: %v", i, err)
		}
	}
	bodyPW.Close()

	// Wait for the response.
	var resp *gohttp.Response
	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client request: %v", r.err)
		}
		resp = r.resp
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for response — possible deadlock")
	}
	defer resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Read all echoed frames.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	frames, err := protogrpc.ReadAllFrames(body)
	if err != nil {
		t.Fatalf("parse response frames: %v", err)
	}
	if len(frames) != numFrames {
		t.Fatalf("expected %d response frames, got %d", numFrames, len(frames))
	}
	for i, f := range frames {
		if string(f.Payload) != "ping" {
			t.Errorf("frame %d: payload = %q, want %q", i, f.Payload, "ping")
		}
	}
}

// TestHandleGRPCStream_NonGRPCUsesBufferedPath verifies that non-gRPC HTTP/2
// requests still go through the buffered readAndTruncateBody path.
func TestHandleGRPCStream_NonGRPCUsesBufferedPath(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.WriteHeader(gohttp.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	// No gRPC handler set — should use buffered path.

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-1", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/api/data", bytes.NewReader([]byte("body")))
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify the flow was recorded as HTTP/2 (not gRPC).
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Error("expected at least one flow to be recorded")
		return
	}
	if store.flows[0].Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", store.flows[0].Protocol, "HTTP/2")
	}
}

// TestHandleGRPCStream_EmptyBody verifies that a gRPC request with no body
// frames is handled gracefully.
func TestHandleGRPCStream_EmptyBody(t *testing.T) {
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-empty", "127.0.0.1:9999", "", tlsMetadata{})
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

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
}

// TestHandleGRPCStream_MultipleRequestFrames verifies that a gRPC client
// streaming request with multiple frames is correctly forwarded and recorded.
func TestHandleGRPCStream_MultipleRequestFrames(t *testing.T) {
	payloads := []string{"frame-1", "frame-2", "frame-3"}

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
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

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-multi", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	var reqBody bytes.Buffer
	for _, p := range payloads {
		reqBody.Write(protogrpc.EncodeFrame(false, []byte(p)))
	}

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/ClientStream", &reqBody)
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify gRPC flow was recorded with correct frame count.
	time.Sleep(100 * time.Millisecond)
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.flows) == 0 {
		t.Error("expected at least one flow to be recorded")
		return
	}

	// Count send messages (should be 3 frames + maybe metadata).
	var sendCount int
	for _, msg := range store.messages {
		if msg.Direction == "send" {
			sendCount++
		}
	}
	if sendCount < len(payloads) {
		t.Errorf("expected at least %d send messages, got %d", len(payloads), sendCount)
	}
}
