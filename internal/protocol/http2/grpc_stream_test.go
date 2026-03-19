package http2

import (
	"bytes"
	"fmt"
	"io"
	"net"
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

// TestIsGRPCTrailersOnly verifies detection of gRPC Trailers-Only responses.
func TestIsGRPCTrailersOnly(t *testing.T) {
	tests := []struct {
		name string
		resp *gohttp.Response
		want bool
	}{
		{
			name: "trailers-only: grpc-status in header, empty trailer",
			resp: &gohttp.Response{
				Header:  gohttp.Header{"Grpc-Status": {"0"}, "Content-Type": {"application/grpc"}},
				Trailer: gohttp.Header{},
			},
			want: true,
		},
		{
			name: "trailers-only: grpc-status in header, nil trailer",
			resp: &gohttp.Response{
				Header:  gohttp.Header{"Grpc-Status": {"0"}},
				Trailer: nil,
			},
			want: true,
		},
		{
			name: "normal response: grpc-status in trailer",
			resp: &gohttp.Response{
				Header:  gohttp.Header{"Content-Type": {"application/grpc"}},
				Trailer: gohttp.Header{"Grpc-Status": {"0"}},
			},
			want: false,
		},
		{
			name: "no grpc-status at all",
			resp: &gohttp.Response{
				Header:  gohttp.Header{"Content-Type": {"application/grpc"}},
				Trailer: gohttp.Header{},
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGRPCTrailersOnly(tt.resp)
			if got != tt.want {
				t.Errorf("isGRPCTrailersOnly() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestIsGRPCTrailerKey verifies gRPC trailer key detection.
func TestIsGRPCTrailerKey(t *testing.T) {
	tests := []struct {
		key  string
		want bool
	}{
		{"Grpc-Status", true},
		{"Grpc-Message", true},
		{"Grpc-Status-Details-Bin", true},
		{"grpc-status", true},
		{"GRPC-STATUS", true},
		{"Content-Type", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.key, func(t *testing.T) {
			got := isGRPCTrailerKey(tt.key)
			if got != tt.want {
				t.Errorf("isGRPCTrailerKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

// TestHandleGRPCStream_TrailersOnly verifies that a gRPC Trailers-Only
// response is correctly proxied. In a Trailers-Only response, the upstream
// returns grpc-status as a regular header with no body. This produces the
// same resp.Header/resp.Trailer state as a real HTTP/2 Trailers-Only frame
// (where Go's http2.Transport merges all fields into resp.Header and leaves
// resp.Trailer empty), so an HTTP/1.1 upstream is sufficient to exercise
// the proxy's isGRPCTrailersOnly detection and fallback trailer extraction.
func TestHandleGRPCStream_TrailersOnly(t *testing.T) {
	tests := []struct {
		name       string
		grpcStatus string
		grpcMsg    string
	}{
		{
			name:       "OK status",
			grpcStatus: "0",
			grpcMsg:    "",
		},
		{
			name:       "error status with message",
			grpcStatus: "5",
			grpcMsg:    "not found",
		},
		{
			name:       "permission denied",
			grpcStatus: "7",
			grpcMsg:    "access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Upstream sets grpc-status as a regular header with no body.
			// This simulates the Trailers-Only state: resp.Header contains
			// grpc-status and resp.Trailer is empty.
			upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				io.Copy(io.Discard, r.Body)
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Grpc-Status", tt.grpcStatus)
				if tt.grpcMsg != "" {
					w.Header().Set("Grpc-Message", tt.grpcMsg)
				}
				w.WriteHeader(gohttp.StatusOK)
				// No body — Trailers-Only pattern.
			}))
			defer upstream.Close()

			store := &mockStore{}
			handler := NewHandler(store, testutil.DiscardLogger())
			grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
			handler.SetGRPCHandler(grpcHandler)

			proxyAddr, cancel := startH2CProxyListener(t, handler,
				fmt.Sprintf("conn-trailers-only-%s", tt.name), "127.0.0.1:9999", "", tlsMetadata{})
			defer cancel()

			client := newH2CClientForAddr(proxyAddr)

			req, _ := gohttp.NewRequest("POST",
				upstream.URL+"/test.Service/TrailersOnly", gohttp.NoBody)
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

			// gRPC clients read grpc-status from trailers. Verify it's present.
			grpcStatus := resp.Trailer.Get("Grpc-Status")
			if grpcStatus == "" {
				// Also check Header for TrailerPrefix pattern (h2c client behavior).
				grpcStatus = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Status")
			}
			if grpcStatus != tt.grpcStatus {
				t.Errorf("grpc-status = %q, want %q (trailer=%v, header=%v)",
					grpcStatus, tt.grpcStatus, resp.Trailer, resp.Header)
			}

			if tt.grpcMsg != "" {
				grpcMsg := resp.Trailer.Get("Grpc-Message")
				if grpcMsg == "" {
					grpcMsg = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Message")
				}
				if grpcMsg != tt.grpcMsg {
					t.Errorf("grpc-message = %q, want %q", grpcMsg, tt.grpcMsg)
				}
			}
		})
	}
}

// TestHandleGRPCStream_TrailersOnlyNoDeadlock verifies that a gRPC
// Trailers-Only response (no DATA frames, only HEADERS+END_STREAM) does not
// deadlock when the client uses a streaming request body. This is the
// regression test for USK-434.
//
// The deadlock scenario:
//  1. Client sends request via a pipe (body not yet closed).
//  2. Upstream returns Trailers-Only (grpc-status in headers, empty body).
//  3. Proxy must flush the response to the client before waiting for the
//     request goroutine to finish — otherwise the client never sees the
//     response and cannot close its request stream, causing a deadlock.
//
// This test uses an h2c upstream to enable true HTTP/2 bidirectional streaming,
// where the server can respond before the client finishes sending its body.
// An HTTP/1.1 upstream cannot reproduce this deadlock because its transport
// blocks until the entire request body is sent.
func TestHandleGRPCStream_TrailersOnlyNoDeadlock(t *testing.T) {
	// Start an h2c upstream that returns a Trailers-Only response immediately
	// without draining the request body, simulating a gRPC UNIMPLEMENTED error.
	upstreamHandler := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Grpc-Status", "12") // UNIMPLEMENTED
		w.Header().Set("Grpc-Message", "method not found")
		w.WriteHeader(gohttp.StatusOK)
		// No body — Trailers-Only pattern.
		// Do NOT drain body: server responds before client finishes.
	})

	upstreamProtos := &gohttp.Protocols{}
	upstreamProtos.SetHTTP1(true)
	upstreamProtos.SetUnencryptedHTTP2(true)
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	upstreamServer := &gohttp.Server{Handler: upstreamHandler, Protocols: upstreamProtos}
	go upstreamServer.Serve(upstreamLn)
	defer upstreamServer.Close()
	upstreamURL := "http://" + upstreamLn.Addr().String()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	// Configure proxy transport to use h2c to the upstream.
	upstreamTransportProtos := &gohttp.Protocols{}
	upstreamTransportProtos.SetUnencryptedHTTP2(true)
	upstreamTransportProtos.SetHTTP2(true)
	handler.Transport = &gohttp.Transport{
		Protocols: upstreamTransportProtos,
	}

	proxyAddr, cancel := startH2CProxyListener(t, handler,
		"conn-trailers-only-deadlock", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	// Use a pipe for the request body. The client will only close the pipe
	// after it receives the response — mimicking real gRPC client behavior
	// where the client waits for the server response before finishing.
	bodyPR, bodyPW := io.Pipe()
	defer bodyPW.Close()

	req, _ := gohttp.NewRequest("POST",
		upstreamURL+"/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", bodyPR)
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

	// Write one gRPC frame so the proxy can forward it to the upstream.
	// The upstream will respond immediately with Trailers-Only.
	frame := protogrpc.EncodeFrame(false, []byte("reflection-request"))
	if _, err := bodyPW.Write(frame); err != nil {
		t.Fatalf("write initial frame: %v", err)
	}

	// Wait for the response with a timeout. Before the fix, this would
	// deadlock because the proxy never flushed the trailers-only response.
	var resp *gohttp.Response
	select {
	case r := <-resCh:
		if r.err != nil {
			t.Fatalf("client request: %v", r.err)
		}
		resp = r.resp
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for response — deadlock detected (USK-434)")
	}
	defer resp.Body.Close()

	// Close the pipe now that we have the response.
	bodyPW.Close()

	io.Copy(io.Discard, resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify grpc-status trailer was received.
	grpcStatus := resp.Trailer.Get("Grpc-Status")
	if grpcStatus == "" {
		grpcStatus = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Status")
	}
	if grpcStatus != "12" {
		t.Errorf("grpc-status = %q, want %q (trailer=%v, header=%v)",
			grpcStatus, "12", resp.Trailer, resp.Header)
	}

	grpcMsg := resp.Trailer.Get("Grpc-Message")
	if grpcMsg == "" {
		grpcMsg = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Message")
	}
	if grpcMsg != "method not found" {
		t.Errorf("grpc-message = %q, want %q", grpcMsg, "method not found")
	}
}

// TestHandleGRPCStream_NormalTrailers verifies that a normal gRPC response
// (with body and proper trailers) still works correctly after the
// Trailers-Only fix. This is a regression test ensuring the fallback path
// does not interfere with responses that have resp.Trailer populated.
func TestHandleGRPCStream_NormalTrailers(t *testing.T) {
	respPayload := []byte("normal-response")

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, respPayload))
		// Use TrailerPrefix to set trailer values after the body, following
		// Go's net/http convention (see trailer_test.go for the same pattern).
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	proxyAddr, cancel := startH2CProxyListener(t, handler,
		"conn-normal-trailers", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqBody := protogrpc.EncodeFrame(false, []byte("request"))
	req, _ := gohttp.NewRequest("POST",
		upstream.URL+"/test.Service/Normal", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client request: %v", err)
	}
	defer resp.Body.Close()

	// Must read body fully before trailers are available.
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Verify response body contains the gRPC frame.
	frames, err := protogrpc.ReadAllFrames(body)
	if err != nil {
		t.Fatalf("parse response frames: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(frames))
	}
	if string(frames[0].Payload) != string(respPayload) {
		t.Errorf("response payload = %q, want %q", frames[0].Payload, respPayload)
	}

	// Verify trailers are delivered to the client (the main regression check).
	grpcStatus := resp.Trailer.Get("Grpc-Status")
	if grpcStatus == "" {
		grpcStatus = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Status")
	}
	if grpcStatus != "0" {
		t.Errorf("Grpc-Status trailer = %q, want %q (trailer=%v)", grpcStatus, "0", resp.Trailer)
	}

	grpcMsg := resp.Trailer.Get("Grpc-Message")
	if grpcMsg == "" {
		grpcMsg = resp.Header.Get(gohttp.TrailerPrefix + "Grpc-Message")
	}
	if grpcMsg != "OK" {
		t.Errorf("Grpc-Message trailer = %q, want %q", grpcMsg, "OK")
	}
}

// TestForwardGRPCRequestChunk_SubsystemError verifies that when the subsystem
// buffer returns an error, raw bytes are NOT forwarded to the upstream pipe.
// This prevents safety filter bypass (USK-441).
func TestForwardGRPCRequestChunk_SubsystemError(t *testing.T) {
	tests := []struct {
		name       string
		reqBlocked bool
	}{
		{
			name:       "subsystem error with reqBlocked flag set",
			reqBlocked: true,
		},
		{
			name:       "subsystem error without reqBlocked flag",
			reqBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

			state := &grpcStreamState{}
			if tt.reqBlocked {
				state.reqBlocked = true
			}

			// Create a pipe to capture any bytes written to upstream.
			pr, pw := io.Pipe()

			// Create a subsystem buffer that always returns an error.
			subsystemBuf := protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
				return fmt.Errorf("subsystem rejected frame")
			})

			sc := &streamContext{
				logger: testutil.DiscardLogger(),
			}

			chunk := protogrpc.EncodeFrame(false, []byte("blocked-payload"))

			err := handler.forwardGRPCRequestChunk(sc, state, pw, subsystemBuf, chunk, true)
			if err == nil {
				t.Fatal("expected error from forwardGRPCRequestChunk, got nil")
			}

			// Close the write end so Read won't block.
			pw.Close()

			// Verify no raw bytes leaked through the pipe.
			leaked, _ := io.ReadAll(pr)
			if len(leaked) > 0 {
				t.Errorf("raw bytes leaked to upstream: got %d bytes, want 0", len(leaked))
			}
		})
	}
}

// TestForwardGRPCResponseChunk_SubsystemError verifies that when the subsystem
// buffer returns an error, raw bytes are NOT forwarded to the client.
// This prevents output filter bypass (USK-441).
func TestForwardGRPCResponseChunk_SubsystemError(t *testing.T) {
	tests := []struct {
		name        string
		respBlocked bool
	}{
		{
			name:        "subsystem error with respBlocked flag set",
			respBlocked: true,
		},
		{
			name:        "subsystem error without respBlocked flag",
			respBlocked: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

			state := &grpcStreamState{}
			if tt.respBlocked {
				state.respBlocked = true
			}

			rec := httptest.NewRecorder()
			sc := &streamContext{
				w:      rec,
				logger: testutil.DiscardLogger(),
			}

			// Create a subsystem buffer that always returns an error.
			subsystemBuf := protogrpc.NewFrameBuffer(func(raw []byte, frame *protogrpc.Frame) error {
				return fmt.Errorf("output filter rejected frame")
			})

			chunk := protogrpc.EncodeFrame(false, []byte("sensitive-data"))

			done := handler.forwardGRPCResponseChunk(sc, state, subsystemBuf, rec, chunk, true)
			if !done {
				t.Error("expected forwardGRPCResponseChunk to return true (stop), got false")
			}

			// Verify no raw response bytes leaked to the client body.
			// The recorder body should only contain the gRPC error status trailer,
			// not the original chunk data.
			body := rec.Body.Bytes()
			if bytes.Contains(body, []byte("sensitive-data")) {
				t.Error("raw response bytes leaked to client: found sensitive-data in response body")
			}
		})
	}
}

// TestForwardGRPCRequestChunk_NoSubsystems verifies that when subsystems are
// disabled, chunks are written directly to the pipe writer without error.
func TestForwardGRPCRequestChunk_NoSubsystems(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	state := &grpcStreamState{}
	pr, pw := io.Pipe()

	sc := &streamContext{
		logger: testutil.DiscardLogger(),
	}

	chunk := protogrpc.EncodeFrame(false, []byte("pass-through"))

	// Write in a goroutine since pipe blocks until read.
	errCh := make(chan error, 1)
	go func() {
		errCh <- handler.forwardGRPCRequestChunk(sc, state, pw, nil, chunk, false)
		pw.Close()
	}()

	got, readErr := io.ReadAll(pr)
	if readErr != nil {
		t.Fatalf("read pipe: %v", readErr)
	}

	if err := <-errCh; err != nil {
		t.Fatalf("forwardGRPCRequestChunk error: %v", err)
	}

	if !bytes.Equal(got, chunk) {
		t.Errorf("pipe output = %q, want %q", got, chunk)
	}
}
