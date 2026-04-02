//go:build e2e

package proxy_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	protohttp2 "github.com/usk6666/yorishiro-proxy/internal/protocol/http2"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// =============================================================================
// Data integrity test helpers
// =============================================================================

// generateBinaryData creates a byte slice of the given size containing all
// possible byte values (0x00-0xFF) in a repeating pattern. This covers null
// bytes, high bytes, and control characters to catch silent corruption.
func generateBinaryData(size int) []byte {
	data := make([]byte, size)
	for i := range data {
		data[i] = byte(i % 256)
	}
	return data
}

// containsSubstring checks if s contains substr.
func containsSubstring(s, substr string) bool {
	return strings.Contains(s, substr)
}

// sha256sum returns the hex-encoded SHA-256 digest of the given data.
func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return fmt.Sprintf("%x", h[:])
}

// =============================================================================
// HTTP/2 body integrity tests — byte-for-byte comparison
// =============================================================================

func TestIntegration_DataIntegrity_H2C_LargeBody_ByteForByte(t *testing.T) {
	tests := []struct {
		name     string
		bodySize int
		timeout  time.Duration
	}{
		{"128KB", 128 * 1024, 30 * time.Second},
		{"512KB", 512 * 1024, 30 * time.Second},
		{"1MB", 1 << 20, 60 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), tt.timeout)
			defer cancel()

			// Generate deterministic test data.
			reqBody := bytes.Repeat([]byte("ABCDEFGHIJKLMNOP"), tt.bodySize/16)
			if len(reqBody) != tt.bodySize {
				reqBody = reqBody[:tt.bodySize]
			}

			// Echo server: reads body fully, then responds with the same body.
			upstreamAddr, closeUpstream := startH2FEUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(gohttp.StatusOK)
				w.Write(body)
			}))
			defer closeUpstream()

			store := newH2FEStore(t, ctx)
			proxyAddr, proxyCancel := startH2FEProxy(t, ctx, store)
			defer proxyCancel()

			client := newH2FEClient(proxyAddr)

			targetURL := fmt.Sprintf("http://%s/data-integrity-h2c", upstreamAddr)
			resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("h2c POST: %v", err)
			}
			defer resp.Body.Close()
			respBody, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read response body: %v", err)
			}

			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
			}

			// Byte-for-byte comparison (the core assertion this Issue addresses).
			if !bytes.Equal(respBody, reqBody) {
				t.Errorf("response body differs from request body (size got=%d want=%d, sha256 got=%s want=%s)",
					len(respBody), len(reqBody), sha256sum(respBody), sha256sum(reqBody))
			}

			// Verify flow recording with content comparison.
			flows := pollH2FEFlows(t, ctx, store, "HTTP/2", 1)
			fl := flows[0]
			if fl.State != "complete" {
				t.Errorf("state = %q, want %q", fl.State, "complete")
			}

			send, recv := pollH2FEFlowMessages(t, ctx, store, fl.ID)
			if send == nil {
				t.Fatal("send message not found")
			}
			if recv == nil {
				t.Fatal("receive message not found")
			}

			// Verify recorded request body content (not just length).
			if !send.BodyTruncated && !bytes.Equal(send.Body, reqBody) {
				t.Errorf("recorded request body differs (size got=%d want=%d, sha256 got=%s want=%s)",
					len(send.Body), len(reqBody), sha256sum(send.Body), sha256sum(reqBody))
			}

			// Verify recorded response body content (not just length).
			if !recv.BodyTruncated && !bytes.Equal(recv.Body, reqBody) {
				t.Errorf("recorded response body differs (size got=%d want=%d, sha256 got=%s want=%s)",
					len(recv.Body), len(reqBody), sha256sum(recv.Body), sha256sum(reqBody))
			}

			// Verify raw bytes exist.
			if len(send.RawBytes) == 0 {
				t.Error("send RawBytes is empty for large body request")
			}
		})
	}
}

func TestIntegration_DataIntegrity_H2TLS_LargeBody_ByteForByte(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bodySize := 256 * 1024
	reqBody := bytes.Repeat([]byte("TLS-H2-INTEGRITY"), bodySize/16)

	// Start TLS upstream that echoes the body.
	upstream := startH2FETLSUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
	}))

	_, upstreamPort, _ := net.SplitHostPort(upstream.Listener.Addr().String())

	store := newH2FEStore(t, ctx)

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	listener, httpHandler, h2Handler, proxyCancel := startH2FETLSProxy(t, ctx, store, ca)
	defer proxyCancel()

	// Configure transports to trust the test upstream.
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	})
	h2Handler.SetTransport(&gohttp.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
		ForceAttemptHTTP2: true,
	})

	client := newH2FETLSClient(listener.Addr(), ca.Certificate())
	client.Timeout = 60 * time.Second

	targetURL := fmt.Sprintf("https://localhost:%s/data-integrity-h2-tls", upstreamPort)
	resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("h2 TLS POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Byte-for-byte comparison through TLS MITM.
	if !bytes.Equal(respBody, reqBody) {
		t.Errorf("h2 TLS: response body differs from request (size got=%d want=%d, sha256 got=%s want=%s)",
			len(respBody), len(reqBody), sha256sum(respBody), sha256sum(reqBody))
	}

	// Verify flow recording.
	flows := pollH2FEFlows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]
	if fl.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "HTTP/2")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	send, recv := pollH2FEFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	// Verify recorded body content.
	if !send.BodyTruncated && !bytes.Equal(send.Body, reqBody) {
		t.Errorf("recorded request body differs (sha256 got=%s want=%s)",
			sha256sum(send.Body), sha256sum(reqBody))
	}
	if !recv.BodyTruncated && !bytes.Equal(recv.Body, reqBody) {
		t.Errorf("recorded response body differs (sha256 got=%s want=%s)",
			sha256sum(recv.Body), sha256sum(reqBody))
	}
}

// =============================================================================
// gRPC protobuf payload integrity
// =============================================================================

func TestIntegration_DataIntegrity_GRPC_ProtobufPayload(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The upstream echoes the gRPC frame body back in the response.
	upstreamAddr, closeUpstream := startH2FEUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		w.WriteHeader(gohttp.StatusOK)
		// Echo back the exact gRPC frame received.
		w.Write(body)
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Status", "0")
		w.Header().Set(gohttp.TrailerPrefix+"Grpc-Message", "OK")
	}))
	defer closeUpstream()

	store := newH2FEStore(t, ctx)
	proxyAddr, proxyCancel := startH2FEProxy(t, ctx, store, func(h *protohttp2.Handler) {
		logger := testutil.DiscardLogger()
		grpcHandler := protogrpc.NewHandler(store, logger)
		h.SetGRPCHandler(grpcHandler)
	})
	defer proxyCancel()

	client := newH2FEClient(proxyAddr)

	// Build a protobuf gRPC frame with known content.
	reqJSON := `{"0001:0000:String":"integrity-test-payload","0002:0000:String":"verification-data-12345"}`
	payload, err := protobuf.Encode(reqJSON)
	if err != nil {
		t.Fatalf("protobuf encode: %v", err)
	}
	reqFrame := protogrpc.EncodeFrame(false, payload)

	targetURL := fmt.Sprintf("http://%s/integrity.Service/Echo", upstreamAddr)
	req, _ := gohttp.NewRequestWithContext(ctx, "POST", targetURL, bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("gRPC echo: %v", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Parse response frames and verify the protobuf content survived the proxy.
	respFrames, parseErr := protogrpc.ReadAllFrames(respBody)
	if parseErr != nil {
		t.Fatalf("parse response frames: %v", parseErr)
	}
	if len(respFrames) != 1 {
		t.Fatalf("expected 1 response frame, got %d", len(respFrames))
	}

	// Byte-for-byte comparison of the gRPC payload.
	if !bytes.Equal(respFrames[0].Payload, payload) {
		t.Errorf("gRPC response payload differs from request (size got=%d want=%d)",
			len(respFrames[0].Payload), len(payload))
	}

	// Verify the protobuf payload can be decoded back to valid JSON.
	decoded, decErr := protobuf.Decode(respFrames[0].Payload)
	if decErr != nil {
		t.Fatalf("protobuf decode response: %v", decErr)
	}
	// The protobuf codec may reformat JSON (pretty-print, renumber fields),
	// so we verify that the decoded content contains the expected field values
	// rather than exact string match.
	if decoded == "" {
		t.Error("decoded protobuf response is empty")
	}
	for _, expected := range []string{"integrity-test-payload", "verification-data-12345"} {
		if !containsSubstring(decoded, expected) {
			t.Errorf("decoded protobuf missing expected value %q in: %s", expected, decoded)
		}
	}

	// Verify flow recording.
	flows := pollH2FEFlows(t, ctx, store, "gRPC", 1)
	fl := flows[0]
	if fl.Protocol != "gRPC" {
		t.Errorf("protocol = %q, want %q", fl.Protocol, "gRPC")
	}
	if fl.State != "complete" {
		t.Errorf("state = %q, want %q", fl.State, "complete")
	}

	// Verify recorded messages contain the protobuf payload.
	msgs, err := store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}

	// Find the send message with body content.
	var sendWithBody *flow.Message
	for _, m := range msgs {
		if m.Direction == "send" && len(m.Body) > 0 {
			sendWithBody = m
			break
		}
	}
	if sendWithBody != nil {
		// Verify the recorded protobuf can be decoded correctly.
		recordedDecoded, recDecErr := protobuf.Decode(sendWithBody.Body)
		if recDecErr != nil {
			t.Errorf("protobuf decode recorded body: %v", recDecErr)
		} else {
			for _, expected := range []string{"integrity-test-payload", "verification-data-12345"} {
				if !containsSubstring(recordedDecoded, expected) {
					t.Errorf("recorded decoded protobuf missing %q in: %s", expected, recordedDecoded)
				}
			}
		}
	}
}

// =============================================================================
// Binary data integrity — null bytes, high bytes, control characters
// =============================================================================

func TestIntegration_DataIntegrity_H2C_BinaryBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate binary data with all byte values (0x00-0xFF) repeated.
	binaryBody := generateBinaryData(4096)

	upstreamAddr, closeUpstream := startH2FEUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
	}))
	defer closeUpstream()

	store := newH2FEStore(t, ctx)
	proxyAddr, proxyCancel := startH2FEProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2FEClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/binary-integrity-h2c", upstreamAddr)
	resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(binaryBody))
	if err != nil {
		t.Fatalf("h2c binary POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Byte-for-byte comparison of binary data through h2c proxy.
	if !bytes.Equal(respBody, binaryBody) {
		t.Errorf("binary body corrupted through h2c proxy (size got=%d want=%d, sha256 got=%s want=%s)",
			len(respBody), len(binaryBody), sha256sum(respBody), sha256sum(binaryBody))
		// Find first differing byte for debugging.
		for i := 0; i < len(respBody) && i < len(binaryBody); i++ {
			if respBody[i] != binaryBody[i] {
				t.Errorf("first difference at byte %d: got 0x%02x, want 0x%02x", i, respBody[i], binaryBody[i])
				break
			}
		}
	}

	// Verify flow recording preserves binary content.
	flows := pollH2FEFlows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]

	send, recv := pollH2FEFlowMessages(t, ctx, store, fl.ID)
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	if !send.BodyTruncated && !bytes.Equal(send.Body, binaryBody) {
		t.Errorf("recorded request binary body corrupted (size got=%d want=%d)",
			len(send.Body), len(binaryBody))
	}
	if !recv.BodyTruncated && !bytes.Equal(recv.Body, binaryBody) {
		t.Errorf("recorded response binary body corrupted (size got=%d want=%d)",
			len(recv.Body), len(binaryBody))
	}
}

func TestIntegration_DataIntegrity_HTTP1_BinaryBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate binary data with all byte values.
	binaryBody := generateBinaryData(4096)

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body)
	})
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamLn)
	defer upstreamServer.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())
	client.Timeout = 30 * time.Second

	targetURL := fmt.Sprintf("http://%s/binary-integrity-http1", upstreamLn.Addr().String())
	resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(binaryBody))
	if err != nil {
		t.Fatalf("HTTP/1.x binary POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Byte-for-byte comparison of binary data through HTTP/1.x proxy.
	if !bytes.Equal(respBody, binaryBody) {
		t.Errorf("binary body corrupted through HTTP/1.x proxy (size got=%d want=%d, sha256 got=%s want=%s)",
			len(respBody), len(binaryBody), sha256sum(respBody), sha256sum(binaryBody))
		for i := 0; i < len(respBody) && i < len(binaryBody); i++ {
			if respBody[i] != binaryBody[i] {
				t.Errorf("first difference at byte %d: got 0x%02x, want 0x%02x", i, respBody[i], binaryBody[i])
				break
			}
		}
	}

	// Verify flow recording.
	var flows []*flow.Flow
	var send, recv *flow.Message
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= 1 {
			msgs, mErr := store.GetMessages(ctx, flows[0].ID, flow.MessageListOptions{})
			if mErr != nil {
				t.Fatalf("GetMessages: %v", mErr)
			}
			for _, m := range msgs {
				switch m.Direction {
				case "send":
					send = m
				case "receive":
					recv = m
				}
			}
			if send != nil && recv != nil {
				break
			}
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded")
	}
	if send == nil {
		t.Fatal("send message not found")
	}
	if recv == nil {
		t.Fatal("receive message not found")
	}

	if !send.BodyTruncated && !bytes.Equal(send.Body, binaryBody) {
		t.Errorf("HTTP/1.x recorded request binary body corrupted (size got=%d want=%d)",
			len(send.Body), len(binaryBody))
	}
	if !recv.BodyTruncated && !bytes.Equal(recv.Body, binaryBody) {
		t.Errorf("HTTP/1.x recorded response binary body corrupted (size got=%d want=%d)",
			len(recv.Body), len(binaryBody))
	}
}

func TestIntegration_DataIntegrity_HTTPS_BinaryBody(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate binary data with all byte values.
	binaryBody := generateBinaryData(4096)

	// Start HTTPS upstream.
	upstreamCA := &cert.CA{}
	if err := upstreamCA.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(upstreamCA)
	tlsCert, err := issuer.GetCertificate("localhost")
	if err != nil {
		t.Fatal(err)
	}

	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tlsLn := tls.NewListener(upstreamLn, &tls.Config{
		Certificates: []tls.Certificate{*tlsCert},
	})
	upstreamServer := &gohttp.Server{
		Handler: gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/octet-stream")
			w.WriteHeader(gohttp.StatusOK)
			w.Write(body)
		}),
	}
	go upstreamServer.Serve(tlsLn)
	defer upstreamServer.Close()

	_, upstreamPort, _ := net.SplitHostPort(upstreamLn.Addr().String())

	// Start MITM proxy with CA.
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, storeErr := flow.NewSQLiteStore(ctx, dbPath, logger)
	if storeErr != nil {
		t.Fatalf("NewSQLiteStore: %v", storeErr)
	}
	defer store.Close()

	listener, httpHandler, proxyCancel := startHTTPSProxy(t, ctx, store, ca)
	defer proxyCancel()

	// Configure upstream transport to trust the test upstream server.
	httpHandler.SetTransport(&gohttp.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	})

	client := httpsProxyClient(listener.Addr(), ca.Certificate())
	client.Timeout = 30 * time.Second

	targetURL := fmt.Sprintf("https://localhost:%s/binary-integrity-https", upstreamPort)
	resp, err := client.Post(targetURL, "application/octet-stream", bytes.NewReader(binaryBody))
	if err != nil {
		t.Fatalf("HTTPS binary POST: %v", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Byte-for-byte comparison of binary data through HTTPS MITM proxy.
	if !bytes.Equal(respBody, binaryBody) {
		t.Errorf("binary body corrupted through HTTPS MITM (size got=%d want=%d, sha256 got=%s want=%s)",
			len(respBody), len(binaryBody), sha256sum(respBody), sha256sum(binaryBody))
	}

	// Verify flow recording.
	var flows []*flow.Flow
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		flows, err = store.ListFlows(ctx, flow.ListOptions{Limit: 10})
		if err != nil {
			t.Fatalf("ListFlows: %v", err)
		}
		if len(flows) >= 1 {
			break
		}
	}
	if len(flows) == 0 {
		t.Fatal("no flows recorded")
	}
}

// =============================================================================
// Response header fidelity tests
// =============================================================================

func TestIntegration_DataIntegrity_H2C_ResponseHeaderFidelity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Upstream sends multi-value headers and multiple Set-Cookie headers.
	upstreamAddr, closeUpstream := startH2FEUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		// Multiple Set-Cookie headers (common in real-world responses).
		w.Header().Add("Set-Cookie", "session=abc123; Path=/; HttpOnly")
		w.Header().Add("Set-Cookie", "lang=en; Path=/; Max-Age=3600")
		w.Header().Add("Set-Cookie", "theme=dark; Path=/")
		// Multi-value header.
		w.Header().Add("X-Custom-Multi", "value-one")
		w.Header().Add("X-Custom-Multi", "value-two")
		// Cache-Control with multiple directives.
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("X-Fingerprint", "test-fidelity-check")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "header-fidelity-test")
	}))
	defer closeUpstream()

	store := newH2FEStore(t, ctx)
	proxyAddr, proxyCancel := startH2FEProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2FEClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/header-fidelity", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if string(body) != "header-fidelity-test" {
		t.Errorf("body = %q, want %q", body, "header-fidelity-test")
	}

	// Verify multiple Set-Cookie headers are preserved (not merged).
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) != 3 {
		t.Errorf("Set-Cookie count = %d, want 3; values = %v", len(setCookies), setCookies)
	}

	// Verify multi-value headers are preserved.
	customMulti := resp.Header.Values("X-Custom-Multi")
	if len(customMulti) != 2 {
		t.Errorf("X-Custom-Multi count = %d, want 2; values = %v", len(customMulti), customMulti)
	}

	// Verify Cache-Control is not altered.
	cacheControl := resp.Header.Get("Cache-Control")
	if cacheControl != "no-cache, no-store, must-revalidate" {
		t.Errorf("Cache-Control = %q, want %q", cacheControl, "no-cache, no-store, must-revalidate")
	}

	// Verify the fingerprint header passes through unmodified.
	fingerprint := resp.Header.Get("X-Fingerprint")
	if fingerprint != "test-fidelity-check" {
		t.Errorf("X-Fingerprint = %q, want %q", fingerprint, "test-fidelity-check")
	}

	// Verify flow recording preserves multi-value headers.
	flows := pollH2FEFlows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]

	_, recv := pollH2FEFlowMessages(t, ctx, store, fl.ID)
	if recv == nil {
		t.Fatal("receive message not found")
	}

	// In flow recording, Headers is map[string][]string.
	if recv.Headers != nil {
		// Check Set-Cookie values are recorded as separate entries.
		if sc, ok := recv.Headers["set-cookie"]; ok {
			if len(sc) != 3 {
				t.Errorf("recorded set-cookie count = %d, want 3; values = %v", len(sc), sc)
			}
		}
	}
}

func TestIntegration_DataIntegrity_HTTP1_ResponseHeaderFidelity(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Add("Set-Cookie", "a=1; Path=/")
		w.Header().Add("Set-Cookie", "b=2; Path=/; Secure")
		w.Header().Add("X-Multi", "first")
		w.Header().Add("X-Multi", "second")
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(gohttp.StatusOK)
		fmt.Fprint(w, "ok")
	})
	upstreamLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	upstreamServer := &gohttp.Server{Handler: upstream}
	go upstreamServer.Serve(upstreamLn)
	defer upstreamServer.Close()

	dbPath := filepath.Join(t.TempDir(), "test.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	defer store.Close()

	listener, proxyCancel := startProxy(t, ctx, store)
	defer proxyCancel()

	client := proxyClient(listener.Addr())

	targetURL := fmt.Sprintf("http://%s/header-fidelity-http1", upstreamLn.Addr().String())
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("HTTP/1.x GET: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// Verify multiple Set-Cookie headers are preserved.
	setCookies := resp.Header.Values("Set-Cookie")
	if len(setCookies) != 2 {
		t.Errorf("Set-Cookie count = %d, want 2; values = %v", len(setCookies), setCookies)
	}

	// Verify multi-value headers.
	xMulti := resp.Header.Values("X-Multi")
	if len(xMulti) != 2 {
		t.Errorf("X-Multi count = %d, want 2; values = %v", len(xMulti), xMulti)
	}

	// Verify no whitespace normalization on Content-Type.
	ct := resp.Header.Get("Content-Type")
	if ct != "text/plain" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/plain")
	}
}

// =============================================================================
// Response large body integrity — verifies the response path independently
// =============================================================================

func TestIntegration_DataIntegrity_H2C_LargeResponse_ByteForByte(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Generate a known large response body.
	responseBody := bytes.Repeat([]byte("RESPONSE-DATA-16"), 128*1024/16)

	upstreamAddr, closeUpstream := startH2FEUpstream(t, gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(responseBody)
	}))
	defer closeUpstream()

	store := newH2FEStore(t, ctx)
	proxyAddr, proxyCancel := startH2FEProxy(t, ctx, store)
	defer proxyCancel()

	client := newH2FEClient(proxyAddr)

	targetURL := fmt.Sprintf("http://%s/large-response-integrity", upstreamAddr)
	resp, err := client.Get(targetURL)
	if err != nil {
		t.Fatalf("h2c GET: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Byte-for-byte response comparison (the key improvement over length-only check).
	if !bytes.Equal(body, responseBody) {
		t.Errorf("response body differs (size got=%d want=%d, sha256 got=%s want=%s)",
			len(body), len(responseBody), sha256sum(body), sha256sum(responseBody))
	}

	// Verify recorded response body content.
	flows := pollH2FEFlows(t, ctx, store, "HTTP/2", 1)
	fl := flows[0]

	_, recv := pollH2FEFlowMessages(t, ctx, store, fl.ID)
	if recv == nil {
		t.Fatal("receive message not found")
	}
	if !recv.BodyTruncated && !bytes.Equal(recv.Body, responseBody) {
		t.Errorf("recorded response body differs (size got=%d want=%d, sha256 got=%s want=%s)",
			len(recv.Body), len(responseBody), sha256sum(recv.Body), sha256sum(responseBody))
	}
}
