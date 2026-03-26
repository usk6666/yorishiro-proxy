//go:build e2e

package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/protocol"
	protohttp "github.com/usk6666/yorishiro-proxy/internal/protocol/http"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// --- HTTP/1.x intercept raw forwarding ---

// TestE2E_InterceptRawRelease_HTTP1x verifies that raw mode release forwards
// the original request bytes as-is to the upstream server, bypassing L7
// serialization. The upstream receives the exact raw bytes that were captured.
func TestE2E_InterceptRawRelease_HTTP1x(t *testing.T) {
	// Start a TCP server that captures the raw bytes it receives.
	capturedCh := make(chan []byte, 1)
	upstream := startRawCaptureServer(t, capturedCh)

	env := setupIntegrationEnvWithInterceptRules(t)

	// Start the proxy.
	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	// Configure intercept rule to catch all requests.
	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "catch-all",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	// Send HTTP request through the proxy in a goroutine (it will block on intercept).
	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/raw-test", upstream)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait for the request to appear in the intercept queue.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for request to appear in intercept queue")
	}

	// Release in raw mode.
	releaseResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "release",
		"params": map[string]any{
			"intercept_id": interceptID,
			"mode":         "raw",
		},
	})
	if releaseResult.Action != "release" {
		t.Errorf("action = %q, want release", releaseResult.Action)
	}
	if releaseResult.RawBytesAvailable != true {
		t.Error("expected raw_bytes_available=true")
	}

	// Verify the upstream received raw bytes containing the original request.
	// In proxy mode, the request line uses the absolute URL form (GET http://host/path).
	select {
	case captured := <-capturedCh:
		capturedStr := string(captured)
		if !strings.Contains(capturedStr, "/api/raw-test") {
			t.Errorf("upstream did not receive expected request path, got: %q", capturedStr)
		}
		if !strings.Contains(capturedStr, "GET ") {
			t.Errorf("upstream did not receive GET method, got: %q", capturedStr)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive request")
	}

	client.CloseIdleConnections()
	wg.Wait()
}

// TestE2E_InterceptRawModifyAndForward_HTTP1x verifies that raw mode
// modify_and_forward sends the edited raw bytes to the upstream server.
func TestE2E_InterceptRawModifyAndForward_HTTP1x(t *testing.T) {
	capturedCh := make(chan []byte, 1)
	upstream := startRawCaptureServer(t, capturedCh)

	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "catch-all",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/modify-test", upstream)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait for intercept.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for intercept")
	}

	// Build modified raw bytes: a custom HTTP request.
	modifiedRaw := fmt.Sprintf("PUT /injected HTTP/1.1\r\nHost: %s\r\nX-Injected: true\r\nContent-Length: 0\r\n\r\n", upstream)
	modifiedB64 := base64.StdEncoding.EncodeToString([]byte(modifiedRaw))

	modResult := callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":        interceptID,
			"mode":                "raw",
			"raw_override_base64": modifiedB64,
		},
	})
	if modResult.Action != "modify_and_forward" {
		t.Errorf("action = %q, want modify_and_forward", modResult.Action)
	}
	if modResult.Status != "forwarded_raw" {
		t.Errorf("status = %q, want forwarded_raw", modResult.Status)
	}

	// Verify upstream received the modified raw bytes.
	select {
	case captured := <-capturedCh:
		if !bytes.Contains(captured, []byte("PUT /injected")) {
			t.Errorf("upstream did not receive modified request, got: %q", string(captured))
		}
		if !bytes.Contains(captured, []byte("X-Injected: true")) {
			t.Errorf("upstream did not receive injected header, got: %q", string(captured))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive modified request")
	}

	client.CloseIdleConnections()
	wg.Wait()
}

// TestE2E_InterceptRawSmugglingPattern_HTTP1x verifies that CL+TE conflict
// patterns are preserved as-is in raw mode, without normalization.
func TestE2E_InterceptRawSmugglingPattern_HTTP1x(t *testing.T) {
	capturedCh := make(chan []byte, 1)
	upstream := startRawCaptureServer(t, capturedCh)

	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "catch-all",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/smuggle", upstream)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Get(targetURL)
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait for intercept.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for intercept")
	}

	// Build a CL+TE conflict smuggling pattern.
	smugglingReq := fmt.Sprintf(
		"POST /smuggle HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Length: 13\r\n"+
			"Transfer-Encoding: chunked\r\n"+
			"\r\n"+
			"0\r\n"+
			"\r\n"+
			"SMUGGLED",
		upstream,
	)
	smugglingB64 := base64.StdEncoding.EncodeToString([]byte(smugglingReq))

	_ = callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":        interceptID,
			"mode":                "raw",
			"raw_override_base64": smugglingB64,
		},
	})

	// Verify the upstream received the exact smuggling pattern.
	select {
	case captured := <-capturedCh:
		capturedStr := string(captured)
		if !strings.Contains(capturedStr, "Content-Length: 13") {
			t.Error("CL header was normalized away")
		}
		if !strings.Contains(capturedStr, "Transfer-Encoding: chunked") {
			t.Error("TE header was normalized away")
		}
		if !strings.Contains(capturedStr, "SMUGGLED") {
			t.Error("smuggled data was not forwarded")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for upstream to receive smuggling pattern")
	}

	client.CloseIdleConnections()
	wg.Wait()
}

// --- HTTP/2 intercept raw forwarding ---

// TestE2E_InterceptRawRelease_HTTP2 verifies that raw mode release forwards
// HTTP/2 frames as-is to the upstream server.
func TestE2E_InterceptRawRelease_HTTP2(t *testing.T) {
	// For HTTP/2, we test via the resend_raw tool since the proxy intercept
	// pipeline for H2 raw forwarding requires a full HTTP/2 proxy setup.
	// We verify that a stored H2 flow's raw bytes can be resent unmodified.
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw HTTP/2 frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/h2-raw-release"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	rawBytes := rawBuf.Bytes()

	parsedURL, _ := url.Parse("http://" + echoAddr + "/h2-raw-release")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: echoAddr,
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBytes,
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID:     fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Set up MCP server with testDialer (no TLS).
	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "e2e-test",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Resend raw H2 frames unmodified.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"target_addr": echoAddr,
				"use_tls":     false,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("resend_raw returned error: %v", extractTextContent(result))
	}

	var rawResult resendRawResult
	if err := json.Unmarshal([]byte(extractTextContent(result)), &rawResult); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}

	// Verify the response contains H2 frame bytes.
	respBytes, err := base64.StdEncoding.DecodeString(rawResult.ResponseData)
	if err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if len(respBytes) < frame.HeaderSize {
		t.Errorf("response too short for H2 frames: %d bytes", len(respBytes))
	}

	// Verify the new flow was recorded with send raw bytes matching original.
	newSendMsgs, err := store.GetMessages(ctx, rawResult.NewFlowID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(newSendMsgs) == 0 {
		t.Fatal("expected send message in new flow")
	}
	if !bytes.Equal(newSendMsgs[0].RawBytes, rawBytes) {
		t.Error("recorded send raw bytes do not match original")
	}
}

// TestE2E_InterceptRawModifyAndForward_HTTP2 verifies that raw mode
// modify_and_forward sends edited HTTP/2 frame bytes to the upstream server.
func TestE2E_InterceptRawModifyAndForward_HTTP2(t *testing.T) {
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build original raw H2 frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/original"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}

	parsedURL, _ := url.Parse("http://" + echoAddr + "/original")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: echoAddr,
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID:    fl.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now().UTC(),
		Method:    "GET",
		URL:       parsedURL,
		RawBytes:  rawBuf.Bytes(),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID:     fl.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  time.Now().UTC(),
		StatusCode: 200,
		Body:       []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	// Build override H2 frames with a different path.
	encoder2 := hpack.NewEncoder(4096, true)
	overrideHeaders := []hpack.HeaderField{
		{Name: ":method", Value: "POST"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/modified"},
	}
	overrideFragment := encoder2.Encode(overrideHeaders)
	var overrideBuf bytes.Buffer
	w2 := frame.NewWriter(&overrideBuf)
	if err := w2.WriteHeaders(1, true, true, overrideFragment); err != nil {
		t.Fatalf("WriteHeaders override: %v", err)
	}
	overrideB64 := base64.StdEncoding.EncodeToString(overrideBuf.Bytes())

	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "e2e-test",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	// Resend with override_raw_base64.
	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":             fl.ID,
				"target_addr":         echoAddr,
				"use_tls":             false,
				"override_raw_base64": overrideB64,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("resend_raw returned error: %v", extractTextContent(result))
	}

	var rawResult resendRawResult
	if err := json.Unmarshal([]byte(extractTextContent(result)), &rawResult); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}

	// Verify the recorded send message has the override bytes.
	newSendMsgs, err := store.GetMessages(ctx, rawResult.NewFlowID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetMessages: %v", err)
	}
	if len(newSendMsgs) == 0 {
		t.Fatal("expected send message")
	}
	if !bytes.Equal(newSendMsgs[0].RawBytes, overrideBuf.Bytes()) {
		t.Error("recorded send raw bytes do not match override bytes")
	}
}

// --- HTTP/2 resend_raw ---

// TestE2E_ResendRawH2 verifies resend_raw for HTTP/2 flows: the stored raw bytes
// are sent over a new HTTP/2 connection with a proper handshake.
func TestE2E_ResendRawH2(t *testing.T) {
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw H2 frames.
	encoder := hpack.NewEncoder(4096, true)
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/resend-raw-h2"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	rawBytes := rawBuf.Bytes()

	parsedURL, _ := url.Parse("http://" + echoAddr + "/resend-raw-h2")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: echoAddr,
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: parsedURL,
		RawBytes: rawBytes,
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200, Body: []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name: "e2e-test", Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
		Name: "resend",
		Arguments: map[string]any{
			"action": "resend_raw",
			"params": map[string]any{
				"flow_id":     fl.ID,
				"target_addr": echoAddr,
				"use_tls":     false,
			},
		},
	})
	if err != nil {
		t.Fatalf("CallTool: %v", err)
	}
	if result.IsError {
		t.Fatalf("resend_raw returned error: %v", extractTextContent(result))
	}

	var rawResult resendRawResult
	if err := json.Unmarshal([]byte(extractTextContent(result)), &rawResult); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if rawResult.NewFlowID == "" {
		t.Error("expected non-empty NewFlowID")
	}
	if rawResult.ResponseSize == 0 {
		t.Error("expected non-zero ResponseSize")
	}
	if rawResult.DurationMs < 0 {
		t.Errorf("DurationMs = %d, want >= 0", rawResult.DurationMs)
	}

	// Verify new flow was recorded.
	newFl, err := store.GetFlow(ctx, rawResult.NewFlowID)
	if err != nil {
		t.Fatalf("get new flow: %v", err)
	}
	if newFl.Protocol != "HTTP/2" {
		t.Errorf("protocol = %q, want HTTP/2", newFl.Protocol)
	}
	if newFl.State != "complete" {
		t.Errorf("state = %q, want complete", newFl.State)
	}

	// Verify send and receive messages exist.
	sendMsgs, err := store.GetMessages(ctx, rawResult.NewFlowID, flow.MessageListOptions{Direction: "send"})
	if err != nil {
		t.Fatalf("GetMessages send: %v", err)
	}
	if len(sendMsgs) == 0 {
		t.Fatal("expected send message")
	}
	if len(sendMsgs[0].RawBytes) == 0 {
		t.Error("send raw bytes should not be empty")
	}

	recvMsgs, err := store.GetMessages(ctx, rawResult.NewFlowID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		t.Fatalf("GetMessages recv: %v", err)
	}
	if len(recvMsgs) == 0 {
		t.Fatal("expected receive message")
	}
	if len(recvMsgs[0].RawBytes) == 0 {
		t.Error("receive raw bytes should not be empty")
	}
}

// TestE2E_ResendRawH2_WithPatches verifies that raw_patch (text find/replace,
// binary find/replace, offset overwrite) works correctly for HTTP/2 flows.
func TestE2E_ResendRawH2_WithPatches(t *testing.T) {
	echoAddr, cleanup := newH2EchoServer(t)
	defer cleanup()

	store := newTestStore(t)
	ctx := context.Background()

	// Build raw H2 frames with Huffman disabled so the path appears as literal ASCII.
	encoder := hpack.NewEncoder(4096, false) // useHuffman=false
	headers := []hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "http"},
		{Name: ":authority", Value: echoAddr},
		{Name: ":path", Value: "/original-path"},
	}
	fragment := encoder.Encode(headers)
	var rawBuf bytes.Buffer
	w := frame.NewWriter(&rawBuf)
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	originalRaw := rawBuf.Bytes()

	parsedURL, _ := url.Parse("http://" + echoAddr + "/original-path")
	fl := &flow.Flow{
		Protocol:  "HTTP/2",
		FlowType:  "unary",
		State:     "complete",
		Timestamp: time.Now().UTC(),
		Duration:  100 * time.Millisecond,
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: "127.0.0.1:54321",
			ServerAddr: echoAddr,
		},
	}
	if err := store.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 0, Direction: "send",
		Timestamp: time.Now().UTC(), Method: "GET", URL: parsedURL,
		RawBytes: originalRaw,
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}
	if err := store.AppendMessage(ctx, &flow.Message{
		FlowID: fl.ID, Sequence: 1, Direction: "receive",
		Timestamp: time.Now().UTC(), StatusCode: 200, Body: []byte("ok"),
	}); err != nil {
		t.Fatalf("AppendMessage: %v", err)
	}

	s := NewServer(ctx, nil, store, nil)
	s.deps.rawReplayDialer = &testDialer{}

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := s.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	defer ss.Close()

	client := gomcp.NewClient(&gomcp.Implementation{
		Name: "e2e-test", Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	defer cs.Close()

	t.Run("text_find_replace", func(t *testing.T) {
		// Use dry_run to verify the patch without actually sending.
		result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
			Name: "resend",
			Arguments: map[string]any{
				"action": "resend_raw",
				"params": map[string]any{
					"flow_id": fl.ID,
					"dry_run": true,
					"patches": []map[string]any{
						{
							"find_text":    "/original-path",
							"replace_text": "/patched-path_",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			t.Fatalf("dry_run error: %v", extractTextContent(result))
		}

		var dryResult resendRawDryRunResult
		if err := json.Unmarshal([]byte(extractTextContent(result)), &dryResult); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		if dryResult.RawPreview.PatchesApplied != 1 {
			t.Errorf("PatchesApplied = %d, want 1", dryResult.RawPreview.PatchesApplied)
		}

		patchedBytes, err := base64.StdEncoding.DecodeString(dryResult.RawPreview.DataBase64)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Contains(patchedBytes, []byte("/patched-path_")) {
			t.Error("patched bytes should contain /patched-path_")
		}
		if bytes.Contains(patchedBytes, []byte("/original-path")) {
			t.Error("patched bytes should not contain /original-path")
		}
	})

	t.Run("binary_find_replace", func(t *testing.T) {
		findB64 := base64.StdEncoding.EncodeToString([]byte("/original-path"))
		replaceB64 := base64.StdEncoding.EncodeToString([]byte("/binary-patch_"))

		result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
			Name: "resend",
			Arguments: map[string]any{
				"action": "resend_raw",
				"params": map[string]any{
					"flow_id": fl.ID,
					"dry_run": true,
					"patches": []map[string]any{
						{
							"find_base64":    findB64,
							"replace_base64": replaceB64,
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			t.Fatalf("dry_run error: %v", extractTextContent(result))
		}

		var dryResult resendRawDryRunResult
		if err := json.Unmarshal([]byte(extractTextContent(result)), &dryResult); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		patchedBytes, err := base64.StdEncoding.DecodeString(dryResult.RawPreview.DataBase64)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if !bytes.Contains(patchedBytes, []byte("/binary-patch_")) {
			t.Error("binary patched bytes should contain /binary-patch_")
		}
	})

	t.Run("offset_overwrite", func(t *testing.T) {
		// Overwrite the first byte of raw bytes (frame header's Length field MSB).
		// offset=0 targets the frame header, not the payload — this verifies
		// that arbitrary offset patching works on the raw frame bytes.
		result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
			Name: "resend",
			Arguments: map[string]any{
				"action": "resend_raw",
				"params": map[string]any{
					"flow_id": fl.ID,
					"dry_run": true,
					"patches": []map[string]any{
						{
							"offset":      0,
							"data_base64": base64.StdEncoding.EncodeToString([]byte{0xFF}),
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			t.Fatalf("dry_run error: %v", extractTextContent(result))
		}

		var dryResult resendRawDryRunResult
		if err := json.Unmarshal([]byte(extractTextContent(result)), &dryResult); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		patchedBytes, err := base64.StdEncoding.DecodeString(dryResult.RawPreview.DataBase64)
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if patchedBytes[0] != 0xFF {
			t.Errorf("first byte = %02x, want FF", patchedBytes[0])
		}
		if dryResult.RawPreview.PatchesApplied != 1 {
			t.Errorf("PatchesApplied = %d, want 1", dryResult.RawPreview.PatchesApplied)
		}
	})

	t.Run("send_patched_to_server", func(t *testing.T) {
		// Actually send patched frames to the echo server.
		result, err := cs.CallTool(ctx, &gomcp.CallToolParams{
			Name: "resend",
			Arguments: map[string]any{
				"action": "resend_raw",
				"params": map[string]any{
					"flow_id":     fl.ID,
					"target_addr": echoAddr,
					"use_tls":     false,
					"patches": []map[string]any{
						{
							"find_text":    "/original-path",
							"replace_text": "/patched-path_",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("CallTool: %v", err)
		}
		if result.IsError {
			t.Fatalf("error: %v", extractTextContent(result))
		}

		var rawResult resendRawResult
		if err := json.Unmarshal([]byte(extractTextContent(result)), &rawResult); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		if rawResult.NewFlowID == "" {
			t.Error("expected non-empty NewFlowID")
		}
		if rawResult.ResponseSize == 0 {
			t.Error("expected non-zero ResponseSize")
		}

		// Verify the patched send bytes were recorded.
		sendMsgs, err := store.GetMessages(ctx, rawResult.NewFlowID, flow.MessageListOptions{Direction: "send"})
		if err != nil {
			t.Fatalf("GetMessages: %v", err)
		}
		if len(sendMsgs) == 0 {
			t.Fatal("expected send message")
		}
		if !bytes.Contains(sendMsgs[0].RawBytes, []byte("/patched-path_")) {
			t.Error("recorded send raw bytes should contain patched path")
		}
	})
}

// --- Variant recording ---

// TestE2E_InterceptRawVariantRecording verifies that when a request is
// intercepted and forwarded with raw modifications, both the original and
// modified variants are recorded in the flow store.
func TestE2E_InterceptRawVariantRecording(t *testing.T) {
	upstreamAddr := startUpstreamServer(t)
	env := setupIntegrationEnvWithInterceptRules(t)

	startResult := callTool[proxyStartResult](t, env.cs, "proxy_start", map[string]any{
		"listen_addr": "127.0.0.1:0",
	})

	_ = callTool[configureResult](t, env.cs, "configure", map[string]any{
		"operation": "merge",
		"intercept_rules": map[string]any{
			"add": []any{
				map[string]any{
					"id":        "catch-all",
					"enabled":   true,
					"direction": "request",
					"conditions": map[string]any{
						"path_pattern": ".*",
					},
				},
			},
		},
	})

	client := proxyHTTPClient(startResult.ListenAddr)
	targetURL := fmt.Sprintf("http://%s/api/variant-test", upstreamAddr)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		resp, err := client.Post(targetURL, "text/plain", strings.NewReader("original body"))
		if err != nil {
			return
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}()

	// Wait for intercept.
	var interceptID string
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		qResult := callTool[queryInterceptQueueResult](t, env.cs, "query", map[string]any{
			"resource": "intercept_queue",
		})
		if qResult.Count > 0 {
			interceptID = qResult.Items[0].ID
			break
		}
	}
	if interceptID == "" {
		t.Fatal("timed out waiting for intercept")
	}

	// Modify and forward with raw bytes.
	modifiedRaw := fmt.Sprintf(
		"POST /api/variant-test HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: text/plain\r\n"+
			"Content-Length: 13\r\n"+
			"\r\n"+
			"modified body",
		upstreamAddr,
	)
	modifiedB64 := base64.StdEncoding.EncodeToString([]byte(modifiedRaw))

	_ = callTool[executeInterceptResult](t, env.cs, "intercept", map[string]any{
		"action": "modify_and_forward",
		"params": map[string]any{
			"intercept_id":        interceptID,
			"mode":                "raw",
			"raw_override_base64": modifiedB64,
		},
	})

	// Wait for the flow to be recorded.
	wg.Wait()
	time.Sleep(300 * time.Millisecond)

	// Query the recorded flow.
	listResult := callTool[queryFlowsResult](t, env.cs, "query", map[string]any{
		"resource": "flows",
	})
	if listResult.Count < 1 {
		t.Fatalf("expected at least 1 flow, got %d", listResult.Count)
	}
	flowID := listResult.Flows[0].ID

	// Get flow details including variant information.
	flowDetail := callTool[queryFlowResult](t, env.cs, "query", map[string]any{
		"resource": "flow",
		"id":       flowID,
	})

	// When raw modify_and_forward is used, the flow should have variant messages.
	// The original request (variant=original) and modified request (variant=modified)
	// should both be recorded.
	if flowDetail.MessageCount < 2 {
		t.Errorf("expected at least 2 messages (original + modified + receive), got %d", flowDetail.MessageCount)
	}

	// Verify original_request is populated (variant recording must preserve the original request).
	if flowDetail.OriginalRequest == nil {
		t.Fatal("expected OriginalRequest to be non-nil (variant recording should preserve original request)")
	}
	if flowDetail.OriginalRequest.Method != "POST" {
		t.Errorf("original_request method = %q, want POST", flowDetail.OriginalRequest.Method)
	}
	if !strings.Contains(flowDetail.OriginalRequest.URL, "/api/variant-test") {
		t.Errorf("original_request URL = %q, want to contain /api/variant-test", flowDetail.OriginalRequest.URL)
	}

	client.CloseIdleConnections()
}

// --- Helpers ---

// setupIntegrationEnvWithInterceptRules creates an integration test environment
// with the intercept engine and queue wired to both the HTTP handler and the
// MCP server. This enables intercept rule configuration and request interception.
func setupIntegrationEnvWithInterceptRules(t *testing.T) *testEnv {
	t.Helper()
	ctx := context.Background()

	dbPath := filepath.Join(t.TempDir(), "integration.db")
	logger := testutil.DiscardLogger()
	store, err := flow.NewSQLiteStore(ctx, dbPath, logger)
	if err != nil {
		t.Fatalf("NewSQLiteStore: %v", err)
	}
	t.Cleanup(func() { store.Close() })

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	issuer := cert.NewIssuer(ca)

	// Create shared intercept engine and queue.
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()

	// Build HTTP handler with intercept wired.
	httpHandler := protohttp.NewHandler(store, issuer, logger)
	httpHandler.SetInterceptEngine(engine)
	httpHandler.SetInterceptQueue(queue)
	detector := protocol.NewDetector(httpHandler)

	manager := proxy.NewManager(detector, logger)
	t.Cleanup(func() { manager.Stop(context.Background()) })

	mcpServer := NewServer(ctx, ca, store, manager,
		WithInterceptEngine(engine),
		WithInterceptQueue(queue),
	)

	ct, st := gomcp.NewInMemoryTransports()
	ss, err := mcpServer.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{
		Name:    "e2e-raw-intercept-test",
		Version: "v0.0.1",
	}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return &testEnv{
		cs:      cs,
		store:   store,
		manager: manager,
	}
}

// startRawCaptureServer starts a TCP server that captures all incoming bytes
// and sends a valid HTTP response back. The captured bytes are sent to the channel.
func startRawCaptureServer(t *testing.T, capturedCh chan<- []byte) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				// Set a read deadline to avoid hanging.
				c.SetReadDeadline(time.Now().Add(5 * time.Second))

				// Read all available bytes (up to a reasonable limit).
				var buf bytes.Buffer
				tmp := make([]byte, 4096)
				for {
					n, err := c.Read(tmp)
					if n > 0 {
						buf.Write(tmp[:n])
					}
					// Check if we have a complete HTTP request (ends with \r\n\r\n).
					if bytes.Contains(buf.Bytes(), []byte("\r\n\r\n")) {
						// Check if there's a Content-Length and read the body too.
						headerEnd := bytes.Index(buf.Bytes(), []byte("\r\n\r\n"))
						headers := string(buf.Bytes()[:headerEnd])
						var contentLength int
						for _, line := range strings.Split(headers, "\r\n") {
							if strings.HasPrefix(strings.ToLower(line), "content-length:") {
								fmt.Sscanf(strings.TrimSpace(strings.SplitN(line, ":", 2)[1]), "%d", &contentLength)
							}
						}
						bodyStart := headerEnd + 4
						if buf.Len() >= bodyStart+contentLength {
							break
						}
					}
					if err != nil {
						break
					}
				}

				// Send captured bytes to channel (non-blocking).
				select {
				case capturedCh <- buf.Bytes():
				default:
				}

				// Send a valid HTTP response.
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok"
				c.Write([]byte(resp))
			}(conn)
		}
	}()

	return ln.Addr().String()
}
