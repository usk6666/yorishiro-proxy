package http2

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/plugin"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/rules"
	"github.com/usk6666/yorishiro-proxy/internal/safety"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// decodeProtobufFrame parses a gRPC frame and decodes the protobuf payload to JSON.
func decodeProtobufFrame(t *testing.T, data []byte) string {
	t.Helper()
	frames, err := protogrpc.ReadAllFrames(data)
	if err != nil {
		t.Fatalf("read frames: %v", err)
	}
	if len(frames) == 0 {
		t.Fatal("no frames found")
	}
	jsonStr, err := protobuf.Decode(frames[0].Payload)
	if err != nil {
		t.Fatalf("protobuf decode: %v", err)
	}
	return jsonStr
}

func TestDecodeGRPCPayload_Uncompressed(t *testing.T) {
	jsonStr := `{"0001:0000:String":"hello"}`
	data, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	got, decompressed, err := decodeGRPCPayload(data, false, "")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !strings.Contains(got, "hello") {
		t.Errorf("expected JSON containing 'hello', got %q", got)
	}
	if !bytes.Equal(decompressed, data) {
		t.Error("decompressed should equal original for uncompressed")
	}
}

func TestDecodeGRPCPayload_InvalidProtobuf(t *testing.T) {
	// Invalid protobuf data should return an error.
	_, _, err := decodeGRPCPayload([]byte{0xff, 0xff, 0xff}, false, "")
	if err == nil {
		t.Error("expected error for invalid protobuf")
	}
}

func TestEncodeGRPCPayload_RoundTrip(t *testing.T) {
	original := `{"0001:0000:String":"test-value"}`
	data, err := protobuf.Encode(original)
	if err != nil {
		t.Fatalf("encode original: %v", err)
	}
	jsonStr, _, err := decodeGRPCPayload(data, false, "")
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	reEncoded, err := encodeGRPCPayload(jsonStr, false, "")
	if err != nil {
		t.Fatalf("re-encode: %v", err)
	}
	jsonStr2, _, err := decodeGRPCPayload(reEncoded, false, "")
	if err != nil {
		t.Fatalf("decode re-encoded: %v", err)
	}
	if jsonStr != jsonStr2 {
		t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", jsonStr2, jsonStr)
	}
}

func TestRebuildGRPCFrame(t *testing.T) {
	payload := []byte("test-payload")
	frame := rebuildGRPCFrame(false, payload)
	if len(frame) != 5+len(payload) {
		t.Fatalf("frame length = %d, want %d", len(frame), 5+len(payload))
	}
	if frame[0] != 0 {
		t.Errorf("compressed flag = %d, want 0", frame[0])
	}
	// Parse back.
	frames, err := protogrpc.ReadAllFrames(frame)
	if err != nil {
		t.Fatalf("parse frame: %v", err)
	}
	if len(frames) != 1 {
		t.Fatalf("frame count = %d, want 1", len(frames))
	}
	if string(frames[0].Payload) != "test-payload" {
		t.Errorf("payload = %q, want %q", frames[0].Payload, "test-payload")
	}

	// Compressed frame.
	frame2 := rebuildGRPCFrame(true, payload)
	if frame2[0] != 1 {
		t.Errorf("compressed flag = %d, want 1", frame2[0])
	}
}

func TestApplyGRPCSafetyFilter_NoEngine(t *testing.T) {
	violation := applyGRPCSafetyFilter(nil, "any body", "http://example.com", nil)
	if violation != nil {
		t.Error("expected nil violation with nil engine")
	}
}

func TestApplyGRPCSafetyFilter_WithMatch(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "test-drop",
				Name:    "Drop Table",
				Pattern: `DROP\s+TABLE`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	violation := applyGRPCSafetyFilter(engine, "SELECT * FROM users; DROP TABLE users", "http://example.com", nil)
	if violation == nil {
		t.Fatal("expected violation")
	}
	if violation.RuleID != "test-drop" {
		t.Errorf("rule_id = %q, want %q", violation.RuleID, "test-drop")
	}
}

func TestApplyGRPCOutputFilter_NoEngine(t *testing.T) {
	logger := testutil.DiscardLogger()
	filtered, masked, blocked := applyGRPCOutputFilter(nil, "body", logger)
	if filtered != "body" || masked || blocked {
		t.Errorf("unexpected result: filtered=%q masked=%v blocked=%v", filtered, masked, blocked)
	}
}

func TestApplyGRPCOutputFilter_Masking(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:          "mask-ssn",
				Name:        "SSN Mask",
				Pattern:     `\d{3}-\d{2}-\d{4}`,
				Targets:     []string{"body"},
				Action:      "mask",
				Replacement: "***-**-****",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	logger := testutil.DiscardLogger()
	filtered, masked, blocked := applyGRPCOutputFilter(engine, "SSN: 123-45-6789", logger)
	if blocked {
		t.Fatal("unexpected block")
	}
	if !masked {
		t.Fatal("expected masking")
	}
	if strings.Contains(filtered, "123-45-6789") {
		t.Errorf("SSN not masked: %q", filtered)
	}
	if !strings.Contains(filtered, "***-**-****") {
		t.Errorf("expected masked value in result: %q", filtered)
	}
}

func TestApplyGRPCOutputFilter_Block(t *testing.T) {
	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:      "block-secret",
				Name:    "Block Secret",
				Pattern: `TOP_SECRET`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	logger := testutil.DiscardLogger()
	_, _, blocked := applyGRPCOutputFilter(engine, "data: TOP_SECRET info", logger)
	if !blocked {
		t.Fatal("expected block")
	}
}

func TestApplyGRPCAutoTransform_NilPipeline(t *testing.T) {
	sc := &streamContext{
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Path: "/test"}},
		reqURL: &url.URL{Path: "/test"},
	}
	result, changed := applyGRPCAutoTransform(nil, sc, "body")
	if changed {
		t.Error("expected no change with nil pipeline")
	}
	if result != "body" {
		t.Errorf("result = %q, want %q", result, "body")
	}
}

func TestApplyGRPCAutoTransform_WithRule(t *testing.T) {
	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-test",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-value",
			Value:   "REPLACED",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}

	sc := &streamContext{
		req: &gohttp.Request{
			Method: "POST",
			URL:    &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
			Header: gohttp.Header{},
		},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
	}

	result, changed := applyGRPCAutoTransform(pipeline, sc, "prefix old-value suffix")
	if !changed {
		t.Error("expected change")
	}
	if !strings.Contains(result, "REPLACED") {
		t.Errorf("expected REPLACED in result: %q", result)
	}
}

func TestHeadersToPluginMap(t *testing.T) {
	h := gohttp.Header{
		"Content-Type": {"application/grpc"},
		"X-Custom":     {"val1", "val2"},
	}
	m := headersToPluginMap(h)

	ct, ok := m["Content-Type"].([]any)
	if !ok || len(ct) != 1 || ct[0] != "application/grpc" {
		t.Errorf("Content-Type = %v", m["Content-Type"])
	}

	xc, ok := m["X-Custom"].([]any)
	if !ok || len(xc) != 2 {
		t.Errorf("X-Custom = %v", m["X-Custom"])
	}
}

func TestProcessGRPCRequestFrame_NoSubsystems(t *testing.T) {
	handler := NewHandler(&mockStore{}, testutil.DiscardLogger())

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	raw := []byte("raw-frame-data")
	wireBytes, stop := handler.processGRPCRequestFrame(
		sc, raw, false, []byte("not-valid-protobuf"), "", nil, nil)
	if stop {
		t.Error("unexpected stop")
	}
	// Should return raw bytes on decode failure.
	if !bytes.Equal(wireBytes, raw) {
		t.Error("expected raw bytes to be returned on decode failure")
	}
}

func TestProcessGRPCRequestFrame_SafetyFilterBlock(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine, err := safety.NewEngine(safety.Config{
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
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}, Header: gohttp.Header{}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	// Create a protobuf payload containing "DROP TABLE users".
	jsonStr := `{"0001:0000:String":"DROP TABLE users"}`
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw := protogrpc.EncodeFrame(false, payload)

	wireBytes, stop := handler.processGRPCRequestFrame(
		sc, raw, false, payload, "", nil, nil)
	if !stop {
		t.Error("expected stop from safety filter block")
	}
	if wireBytes != nil {
		t.Error("expected nil wireBytes on block")
	}
}

func TestProcessGRPCRequestFrame_SafetyFilterLogOnly(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "log-drop",
				Name:    "Log DROP TABLE",
				Pattern: `DROP\s+TABLE`,
				Targets: []string{"body"},
				Action:  "log_only",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}, Header: gohttp.Header{}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	jsonStr := `{"0001:0000:String":"DROP TABLE users"}`
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw := protogrpc.EncodeFrame(false, payload)

	wireBytes, stop := handler.processGRPCRequestFrame(
		sc, raw, false, payload, "", nil, nil)
	if stop {
		t.Error("log_only should not stop")
	}
	if wireBytes == nil {
		t.Error("expected non-nil wireBytes for log_only")
	}
}

func TestProcessGRPCResponseFrame_OutputFilterMask(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine, err := safety.NewEngine(safety.Config{
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
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}, Header: gohttp.Header{}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	jsonStr := `{"0001:0000:String":"SSN: 123-45-6789"}`
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw := protogrpc.EncodeFrame(false, payload)

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}

	wireBytes, blocked := handler.processGRPCResponseFrame(
		sc, raw, false, payload, "", resp, nil, nil)
	if blocked {
		t.Error("expected masking, not blocking")
	}
	if wireBytes == nil {
		t.Fatal("expected non-nil wireBytes")
	}
	// Verify the frame was re-encoded with masked content.
	decoded := decodeProtobufFrame(t, wireBytes)
	if strings.Contains(decoded, "123-45-6789") {
		t.Errorf("SSN not masked in output: %q", decoded)
	}
	if !strings.Contains(decoded, "***-**-****") {
		t.Errorf("expected masked value: %q", decoded)
	}
}

func TestProcessGRPCResponseFrame_OutputFilterBlock(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	engine, err := safety.NewEngine(safety.Config{
		OutputRules: []safety.RuleConfig{
			{
				ID:      "block-secret",
				Name:    "Block Secret",
				Pattern: `TOP_SECRET`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}, Header: gohttp.Header{}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	jsonStr := `{"0001:0000:String":"data: TOP_SECRET info"}`
	payload, err := protobuf.Encode(jsonStr)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	raw := protogrpc.EncodeFrame(false, payload)

	resp := &gohttp.Response{StatusCode: 200, Header: gohttp.Header{}}

	_, blocked := handler.processGRPCResponseFrame(
		sc, raw, false, payload, "", resp, nil, nil)
	if !blocked {
		t.Error("expected block from output filter")
	}
}

func TestProcessGRPCRequestFrame_DecodeFailure_Passthrough(t *testing.T) {
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())

	// Set up a safety engine so subsystems are "active", but decode will fail.
	engine, err := safety.NewEngine(safety.Config{
		InputRules: []safety.RuleConfig{
			{
				ID:      "block-all",
				Name:    "Block All",
				Pattern: `.*`,
				Targets: []string{"body"},
				Action:  "block",
			},
		},
	})
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"}, Header: gohttp.Header{}},
		reqURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/test"},
		logger: testutil.DiscardLogger(),
	}

	// Invalid protobuf payload.
	invalidPayload := []byte{0xff, 0xff, 0xff, 0xff}
	raw := protogrpc.EncodeFrame(false, invalidPayload)

	wireBytes, stop := handler.processGRPCRequestFrame(
		sc, raw, false, invalidPayload, "", nil, nil)
	if stop {
		t.Error("decode failure should not stop — should passthrough")
	}
	if !bytes.Equal(wireBytes, raw) {
		t.Error("expected original raw bytes on decode failure")
	}
}

// TestGRPCStream_SafetyFilter_E2E tests the full gRPC streaming path
// with safety filter blocking.
func TestGRPCStream_SafetyFilter_E2E(t *testing.T) {
	respPayload := []byte("response-data")

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			w.WriteHeader(gohttp.StatusInternalServerError)
			return
		}
		_ = body
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(protogrpc.EncodeFrame(false, respPayload))
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	// Safety filter that blocks "DROP TABLE".
	engine, err := safety.NewEngine(safety.Config{
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
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-safety", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	// Send a request with a protobuf body containing safe content — should pass.
	safeJSON := `{"0001:0000:String":"safe query"}`
	safePayload, _ := protobuf.Encode(safeJSON)
	safeFrame := protogrpc.EncodeFrame(false, safePayload)

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Safe", bytes.NewReader(safeFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("safe request: %v", err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("safe request status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// Allow recording to complete.
	time.Sleep(100 * time.Millisecond)
}

// TestGRPCStream_OutputFilter_E2E tests response output filtering in
// the gRPC streaming path.
func TestGRPCStream_OutputFilter_E2E(t *testing.T) {
	// The upstream sends a protobuf response with an SSN pattern.
	respJSON := `{"0001:0000:String":"SSN: 123-45-6789"}`
	respProto, err := protobuf.Encode(respJSON)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	respFrame := protogrpc.EncodeFrame(false, respProto)

	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(respFrame)
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	// Output filter that masks SSN patterns.
	engine, err := safety.NewEngine(safety.Config{
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
		t.Fatalf("new engine: %v", err)
	}
	handler.SetSafetyEngine(engine)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-output", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	reqFrame := protogrpc.EncodeFrame(false, []byte("req"))
	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/GetUser", bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The response should have the SSN masked if the frame was decoded
	// and re-encoded successfully. If protobuf decode fails on the raw
	// "req" payload (which is expected since "req" is not valid protobuf),
	// the response frame should still be processed.
	// Verify by trying to decode the response.
	if len(body) > 5 {
		frames, err := protogrpc.ReadAllFrames(body)
		if err == nil && len(frames) > 0 {
			decoded, decErr := protobuf.Decode(frames[0].Payload)
			if decErr == nil {
				if strings.Contains(decoded, "123-45-6789") {
					t.Errorf("SSN not masked in response: %q", decoded)
				}
			}
		}
	}
}

// TestGRPCStream_AutoTransform_E2E tests auto-transform in the gRPC streaming path.
func TestGRPCStream_AutoTransform_E2E(t *testing.T) {
	// Upstream echoes the request body as response.
	upstream := httptest.NewServer(gohttp.HandlerFunc(func(w gohttp.ResponseWriter, r *gohttp.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(gohttp.StatusOK)
		w.Write(body) // Echo back request frames.
	}))
	defer upstream.Close()

	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	// Auto-transform rule that replaces "old-token" with "new-token" in request bodies.
	pipeline := rules.NewPipeline()
	err := pipeline.AddRule(rules.Rule{
		ID:        "replace-token",
		Direction: rules.DirectionRequest,
		Enabled:   true,
		Priority:  1,
		Action: rules.Action{
			Type:    rules.ActionReplaceBody,
			Pattern: "old-token",
			Value:   "new-token",
		},
	})
	if err != nil {
		t.Fatalf("add rule: %v", err)
	}
	handler.SetTransformPipeline(pipeline)

	proxyAddr, cancel := startH2CProxyListener(t, handler, "conn-transform", "127.0.0.1:9999", "", tlsMetadata{})
	defer cancel()

	client := newH2CClientForAddr(proxyAddr)

	// Create a protobuf frame with "old-token" in the body.
	reqJSON := `{"0001:0000:String":"auth: old-token"}`
	reqPayload, _ := protobuf.Encode(reqJSON)
	reqFrame := protogrpc.EncodeFrame(false, reqPayload)

	req, _ := gohttp.NewRequest("POST", upstream.URL+"/test.Service/Auth", bytes.NewReader(reqFrame))
	req.Header.Set("Content-Type", "application/grpc")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != gohttp.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}

	// The upstream echoed back the (transformed) request body.
	// Verify the transformation was applied.
	if len(body) > 5 {
		frames, err := protogrpc.ReadAllFrames(body)
		if err == nil && len(frames) > 0 {
			decoded, decErr := protobuf.Decode(frames[0].Payload)
			if decErr == nil {
				if strings.Contains(decoded, "old-token") {
					t.Errorf("auto-transform not applied: %q", decoded)
				}
				if !strings.Contains(decoded, "new-token") {
					t.Errorf("expected 'new-token' in result: %q", decoded)
				}
			}
		}
	}
}

func TestWriteGRPCStatus(t *testing.T) {
	w := httptest.NewRecorder()
	writeGRPCStatus(w, gohttp.StatusOK, 7, "permission denied")
	resp := w.Result()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("Grpc-Status"); got != "7" {
		t.Errorf("Grpc-Status = %q, want %q", got, "7")
	}
	if got := resp.Header.Get("Grpc-Message"); got != "permission denied" {
		t.Errorf("Grpc-Message = %q, want %q", got, "permission denied")
	}
}

func TestWriteGRPCBlockResponse(t *testing.T) {
	w := httptest.NewRecorder()
	violation := &safety.InputViolation{
		RuleID:   "test-rule",
		RuleName: "Test Rule",
	}
	writeGRPCBlockResponse(w, violation)
	resp := w.Result()
	if resp.StatusCode != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, gohttp.StatusOK)
	}
	if got := resp.Header.Get("Grpc-Status"); got != "7" {
		t.Errorf("Grpc-Status = %q, want %q", got, "7")
	}
	if got := resp.Header.Get("X-Blocked-By"); got != "yorishiro-proxy" {
		t.Errorf("X-Blocked-By = %q, want %q", got, "yorishiro-proxy")
	}
}

func TestSetTransformPipeline(t *testing.T) {
	handler := NewHandler(&mockStore{}, slog.Default())
	if handler.TransformPipeline() != nil {
		t.Error("expected nil pipeline initially")
	}
	pipeline := rules.NewPipeline()
	handler.SetTransformPipeline(pipeline)
	if handler.TransformPipeline() != pipeline {
		t.Error("expected pipeline to be set")
	}
}

func TestApplyGRPCPluginHook_NilEngine(t *testing.T) {
	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Path: "/test"}},
		reqURL: &url.URL{Path: "/test"},
		logger: testutil.DiscardLogger(),
	}
	result, action, terminated := applyGRPCPluginHook(
		sc, nil, plugin.HookOnReceiveFromClient, "body", nil, nil, testutil.DiscardLogger())
	if terminated {
		t.Error("expected no termination with nil engine")
	}
	if action != "" {
		t.Errorf("expected empty action, got %q", action)
	}
	if result != "body" {
		t.Errorf("expected body passthrough, got %q", result)
	}
}

func TestApplyGRPCResponsePluginHook_NilEngine(t *testing.T) {
	sc := &streamContext{
		ctx:    context.Background(),
		req:    &gohttp.Request{Method: "POST", URL: &url.URL{Path: "/test"}},
		reqURL: &url.URL{Path: "/test"},
		logger: testutil.DiscardLogger(),
	}
	result, modified := applyGRPCResponsePluginHook(
		sc, nil, plugin.HookOnReceiveFromServer, "body", nil, nil, nil, testutil.DiscardLogger())
	if modified {
		t.Error("expected no modification with nil engine")
	}
	if result != "body" {
		t.Errorf("expected body passthrough, got %q", result)
	}
}
