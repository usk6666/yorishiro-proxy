package http2

import (
	"bytes"
	"context"
	"io"
	gohttp "net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	protogrpc "github.com/usk6666/yorishiro-proxy/internal/protocol/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// buildGRPCUnaryBody creates a gRPC wire body with a single uncompressed frame
// containing the given protobuf payload.
func buildGRPCUnaryBody(t *testing.T, pbPayload []byte) []byte {
	t.Helper()
	frame := protobuf.Frame{Compressed: 0, Payload: pbPayload}
	wire, err := protobuf.BuildFrame(frame)
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	return wire
}

// buildGRPCStreamBody creates a gRPC wire body with multiple frames.
func buildGRPCStreamBody(t *testing.T, payloads ...[]byte) []byte {
	t.Helper()
	var frames []protobuf.Frame
	for _, p := range payloads {
		frames = append(frames, protobuf.Frame{Compressed: 0, Payload: p})
	}
	wire, err := protobuf.BuildFrames(frames)
	if err != nil {
		t.Fatalf("BuildFrames: %v", err)
	}
	return wire
}

// makeGRPCStreamContext creates a streamContext for gRPC intercept testing.
// If endStreamCh is non-nil, it is stored in the context so that
// bufferGRPCUnaryBody can use it for unary/streaming detection.
func makeGRPCStreamContext(t *testing.T, body []byte, endStreamCh chan struct{}) (*streamContext, *httptest.ResponseRecorder) {
	t.Helper()
	reqURL, _ := url.Parse("https://example.com/test.Service/Method")
	req := &gohttp.Request{
		Method: "POST",
		URL:    reqURL,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc+proto"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}
	w := httptest.NewRecorder()
	ctx := context.Background()
	if endStreamCh != nil {
		ctx = contextWithEndStreamCh(ctx, endStreamCh)
	}
	return &streamContext{
		ctx:    ctx,
		req:    req,
		reqURL: reqURL,
		w:      w,
		logger: testutil.DiscardLogger(),
		start:  time.Now(),
	}, w
}

func TestHandleGRPCIntercept_UnaryDrop(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	// Field 1 = "Hello"
	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	// Simulate END_STREAM received (unary RPC).
	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, w := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	// Respond with drop in background.
	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if !handled {
		t.Error("expected drop to be handled (return true)")
	}
	// Should have written gRPC status.
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}
}

func TestHandleGRPCIntercept_UnaryRelease(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, _ := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	// Respond with release in background.
	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if handled {
		t.Error("expected release to not be handled (return false to continue)")
	}

	// Body should be restored.
	restoredBody, err := io.ReadAll(sc.req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(restoredBody, body) {
		t.Errorf("restored body mismatch: got %d bytes, want %d bytes", len(restoredBody), len(body))
	}
}

func TestHandleGRPCIntercept_UnaryModifyAndForward(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, _ := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	// The override body should be the re-encoded gRPC frame bytes (as string).
	// Simulate what the MCP tool layer does.
	modifiedJSON := `{"0001:0000:String": "World"}`
	modifiedPB, err := protobuf.Encode(modifiedJSON)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	modifiedFrame, err := protobuf.BuildFrame(protobuf.Frame{Compressed: 0, Payload: modifiedPB})
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	modifiedStr := string(modifiedFrame)

	// Respond with modify_and_forward in background.
	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				// Verify the held item has JSON body and gRPC metadata.
				item := items[0]
				if item.Metadata == nil {
					t.Error("expected gRPC metadata on held item")
				}
				if ct := item.Metadata["grpc_content_type"]; ct != "application/grpc+proto" {
					t.Errorf("grpc_content_type = %q, want application/grpc+proto", ct)
				}

				queue.Respond(item.ID, intercept.InterceptAction{
					Type:         intercept.ActionModifyAndForward,
					OverrideBody: &modifiedStr,
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if handled {
		t.Error("expected modify_and_forward to not be handled (continue to streaming path)")
	}

	// Body should be replaced with the modified frame bytes.
	resultBody, err := io.ReadAll(sc.req.Body)
	if err != nil {
		t.Fatalf("read modified body: %v", err)
	}
	if !bytes.Equal(resultBody, modifiedFrame) {
		t.Errorf("modified body mismatch: got %d bytes, want %d bytes", len(resultBody), len(modifiedFrame))
	}
}

func TestHandleGRPCIntercept_StreamingFallback(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	// Two frames = streaming, should fall back to release.
	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCStreamBody(t, pbPayload, pbPayload)

	// endStreamCh is NOT closed — simulates streaming RPC where END_STREAM
	// has not arrived. bufferGRPCUnaryBody should timeout and fall back.
	endStreamCh := make(chan struct{})
	sc, _ := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if handled {
		t.Error("expected streaming fallback to not be handled (return false)")
	}

	// Body should be restored for streaming path. The first frame's bytes
	// are prepended back, and the remaining body (second frame) follows.
	restoredBody, err := io.ReadAll(sc.req.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(restoredBody, body) {
		t.Errorf("restored body mismatch: got %d bytes, want %d bytes", len(restoredBody), len(body))
	}
}

func TestHandleGRPCIntercept_TimeoutAutoRelease(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, _ := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	// Do not respond — let it timeout.
	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if handled {
		t.Error("expected auto-release timeout to not be handled (continue to streaming path)")
	}
}

func TestHandleGRPCIntercept_TimeoutAutoDrop(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	queue.SetTimeout(100 * time.Millisecond)
	queue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, w := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	handled := handler.handleGRPCIntercept(sc, matchedRules)
	if !handled {
		t.Error("expected auto-drop timeout to be handled (return true)")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}
}

func TestHandleGRPCIntercept_BodyDecodeJSON(t *testing.T) {
	// Verify that the held item body is the decoded JSON, not raw protobuf.
	handler := NewHandler(nil, testutil.DiscardLogger())
	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	body := buildGRPCUnaryBody(t, pbPayload)

	endStreamCh := make(chan struct{})
	close(endStreamCh)
	sc, _ := makeGRPCStreamContext(t, body, endStreamCh)
	matchedRules := []string{"rule1"}

	var heldBody []byte
	var heldMetadata map[string]string
	var mu sync.Mutex

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				mu.Lock()
				heldBody = items[0].Body
				heldMetadata = items[0].Metadata
				mu.Unlock()
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}()

	handler.handleGRPCIntercept(sc, matchedRules)

	mu.Lock()
	defer mu.Unlock()

	// Body should be JSON string from protobuf.Decode.
	expectedJSON, err := protobuf.Decode(pbPayload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(heldBody) != expectedJSON {
		t.Errorf("held body = %q, want %q", string(heldBody), expectedJSON)
	}

	// Metadata should include gRPC info.
	if heldMetadata == nil {
		t.Fatal("expected metadata to be set")
	}
	if heldMetadata["grpc_content_type"] != "application/grpc+proto" {
		t.Errorf("grpc_content_type = %q", heldMetadata["grpc_content_type"])
	}
	if heldMetadata["grpc_compressed"] != "false" {
		t.Errorf("grpc_compressed = %q", heldMetadata["grpc_compressed"])
	}
	if heldMetadata["original_frames"] != "1" {
		t.Errorf("original_frames = %q", heldMetadata["original_frames"])
	}
}

// --- Response intercept tests ---

// makeGRPCResponseInterceptContext creates a streamContext and handler configured
// for response intercept testing. The handler has InterceptEngine and InterceptQueue
// set, and a gRPC handler for progressive recording.
func makeGRPCResponseInterceptContext(t *testing.T) (*Handler, *streamContext, *httptest.ResponseRecorder, *intercept.Queue) {
	t.Helper()
	store := &mockStore{}
	handler := NewHandler(store, testutil.DiscardLogger())
	grpcHandler := protogrpc.NewHandler(store, testutil.DiscardLogger())
	handler.SetGRPCHandler(grpcHandler)

	engine := intercept.NewEngine()
	queue := intercept.NewQueue()
	handler.SetInterceptEngine(engine)
	handler.SetInterceptQueue(queue)

	reqURL, _ := url.Parse("https://example.com/test.Service/Method")
	req := &gohttp.Request{
		Method: "POST",
		URL:    reqURL,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc+proto"},
		},
		Body: gohttp.NoBody,
	}
	w := httptest.NewRecorder()
	sc := &streamContext{
		ctx:    context.Background(),
		req:    req,
		reqURL: reqURL,
		w:      w,
		logger: testutil.DiscardLogger(),
		start:  time.Now(),
	}
	return handler, sc, w, queue
}

// makeGRPCResponse creates an *http.Response with a gRPC body and trailers.
func makeGRPCResponse(t *testing.T, pbPayload []byte, grpcStatus string) *gohttp.Response {
	t.Helper()
	body := buildGRPCUnaryBody(t, pbPayload)
	return &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc+proto"},
		},
		Body:    io.NopCloser(bytes.NewReader(body)),
		Trailer: gohttp.Header{"Grpc-Status": {grpcStatus}},
	}
}

func TestBufferGRPCUnaryResponseBody_Valid(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	body, jsonBody, frame, trailers, ok := handler.bufferGRPCUnaryResponseBody(sc, resp)
	if !ok {
		t.Fatal("expected bufferGRPCUnaryResponseBody to return ok=true")
	}
	if len(body) == 0 {
		t.Error("expected non-empty body")
	}
	if jsonBody == "" {
		t.Error("expected non-empty jsonBody")
	}
	if frame.Compressed != 0 {
		t.Errorf("expected uncompressed frame, got compressed=%d", frame.Compressed)
	}
	if !bytes.Equal(frame.Payload, pbPayload) {
		t.Errorf("payload mismatch: got %q, want %q", frame.Payload, pbPayload)
	}
	if trailers.Get("Grpc-Status") != "0" {
		t.Errorf("trailers Grpc-Status = %q, want %q", trailers.Get("Grpc-Status"), "0")
	}
}

func TestBufferGRPCUnaryResponseBody_Streaming(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	multiFrameBody := buildGRPCStreamBody(t, pbPayload, pbPayload)
	resp := &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc+proto"},
		},
		Body:    io.NopCloser(bytes.NewReader(multiFrameBody)),
		Trailer: gohttp.Header{"Grpc-Status": {"0"}},
	}

	_, _, _, _, ok := handler.bufferGRPCUnaryResponseBody(sc, resp)
	if ok {
		t.Error("expected bufferGRPCUnaryResponseBody to return ok=false for streaming response")
	}

	// Body should be restored for streaming fallback.
	restoredBody, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read restored body: %v", err)
	}
	if !bytes.Equal(restoredBody, multiFrameBody) {
		t.Errorf("restored body mismatch: got %d bytes, want %d bytes", len(restoredBody), len(multiFrameBody))
	}
}

func TestBufferGRPCUnaryResponseBody_EmptyBody(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)

	resp := &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc"},
		},
		Body:    io.NopCloser(bytes.NewReader(nil)),
		Trailer: gohttp.Header{"Grpc-Status": {"0"}},
	}

	_, _, _, _, ok := handler.bufferGRPCUnaryResponseBody(sc, resp)
	if ok {
		t.Error("expected bufferGRPCUnaryResponseBody to return ok=false for empty body")
	}
}

func TestBufferGRPCUnaryResponseBody_ShortBody(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)

	resp := &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc"},
		},
		Body:    io.NopCloser(bytes.NewReader([]byte{0x00, 0x01})), // Too short for frame header
		Trailer: gohttp.Header{},
	}

	_, _, _, _, ok := handler.bufferGRPCUnaryResponseBody(sc, resp)
	if ok {
		t.Error("expected bufferGRPCUnaryResponseBody to return ok=false for short body")
	}
}

func TestHandleGRPCResponseIntercept_NoEngine(t *testing.T) {
	handler := NewHandler(nil, testutil.DiscardLogger())
	// No InterceptEngine set.
	sc := &streamContext{
		ctx:    context.Background(),
		logger: testutil.DiscardLogger(),
	}
	state := &grpcStreamState{}
	resp := &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header:     gohttp.Header{},
	}

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if handled {
		t.Error("expected false when no InterceptEngine is set")
	}
}

func TestHandleGRPCResponseIntercept_TrailersOnly(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)

	// Add a response rule so matching would normally trigger.
	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "r1",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := &grpcStreamState{
		reqFrameBuf:  protogrpc.NewFrameBuffer(nil),
		respFrameBuf: protogrpc.NewFrameBuffer(nil),
	}

	// Trailers-Only response: Grpc-Status in Header, empty Trailer.
	resp := &gohttp.Response{
		StatusCode: gohttp.StatusOK,
		Header: gohttp.Header{
			"Content-Type": []string{"application/grpc"},
			"Grpc-Status":  []string{"5"},
		},
		Trailer: gohttp.Header{},
		Body:    io.NopCloser(bytes.NewReader(nil)),
	}

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if handled {
		t.Error("expected false for Trailers-Only response")
	}
}

func TestHandleGRPCResponseIntercept_NoMatchedRules(t *testing.T) {
	handler, sc, _, _ := makeGRPCResponseInterceptContext(t)
	// No rules added — MatchResponseRules will return empty.

	state := &grpcStreamState{
		reqFrameBuf:  protogrpc.NewFrameBuffer(nil),
		respFrameBuf: protogrpc.NewFrameBuffer(nil),
	}

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if handled {
		t.Error("expected false when no response rules match")
	}
}

func TestHandleGRPCResponseIntercept_Drop(t *testing.T) {
	handler, sc, w, queue := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-drop",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionDrop})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for intercept item")
	}()

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true when response is dropped")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}
}

func TestHandleGRPCResponseIntercept_Release(t *testing.T) {
	handler, sc, w, queue := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-release",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for intercept item")
	}()

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true when response intercept handles the response (even for release)")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}

	// Verify the response body was written to the client.
	respBody := w.Body.Bytes()
	if len(respBody) == 0 {
		t.Error("expected non-empty response body written to client")
	}
}

func TestHandleGRPCResponseIntercept_ModifyAndForward(t *testing.T) {
	handler, sc, w, queue := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-modify",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	// The override body should be the re-encoded gRPC frame bytes (as string).
	modifiedJSON := `{"0001:0000:String": "World"}`
	modifiedPB, err := protobuf.Encode(modifiedJSON)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	modifiedFrame, err := protobuf.BuildFrame(protobuf.Frame{Compressed: 0, Payload: modifiedPB})
	if err != nil {
		t.Fatalf("BuildFrame: %v", err)
	}
	modifiedStr := string(modifiedFrame)

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				item := items[0]
				// Verify it's a response phase intercept.
				if item.Phase != intercept.PhaseResponse {
					t.Errorf("phase = %q, want %q", item.Phase, intercept.PhaseResponse)
				}
				// Verify metadata includes gRPC info.
				if item.Metadata == nil {
					t.Error("expected gRPC metadata on held item")
				}
				if ct := item.Metadata["grpc_content_type"]; ct != "application/grpc+proto" {
					t.Errorf("grpc_content_type = %q, want application/grpc+proto", ct)
				}
				// Verify trailers are in metadata.
				if gs := item.Metadata["trailer_grpc-status"]; gs != "0" {
					t.Errorf("trailer_grpc-status = %q, want %q", gs, "0")
				}

				queue.Respond(item.ID, intercept.InterceptAction{
					Type:                 intercept.ActionModifyAndForward,
					OverrideResponseBody: &modifiedStr,
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for intercept item")
	}()

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true when response is modified and forwarded")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}

	// Verify the modified body was written to the client.
	respBody := w.Body.Bytes()
	if !bytes.Equal(respBody, modifiedFrame) {
		t.Errorf("modified body mismatch: got %d bytes, want %d bytes", len(respBody), len(modifiedFrame))
	}
}

func TestHandleGRPCResponseIntercept_RawModeRejected(t *testing.T) {
	handler, sc, w, queue := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-raw",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				queue.Respond(items[0].ID, intercept.InterceptAction{
					Type: intercept.ActionModifyAndForward,
					Mode: intercept.ModeRaw,
				})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for intercept item")
	}()

	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true (raw mode falls back to release, still handled)")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}

	// Even with raw mode rejected, original body should be forwarded.
	respBody := w.Body.Bytes()
	if len(respBody) == 0 {
		t.Error("expected non-empty response body written to client")
	}
}

func TestHandleGRPCResponseIntercept_TimeoutAutoRelease(t *testing.T) {
	handler, sc, w, _ := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-timeout",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})
	handler.InterceptQueue.SetTimeout(100 * time.Millisecond)
	handler.InterceptQueue.SetTimeoutBehavior(intercept.TimeoutAutoRelease)

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	// Do not respond — let it timeout.
	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true (auto-release still handles the response)")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}

	// Body should be forwarded after auto-release.
	respBody := w.Body.Bytes()
	if len(respBody) == 0 {
		t.Error("expected non-empty response body after auto-release")
	}
}

func TestHandleGRPCResponseIntercept_TimeoutAutoDrop(t *testing.T) {
	handler, sc, w, _ := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-timeout-drop",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})
	handler.InterceptQueue.SetTimeout(100 * time.Millisecond)
	handler.InterceptQueue.SetTimeoutBehavior(intercept.TimeoutAutoDrop)

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	// Do not respond — let it timeout.
	handled := handler.handleGRPCResponseIntercept(sc, state, resp)
	if !handled {
		t.Error("expected true (auto-drop handles the response)")
	}
	if w.Code != gohttp.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, gohttp.StatusOK)
	}
}

func TestHandleGRPCResponseIntercept_BodyDecodeJSON(t *testing.T) {
	handler, sc, _, queue := makeGRPCResponseInterceptContext(t)

	handler.InterceptEngine.AddRule(intercept.Rule{
		ID:        "resp-json",
		Enabled:   true,
		Direction: intercept.DirectionResponse,
	})

	state := handler.initGRPCStreamState(sc)

	pbPayload := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}
	resp := makeGRPCResponse(t, pbPayload, "0")

	var heldBody []byte
	var heldMetadata map[string]string
	var heldPhase intercept.InterceptPhase
	var heldRawBytes []byte
	var mu sync.Mutex

	go func() {
		for i := 0; i < 100; i++ {
			items := queue.List()
			if len(items) > 0 {
				mu.Lock()
				heldBody = items[0].Body
				heldMetadata = items[0].Metadata
				heldPhase = items[0].Phase
				heldRawBytes = items[0].RawBytes
				mu.Unlock()
				queue.Respond(items[0].ID, intercept.InterceptAction{Type: intercept.ActionRelease})
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Error("timed out waiting for intercept item")
	}()

	handler.handleGRPCResponseIntercept(sc, state, resp)

	mu.Lock()
	defer mu.Unlock()

	// Body should be JSON string from protobuf.Decode.
	expectedJSON, err := protobuf.Decode(pbPayload)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if string(heldBody) != expectedJSON {
		t.Errorf("held body = %q, want %q", string(heldBody), expectedJSON)
	}

	// Phase should be response.
	if heldPhase != intercept.PhaseResponse {
		t.Errorf("phase = %q, want %q", heldPhase, intercept.PhaseResponse)
	}

	// Metadata should include gRPC info.
	if heldMetadata == nil {
		t.Fatal("expected metadata to be set")
	}
	if heldMetadata["grpc_content_type"] != "application/grpc+proto" {
		t.Errorf("grpc_content_type = %q", heldMetadata["grpc_content_type"])
	}
	if heldMetadata["grpc_compressed"] != "false" {
		t.Errorf("grpc_compressed = %q", heldMetadata["grpc_compressed"])
	}
	if heldMetadata["original_frames"] != "1" {
		t.Errorf("original_frames = %q", heldMetadata["original_frames"])
	}
	// Trailer metadata should be present.
	if heldMetadata["trailer_grpc-status"] != "0" {
		t.Errorf("trailer_grpc-status = %q, want %q", heldMetadata["trailer_grpc-status"], "0")
	}

	// Raw bytes should be the original gRPC wire body.
	if len(heldRawBytes) == 0 {
		t.Error("expected raw bytes to be set")
	}
}
