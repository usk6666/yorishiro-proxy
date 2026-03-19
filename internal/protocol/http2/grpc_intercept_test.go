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
