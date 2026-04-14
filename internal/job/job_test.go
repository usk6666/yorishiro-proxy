package job

import (
	"context"
	"errors"
	"io"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// --- Mock types ---

// mockSource yields a fixed sequence of Envelopes, then io.EOF.
type mockSource struct {
	envelopes []*envelope.Envelope
	index     int
}

func (s *mockSource) Next(_ context.Context) (*envelope.Envelope, error) {
	if s.index >= len(s.envelopes) {
		return nil, io.EOF
	}
	env := s.envelopes[s.index]
	s.index++
	return env, nil
}

// errorSource returns an error on Next.
type errorSource struct {
	err error
}

func (s *errorSource) Next(_ context.Context) (*envelope.Envelope, error) {
	return nil, s.err
}

// mockChannel records Send calls and returns pre-configured responses on Next.
type mockChannel struct {
	streamID  string
	sent      []*envelope.Envelope
	responses []*envelope.Envelope
	nextIndex int
	sendErr   error
	nextErr   error
	closed    bool
}

func (c *mockChannel) StreamID() string { return c.streamID }

func (c *mockChannel) Next(_ context.Context) (*envelope.Envelope, error) {
	if c.nextErr != nil {
		return nil, c.nextErr
	}
	if c.nextIndex >= len(c.responses) {
		return nil, io.EOF
	}
	resp := c.responses[c.nextIndex]
	c.nextIndex++
	return resp, nil
}

func (c *mockChannel) Send(_ context.Context, env *envelope.Envelope) error {
	if c.sendErr != nil {
		return c.sendErr
	}
	c.sent = append(c.sent, env)
	return nil
}

func (c *mockChannel) Close() error {
	c.closed = true
	return nil
}

// --- Helpers ---

func makeHTTPSendEnvelope(method, path string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "test-stream",
		FlowID:    "test-flow",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Method: method,
			Path:   path,
		},
	}
}

func makeHTTPResponseEnvelope(status int, body []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "test-stream",
		FlowID:    "test-resp",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message: &envelope.HTTPMessage{
			Status: status,
			Body:   body,
		},
	}
}

func makeRawSendEnvelope(data []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "test-stream",
		FlowID:    "test-flow",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: data},
	}
}

func makeRawResponseEnvelope(data []byte) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  "test-stream",
		FlowID:    "test-resp",
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolRaw,
		Message:   &envelope.RawMessage{Bytes: data},
	}
}

// noopPipeline returns a Pipeline with no Steps (pass-through).
func noopPipeline() *pipeline.Pipeline {
	return pipeline.New()
}

// dialFunc returns a DialFunc that always returns the given channel.
func dialFunc(ch layer.Channel) func(context.Context, *envelope.Envelope) (layer.Channel, error) {
	return func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return ch, nil
	}
}

// dialErrFunc returns a DialFunc that always returns the given error.
func dialErrFunc(err error) func(context.Context, *envelope.Envelope) (layer.Channel, error) {
	return func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return nil, err
	}
}

// --- HookState tests ---

func TestShouldRunPreSend(t *testing.T) {
	t.Run("Always", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: Always}
		for i := 0; i < 5; i++ {
			if !state.shouldRunPreSend(cfg) {
				t.Errorf("iteration %d: expected true", i)
			}
			state.RequestCount++
		}
	})

	t.Run("EmptyDefaultsToAlways", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: ""}
		if !state.shouldRunPreSend(cfg) {
			t.Error("empty RunInterval should default to Always")
		}
	})

	t.Run("Once", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: Once}

		if !state.shouldRunPreSend(cfg) {
			t.Error("first call should return true")
		}
		state.RequestCount++

		if state.shouldRunPreSend(cfg) {
			t.Error("second call should return false")
		}
	})

	t.Run("EveryN", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: EveryN, N: 3}

		expected := []bool{true, false, false, true, false, false, true}
		for i, want := range expected {
			got := state.shouldRunPreSend(cfg)
			if got != want {
				t.Errorf("iteration %d: got %v, want %v", i, got, want)
			}
			state.RequestCount++
		}
	})

	t.Run("EveryN_ZeroN", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: EveryN, N: 0}
		if state.shouldRunPreSend(cfg) {
			t.Error("N=0 should return false")
		}
	})

	t.Run("OnError_FirstRequest", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: OnError}
		if !state.shouldRunPreSend(cfg) {
			t.Error("first request should always run")
		}
	})

	t.Run("OnError_AfterSuccess", func(t *testing.T) {
		state := &HookState{RequestCount: 1, LastError: false, LastStatusCode: 200}
		cfg := &HookConfig{RunInterval: OnError}
		if state.shouldRunPreSend(cfg) {
			t.Error("should not run after success")
		}
	})

	t.Run("OnError_AfterTransportError", func(t *testing.T) {
		state := &HookState{RequestCount: 1, LastError: true}
		cfg := &HookConfig{RunInterval: OnError}
		if !state.shouldRunPreSend(cfg) {
			t.Error("should run after transport error")
		}
	})

	t.Run("OnError_After4xx", func(t *testing.T) {
		state := &HookState{RequestCount: 1, LastStatusCode: 500}
		cfg := &HookConfig{RunInterval: OnError}
		if !state.shouldRunPreSend(cfg) {
			t.Error("should run after status >= 400")
		}
	})

	t.Run("UnknownInterval", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: "unknown"}
		if state.shouldRunPreSend(cfg) {
			t.Error("unknown interval should return false")
		}
	})
}

func TestShouldRunPostReceive(t *testing.T) {
	t.Run("Always", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: Always}
		if !state.shouldRunPostReceive(cfg, 200, nil) {
			t.Error("Always should return true")
		}
	})

	t.Run("EmptyDefaultsToAlways", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: ""}
		if !state.shouldRunPostReceive(cfg, 200, nil) {
			t.Error("empty RunInterval should default to Always")
		}
	})

	t.Run("OnStatus_Match", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: OnStatus, StatusCodes: []int{200, 302}}
		if !state.shouldRunPostReceive(cfg, 200, nil) {
			t.Error("should match status 200")
		}
		if !state.shouldRunPostReceive(cfg, 302, nil) {
			t.Error("should match status 302")
		}
	})

	t.Run("OnStatus_NoMatch", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: OnStatus, StatusCodes: []int{200}}
		if state.shouldRunPostReceive(cfg, 404, nil) {
			t.Error("should not match status 404")
		}
	})

	t.Run("OnMatch_Match", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{
			RunInterval:     OnMatch,
			CompiledPattern: regexp.MustCompile(`"error":\s*true`),
		}
		body := []byte(`{"error": true, "message": "fail"}`)
		if !state.shouldRunPostReceive(cfg, 200, body) {
			t.Error("should match body containing error:true")
		}
	})

	t.Run("OnMatch_NoMatch", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{
			RunInterval:     OnMatch,
			CompiledPattern: regexp.MustCompile(`"error":\s*true`),
		}
		body := []byte(`{"error": false, "message": "ok"}`)
		if state.shouldRunPostReceive(cfg, 200, body) {
			t.Error("should not match body without error:true")
		}
	})

	t.Run("OnMatch_NilPattern", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: OnMatch}
		if state.shouldRunPostReceive(cfg, 200, []byte("anything")) {
			t.Error("nil pattern should return false")
		}
	})

	t.Run("OnError", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: OnError}
		if state.shouldRunPostReceive(cfg, 200, nil) {
			t.Error("status 200 should not trigger OnError")
		}
		if !state.shouldRunPostReceive(cfg, 500, nil) {
			t.Error("status 500 should trigger OnError")
		}
	})

	t.Run("UnknownInterval", func(t *testing.T) {
		state := &HookState{}
		cfg := &HookConfig{RunInterval: "unknown"}
		if state.shouldRunPostReceive(cfg, 200, nil) {
			t.Error("unknown interval should return false")
		}
	})
}

// --- extractResponseInfo tests ---

func TestExtractResponseInfo(t *testing.T) {
	t.Run("HTTPMessage", func(t *testing.T) {
		env := makeHTTPResponseEnvelope(200, []byte("hello"))
		status, body := extractResponseInfo(env)
		if status != 200 {
			t.Errorf("status: got %d, want 200", status)
		}
		if string(body) != "hello" {
			t.Errorf("body: got %q, want %q", body, "hello")
		}
	})

	t.Run("RawMessage", func(t *testing.T) {
		env := makeRawResponseEnvelope([]byte("raw data"))
		status, body := extractResponseInfo(env)
		if status != 0 {
			t.Errorf("status: got %d, want 0", status)
		}
		if string(body) != "raw data" {
			t.Errorf("body: got %q, want %q", body, "raw data")
		}
	})

	t.Run("Nil", func(t *testing.T) {
		status, body := extractResponseInfo(nil)
		if status != 0 || body != nil {
			t.Errorf("nil env: got status=%d body=%v, want 0 nil", status, body)
		}
	})
}

// --- mergeKVStore tests ---

func TestMergeKVStore(t *testing.T) {
	dst := map[string]string{"a": "1", "b": "2"}
	src := map[string]string{"b": "3", "c": "4"}
	mergeKVStore(dst, src)
	if dst["a"] != "1" {
		t.Error("existing key 'a' should be preserved")
	}
	if dst["b"] != "3" {
		t.Error("key 'b' should be overwritten by src")
	}
	if dst["c"] != "4" {
		t.Error("new key 'c' should be added")
	}
}

// --- Job.Run tests ---

func TestJobRun(t *testing.T) {
	t.Run("BasicHTTP", func(t *testing.T) {
		sendEnv := makeHTTPSendEnvelope("GET", "/test")
		respEnv := makeHTTPResponseEnvelope(200, []byte("OK"))
		ch := &mockChannel{
			streamID:  "upstream",
			responses: []*envelope.Envelope{respEnv},
		}

		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
			Dial:     dialFunc(ch),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ch.sent) != 1 {
			t.Fatalf("expected 1 sent envelope, got %d", len(ch.sent))
		}
		if !ch.closed {
			t.Error("upstream channel should be closed")
		}
		if j.HookState.RequestCount != 1 {
			t.Errorf("RequestCount: got %d, want 1", j.HookState.RequestCount)
		}
		if j.HookState.LastStatusCode != 200 {
			t.Errorf("LastStatusCode: got %d, want 200", j.HookState.LastStatusCode)
		}
	})

	t.Run("BasicRaw", func(t *testing.T) {
		sendEnv := makeRawSendEnvelope([]byte("raw payload"))
		respEnv := makeRawResponseEnvelope([]byte("raw response"))
		ch := &mockChannel{
			streamID:  "upstream",
			responses: []*envelope.Envelope{respEnv},
		}

		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
			Dial:     dialFunc(ch),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(ch.sent) != 1 {
			t.Fatalf("expected 1 sent envelope, got %d", len(ch.sent))
		}
		if j.HookState.LastStatusCode != 0 {
			t.Errorf("raw message should have status 0, got %d", j.HookState.LastStatusCode)
		}
	})

	t.Run("MultipleEnvelopes", func(t *testing.T) {
		envs := []*envelope.Envelope{
			makeHTTPSendEnvelope("GET", "/1"),
			makeHTTPSendEnvelope("POST", "/2"),
			makeHTTPSendEnvelope("PUT", "/3"),
		}

		dialCount := 0
		dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			dialCount++
			return &mockChannel{
				streamID:  "upstream",
				responses: []*envelope.Envelope{makeHTTPResponseEnvelope(200, nil)},
			}, nil
		}

		j := &Job{
			Source:   &mockSource{envelopes: envs},
			Dial:     dialFn,
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dialCount != 3 {
			t.Errorf("expected 3 dials, got %d", dialCount)
		}
		if j.HookState.RequestCount != 3 {
			t.Errorf("RequestCount: got %d, want 3", j.HookState.RequestCount)
		}
	})

	t.Run("EmptySource", func(t *testing.T) {
		j := &Job{
			Source:   &mockSource{},
			Dial:     dialFunc(&mockChannel{}),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("empty source should return nil, got: %v", err)
		}
	})

	t.Run("SourceError", func(t *testing.T) {
		j := &Job{
			Source:   &errorSource{err: errors.New("source failed")},
			Dial:     dialFunc(&mockChannel{}),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err == nil {
			t.Fatal("expected error from source")
		}
		if got := err.Error(); got != "job: source.Next: source failed" {
			t.Errorf("unexpected error message: %s", got)
		}
	})

	t.Run("DialError", func(t *testing.T) {
		sendEnv := makeHTTPSendEnvelope("GET", "/test")
		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
			Dial:     dialErrFunc(errors.New("connection refused")),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err == nil {
			t.Fatal("expected dial error")
		}
		if !j.HookState.LastError {
			t.Error("LastError should be true after dial failure")
		}
	})

	t.Run("SendError", func(t *testing.T) {
		sendEnv := makeHTTPSendEnvelope("GET", "/test")
		ch := &mockChannel{
			streamID: "upstream",
			sendErr:  errors.New("write failed"),
		}

		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
			Dial:     dialFunc(ch),
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err == nil {
			t.Fatal("expected send error")
		}
		if !ch.closed {
			t.Error("channel should be closed after send error")
		}
	})

	t.Run("UpstreamEOF_Continues", func(t *testing.T) {
		envs := []*envelope.Envelope{
			makeHTTPSendEnvelope("GET", "/1"),
			makeHTTPSendEnvelope("GET", "/2"),
		}

		callCount := 0
		dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			callCount++
			if callCount == 1 {
				return &mockChannel{
					streamID: "upstream",
					// No responses — will return EOF.
				}, nil
			}
			return &mockChannel{
				streamID:  "upstream",
				responses: []*envelope.Envelope{makeHTTPResponseEnvelope(200, nil)},
			}, nil
		}

		j := &Job{
			Source:   &mockSource{envelopes: envs},
			Dial:     dialFn,
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if j.HookState.RequestCount != 2 {
			t.Errorf("RequestCount: got %d, want 2", j.HookState.RequestCount)
		}
	})

	t.Run("ContextCancelled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{makeHTTPSendEnvelope("GET", "/")}},
			Dial:     dialFunc(&mockChannel{}),
			Pipeline: noopPipeline(),
		}

		err := j.Run(ctx)
		if err == nil {
			t.Fatal("expected context cancelled error")
		}
	})

	t.Run("PipelineDrop", func(t *testing.T) {
		dropStep := &dropAllStep{}
		p := pipeline.New(dropStep)

		sendEnv := makeHTTPSendEnvelope("GET", "/test")
		dialCalled := false
		dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			dialCalled = true
			return &mockChannel{streamID: "upstream"}, nil
		}

		j := &Job{
			Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
			Dial:     dialFn,
			Pipeline: p,
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if dialCalled {
			t.Error("dial should not be called when pipeline drops")
		}
		if j.HookState.RequestCount != 1 {
			t.Errorf("RequestCount: got %d, want 1", j.HookState.RequestCount)
		}
	})

	t.Run("KVStoreInitialized", func(t *testing.T) {
		j := &Job{
			Source:   &mockSource{},
			Dial:     dialFunc(&mockChannel{}),
			Pipeline: noopPipeline(),
		}
		_ = j.Run(context.Background())
		if j.KVStore == nil {
			t.Error("KVStore should be initialized")
		}
	})

	t.Run("StatusTracking", func(t *testing.T) {
		envs := []*envelope.Envelope{
			makeHTTPSendEnvelope("GET", "/1"),
			makeHTTPSendEnvelope("GET", "/2"),
		}

		callCount := 0
		dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			callCount++
			status := 200
			if callCount == 1 {
				status = 500
			}
			return &mockChannel{
				streamID:  "upstream",
				responses: []*envelope.Envelope{makeHTTPResponseEnvelope(status, nil)},
			}, nil
		}

		j := &Job{
			Source:   &mockSource{envelopes: envs},
			Dial:     dialFn,
			Pipeline: noopPipeline(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if j.HookState.LastError {
			t.Error("LastError should be false after 200 response")
		}
		if j.HookState.LastStatusCode != 200 {
			t.Errorf("LastStatusCode: got %d, want 200", j.HookState.LastStatusCode)
		}
	})
}

// --- Hook integration tests ---

func TestJobRun_PreSendHook(t *testing.T) {
	sendEnv := makeHTTPSendEnvelope("GET", "/test")
	respEnv := makeHTTPResponseEnvelope(200, nil)
	ch := &mockChannel{
		streamID:  "upstream",
		responses: []*envelope.Envelope{respEnv},
	}

	hookCalled := false
	hookFn := func(_ context.Context, _ *HookConfig, _ map[string]string) (map[string]string, error) {
		hookCalled = true
		return map[string]string{"hook_ran": "true"}, nil
	}

	j := &Job{
		Source:         &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
		Dial:           dialFunc(ch),
		Pipeline:       noopPipeline(),
		PreSend:        &HookConfig{Macro: "test", RunInterval: Always},
		RunPreSendHook: hookFn,
	}

	err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hookCalled {
		t.Error("pre-send hook should have been called")
	}
	if j.KVStore["hook_ran"] != "true" {
		t.Error("KVStore should contain hook_ran=true")
	}
}

func TestJobRun_PostReceiveHook(t *testing.T) {
	sendEnv := makeHTTPSendEnvelope("GET", "/test")
	respEnv := makeHTTPResponseEnvelope(200, []byte("response body"))
	ch := &mockChannel{
		streamID:  "upstream",
		responses: []*envelope.Envelope{respEnv},
	}

	hookCalled := false
	hookFn := func(_ context.Context, _ *HookConfig, _ map[string]string) (map[string]string, error) {
		hookCalled = true
		return map[string]string{"post_ran": "true"}, nil
	}

	j := &Job{
		Source:             &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
		Dial:               dialFunc(ch),
		Pipeline:           noopPipeline(),
		PostReceive:        &HookConfig{Macro: "test", RunInterval: Always},
		RunPostReceiveHook: hookFn,
	}

	err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hookCalled {
		t.Error("post-receive hook should have been called")
	}
	if j.KVStore["post_ran"] != "true" {
		t.Error("KVStore should contain post_ran=true")
	}
}

func TestJobRun_HookError(t *testing.T) {
	sendEnv := makeHTTPSendEnvelope("GET", "/test")
	hookFn := func(_ context.Context, _ *HookConfig, _ map[string]string) (map[string]string, error) {
		return nil, errors.New("hook failed")
	}

	j := &Job{
		Source:         &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
		Dial:           dialFunc(&mockChannel{streamID: "upstream", responses: []*envelope.Envelope{makeHTTPResponseEnvelope(200, nil)}}),
		Pipeline:       noopPipeline(),
		PreSend:        &HookConfig{Macro: "test", RunInterval: Always},
		RunPreSendHook: hookFn,
	}

	err := j.Run(context.Background())
	if err == nil {
		t.Fatal("expected hook error")
	}
}

func TestJobRun_HookOnceSkipsSecond(t *testing.T) {
	envs := []*envelope.Envelope{
		makeHTTPSendEnvelope("GET", "/1"),
		makeHTTPSendEnvelope("GET", "/2"),
	}

	hookCallCount := 0
	hookFn := func(_ context.Context, _ *HookConfig, _ map[string]string) (map[string]string, error) {
		hookCallCount++
		return nil, nil
	}

	dialFn := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		return &mockChannel{
			streamID:  "upstream",
			responses: []*envelope.Envelope{makeHTTPResponseEnvelope(200, nil)},
		}, nil
	}

	j := &Job{
		Source:         &mockSource{envelopes: envs},
		Dial:           dialFn,
		Pipeline:       noopPipeline(),
		PreSend:        &HookConfig{Macro: "test", RunInterval: Once},
		RunPreSendHook: hookFn,
	}

	err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if hookCallCount != 1 {
		t.Errorf("Once hook should be called exactly 1 time, got %d", hookCallCount)
	}
}

func TestJobRun_NilHookFunc(t *testing.T) {
	sendEnv := makeHTTPSendEnvelope("GET", "/test")
	respEnv := makeHTTPResponseEnvelope(200, nil)
	ch := &mockChannel{
		streamID:  "upstream",
		responses: []*envelope.Envelope{respEnv},
	}

	j := &Job{
		Source:   &mockSource{envelopes: []*envelope.Envelope{sendEnv}},
		Dial:     dialFunc(ch),
		Pipeline: noopPipeline(),
		PreSend:  &HookConfig{Macro: "test", RunInterval: Always},
		// RunPreSendHook is nil — hook should be silently skipped.
	}

	err := j.Run(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// --- ChannelSource tests ---

func TestChannelSource(t *testing.T) {
	env := makeHTTPSendEnvelope("GET", "/test")
	ch := &mockChannel{
		streamID:  "source",
		responses: []*envelope.Envelope{env},
	}

	src := ChannelSource(ch)
	got, err := src.Next(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != env {
		t.Error("should return the envelope from the channel")
	}

	_, err = src.Next(context.Background())
	if !errors.Is(err, io.EOF) {
		t.Errorf("expected io.EOF, got: %v", err)
	}
}

// --- dropAllStep is a Pipeline Step that drops all Envelopes ---

type dropAllStep struct{}

func (s *dropAllStep) Process(_ context.Context, _ *envelope.Envelope) pipeline.Result {
	return pipeline.Result{Action: pipeline.Drop}
}
