//go:build legacy

package job

import (
	"context"
	"io"
	"regexp"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// mockSource is a test ExchangeSource that returns pre-configured Exchanges.
type mockSource struct {
	exchanges []*exchange.Exchange
	index     int
}

func (s *mockSource) Next(_ context.Context) (*exchange.Exchange, error) {
	if s.index >= len(s.exchanges) {
		return nil, io.EOF
	}
	ex := s.exchanges[s.index]
	s.index++
	return ex, nil
}

// mockCodec is a test Codec for upstream connections.
type mockCodec struct {
	sent     []*exchange.Exchange
	response *exchange.Exchange
}

func (c *mockCodec) Next(_ context.Context) (*exchange.Exchange, error) {
	if c.response != nil {
		resp := c.response
		c.response = nil // only return once
		return resp, nil
	}
	return nil, io.EOF
}

func (c *mockCodec) Send(_ context.Context, ex *exchange.Exchange) error {
	c.sent = append(c.sent, ex)
	return nil
}

func (c *mockCodec) Close() error { return nil }

func TestShouldRunPreSend(t *testing.T) {
	t.Run("Always", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: Always}
		for i := 0; i < 5; i++ {
			if !s.shouldRunPreSend(h) {
				t.Fatalf("expected true on iteration %d", i)
			}
			s.RequestCount++
		}
	})

	t.Run("EmptyDefaultsToAlways", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: ""}
		if !s.shouldRunPreSend(h) {
			t.Fatal("empty RunInterval should default to Always")
		}
	})

	t.Run("Once", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: Once}
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true on first call")
		}
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false on second call")
		}
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false on third call")
		}
	})

	t.Run("EveryN", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: EveryN, N: 3}

		// Request 0: 0%3==0 → true
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true at RequestCount=0")
		}
		s.RequestCount++
		// Request 1: 1%3!=0 → false
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false at RequestCount=1")
		}
		s.RequestCount++
		// Request 2: 2%3!=0 → false
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false at RequestCount=2")
		}
		s.RequestCount++
		// Request 3: 3%3==0 → true
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true at RequestCount=3")
		}
	})

	t.Run("EveryN_ZeroN", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: EveryN, N: 0}
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false when N=0")
		}
	})

	t.Run("OnError_FirstRequest", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: OnError}
		// Always run on first request.
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true on first request")
		}
	})

	t.Run("OnError_AfterSuccess", func(t *testing.T) {
		s := &HookState{RequestCount: 1, LastStatusCode: 200, LastError: false}
		h := &HookConfig{RunInterval: OnError}
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false after successful request")
		}
	})

	t.Run("OnError_AfterTransportError", func(t *testing.T) {
		s := &HookState{RequestCount: 1, LastError: true}
		h := &HookConfig{RunInterval: OnError}
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true after transport error")
		}
	})

	t.Run("OnError_After4xx", func(t *testing.T) {
		s := &HookState{RequestCount: 1, LastStatusCode: 403, LastError: false}
		h := &HookConfig{RunInterval: OnError}
		if !s.shouldRunPreSend(h) {
			t.Fatal("expected true after 403")
		}
	})

	t.Run("UnknownInterval", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: "invalid"}
		if s.shouldRunPreSend(h) {
			t.Fatal("expected false for unknown interval")
		}
	})
}

func TestShouldRunPostReceive(t *testing.T) {
	t.Run("Always", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: Always}
		if !s.shouldRunPostReceive(h, 200, nil) {
			t.Fatal("expected true")
		}
	})

	t.Run("EmptyDefaultsToAlways", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: ""}
		if !s.shouldRunPostReceive(h, 200, nil) {
			t.Fatal("empty RunInterval should default to Always")
		}
	})

	t.Run("OnStatus_Match", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: OnStatus, StatusCodes: []int{200, 302}}
		if !s.shouldRunPostReceive(h, 200, nil) {
			t.Fatal("expected true for matching status 200")
		}
		if !s.shouldRunPostReceive(h, 302, nil) {
			t.Fatal("expected true for matching status 302")
		}
	})

	t.Run("OnStatus_NoMatch", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: OnStatus, StatusCodes: []int{200, 302}}
		if s.shouldRunPostReceive(h, 404, nil) {
			t.Fatal("expected false for non-matching status")
		}
	})

	t.Run("OnMatch_Match", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{
			RunInterval:     OnMatch,
			MatchPattern:    `"error":\s*true`,
			CompiledPattern: regexp.MustCompile(`"error":\s*true`),
		}
		body := []byte(`{"error": true, "message": "fail"}`)
		if !s.shouldRunPostReceive(h, 200, body) {
			t.Fatal("expected true for matching body")
		}
	})

	t.Run("OnMatch_NoMatch", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{
			RunInterval:     OnMatch,
			MatchPattern:    `"error":\s*true`,
			CompiledPattern: regexp.MustCompile(`"error":\s*true`),
		}
		body := []byte(`{"error": false, "message": "ok"}`)
		if s.shouldRunPostReceive(h, 200, body) {
			t.Fatal("expected false for non-matching body")
		}
	})

	t.Run("OnMatch_NilPattern", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: OnMatch}
		if s.shouldRunPostReceive(h, 200, []byte("anything")) {
			t.Fatal("expected false when CompiledPattern is nil")
		}
	})

	t.Run("OnError_4xx", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: OnError}
		if !s.shouldRunPostReceive(h, 500, nil) {
			t.Fatal("expected true for 500")
		}
		if s.shouldRunPostReceive(h, 200, nil) {
			t.Fatal("expected false for 200")
		}
	})

	t.Run("UnknownInterval", func(t *testing.T) {
		s := &HookState{}
		h := &HookConfig{RunInterval: "invalid"}
		if s.shouldRunPostReceive(h, 200, nil) {
			t.Fatal("expected false for unknown interval")
		}
	})
}

func TestJobRun(t *testing.T) {
	t.Run("SourceEOF_ImmediateExit", func(t *testing.T) {
		j := &Job{
			Source:   &mockSource{exchanges: nil},
			Pipeline: pipeline.New(),
		}
		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
	})

	t.Run("SingleExchange", func(t *testing.T) {
		respExchange := &exchange.Exchange{
			Direction: exchange.Receive,
			Status:    200,
			Body:      []byte("OK"),
		}
		mc := &mockCodec{response: respExchange}

		j := &Job{
			Source: &mockSource{
				exchanges: []*exchange.Exchange{
					{Direction: exchange.Send, Method: "GET"},
				},
			},
			Dial: func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
				return mc, nil
			},
			Pipeline: pipeline.New(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if len(mc.sent) != 1 {
			t.Fatalf("expected 1 sent exchange, got %d", len(mc.sent))
		}
		if j.HookState.LastStatusCode != 200 {
			t.Fatalf("expected LastStatusCode=200, got %d", j.HookState.LastStatusCode)
		}
		if j.HookState.RequestCount != 1 {
			t.Fatalf("expected RequestCount=1, got %d", j.HookState.RequestCount)
		}
	})

	t.Run("MultipleExchanges", func(t *testing.T) {
		callCount := 0

		j := &Job{
			Source: &mockSource{
				exchanges: []*exchange.Exchange{
					{Direction: exchange.Send, Method: "GET"},
					{Direction: exchange.Send, Method: "POST"},
					{Direction: exchange.Send, Method: "PUT"},
				},
			},
			Dial: func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
				callCount++
				return &mockCodec{
					response: &exchange.Exchange{
						Direction: exchange.Receive,
						Status:    200,
					},
				}, nil
			},
			Pipeline: pipeline.New(),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if callCount != 3 {
			t.Fatalf("expected 3 dial calls, got %d", callCount)
		}
		if j.HookState.RequestCount != 3 {
			t.Fatalf("expected RequestCount=3, got %d", j.HookState.RequestCount)
		}
	})

	t.Run("ContextCancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		j := &Job{
			Source: &mockSource{
				exchanges: []*exchange.Exchange{
					{Direction: exchange.Send, Method: "GET"},
				},
			},
			Dial: func(ctx context.Context, _ *exchange.Exchange) (codec.Codec, error) {
				return nil, ctx.Err()
			},
			Pipeline: pipeline.New(),
		}

		err := j.Run(ctx)
		if err == nil {
			t.Fatal("expected error on cancelled context")
		}
	})

	t.Run("KVStoreInitialized", func(t *testing.T) {
		j := &Job{
			Source:   &mockSource{exchanges: nil},
			Pipeline: pipeline.New(),
		}
		_ = j.Run(context.Background())
		if j.KVStore == nil {
			t.Fatal("expected KVStore to be initialized")
		}
	})

	t.Run("PipelineDrop", func(t *testing.T) {
		dropStep := &dropAllStep{}
		dialCalled := false

		j := &Job{
			Source: &mockSource{
				exchanges: []*exchange.Exchange{
					{Direction: exchange.Send, Method: "GET"},
				},
			},
			Dial: func(_ context.Context, _ *exchange.Exchange) (codec.Codec, error) {
				dialCalled = true
				return nil, nil
			},
			Pipeline: pipeline.New(dropStep),
		}

		err := j.Run(context.Background())
		if err != nil {
			t.Fatalf("expected nil error, got: %v", err)
		}
		if dialCalled {
			t.Fatal("Dial should not be called when Pipeline drops all exchanges")
		}
		if j.HookState.RequestCount != 1 {
			t.Fatalf("expected RequestCount=1 even on drop, got %d", j.HookState.RequestCount)
		}
	})
}

// dropAllStep is a Pipeline Step that drops all Exchanges.
type dropAllStep struct{}

func (s *dropAllStep) Process(_ context.Context, _ *exchange.Exchange) pipeline.Result {
	return pipeline.Result{Action: pipeline.Drop}
}
