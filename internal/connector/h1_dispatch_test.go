package connector

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
)

// TestExtractHTTPContentType verifies extractHTTPContentType returns the
// first content-type header value (case-insensitive name match), preserves
// the wire-observed value casing, and returns "" when no content-type
// header is present. Mirrors TestExtractContentType for HTTP/2.
func TestExtractHTTPContentType(t *testing.T) {
	tests := []struct {
		name string
		msg  *envelope.HTTPMessage
		want string
	}{
		{
			name: "nil message",
			msg:  nil,
			want: "",
		},
		{
			name: "no content-type header",
			msg:  &envelope.HTTPMessage{Headers: []envelope.KeyValue{{Name: "x-other", Value: "ignore"}}},
			want: "",
		},
		{
			name: "lowercase content-type",
			msg:  &envelope.HTTPMessage{Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc-web+proto"}}},
			want: "application/grpc-web+proto",
		},
		{
			name: "mixed-case header name",
			msg:  &envelope.HTTPMessage{Headers: []envelope.KeyValue{{Name: "Content-Type", Value: "application/grpc-web-text"}}},
			want: "application/grpc-web-text",
		},
		{
			name: "first content-type wins",
			msg: &envelope.HTTPMessage{Headers: []envelope.KeyValue{
				{Name: "content-type", Value: "application/grpc-web+proto"},
				{Name: "content-type", Value: "application/json"},
			}},
			want: "application/grpc-web+proto",
		},
		{
			name: "value case preserved",
			msg: &envelope.HTTPMessage{Headers: []envelope.KeyValue{
				{Name: "Content-Type", Value: "Application/GRPC-WEB; CHARSET=UTF-8"},
			}},
			want: "Application/GRPC-WEB; CHARSET=UTF-8",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractHTTPContentType(tt.msg); got != tt.want {
				t.Errorf("extractHTTPContentType = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestDispatchH1Channel_GRPCWebClassification verifies the dispatcher
// wraps the channel with grpcweb.Wrap iff the request's content-type is
// a gRPC-Web media type. The wrap is detected via the upstream
// symmetry: a grpcweb-wrapped channel accepts *envelope.GRPCStartMessage
// on Send (the default http1-style channel does not).
//
// Negative cases (json / empty / non-grpc-web grpc) confirm the
// dispatcher returns the replay channel unwrapped so the underlying
// HTTPMessage flows through unchanged.
func TestDispatchH1Channel_GRPCWebClassification(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		// wantWrapped is true when the dispatcher is expected to wrap the
		// channel with grpcweb.Wrap. Verified by replaying the first
		// envelope and asserting it carries Protocol=ProtocolGRPCWeb when
		// the wrap fired.
		wantWrapped bool
	}{
		{"grpc-web binary +proto", "application/grpc-web+proto", true},
		{"grpc-web binary", "application/grpc-web", true},
		{"grpc-web text", "application/grpc-web-text", true},
		{"grpc-web text +proto", "application/grpc-web-text+proto", true},
		{"grpc-web with charset", "application/grpc-web+proto; charset=utf-8", true},
		{"native grpc (NOT grpc-web)", "application/grpc", false},
		{"native grpc +proto (NOT grpc-web)", "application/grpc+proto", false},
		{"json", "application/json", false},
		{"empty", "", false},
		{"text/plain", "text/plain", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a request HTTPMessage with the test content-type.
			req := &envelope.HTTPMessage{
				Method: "POST",
				Path:   "/hello.HelloService/SayHello",
				Headers: []envelope.KeyValue{
					{Name: "host", Value: "127.0.0.1"},
					{Name: "content-type", Value: tt.contentType},
				},
				// Empty body avoids the layer attempting LPM parse on
				// the unit-test path. The classification decision is
				// based on the content-type only.
				Body: nil,
			}
			env := &envelope.Envelope{
				StreamID:  "h1-test",
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Message:   req,
			}

			fake := newFakeH1Channel([]*envelope.Envelope{env})
			dispatched, err := DispatchH1Channel(context.Background(), fake, grpcweb.RoleServer, nil, nil)
			if err != nil {
				t.Fatalf("DispatchH1Channel returned error: %v", err)
			}
			if dispatched == nil {
				t.Fatalf("DispatchH1Channel returned nil channel")
			}

			// Replay the first envelope. For the wrapped case, grpcweb
			// emits a GRPCStartMessage with Protocol=ProtocolGRPCWeb.
			// For the unwrapped case, the replay channel re-yields the
			// original HTTPMessage envelope with Protocol=ProtocolHTTP.
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			first, err := dispatched.Next(ctx)
			if err != nil {
				t.Fatalf("dispatched.Next returned error: %v", err)
			}
			if tt.wantWrapped {
				if first.Protocol != envelope.ProtocolGRPCWeb {
					t.Errorf("wanted Protocol=ProtocolGRPCWeb (wrapped), got %q for ct=%q",
						first.Protocol, tt.contentType)
				}
				if _, ok := first.Message.(*envelope.GRPCStartMessage); !ok {
					t.Errorf("wanted *GRPCStartMessage (wrapped), got %T for ct=%q",
						first.Message, tt.contentType)
				}
			} else {
				if first.Protocol != envelope.ProtocolHTTP {
					t.Errorf("wanted Protocol=ProtocolHTTP (unwrapped), got %q for ct=%q",
						first.Protocol, tt.contentType)
				}
				if _, ok := first.Message.(*envelope.HTTPMessage); !ok {
					t.Errorf("wanted *HTTPMessage (unwrapped), got %T for ct=%q",
						first.Message, tt.contentType)
				}
			}
		})
	}
}

// TestDispatchH1Channel_PeekError verifies that an error from clientCh.Next
// (e.g., peer hung up before sending a request) is returned to the caller
// verbatim so the caller can distinguish from "wrong Channel type".
func TestDispatchH1Channel_PeekError(t *testing.T) {
	wantErr := io.EOF
	fake := newFakeH1ChannelErr(wantErr)
	_, err := DispatchH1Channel(context.Background(), fake, grpcweb.RoleServer, nil, nil)
	if !errors.Is(err, wantErr) {
		t.Fatalf("wanted err=%v, got %v", wantErr, err)
	}
}

// TestDispatchH1Channel_WrongMessageType verifies the dispatcher returns
// a descriptive error if the first envelope is not an *HTTPMessage. This
// is defensive — the H1 Layer always emits HTTPMessage envelopes, so the
// branch only fires on a programmer wiring error.
func TestDispatchH1Channel_WrongMessageType(t *testing.T) {
	// A WSMessage envelope masquerading on an "h1" channel — wiring bug.
	env := &envelope.Envelope{
		StreamID:  "h1-test",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.WSMessage{Opcode: envelope.WSText, Payload: []byte("oops")},
	}
	fake := newFakeH1Channel([]*envelope.Envelope{env})
	_, err := DispatchH1Channel(context.Background(), fake, grpcweb.RoleServer, nil, nil)
	if err == nil {
		t.Fatalf("wanted error on wrong message type, got nil")
	}
}

// TestWrapH1UpstreamForDispatch verifies per-Protocol dispatch of the
// upstream wrapper:
//
//   - ProtocolGRPCWeb returns a grpcweb-wrapped Channel that accepts a
//     *envelope.GRPCStartMessage on Send (the symmetric pattern to
//     USK-771's H2 fix — without this, the upstream bare http1 Channel
//     would only accept *envelope.HTTPMessage and reject the gRPC
//     envelopes the session forwards from the client side).
//   - any other Protocol returns the inner Channel unchanged (verified by
//     pointer identity).
//
// The grpc-web Send acceptance is a structural test: the fake upstream
// silently absorbs any Send, so the wrapper's Send-side accept/reject
// decision is observable as nil/non-nil at the Send return.
func TestWrapH1UpstreamForDispatch(t *testing.T) {
	t.Run("grpc-web wraps and accepts GRPCStartMessage", func(t *testing.T) {
		fake := newFakeUpstreamChannel()
		ch := WrapH1UpstreamForDispatch(fake, envelope.ProtocolGRPCWeb, nil)
		if ch == nil {
			t.Fatalf("WrapH1UpstreamForDispatch returned nil for grpc-web")
		}
		defer ch.Close()
		// Identity guard: the grpc-web branch must wrap (returning a
		// new Channel), not return the inner unchanged.
		if any(ch) == any(fake) {
			t.Errorf("grpc-web path returned inner unchanged; expected wrap")
		}
		env := &envelope.Envelope{
			StreamID:  "test",
			Direction: envelope.Send,
			Protocol:  envelope.ProtocolGRPCWeb,
			Message:   &envelope.GRPCStartMessage{Service: "x.Y", Method: "Z", ContentType: "application/grpc-web+proto"},
		}
		if err := ch.Send(context.Background(), env); err != nil {
			t.Fatalf("grpc-web wrapper rejected GRPCStartMessage: %v", err)
		}
	})

	t.Run("default (http) returns inner unchanged", func(t *testing.T) {
		fake := newFakeUpstreamChannel()
		ch := WrapH1UpstreamForDispatch(fake, envelope.ProtocolHTTP, nil)
		if ch == nil {
			t.Fatalf("WrapH1UpstreamForDispatch returned nil for http")
		}
		// Pointer identity: the default branch returns the inner Channel.
		if any(ch) != any(fake) {
			t.Errorf("default path wrapped the inner channel; expected unchanged")
		}
	})

	t.Run("empty Protocol returns inner unchanged", func(t *testing.T) {
		fake := newFakeUpstreamChannel()
		ch := WrapH1UpstreamForDispatch(fake, "", nil)
		if any(ch) != any(fake) {
			t.Errorf("empty Protocol path wrapped the inner channel; expected unchanged")
		}
	})
}

// TestHTTP1ReplayChannel_NextReplaysQueuedFirst verifies the replay
// wrapper returns queued envelopes before delegating to the underlying
// Channel. Confirms the dispatcher's peek-then-replay invariant: no
// envelope is lost when the dispatcher decides not to wrap.
func TestHTTP1ReplayChannel_NextReplaysQueuedFirst(t *testing.T) {
	queued := &envelope.Envelope{StreamID: "x", Sequence: 0, Message: &envelope.HTTPMessage{Method: "GET"}}
	follow := &envelope.Envelope{StreamID: "x", Sequence: 1, Message: &envelope.HTTPMessage{Method: "POST"}}
	fake := newFakeH1Channel([]*envelope.Envelope{follow})

	c := &http1ReplayChannel{
		underlying: fake,
		queued:     []*envelope.Envelope{queued},
	}
	got1, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #1 err: %v", err)
	}
	if got1 != queued {
		t.Errorf("Next #1 = %v, want queued envelope", got1)
	}

	got2, err := c.Next(context.Background())
	if err != nil {
		t.Fatalf("Next #2 err: %v", err)
	}
	if got2 != follow {
		t.Errorf("Next #2 = %v, want underlying follow envelope", got2)
	}
}

// TestHTTP1ReplayChannel_PassThrough verifies StreamID / Send / Close /
// Closed / Err delegate to the underlying Channel.
func TestHTTP1ReplayChannel_PassThrough(t *testing.T) {
	fake := newFakeH1Channel(nil)
	c := &http1ReplayChannel{underlying: fake}

	if got := c.StreamID(); got != fake.StreamID() {
		t.Errorf("StreamID = %q, want %q", got, fake.StreamID())
	}
	if err := c.Send(context.Background(), &envelope.Envelope{}); err != nil {
		t.Errorf("Send err = %v", err)
	}
	if err := c.Close(); err != nil {
		t.Errorf("Close err = %v", err)
	}
	if c.Closed() != fake.Closed() {
		t.Errorf("Closed() did not pass through")
	}
	if err := c.Err(); err != nil {
		t.Errorf("Err = %v", err)
	}
}

// fakeH1Channel is a layer.Channel test double that yields a fixed
// queue of envelopes on Next and silently absorbs Send.
type fakeH1Channel struct {
	mu       sync.Mutex
	envs     []*envelope.Envelope
	closed   chan struct{}
	closedOn sync.Once
	nextErr  error
}

func newFakeH1Channel(envs []*envelope.Envelope) *fakeH1Channel {
	return &fakeH1Channel{
		envs:   envs,
		closed: make(chan struct{}),
	}
}

func newFakeH1ChannelErr(err error) *fakeH1Channel {
	return &fakeH1Channel{
		closed:  make(chan struct{}),
		nextErr: err,
	}
}

func (f *fakeH1Channel) StreamID() string { return "fake-h1" }

func (f *fakeH1Channel) Next(_ context.Context) (*envelope.Envelope, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.nextErr != nil {
		return nil, f.nextErr
	}
	if len(f.envs) == 0 {
		return nil, io.EOF
	}
	env := f.envs[0]
	f.envs = f.envs[1:]
	return env, nil
}

func (f *fakeH1Channel) Send(_ context.Context, _ *envelope.Envelope) error { return nil }

func (f *fakeH1Channel) Close() error {
	f.closedOn.Do(func() { close(f.closed) })
	return nil
}

func (f *fakeH1Channel) Closed() <-chan struct{} { return f.closed }

func (f *fakeH1Channel) Err() error { return nil }

// compile-time assertion: fakeH1Channel implements layer.Channel.
var _ layer.Channel = (*fakeH1Channel)(nil)
