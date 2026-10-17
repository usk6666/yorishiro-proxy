package session

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// refusedCloseMock is a client Channel that, like the HTTP/2 stream channel
// (and its aggregator / gRPC / gRPC-Web wrappers), offers CloseRefused in
// addition to Close. CloseRefused still tears the mock down via Close so the
// session's lifecycle is unchanged; refusedCalls records which entry point
// the session picked.
type refusedCloseMock struct {
	*mockChannel
	refusedMu    sync.Mutex
	refusedCalls int
}

func (r *refusedCloseMock) CloseRefused() error {
	r.refusedMu.Lock()
	r.refusedCalls++
	r.refusedMu.Unlock()
	return r.mockChannel.Close()
}

func (r *refusedCloseMock) getRefusedCalls() int {
	r.refusedMu.Lock()
	defer r.refusedMu.Unlock()
	return r.refusedCalls
}

// TestRunSession_UpstreamRefused_ClosesClientRefused pins USK-1157: when the
// UPSTREAM declared the stream unprocessed (GOAWAY above last_stream_id, or
// RST_STREAM(REFUSED_STREAM)), the session tears the client stream down
// with CloseRefused so the client sees REFUSED_STREAM and retries, instead
// of the generic Close (CANCEL). Refusals that did not originate upstream,
// and non-refused upstream failures, keep the plain Close.
func TestRunSession_UpstreamRefused_ClosesClientRefused(t *testing.T) {
	refused := func() error { return &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY (NO_ERROR)"} }

	tests := []struct {
		name string
		// setup returns the client Channel's Next behaviour and the dial
		// function under test.
		setup       func() (*mockChannel, DialFunc)
		wantRefused bool
	}{
		{
			name: "upstream Next returns StreamError{refused}",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)}}
				up := &mockChannel{streamID: "u", nextErr: refused()}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantRefused: true,
		},
		{
			name: "dial returns StreamError{refused}",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)}}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return nil, refused() }
			},
			wantRefused: true,
		},
		{
			name: "upstream Send fails with a plain error while upstream Err is refused",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)}}
				up := &mockChannel{
					streamID:  "u",
					sendErr:   errors.New("http2: stream 3 does not exist for window check"),
					blockNext: make(chan struct{}),
				}
				up.fireTerminated(refused())
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantRefused: true,
		},
		{
			name: "client-originated refused keeps plain Close",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{
					streamID:      "c",
					nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)},
					nextErr:       refused(),
				}
				up := &mockChannel{streamID: "u", blockNext: make(chan struct{})}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantRefused: false,
		},
		{
			name: "upstream canceled keeps plain Close",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: []*envelope.Envelope{makeEnvelope(envelope.Send, 0)}}
				up := &mockChannel{streamID: "u", nextErr: &layer.StreamError{Code: layer.ErrorCanceled, Reason: "CANCEL"}}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantRefused: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner, dial := tt.setup()
			client := &refusedCloseMock{mockChannel: inner}

			done := make(chan error, 1)
			go func() {
				done <- RunSession(context.Background(), client, dial, pipeline.New(passStep{}))
			}()
			var err error
			select {
			case err = <-done:
			case <-time.After(5 * time.Second):
				t.Fatal("RunSession did not return")
			}
			if err == nil {
				t.Fatal("RunSession returned nil, want the terminal error")
			}

			if !client.isClosed() {
				t.Fatal("client channel not torn down")
			}
			gotRefused := client.getRefusedCalls() == 1
			if gotRefused != tt.wantRefused {
				t.Errorf("client CloseRefused called = %v (calls=%d), want %v; RunSession err = %v",
					gotRefused, client.getRefusedCalls(), tt.wantRefused, err)
			}
		})
	}
}
