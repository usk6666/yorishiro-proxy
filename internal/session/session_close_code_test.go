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

// codeCloseMock is a client Channel that, like the HTTP/2 stream channel
// (and its aggregator / gRPC / gRPC-Web wrappers), offers CloseWithCode in
// addition to Close. CloseWithCode still tears the mock down via Close so
// the session's lifecycle is unchanged; codes records which RST_STREAM codes
// the session asked for.
type codeCloseMock struct {
	*mockChannel
	codesMu sync.Mutex
	codes   []uint32
}

func (r *codeCloseMock) CloseWithCode(code uint32) error {
	r.codesMu.Lock()
	r.codes = append(r.codes, code)
	r.codesMu.Unlock()
	return r.mockChannel.Close()
}

func (r *codeCloseMock) getCodes() []uint32 {
	r.codesMu.Lock()
	defer r.codesMu.Unlock()
	return append([]uint32(nil), r.codes...)
}

// HTTP/2 error codes (RFC 9113 §7) used below; the session treats them as
// opaque values.
const (
	h2Internal    uint32 = 0x2
	h2Refused     uint32 = 0x7
	h2Cancel      uint32 = 0x8
	h2EnhanceCalm uint32 = 0xb
	h2Unknown     uint32 = 0xff
)

// peerRST builds the StreamError the HTTP/2 Layer surfaces for a peer
// RST_STREAM(code) (handleStreamRST).
func peerRST(class layer.ErrorCode, code uint32) error {
	return &layer.StreamError{Code: class, Reason: "peer RST_STREAM", PeerWireCode: code, HasPeerWireCode: true}
}

// TestRunSession_UpstreamTermination_ClientCloseCode pins how the session
// tears the client stream down after the upstream ended it:
//
//   - the upstream peer put an RST_STREAM code on the wire → the client gets
//     that exact code via CloseWithCode, as it would talking to the origin
//     directly (USK-1269);
//   - else the upstream declared the stream unprocessed (GOAWAY above
//     last_stream_id, or an OpenStream refusal) → CloseWithCode(REFUSED_STREAM)
//     so the client retries (USK-1157);
//   - else (local failures, client-originated errors) → plain Close (CANCEL).
func TestRunSession_UpstreamTermination_ClientCloseCode(t *testing.T) {
	refused := func() error { return &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY (NO_ERROR)"} }
	oneSend := func() []*envelope.Envelope { return []*envelope.Envelope{makeEnvelope(envelope.Send, 0)} }
	upstreamNextErr := func(err error) func() (*mockChannel, DialFunc) {
		return func() (*mockChannel, DialFunc) {
			client := &mockChannel{streamID: "c", nextEnvelopes: oneSend()}
			up := &mockChannel{streamID: "u", nextErr: err}
			return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
		}
	}

	tests := []struct {
		name string
		// setup returns the client Channel's Next behaviour and the dial
		// function under test.
		setup func() (*mockChannel, DialFunc)
		// wantCodes is the CloseWithCode calls expected; nil means the
		// session must use the plain Close.
		wantCodes []uint32
	}{
		{
			name:      "upstream Next returns StreamError{refused}",
			setup:     upstreamNextErr(refused()),
			wantCodes: []uint32{h2Refused},
		},
		{
			name: "dial returns StreamError{refused}",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: oneSend()}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return nil, refused() }
			},
			wantCodes: []uint32{h2Refused},
		},
		{
			name: "upstream Send fails with a plain error while upstream Err is refused",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: oneSend()}
				up := &mockChannel{
					streamID:  "u",
					sendErr:   errors.New("http2: stream 3 does not exist for window check"),
					blockNext: make(chan struct{}),
				}
				up.fireTerminated(refused())
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantCodes: []uint32{h2Refused},
		},
		{
			name: "client-originated refused keeps plain Close",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: oneSend(), nextErr: refused()}
				up := &mockChannel{streamID: "u", blockNext: make(chan struct{})}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantCodes: nil,
		},
		{
			name:      "upstream canceled without a peer code keeps plain Close",
			setup:     upstreamNextErr(&layer.StreamError{Code: layer.ErrorCanceled, Reason: "CANCEL"}),
			wantCodes: nil,
		},
		{
			name:      "upstream internal_error without a peer code keeps plain Close",
			setup:     upstreamNextErr(&layer.StreamError{Code: layer.ErrorInternalError, Reason: "local"}),
			wantCodes: nil,
		},
		{
			name:      "upstream peer RST_STREAM(INTERNAL_ERROR) is relayed",
			setup:     upstreamNextErr(peerRST(layer.ErrorInternalError, h2Internal)),
			wantCodes: []uint32{h2Internal},
		},
		{
			name:      "upstream peer RST_STREAM(ENHANCE_YOUR_CALM) is relayed",
			setup:     upstreamNextErr(peerRST(layer.ErrorAborted, h2EnhanceCalm)),
			wantCodes: []uint32{h2EnhanceCalm},
		},
		{
			name:      "upstream peer RST_STREAM(unknown 0xff) is relayed",
			setup:     upstreamNextErr(peerRST(layer.ErrorAborted, h2Unknown)),
			wantCodes: []uint32{h2Unknown},
		},
		{
			name:      "upstream peer RST_STREAM(CANCEL) is relayed",
			setup:     upstreamNextErr(peerRST(layer.ErrorCanceled, h2Cancel)),
			wantCodes: []uint32{h2Cancel},
		},
		{
			name:      "upstream peer RST_STREAM(REFUSED_STREAM) is relayed",
			setup:     upstreamNextErr(peerRST(layer.ErrorRefused, h2Refused)),
			wantCodes: []uint32{h2Refused},
		},
		{
			name: "upstream Send fails with a plain error while upstream Err carries a peer code",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: oneSend()}
				up := &mockChannel{
					streamID:  "u",
					sendErr:   errors.New("http2: stream 3 reset"),
					blockNext: make(chan struct{}),
				}
				up.fireTerminated(peerRST(layer.ErrorInternalError, h2Internal))
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantCodes: []uint32{h2Internal},
		},
		{
			name: "client-originated peer RST code keeps plain Close",
			setup: func() (*mockChannel, DialFunc) {
				client := &mockChannel{streamID: "c", nextEnvelopes: oneSend(), nextErr: peerRST(layer.ErrorInternalError, h2Internal)}
				up := &mockChannel{streamID: "u", blockNext: make(chan struct{})}
				return client, func(context.Context, *envelope.Envelope) (layer.Channel, error) { return up, nil }
			},
			wantCodes: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inner, dial := tt.setup()
			client := &codeCloseMock{mockChannel: inner}

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
			codes := client.getCodes()
			if len(codes) != len(tt.wantCodes) {
				t.Fatalf("client CloseWithCode calls = %v, want %v (nil = plain Close); RunSession err = %v", codes, tt.wantCodes, err)
			}
			for i := range codes {
				if codes[i] != tt.wantCodes[i] {
					t.Fatalf("client CloseWithCode calls = %v, want %v; RunSession err = %v", codes, tt.wantCodes, err)
				}
			}
		})
	}
}
