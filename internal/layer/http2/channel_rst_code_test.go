package http2

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// USK-1269: the RST_STREAM error code a peer put on the wire is carried
// verbatim on the surfaced *layer.StreamError (PeerWireCode), and the
// session relays it to the other leg with CloseWithCode. Only a genuine peer
// RST_STREAM sets it; every proxy-synthesized termination leaves it unset so
// the teardown stays CANCEL.

// TestChannel_PeerRST_CarriesPeerWireCode pins that a peer RST_STREAM with a
// non-NO_ERROR code surfaces as a StreamError carrying that exact code — for
// codes the classification folds (ENHANCE_YOUR_CALM, HTTP_1_1_REQUIRED →
// aborted) and for an unknown extension code (RFC 9113 §7: unknown codes
// MUST NOT trigger special behavior) alike — while the lossy classification
// in Code is unchanged.
func TestChannel_PeerRST_CarriesPeerWireCode(t *testing.T) {
	tests := []struct {
		code      uint32
		wantClass layer.ErrorCode
	}{
		{ErrCodeProtocol, layer.ErrorProtocol},
		{ErrCodeInternal, layer.ErrorInternalError},
		{ErrCodeFlowControl, layer.ErrorAborted},
		{ErrCodeRefusedStream, layer.ErrorRefused},
		{ErrCodeCancel, layer.ErrorCanceled},
		{ErrCodeEnhanceYourCalm, layer.ErrorAborted},
		{ErrCodeHTTP11Required, layer.ErrorAborted},
		{0xff, layer.ErrorAborted},
	}
	for _, tt := range tests {
		t.Run(ErrCodeString(tt.code), func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)

			ch, id := openClientGET(t, l, peer)
			if err := peer.wr.WriteRSTStream(id, tt.code); err != nil {
				t.Fatalf("write RST_STREAM: %v", err)
			}

			err := nextUntilError(t, ch)
			var se *layer.StreamError
			if !errors.As(err, &se) {
				t.Fatalf("Next err = %v, want *layer.StreamError", err)
			}
			if se.Code != tt.wantClass {
				t.Errorf("Code = %v, want %v", se.Code, tt.wantClass)
			}
			if !se.HasPeerWireCode || se.PeerWireCode != tt.code {
				t.Errorf("PeerWireCode = %#x (has=%v), want %#x (has=true)", se.PeerWireCode, se.HasPeerWireCode, tt.code)
			}
		})
	}
}

// TestChannel_LocalTermination_NoPeerWireCode pins that terminations the
// proxy synthesized — a GOAWAY refusal (the peer sent no RST_STREAM for the
// stream) and MarkTerminatedWithRST (the proxy's own reset) — never carry a
// peer wire code, so the session cannot relay a code nobody received.
func TestChannel_LocalTermination_NoPeerWireCode(t *testing.T) {
	tests := []struct {
		name      string
		terminate func(t *testing.T, peer *h2Peer, ch *channel)
	}{
		{
			name: "peer GOAWAY below the stream id",
			terminate: func(t *testing.T, peer *h2Peer, _ *channel) {
				if err := peer.wr.WriteGoAway(0, ErrCodeEnhanceYourCalm, nil); err != nil {
					t.Fatalf("write GOAWAY: %v", err)
				}
			},
		},
		{
			name: "MarkTerminatedWithRST",
			terminate: func(_ *testing.T, _ *h2Peer, ch *channel) {
				ch.MarkTerminatedWithRST(ErrCodeInternal, &layer.StreamError{Code: layer.ErrorInternalError, Reason: "max body size"})
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t)
			defer cleanup()
			peer.consumePeerSettings(t)

			ch, _ := openClientGET(t, l, peer)
			tt.terminate(t, peer, ch)

			select {
			case <-ch.Closed():
			case <-time.After(2 * time.Second):
				t.Fatal("channel not terminated")
			}
			var se *layer.StreamError
			if !errors.As(ch.Err(), &se) {
				t.Fatalf("Err = %v, want *layer.StreamError", ch.Err())
			}
			if se.HasPeerWireCode {
				t.Errorf("PeerWireCode set (%#x) on a proxy-synthesized termination", se.PeerWireCode)
			}
		})
	}
}

// TestChannel_CloseWithCode_ServerRole pins the client-facing half of the
// relay: CloseWithCode(c) resets the client stream with exactly c, also after
// a response (here a 1xx) began — only REFUSED_STREAM is downgraded to
// CANCEL then (RFC 9113 §8.7) — and sends nothing when the client already
// reset the stream (RFC 9113 §5.4.2).
func TestChannel_CloseWithCode_ServerRole(t *testing.T) {
	send103 := func(t *testing.T, peer *h2Peer, ch layer.Channel) {
		t.Helper()
		sendErr := make(chan error, 1)
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			sendErr <- ch.Send(ctx, &envelope.Envelope{
				Direction: envelope.Receive,
				Protocol:  envelope.ProtocolHTTP,
				Message:   &H2HeadersEvent{Status: 103},
			})
		}()
		drainUntil(t, peer, frame.TypeHeaders)
		if err := <-sendErr; err != nil {
			t.Fatalf("Send(103): %v", err)
		}
	}
	none := func(*testing.T, *h2Peer, layer.Channel) {}

	tests := []struct {
		name    string
		prepare func(t *testing.T, peer *h2Peer, ch layer.Channel)
		code    uint32
		want    []uint32
	}{
		{name: "INTERNAL_ERROR", prepare: none, code: ErrCodeInternal, want: []uint32{ErrCodeInternal}},
		{name: "ENHANCE_YOUR_CALM", prepare: none, code: ErrCodeEnhanceYourCalm, want: []uint32{ErrCodeEnhanceYourCalm}},
		{name: "HTTP_1_1_REQUIRED", prepare: none, code: ErrCodeHTTP11Required, want: []uint32{ErrCodeHTTP11Required}},
		{name: "unknown 0xff", prepare: none, code: 0xff, want: []uint32{0xff}},
		{name: "INTERNAL_ERROR after 1xx", prepare: send103, code: ErrCodeInternal, want: []uint32{ErrCodeInternal}},
		{name: "REFUSED_STREAM after 1xx downgrades to CANCEL", prepare: send103, code: ErrCodeRefusedStream, want: []uint32{ErrCodeCancel}},
		{
			name: "client already reset the stream",
			prepare: func(t *testing.T, peer *h2Peer, ch layer.Channel) {
				if err := peer.wr.WriteRSTStream(1, ErrCodeCancel); err != nil {
					t.Fatalf("write RST_STREAM: %v", err)
				}
				select {
				case <-ch.Closed():
				case <-time.After(2 * time.Second):
					t.Fatal("channel not terminated after client RST_STREAM")
				}
			},
			code: ErrCodeInternal,
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, peer, cleanup := startServerLayer(t)
			defer cleanup()
			ch := acceptServerStream(t, l, peer)
			tt.prepare(t, peer, ch)

			cc, ok := ch.(codeCloser)
			if !ok {
				t.Fatalf("server-role channel %T does not implement CloseWithCode", ch)
			}
			if err := cc.CloseWithCode(tt.code); err != nil {
				t.Fatalf("CloseWithCode: %v", err)
			}
			// A follow-up Close must not add a second RST.
			if err := ch.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}

			got := collectRSTs(t, peer, 300*time.Millisecond)[1]
			if len(got) != len(tt.want) {
				t.Fatalf("RST_STREAM codes on stream 1 = %v, want %v", got, tt.want)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Fatalf("RST_STREAM codes on stream 1 = %v, want %v", got, tt.want)
				}
			}
		})
	}
}
