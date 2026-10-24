package grpc

import (
	"bytes"
	"context"
	"fmt"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1256: the LPM compressed-flag byte is wire data. RFC values are 0
// and 1, but a peer can send any byte; the Channel must record and
// forward it verbatim (MITM Principle 1, L7/L4 principle 3). The
// GRPCDataMessage.Compressed bool stays the convenience view
// (flag != 0); Envelope.Raw is the lossless one.

// makeLPMFlag builds an LPM wire form with an arbitrary flag byte.
func makeLPMFlag(flag byte, payload []byte) []byte {
	return concat(lpmPrefix(flag, uint32(len(payload))), payload)
}

// flagFidelityFlags covers the RFC values (guards) and non-RFC values.
var flagFidelityFlags = []byte{0x00, 0x01, 0x02, 0x7F, 0x80, 0xFF}

// pushStartFor pushes the opening HEADERS for dir: a request Start on
// Send, a response Start on Receive.
func pushStartFor(s *stubInner, dir envelope.Direction) {
	if dir == envelope.Send {
		s.pushHeaders(envelope.Send, []byte("HPACK-req"), requestStartHeaders("/svc.S/M"))
		return
	}
	s.pushHeaders(envelope.Receive, []byte("HPACK-resp"), &http2.H2HeadersEvent{
		Status:  200,
		Headers: []envelope.KeyValue{{Name: "content-type", Value: "application/grpc"}},
	})
}

// roleFor returns the Role whose Next yields dir-direction envelopes.
func roleFor(dir envelope.Direction) Role {
	if dir == envelope.Send {
		return RoleServer
	}
	return RoleClient
}

// T5: Next's Data envelope Raw and the LPM record callback's Raw are the
// pushed wire bytes, flag byte included, in both directions.
func TestChannel_LPMFlagByteVerbatim(t *testing.T) {
	t.Parallel()
	for _, dir := range []envelope.Direction{envelope.Send, envelope.Receive} {
		for _, flag := range flagFidelityFlags {
			t.Run(fmt.Sprintf("%v/flag=0x%02x", dir, flag), func(t *testing.T) {
				t.Parallel()
				wire := makeLPMFlag(flag, []byte("abc"))
				stub := newStubInner("stream-flag")
				pushStartFor(stub, dir)
				stub.pushData(dir, wire, false)

				rec := &lpmRecorder{}
				ch := Wrap(stub, nil, roleFor(dir), WithLPMFrameRecordCallback(rec.cb))
				defer ch.Close()

				envs := drainNext(t, ch, 2)
				dm, ok := envs[1].Message.(*envelope.GRPCDataMessage)
				if !ok {
					t.Fatalf("envs[1].Message = %T, want *GRPCDataMessage", envs[1].Message)
				}
				if !bytes.Equal(envs[1].Raw, wire) {
					t.Errorf("Data env Raw = %x, want %x (wire bytes verbatim)", envs[1].Raw, wire)
				}
				if dm.Compressed != (flag != 0) {
					t.Errorf("Compressed = %v, want %v (flag != 0)", dm.Compressed, flag != 0)
				}
				if string(dm.Payload) != "abc" {
					t.Errorf("Payload = %q, want %q", dm.Payload, "abc")
				}

				got := rec.snapshot()
				if len(got) != 1 {
					t.Fatalf("LPM record callback fired %d times, want 1", len(got))
				}
				if !bytes.Equal(got[0].Raw, wire) {
					t.Errorf("LPM record env Raw = %x, want %x (wire bytes verbatim)", got[0].Raw, wire)
				}
			})
		}
	}
}

// sentDataPayloads returns the payloads of every H2DataEvent in sent.
func sentDataPayloads(sent []*envelope.Envelope) [][]byte {
	var out [][]byte
	for _, e := range sent {
		if d, ok := e.Message.(*http2.H2DataEvent); ok {
			out = append(out, d.Payload)
		}
	}
	return out
}

// requireSentLPM asserts the first DATA frame handed to the inner HTTP/2
// Channel carries wire byte-identical.
func requireSentLPM(t *testing.T, sent []*envelope.Envelope, wire []byte) {
	t.Helper()
	datas := sentDataPayloads(sent)
	if len(datas) == 0 {
		t.Fatalf("no DATA sent; sent = %v", describeSent(sent))
	}
	if !bytes.Equal(datas[0], wire) {
		t.Errorf("forwarded DATA payload = %x, want %x (wire bytes verbatim)", datas[0], wire)
	}
}

// T6: a non-RFC flag byte relayed between the two legs leaves the
// opposite inner Channel byte-identical, in both directions.
func TestRelay_LPMFlagByteVerbatim(t *testing.T) {
	t.Parallel()
	wire := makeLPMFlag(0x02, []byte("abc"))

	t.Run("request", func(t *testing.T) {
		t.Parallel()
		sent := relayRequestPush(t, func(s *stubInner) {
			s.pushHeaders(envelope.Send, []byte("HPACK-req"), requestStartHeaders("/svc.S/M"))
			s.pushData(envelope.Send, wire, true)
		}, nil)
		requireSentLPM(t, sent, wire)
	})

	t.Run("response", func(t *testing.T) {
		t.Parallel()
		_, sent := relayResponse(t, func(s *stubInner) {
			pushStartFor(s, envelope.Receive)
			s.pushData(envelope.Receive, wire, false)
			s.pushTrailers(envelope.Receive, []byte("HPACK-trl"), []envelope.KeyValue{
				{Name: "grpc-status", Value: "0"},
			})
		}, nil)
		requireSentLPM(t, sent, wire)
	})
}

// T7: every record path agrees on the flag byte of a complete LPM that
// precedes a failing one in the same DATA event — the cap-trip path, the
// END_STREAM-mid-LPM path and the decode-failure path.
func TestChannel_LPMFlagByteVerbatim_RecordPathsAgree(t *testing.T) {
	t.Parallel()
	plain := makeLPMFlag(0x02, []byte("good"))

	tests := []struct {
		name       string
		first      func(t *testing.T) []byte
		tail       []byte
		endStream  bool
		maxMsg     uint32
		encoding   string
		wantCode   layer.ErrorCode
		wantReason string // exact unless empty
	}{
		{
			name:       "too large",
			first:      func(*testing.T) []byte { return plain },
			tail:       concat(lpmPrefix(0, 300), []byte("zz")),
			maxMsg:     100,
			wantCode:   layer.ErrorInternalError,
			wantReason: "grpc: message too large",
		},
		{
			name:       "end stream mid-LPM",
			first:      func(*testing.T) []byte { return plain },
			tail:       concat(lpmPrefix(0, 9), []byte("zz")),
			endStream:  true,
			wantCode:   layer.ErrorProtocol,
			wantReason: "grpc: stream ended mid-LPM",
		},
		{
			name: "decode failure",
			first: func(t *testing.T) []byte {
				return makeLPMFlag(0x02, gzipCompress(t, []byte("good")))
			},
			tail:     makeLPM(true, []byte("not-gzip")),
			encoding: "gzip",
			wantCode: layer.ErrorProtocol,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			first := tt.first(t)
			var extra []envelope.KeyValue
			if tt.encoding != "" {
				extra = append(extra, envelope.KeyValue{Name: "grpc-encoding", Value: tt.encoding})
			}
			stub := newStubInner("stream-paths")
			stub.pushHeaders(envelope.Send, []byte("HPACK"), requestStartHeaders("/svc.S/M", extra...))
			stub.pushData(envelope.Send, concat(first, tt.tail), tt.endStream)

			rec := &lpmRecorder{}
			opts := []Option{WithLPMFrameRecordCallback(rec.cb)}
			if tt.maxMsg > 0 {
				opts = append(opts, WithMaxMessageSize(tt.maxMsg))
			}
			ch := Wrap(stub, nil, RoleServer, opts...)
			defer ch.Close()

			_, err := nextUntilErr(t, ch, 4)
			if tt.wantReason != "" {
				requireStreamError(t, err, tt.wantCode, tt.wantReason)
			}

			got := rec.snapshot()
			if len(got) == 0 {
				t.Fatalf("LPM record callback never fired; want the complete LPM's row first")
			}
			if !bytes.Equal(got[0].Raw, first) {
				t.Errorf("complete LPM row Raw = %x, want %x (flag byte verbatim)", got[0].Raw, first)
			}
		})
	}
}

// T8 guard (decision: re-encode of a Raw-less message is derived data):
// a Compressed=true Data envelope without Raw is written with flag 0x01.
func TestChannel_SendRawlessCompressedDataWritesFlagOne(t *testing.T) {
	t.Parallel()
	stub := newStubInner("stream-rawless")
	ch := Wrap(stub, nil, RoleClient)
	defer ch.Close()

	ctx := context.Background()
	if err := ch.Send(ctx, &envelope.Envelope{
		StreamID:  "stream-rawless",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCStartMessage{Service: "svc.S", Method: "M"},
	}); err != nil {
		t.Fatalf("Send Start: %v", err)
	}
	if err := ch.Send(ctx, &envelope.Envelope{
		StreamID:  "stream-rawless",
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolGRPC,
		Message:   &envelope.GRPCDataMessage{Compressed: true, Payload: []byte("abc")},
	}); err != nil {
		t.Fatalf("Send Data: %v", err)
	}
	requireSentLPM(t, stub.sentSnapshot(), makeLPMFlag(0x01, []byte("abc")))
}
