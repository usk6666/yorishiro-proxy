package grpcweb

import (
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// policyDropEnd mirrors the GRPCEndMessage pipeline.buildGRPCPolicyDropResponse
// synthesizes for a blocked gRPC-Web request (USK-1220): grpc-status 7,
// grpc-message "blocked by <reason>", server and x-yorishiro-matched-rules
// trailers, no Raw (the Layer renders the wire form from the fields).
func policyDropEnd(streamID string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID:  streamID,
		Sequence:  2,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolGRPCWeb,
		Message: &envelope.GRPCEndMessage{
			Status:  7,
			Message: "blocked by safety_filter",
			Trailers: []envelope.KeyValue{
				{Name: "server", Value: "yorishiro-proxy"},
				{Name: "x-yorishiro-matched-rules", Value: "destructive-sql:drop"},
			},
		},
	}
}

// TestSend_ReceiveEndWithoutStart_Terminator pins USK-1220 (U1): a
// RoleServer Channel asked to Send a Receive-direction End before any
// response Start (a proxy policy terminator, or a plugin RESPOND_GRPC)
// renders a complete gRPC-Web response: HTTP 200, the request's
// content-type verbatim (so a -text client gets a base64 body), and a body
// holding exactly one trailer frame with the End's status and trailers. The
// status is not projected into the HTTP headers.
func TestSend_ReceiveEndWithoutStart_Terminator(t *testing.T) {
	tests := []struct {
		name        string
		reqCT       string // "" = no request was read before the Send
		wantCT      string
		wantBase64  bool
		readRequest bool
	}{
		{name: "binary", reqCT: "application/grpc-web", wantCT: "application/grpc-web", readRequest: true},
		{name: "binary proto", reqCT: "application/grpc-web+proto", wantCT: "application/grpc-web+proto", readRequest: true},
		{name: "binary json", reqCT: "application/grpc-web+json", wantCT: "application/grpc-web+json", readRequest: true},
		{name: "text", reqCT: "application/grpc-web-text", wantCT: "application/grpc-web-text", wantBase64: true, readRequest: true},
		{name: "text proto", reqCT: "application/grpc-web-text+proto", wantCT: "application/grpc-web-text+proto", wantBase64: true, readRequest: true},
		{name: "no request read", wantCT: "application/grpc-web"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var queue []*envelope.Envelope
			if tt.readRequest {
				body := EncodeFrame(false, false, []byte("DROP TABLE users"))
				if tt.wantBase64 {
					body = EncodeBase64Body(body)
				}
				queue = append(queue, mustHTTPRequestEnv("s-term",
					[]envelope.KeyValue{{Name: "Content-Type", Value: tt.reqCT}},
					body, "/admin.Admin/Query"))
			}
			mock := newMockChannel("s-term", queue...)
			ch := Wrap(mock, RoleServer)
			if tt.readRequest {
				// Start, Data, Send End sentinel.
				if got := drainEnvelopes(t, ch, 3); len(got) != 3 {
					t.Fatalf("drained %d envelopes, want 3", len(got))
				}
			}

			if err := ch.Send(context.Background(), policyDropEnd("s-term")); err != nil {
				t.Fatalf("Send(Receive End without Start) = %v, want nil", err)
			}

			if len(mock.sent) != 1 {
				t.Fatalf("inner received %d envelopes, want 1", len(mock.sent))
			}
			out := mock.sent[0]
			if out.Direction != envelope.Receive {
				t.Errorf("Direction = %v, want Receive", out.Direction)
			}
			hm, ok := out.Message.(*envelope.HTTPMessage)
			if !ok {
				t.Fatalf("inner Message = %T, want *HTTPMessage", out.Message)
			}
			if hm.Status != 200 {
				t.Errorf("Status = %d, want 200", hm.Status)
			}
			if got := headerValuesKV(hm.Headers, "content-type"); len(got) != 1 || got[0] != tt.wantCT {
				t.Errorf("content-type = %q, want [%q]", got, tt.wantCT)
			}
			if hasHeader(hm.Headers, "grpc-status") || hasHeader(hm.Headers, "grpc-message") {
				t.Errorf("status projected into HTTP headers %v; want it only in the trailer frame", hm.Headers)
			}
			if hasHeader(hm.Headers, "connection") {
				t.Errorf("headers %v carry Connection; the keep-alive connection must survive", hm.Headers)
			}

			res, err := DecodeBody(hm.Body, tt.wantBase64)
			if err != nil {
				t.Fatalf("DecodeBody(base64=%v) of %q: %v", tt.wantBase64, hm.Body, err)
			}
			if len(res.DataFrames) != 0 {
				t.Errorf("DataFrames = %d, want 0", len(res.DataFrames))
			}
			if res.TrailerFrame == nil {
				t.Fatal("no trailer frame in the body")
			}
			trailers, err := ParseTrailers(res.TrailerFrame.Payload)
			if err != nil {
				t.Fatalf("ParseTrailers: %v", err)
			}
			want := map[string]string{
				"grpc-status":               "7",
				"grpc-message":              "blocked by safety_filter",
				"server":                    "yorishiro-proxy",
				"x-yorishiro-matched-rules": "destructive-sql:drop",
			}
			for k, v := range want {
				if trailers[k] != v {
					t.Errorf("trailer %s = %q, want %q (all: %v)", k, trailers[k], v, trailers)
				}
			}
		})
	}
}

// TestSend_SendEndWithoutStart_StillErrors guards the other half of the
// U1 contract: only a Receive End may stand alone. A Send-direction End
// with no request Start has no request to flush and keeps erroring.
func TestSend_SendEndWithoutStart_StillErrors(t *testing.T) {
	for _, role := range []Role{RoleServer, RoleClient} {
		mock := newMockChannel("s-send")
		ch := Wrap(mock, role)
		err := ch.Send(context.Background(), &envelope.Envelope{
			StreamID:  "s-send",
			Direction: envelope.Send,
			Message:   &envelope.GRPCEndMessage{},
		})
		if err == nil || !strings.Contains(err.Error(), "GRPCEndMessage before GRPCStartMessage") {
			t.Errorf("role %v: Send(Send End without Start) err = %v, want the before-Start error", role, err)
		}
		if len(mock.sent) != 0 {
			t.Errorf("role %v: inner received %d envelopes, want 0", role, len(mock.sent))
		}
	}
}
