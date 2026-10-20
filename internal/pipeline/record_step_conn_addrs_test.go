package pipeline

import (
	"context"
	"net"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// serverAddrUpdates returns the UpdateStream calls that carried a
// ServerAddr or UpstreamProxy projection.
func serverAddrUpdates(w *mockWriter) []streamUpdateRecord {
	var out []streamUpdateRecord
	for _, u := range w.updates {
		if u.update.ServerAddr != "" || u.update.UpstreamProxy != "" {
			out = append(out, u)
		}
	}
	return out
}

func TestRecordStep_CreateStream_RecordsClientAddrAndListenerName(t *testing.T) {
	tests := []struct {
		name         string
		ctxAddr      string
		listener     string
		wantConnInfo *flow.ConnectionInfo
	}{
		{
			name:         "client addr and listener name",
			ctxAddr:      "127.0.0.1:54321",
			listener:     "worker-a",
			wantConnInfo: &flow.ConnectionInfo{ClientAddr: "127.0.0.1:54321"},
		},
		{
			name:         "no client addr on ctx leaves ConnInfo nil",
			ctxAddr:      "",
			listener:     "default",
			wantConnInfo: nil,
		},
		{
			name:         "no listener option leaves name empty",
			ctxAddr:      "[::1]:4000",
			listener:     "",
			wantConnInfo: &flow.ConnectionInfo{ClientAddr: "[::1]:4000"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := &mockWriter{}
			var opts []Option
			if tt.listener != "" {
				opts = append(opts, WithListenerName(tt.listener))
			}
			step := NewRecordStep(w, nil, opts...)

			ctx := context.Background()
			if tt.ctxAddr != "" {
				ctx = connector.ContextWithClientAddr(ctx, tt.ctxAddr)
			}
			step.Process(ctx, &envelope.Envelope{
				StreamID:  "s1",
				FlowID:    "f1",
				Direction: envelope.Send,
				Protocol:  envelope.ProtocolHTTP,
				Raw:       []byte("GET / HTTP/1.1\r\n\r\n"),
				Message:   &envelope.HTTPMessage{Method: "GET", Path: "/", Scheme: "http"},
				Context:   envelope.EnvelopeContext{ConnID: "c1"},
			})

			if len(w.streams) != 1 {
				t.Fatalf("SaveStream calls = %d, want 1", len(w.streams))
			}
			st := w.streams[0]
			if st.ListenerName != tt.listener {
				t.Errorf("ListenerName = %q, want %q", st.ListenerName, tt.listener)
			}
			switch {
			case tt.wantConnInfo == nil && st.ConnInfo != nil:
				t.Errorf("ConnInfo = %+v, want nil", st.ConnInfo)
			case tt.wantConnInfo != nil && st.ConnInfo == nil:
				t.Errorf("ConnInfo = nil, want %+v", tt.wantConnInfo)
			case tt.wantConnInfo != nil && *st.ConnInfo != *tt.wantConnInfo:
				t.Errorf("ConnInfo = %+v, want %+v", st.ConnInfo, tt.wantConnInfo)
			}
		})
	}
}

func TestRecordStep_FirstReceive_ProjectsServerAddrOncePerStream(t *testing.T) {
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	ctx := context.Background()

	upstreamPeer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
	recvCtx := envelope.EnvelopeContext{
		ConnID:        "c1",
		ServerAddr:    upstreamPeer,
		UpstreamProxy: "http://proxy.example:3128",
	}

	// h2-frame overlay first: no ServerAddr on its context, so it must
	// neither project nor consume the once-per-stream gate.
	step.Process(ctx, &envelope.Envelope{
		StreamID: "s1", FlowID: "o1", Direction: envelope.Send, Sequence: 0,
		Protocol: envelope.ProtocolHTTP, Raw: []byte{0, 0, 0},
		Context: envelope.EnvelopeContext{ConnID: "c1", WireLevel: flow.WireLevelH2Frame},
	})
	step.Process(ctx, &envelope.Envelope{
		StreamID: "s1", FlowID: "o2", Direction: envelope.Receive, Sequence: 0,
		Protocol: envelope.ProtocolHTTP, Raw: []byte{0, 0, 1},
		Context: envelope.EnvelopeContext{ConnID: "c1", WireLevel: flow.WireLevelH2Frame},
	})
	if got := serverAddrUpdates(w); len(got) != 0 {
		t.Fatalf("overlay without ServerAddr projected %d updates, want 0", len(got))
	}

	for i := 0; i < 3; i++ {
		step.Process(ctx, &envelope.Envelope{
			StreamID: "s1", FlowID: "r", Direction: envelope.Receive, Sequence: i + 1,
			Protocol: envelope.ProtocolHTTP, Raw: []byte("HTTP/1.1 200 OK\r\n\r\n"),
			Message: &envelope.HTTPMessage{Status: 200},
			Context: recvCtx,
		})
	}
	// A second stream gets its own projection.
	step.Process(ctx, &envelope.Envelope{
		StreamID: "s2", FlowID: "r2", Direction: envelope.Receive, Sequence: 1,
		Protocol: envelope.ProtocolHTTP, Raw: []byte("HTTP/1.1 200 OK\r\n\r\n"),
		Message: &envelope.HTTPMessage{Status: 200},
		Context: recvCtx,
	})

	got := serverAddrUpdates(w)
	if len(got) != 2 {
		t.Fatalf("server addr updates = %d, want 2 (one per stream); updates=%+v", len(got), w.updates)
	}
	for i, wantID := range []string{"s1", "s2"} {
		if got[i].streamID != wantID {
			t.Errorf("update[%d].streamID = %q, want %q", i, got[i].streamID, wantID)
		}
		if got[i].update.ServerAddr != "127.0.0.1:8443" {
			t.Errorf("update[%d].ServerAddr = %q, want 127.0.0.1:8443", i, got[i].update.ServerAddr)
		}
		if got[i].update.UpstreamProxy != "http://proxy.example:3128" {
			t.Errorf("update[%d].UpstreamProxy = %q, want http://proxy.example:3128", i, got[i].update.UpstreamProxy)
		}
	}
}

func TestRecordStep_SendWithServerAddr_DoesNotProject(t *testing.T) {
	// The client leg never carries ServerAddr in production; even if a Send
	// envelope did, the projection is upstream-leg (Receive) only.
	w := &mockWriter{}
	step := NewRecordStep(w, nil)
	step.Process(context.Background(), &envelope.Envelope{
		StreamID: "s1", FlowID: "f1", Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP, Raw: []byte("GET / HTTP/1.1\r\n\r\n"),
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/"},
		Context: envelope.EnvelopeContext{ServerAddr: &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 80}},
	})
	if got := serverAddrUpdates(w); len(got) != 0 {
		t.Errorf("Send envelope projected server addr: %+v", got)
	}
}

func TestRecordStep_RawReceiveFirst_ProjectsServerAddr(t *testing.T) {
	// Server-speaks-first raw stream: the Receive opener creates the row and
	// then projects the upstream peer.
	w := &mockWriter{}
	step := NewRecordStep(w, nil, WithListenerName("tcp-l"))
	ctx := connector.ContextWithClientAddr(context.Background(), "127.0.0.1:1111")
	step.Process(ctx, &envelope.Envelope{
		StreamID: "raw1", FlowID: "f1", Direction: envelope.Receive, Sequence: 0,
		Protocol: envelope.ProtocolRaw, Raw: []byte("220 banner\r\n"),
		Message: &envelope.RawMessage{Bytes: []byte("220 banner\r\n")},
		Context: envelope.EnvelopeContext{ConnID: "c1", ServerAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 25}},
	})
	if len(w.streams) != 1 {
		t.Fatalf("SaveStream calls = %d, want 1", len(w.streams))
	}
	if w.streams[0].ListenerName != "tcp-l" {
		t.Errorf("ListenerName = %q, want tcp-l", w.streams[0].ListenerName)
	}
	if ci := w.streams[0].ConnInfo; ci == nil || ci.ClientAddr != "127.0.0.1:1111" {
		t.Errorf("ConnInfo = %+v, want ClientAddr 127.0.0.1:1111", ci)
	}
	got := serverAddrUpdates(w)
	if len(got) != 1 || got[0].update.ServerAddr != "127.0.0.1:25" {
		t.Errorf("server addr updates = %+v, want one with 127.0.0.1:25", got)
	}
}
