package pipeline

import (
	"context"
	"errors"
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

// failingUpdateWriter fails the first failN UpdateStream calls, then
// records like mockWriter.
type failingUpdateWriter struct {
	*mockWriter
	failN int
}

func (f *failingUpdateWriter) UpdateStream(ctx context.Context, id string, u flow.StreamUpdate) error {
	if f.failN > 0 {
		f.failN--
		return errors.New("store unavailable")
	}
	return f.mockWriter.UpdateStream(ctx, id, u)
}

// sendOpener records a Stream through the Pipeline the way the live
// session does before the lazy upstream dial runs.
func sendOpener(t *testing.T, p *Pipeline, streamID string) {
	t.Helper()
	p.Run(context.Background(), &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-f0", Direction: envelope.Send,
		Protocol: envelope.ProtocolHTTP, Raw: []byte("GET / HTTP/1.1\r\n\r\n"),
		Message: &envelope.HTTPMessage{Method: "GET", Path: "/"},
		Context: envelope.EnvelopeContext{ConnID: "c1"},
	})
}

func receiveFrom(streamID string, peer net.Addr, proxy string) *envelope.Envelope {
	return &envelope.Envelope{
		StreamID: streamID, FlowID: streamID + "-r", Direction: envelope.Receive, Sequence: 1,
		Protocol: envelope.ProtocolHTTP, Raw: []byte("HTTP/1.1 200 OK\r\n\r\n"),
		Message: &envelope.HTTPMessage{Status: 200},
		Context: envelope.EnvelopeContext{ConnID: "c1", ServerAddr: peer, UpstreamProxy: proxy},
	}
}

func TestPipeline_RecordUpstreamPeer_WritesWithoutReceive(t *testing.T) {
	peerA := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 8443}
	peerB := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2), Port: 9443}
	const proxyURL = "http://proxy.example:3128"

	w := &mockWriter{}
	p := New(NewRecordStep(w, nil))
	ctx := context.Background()
	sendOpener(t, p, "s1")

	// Dial-time stamp: the upstream socket exists, nothing received yet.
	p.RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peerA, UpstreamProxy: proxyURL})
	got := serverAddrUpdates(w)
	if len(got) != 1 {
		t.Fatalf("server addr updates after dial-time stamp = %d, want 1; updates=%+v", len(got), w.updates)
	}
	if got[0].streamID != "s1" || got[0].update.ServerAddr != "127.0.0.1:8443" || got[0].update.UpstreamProxy != proxyURL {
		t.Errorf("dial-time update = %+v, want s1 / 127.0.0.1:8443 / %s", got[0], proxyURL)
	}

	// The same socket stamped again, then its first Receive: no extra write.
	p.RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peerA, UpstreamProxy: proxyURL})
	p.Run(ctx, receiveFrom("s1", peerA, proxyURL))
	if got := serverAddrUpdates(w); len(got) != 1 {
		t.Fatalf("server addr updates after same-value stamp + Receive = %d, want 1", len(got))
	}

	// A Receive from a different socket (swapped upstream) overwrites.
	p.Run(ctx, receiveFrom("s1", peerB, ""))
	got = serverAddrUpdates(w)
	if len(got) != 2 {
		t.Fatalf("server addr updates after different-socket Receive = %d, want 2", len(got))
	}
	if got[1].update.ServerAddr != "127.0.0.2:9443" {
		t.Errorf("overwrite ServerAddr = %q, want 127.0.0.2:9443", got[1].update.ServerAddr)
	}
}

func TestRecordStep_ReceiveFromDifferentSocket_OverwritesServerAddr(t *testing.T) {
	// The value written is the socket actually used: a later Receive from
	// a different upstream socket (h1 stale-conn replay, swapped Layer)
	// corrects an earlier projection; a repeat of the same value is free.
	w := &mockWriter{}
	p := New(NewRecordStep(w, nil))
	ctx := context.Background()
	peerA := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1001}
	peerB := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1002}

	p.Run(ctx, receiveFrom("s1", peerA, "http://p:1"))
	p.Run(ctx, receiveFrom("s1", peerB, ""))
	p.Run(ctx, receiveFrom("s1", peerB, ""))

	got := serverAddrUpdates(w)
	if len(got) != 2 {
		t.Fatalf("server addr updates = %d, want 2 (A, then B once); updates=%+v", len(got), got)
	}
	if got[1].update.ServerAddr != "127.0.0.1:1002" {
		t.Errorf("second update ServerAddr = %q, want 127.0.0.1:1002", got[1].update.ServerAddr)
	}
}

func TestPipeline_RecordUpstreamPeer_NoOps(t *testing.T) {
	peer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	ctx := context.Background()

	t.Run("nil server addr", func(t *testing.T) {
		w := &mockWriter{}
		p := New(NewRecordStep(w, nil))
		sendOpener(t, p, "s1")
		p.RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{UpstreamProxy: "http://p:1"})
		if n := len(serverAddrUpdates(w)); n != 0 {
			t.Errorf("server addr updates = %d, want 0", n)
		}
	})
	t.Run("empty stream id", func(t *testing.T) {
		w := &mockWriter{}
		p := New(NewRecordStep(w, nil))
		p.RecordUpstreamPeer(ctx, "", envelope.EnvelopeContext{ServerAddr: peer})
		if n := len(w.updates); n != 0 {
			t.Errorf("UpdateStream calls = %d, want 0", n)
		}
	})
	t.Run("nil pipeline", func(t *testing.T) {
		var p *Pipeline
		p.RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peer})
	})
	t.Run("pipeline without record step", func(t *testing.T) {
		New().RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peer})
	})
	t.Run("record step without store", func(t *testing.T) {
		New(NewRecordStep(nil, nil)).RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peer})
	})
}

func TestPipeline_RecordUpstreamPeer_FailedWriteRetries(t *testing.T) {
	peer := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443}
	w := &failingUpdateWriter{mockWriter: &mockWriter{}}
	p := New(NewRecordStep(w, nil))
	ctx := context.Background()
	sendOpener(t, p, "s1")
	w.failN = 1

	p.RecordUpstreamPeer(ctx, "s1", envelope.EnvelopeContext{ServerAddr: peer})
	if w.failN != 0 {
		t.Fatalf("dial-time stamp did not attempt a write (failN = %d, want 0)", w.failN)
	}
	if got := serverAddrUpdates(w.mockWriter); len(got) != 0 {
		t.Fatalf("failed write recorded %d updates, want 0", len(got))
	}
	// The failed write must not consume the gate: the next projection
	// of the same socket retries.
	p.Run(ctx, receiveFrom("s1", peer, ""))
	got := serverAddrUpdates(w.mockWriter)
	if len(got) != 1 || got[0].update.ServerAddr != "127.0.0.1:443" {
		t.Errorf("server addr updates after retry = %+v, want one with 127.0.0.1:443", got)
	}
}
