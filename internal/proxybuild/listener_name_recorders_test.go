package proxybuild

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// The live-path audit / side recorders stamp Stream.ListenerName with the
// accepting listener's configured name, alongside the legacy
// tags["listener"] where one exists.

func TestBuildPipelineDropRecorder_StampsListenerName(t *testing.T) {
	tests := []struct {
		name     string
		param    string
		ctxName  string
		wantName string
	}{
		{name: "configured name", param: "worker-a", wantName: "worker-a"},
		{name: "forward path falls back to ctx listener", param: "", ctxName: "parent-l", wantName: "parent-l"},
		{name: "no name anywhere uses default", param: "", wantName: DefaultListenerName},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			store := &recordingFlowStore{}
			rec := buildPipelineDropRecorder(store, tt.param, silentLogger(), newBlockedStreamSet())
			ctx := connector.ContextWithClientAddr(context.Background(), "127.0.0.1:7000")
			if tt.ctxName != "" {
				ctx = connector.ContextWithListenerName(ctx, tt.ctxName)
			}
			rec(ctx, &envelope.Envelope{
				StreamID: "s1", Protocol: envelope.ProtocolHTTP, Direction: envelope.Send,
				Message: &envelope.HTTPMessage{Method: "GET", Scheme: "http", Path: "/"},
			}, pipeline.BlockedByTargetScope)
			if len(store.saved) != 1 {
				t.Fatalf("SaveStream count = %d, want 1", len(store.saved))
			}
			if got := store.saved[0].ListenerName; got != tt.wantName {
				t.Errorf("ListenerName = %q, want %q", got, tt.wantName)
			}
		})
	}
}

func TestBuildTLSStackBuildErrorRecorder_StampsListenerName(t *testing.T) {
	store := &recordingFlowStore{}
	rec := buildTLSStackBuildErrorRecorder(store, nil, "worker-a", nil, silentLogger())
	ctx := connector.ContextWithClientAddr(context.Background(), "127.0.0.1:7000")
	rec(ctx, "example.test:443", errors.New("tls: handshake failure"))
	if len(store.saved) != 1 {
		t.Fatalf("SaveStream count = %d, want 1", len(store.saved))
	}
	if got := store.saved[0].ListenerName; got != "worker-a" {
		t.Errorf("ListenerName = %q, want worker-a", got)
	}
}

func TestRequestHeadRecorder_StampsListenerName(t *testing.T) {
	store := &headRecStore{}
	rec := buildRequestHeadRecorder(store, nil, "worker-a", silentLogger())
	rec(context.Background(), requestHeadFailure{
		ConnID: "conn-1", ClientAddr: "127.0.0.1:5555", Target: "example.test:443", Head: timeoutHead(),
	})
	streams, _ := store.snapshot()
	if len(streams) != 1 {
		t.Fatalf("streams = %d, want 1", len(streams))
	}
	if got := streams[0].ListenerName; got != "worker-a" {
		t.Errorf("ListenerName = %q, want worker-a", got)
	}
	if got := streams[0].Tags["listener"]; got != "worker-a" {
		t.Errorf("tags[listener] = %q, want worker-a (back-compat)", got)
	}
}

func TestPassthroughRecorder_StampsListenerNameAndUpstreamProxy(t *testing.T) {
	store := &passthroughRecordingStore{}
	r := newPassthroughRecorder(store, "worker-a", silentLogger(), nil)
	obs := connector.PassthroughObservation{
		SNI:           "example.com",
		RemoteAddr:    "192.0.2.1:55555",
		UpstreamAddr:  "127.0.0.1:3128",
		UpstreamProxy: "http://127.0.0.1:3128",
	}
	r.OnStart(context.Background(), obs)

	// Dial failure path (no OnStart).
	failed := connector.PassthroughObservation{
		SNI:        "down.example",
		RemoteAddr: "192.0.2.1:55556",
		Outcome:    envelope.TLSHandshakeOutcomeFailed,
	}
	r.OnComplete(context.Background(), failed)

	streams, _, _ := store.snapshot()
	if len(streams) != 2 {
		t.Fatalf("streams = %d, want 2", len(streams))
	}
	for i, st := range streams {
		if st.ListenerName != "worker-a" {
			t.Errorf("stream[%d].ListenerName = %q, want worker-a", i, st.ListenerName)
		}
	}
	if ci := streams[0].ConnInfo; ci == nil || ci.UpstreamProxy != "http://127.0.0.1:3128" {
		t.Errorf("OnStart ConnInfo = %+v, want UpstreamProxy http://127.0.0.1:3128", ci)
	}
}

func TestConnectionRejections_StampsListenerName(t *testing.T) {
	store := &recordingFlowStore{}
	c := NewConnectionRejections(ConnectionRejectionsConfig{Store: store, Logger: silentLogger()})
	t.Cleanup(c.Close)

	info := connectReject(1, "example.com:443")
	info.Listener = "worker-a"
	info.At = time.Now()
	c.Record(info)

	streams := waitForStreams(t, store, 1)
	if got := streams[0].ListenerName; got != "worker-a" {
		t.Errorf("ListenerName = %q, want worker-a", got)
	}
	if got := streams[0].Tags["listener"]; got != "worker-a" {
		t.Errorf("tags[listener] = %q, want worker-a (back-compat)", got)
	}
}
