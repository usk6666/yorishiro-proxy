//go:build e2e && !e2e_smoke

package grpcweb_test

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1199: grpc-web-text over HTTP/1.1. The grpcweb Layer fires the
// wire_level=grpcweb-base64 overlay (Message=nil) before it decodes the
// body and emits GRPCStart, so the overlay is the stream's first Send
// envelope and RecordStep caches its capture_scope decision on it. The
// decision must match what the semantic GRPCStart would decide.
//
// Drives the real FullListener → CONNECT → TLS → http1 Layer → grpcweb
// Layer → RecordStep path (startGRPCWebHTTP1ProxyBase64), with a
// RecordScope installed on RecordStep.
func TestGRPCWebBase64Recording_CaptureScopeHTTP1Text(t *testing.T) {
	cases := []struct {
		name       string
		includes   []flow.ScopeRule
		excludes   []flow.ScopeRule
		wantRecord bool
	}{
		{name: "include url_prefix records", includes: []flow.ScopeRule{{URLPrefix: "/pkg.Echo/"}}, wantRecord: true},
		{name: "include method POST records", includes: []flow.ScopeRule{{Method: "POST"}}, wantRecord: true},
		{name: "exclude method POST does not record", excludes: []flow.ScopeRule{{Method: "POST"}}, wantRecord: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			upstreamLn, _ := startGRPCWebHTTP1Upstream(t, func(_ []byte) []byte {
				return buildGRPCWebResponseHTTP([]byte("scope-ok"), 0, "OK", true /* base64 */)
			})
			defer upstreamLn.Close()
			target := upstreamLn.Addr().String()

			scope := flow.NewRecordScope()
			scope.SetRules(tc.includes, tc.excludes)
			proxyAddr, store, sessionDone := startGRPCWebHTTP1ProxyBase64(t, ctx, pipelineOptsBase64{
				installBase64Callback: true,
				recordOpts:            []pipeline.Option{pipeline.WithRecordScope(scope)},
			})

			_ = sendGRPCWebHTTP1Request(t, proxyAddr, target, []byte("ping-scope"), true /* base64 */)

			select {
			case <-sessionDone:
			case <-time.After(15 * time.Second):
				t.Fatal("timeout waiting for session to complete")
			}

			store.mu.Lock()
			streams := len(store.streams)
			protocolByID := make(map[string]string, len(store.streams))
			for _, st := range store.streams {
				protocolByID[st.ID] = st.Protocol
			}
			var semantic, overlay int
			semanticStream := ""
			for _, f := range store.flows {
				switch f.WireLevel {
				case "", flow.WireLevelSemantic:
					semantic++
					semanticStream = f.StreamID
				case flow.WireLevelGRPCWebBase64:
					overlay++
				}
			}
			store.mu.Unlock()

			if !tc.wantRecord {
				if streams != 0 || semantic != 0 || overlay != 0 {
					t.Errorf("recorded streams=%d semantic=%d grpcweb-base64=%d, want none", streams, semantic, overlay)
				}
				return
			}
			// The stream-count is deliberately not asserted: on the
			// HTTP/1.x path the base64 overlay is keyed to the http1
			// Layer's connection-level StreamID rather than the
			// exchange's StreamID (pre-existing, outside USK-1199), so
			// overlay and semantic rows land on two Stream rows.
			if got := protocolByID[semanticStream]; got != string(envelope.ProtocolGRPCWeb) {
				t.Errorf("semantic Stream.Protocol = %q, want %q", got, envelope.ProtocolGRPCWeb)
			}
			if semantic == 0 {
				t.Errorf("no semantic gRPC-Web flows recorded")
			}
			if overlay == 0 {
				t.Errorf("no grpcweb-base64 overlay flows recorded")
			}
		})
	}
}
