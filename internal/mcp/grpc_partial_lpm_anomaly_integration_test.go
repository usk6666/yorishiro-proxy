//go:build e2e && !e2e_smoke

// USK-1254 MCP acceptance: an incomplete gRPC LPM recorded through the
// production wiring (proxybuild Manager + gRPC TCP forward listener +
// SQLite store) is retrievable through the `query` tool with
// filter.wire_level="grpc-lpm-frame", carries its typed anomaly in
// metadata and in the flows-level anomalies rollup, and stays hidden from
// the default semantic view.
//
// Tagged `e2e && !e2e_smoke`: spins up a full proxybuild Manager, so it
// belongs in the nightly full tier.
package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// startH2CTruncatedLPMUpstream starts an h2c upstream that answers every
// request with a gRPC response whose only LPM declares 64 bytes but
// carries 10, then ends the stream without trailers.
func startH2CTruncatedLPMUpstream(t *testing.T, wire []byte) string {
	t.Helper()
	var protocols http.Protocols
	protocols.SetUnencryptedHTTP2(true)
	srv := &http.Server{
		Protocols: &protocols,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.Copy(io.Discard, r.Body)
			w.Header().Set("Content-Type", "application/grpc")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(wire)
			w.(http.Flusher).Flush()
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("upstream listen: %v", err)
	}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

// waitForPartialLPMRow polls the store until a Receive grpc-lpm-frame row
// carrying grpc_anomaly_lpm_truncated exists and returns its stream ID.
func waitForPartialLPMRow(t *testing.T, store flow.Store) string {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		streams, err := store.ListStreams(ctx, flow.StreamListOptions{Protocol: "grpc"})
		if err == nil {
			for _, st := range streams {
				rows, ferr := store.GetFlows(ctx, st.ID, flow.FlowListOptions{
					Direction: "receive",
					WireLevel: flow.WireLevelGRPCLPMFrame,
				})
				if ferr != nil {
					continue
				}
				for _, r := range rows {
					if _, ok := r.Metadata["grpc_anomaly_lpm_truncated"]; ok {
						return st.ID
					}
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("no receive grpc-lpm-frame row with grpc_anomaly_lpm_truncated was recorded")
	return ""
}

func decodeQueryBody(t *testing.T, body, enc string) []byte {
	t.Helper()
	if enc == "base64" {
		b, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			t.Fatalf("decode base64 body: %v", err)
		}
		return b
	}
	return []byte(body)
}

// T10.
func TestQuery_GRPCPartialLPMAnomaly_ProductionWiring(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	prefix := make([]byte, 5)
	binary.BigEndian.PutUint32(prefix[1:5], 64)
	wire := append(prefix, []byte("0123456789")...)

	store := newTestStore(t)
	upAddr := startH2CTruncatedLPMUpstream(t, wire)
	mgr, fwdAddr := startGRPCForwardListener(t, ctx, store, upAddr)
	defer mgr.StopAll(context.Background())

	cc, err := grpc.NewClient(fwdAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.ForceCodec(listenerCaptureRawCodec{})),
	)
	if err != nil {
		t.Fatalf("grpc.NewClient: %v", err)
	}
	defer cc.Close()
	req := []byte("hi")
	var resp []byte
	if err := cc.Invoke(ctx, "/svc.S/M", &req, &resp); err == nil {
		t.Fatalf("Invoke succeeded; want an error (upstream response LPM is truncated)")
	}

	streamID := waitForPartialLPMRow(t, store)
	cs := setupListenerCaptureMCPSession(t, store)

	// resource=messages with the overlay filter returns the anomaly row.
	res := queryCallTool(t, cs, map[string]any{
		"resource": "messages",
		"id":       streamID,
		"filter":   map[string]any{"wire_level": flow.WireLevelGRPCLPMFrame},
	})
	if res.IsError {
		t.Fatalf("query messages error: %s", extractTextContent(res))
	}
	var msgs queryMessagesResult
	if err := json.Unmarshal([]byte(extractTextContent(res)), &msgs); err != nil {
		t.Fatalf("unmarshal messages: %v", err)
	}
	var found *queryMessageEntry
	for i := range msgs.Messages {
		if _, ok := msgs.Messages[i].Metadata["grpc_anomaly_lpm_truncated"]; ok {
			found = &msgs.Messages[i]
		}
	}
	if found == nil {
		t.Fatalf("no message with grpc_anomaly_lpm_truncated; messages=%+v", msgs.Messages)
	}
	if found.WireLevel != flow.WireLevelGRPCLPMFrame {
		t.Errorf("wire_level = %q, want %q", found.WireLevel, flow.WireLevelGRPCLPMFrame)
	}
	if found.Direction != "receive" {
		t.Errorf("direction = %q, want receive", found.Direction)
	}
	if got := found.Metadata["grpc_anomaly_lpm_truncated"]; got != "declared=64 observed=10" {
		t.Errorf("grpc_anomaly_lpm_truncated = %q, want %q", got, "declared=64 observed=10")
	}
	// USK-1344: the overlay row has no L7 body; its frame bytes are in
	// raw_bytes (base64), never in body.
	if found.Body != "" {
		t.Errorf("message body = %q, want empty (overlay frame bytes belong in raw_bytes)", found.Body)
	}
	if found.RawBytesEncoding != "base64" {
		t.Errorf("raw_bytes_encoding = %q, want base64", found.RawBytesEncoding)
	}
	if got := decodeQueryBody(t, found.RawBytes, found.RawBytesEncoding); !bytes.Equal(got, wire) {
		t.Errorf("message raw_bytes = %x, want %x", got, wire)
	}
	if found.BodyDecoded != "" || found.BodyDecodeAnomaly != nil {
		t.Errorf("body_decoded = %q / anomaly %+v; the raw-bytes row must not be proto-decoded", found.BodyDecoded, found.BodyDecodeAnomaly)
	}

	// resource=flows with the overlay filter rolls the anomaly up.
	flowsAnomalies := func(filter map[string]any) []queryAnomaly {
		t.Helper()
		args := map[string]any{"resource": "flows"}
		if filter != nil {
			args["filter"] = filter
		}
		r := queryCallTool(t, cs, args)
		if r.IsError {
			t.Fatalf("query flows error: %s", extractTextContent(r))
		}
		var fr queryFlowsResult
		if err := json.Unmarshal([]byte(extractTextContent(r)), &fr); err != nil {
			t.Fatalf("unmarshal flows: %v", err)
		}
		for _, e := range fr.Flows {
			if e.ID == streamID {
				return e.Anomalies
			}
		}
		t.Fatalf("stream %s missing from flows result", streamID)
		return nil
	}
	hasTruncated := func(as []queryAnomaly) bool {
		for _, a := range as {
			if a.Type == "GRPCLPMTruncated" {
				return true
			}
		}
		return false
	}
	if as := flowsAnomalies(map[string]any{"wire_level": flow.WireLevelGRPCLPMFrame}); !hasTruncated(as) {
		t.Errorf("flows anomalies (wire_level=grpc-lpm-frame) = %+v, want an entry with type GRPCLPMTruncated", as)
	}
	// Default semantic view hides the overlay row and its anomaly.
	if as := flowsAnomalies(nil); hasTruncated(as) {
		t.Errorf("flows anomalies (default semantic) = %+v, want no GRPCLPMTruncated (overlay-only)", as)
	}
}
