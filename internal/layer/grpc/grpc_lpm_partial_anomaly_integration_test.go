//go:build e2e && !e2e_smoke

package grpc_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// USK-1254 e2e: an LPM the gRPC Layer cannot complete — declared length
// over the message-size cap (case 2) or cut short by END_STREAM (case 3) —
// is recorded as a wire_level=grpc-lpm-frame row carrying the observed
// bytes and a typed grpc_anomaly_* Metadata key. Recording only: what the
// client and the upstream observe is pinned by characterization asserts
// that hold both before and after the change.
//
// e2e Subsystem Verification Checklist coverage (CLAUDE.md):
//   - Stream recording / state: the Stream ends in State="error".
//   - Flow recording + Raw bytes: the overlay row's RawBytes are the
//     incomplete LPM's wire bytes, verbatim.
//   - Error paths: both directions, both cases.
//   - Forwarding unchanged: client-observed outcome and upstream-observed
//     body bytes are asserted.
// MCP query integration lives in internal/mcp
// (grpc_partial_lpm_anomaly_integration_test.go).

// partialLPMOptFn installs the production LPM record Option plus an
// optional per-Channel message-size cap on every grpclayer.Wrap.
func partialLPMOptFn(maxMsg uint32) func(*pipeline.Pipeline, string) []grpclayer.Option {
	return func(p *pipeline.Pipeline, sessionStreamID string) []grpclayer.Option {
		opts := []grpclayer.Option{
			session.GRPCLPMRecordOption(context.Background(), p, sessionStreamID, envelope.EnvelopeContext{}),
		}
		if maxMsg > 0 {
			opts = append(opts, grpclayer.WithMaxMessageSize(maxMsg))
		}
		return opts
	}
}

// lpmPrefixBytes builds a 5-byte LPM prefix.
func lpmPrefixBytes(flag byte, declared uint32) []byte {
	p := make([]byte, 5)
	p[0] = flag
	binary.BigEndian.PutUint32(p[1:5], declared)
	return p
}

// waitForAnomalyLPMFlow polls until a grpc-lpm-frame flow in dir carries
// metadata key anomalyKey.
func waitForAnomalyLPMFlow(t *testing.T, store *testStore, streamID, dir, anomalyKey string, timeout time.Duration) *flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		for _, f := range lpmFlowsForStream(store, streamID, dir) {
			if _, ok := f.Metadata[anomalyKey]; ok {
				return f
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: no %s grpc-lpm-frame flow with %q for stream %s; lpm flows=%d",
		dir, anomalyKey, streamID, len(lpmFlowsForStream(store, streamID, dir)))
	return nil
}

// startRawH2Upstream starts a TLS (ALPN h2) net/http upstream running h.
func startRawH2Upstream(t *testing.T, h http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewUnstartedServer(h)
	srv.EnableHTTP2 = true
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

// bodyCountingUpstream returns a handler that reports how many request
// body bytes it read before the body ended (EOF or reset).
func bodyCountingUpstream(got chan<- int64) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		select {
		case got <- n:
		default:
		}
	}
}

// newTunnelH2Transport returns an x/net HTTP/2 Transport that reaches
// target through the MITM proxy's CONNECT tunnel.
func newTunnelH2Transport(proxyAddr, target string) *xhttp2.Transport {
	return &xhttp2.Transport{
		DialTLSContext: func(ctx context.Context, _, _ string, _ *tls.Config) (net.Conn, error) {
			raw, err := connectTunnelDialer(proxyAddr, target)
			if err != nil {
				return nil, err
			}
			tc := tls.Client(raw, &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec // test
				NextProtos:         []string{"h2"},
				ServerName:         "localhost",
			})
			if err := tc.HandshakeContext(ctx); err != nil {
				_ = raw.Close()
				return nil, err
			}
			return tc, nil
		},
	}
}

// newGRPCPost builds a gRPC-shaped POST request to target.
func newGRPCPost(ctx context.Context, t *testing.T, target string, body io.Reader) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+target+"/svc.S/M", body)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	return req
}

// requireUpstreamReadZero waits for the upstream handler's body count and
// asserts the partial LPM bytes were never forwarded.
func requireUpstreamReadZero(t *testing.T, got <-chan int64) {
	t.Helper()
	select {
	case n := <-got:
		if n != 0 {
			t.Errorf("upstream read %d request body bytes, want 0 (the partial LPM is never forwarded)", n)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("upstream handler never finished reading the request body")
	}
}

// requireClientRSTInternal asserts the client observed RST_STREAM
// INTERNAL_ERROR from the proxy.
func requireClientRSTInternal(t *testing.T, err error) {
	t.Helper()
	var se xhttp2.StreamError
	if !errors.As(err, &se) {
		t.Fatalf("client RoundTrip err = %v (%T), want http2.StreamError", err, err)
	}
	if se.Code != xhttp2.ErrCodeInternal {
		t.Errorf("client RST_STREAM code = %v, want INTERNAL_ERROR", se.Code)
	}
}

// T7: Receive case 3 — the upstream sends a prefix declaring 64 bytes,
// 10 payload bytes, then ends the stream without trailers.
func TestGRPCLPMPartialAnomaly_ReceiveTruncated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	wire := append(lpmPrefixBytes(0, 64), []byte("0123456789")...)
	upAddr := startRawH2Upstream(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(wire)
		w.(http.Flusher).Flush()
	})

	ca, issuer := makeCA(t)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: partialLPMOptFn(0),
	})

	cc := dialGRPCViaProxy(ctx, t, proxyAddr, upAddr)
	defer cc.Close()

	var resp []byte
	req := []byte("hi")
	err := cc.Invoke(ctx, "/svc.S/M", &req, &resp)
	// The truncated LPM is a proxy-local failure (the gRPC wrapper's own
	// "stream ended mid-LPM" error; the upstream sent no RST_STREAM), so
	// there is no upstream reset code to relay (USK-1269) and CANCEL is the
	// intended client reset, which grpc-go surfaces as codes.Canceled.
	if got := status.Code(err); got != codes.Canceled {
		t.Errorf("client status = %v (err=%v), want %v (pre-USK-1254 characterization)", got, err, codes.Canceled)
	}

	st := firstGRPCStream(t, store, 5*time.Second)
	f := waitForAnomalyLPMFlow(t, store, st.ID, "receive", "grpc_anomaly_lpm_truncated", 5*time.Second)
	if !bytes.Equal(f.RawBytes, wire) {
		t.Errorf("anomaly row RawBytes = %x, want %x (observed bytes verbatim)", f.RawBytes, wire)
	}
	if got := f.Metadata["grpc_anomaly_lpm_truncated"]; got != "declared=64 observed=10" {
		t.Errorf("grpc_anomaly_lpm_truncated = %q, want %q", got, "declared=64 observed=10")
	}
	if len(f.Body) != 0 {
		t.Errorf("anomaly row Body = %x, want empty", f.Body)
	}
	waitForStreamState(t, store, st.ID, "error", 5*time.Second)
}

// T8: Send case 2 + forwarding unchanged — the client sends a prefix
// declaring 1000 bytes (cap 64) plus 8 payload bytes and keeps the body
// open.
func TestGRPCLPMPartialAnomaly_SendTooLarge(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upGot := make(chan int64, 1)
	upAddr := startRawH2Upstream(t, bodyCountingUpstream(upGot))

	ca, issuer := makeCA(t)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: partialLPMOptFn(64),
	})

	tr := newTunnelH2Transport(proxyAddr, upAddr)
	defer tr.CloseIdleConnections()

	pr, pw := io.Pipe()
	defer pw.Close()
	wire := append(lpmPrefixBytes(0, 1000), []byte("abcdefgh")...)
	go func() { _, _ = pw.Write(wire) }()

	resp, err := tr.RoundTrip(newGRPCPost(ctx, t, upAddr, pr))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("RoundTrip succeeded with status %d; want RST_STREAM INTERNAL_ERROR", resp.StatusCode)
	}
	// Forwarding characterization (passes before and after USK-1254).
	requireClientRSTInternal(t, err)
	requireUpstreamReadZero(t, upGot)

	st := firstGRPCStream(t, store, 5*time.Second)
	f := waitForAnomalyLPMFlow(t, store, st.ID, "send", "grpc_anomaly_lpm_too_large", 5*time.Second)
	if !bytes.Equal(f.RawBytes, wire) {
		t.Errorf("anomaly row RawBytes = %x, want %x (prefix + the 8 observed payload bytes)", f.RawBytes, wire)
	}
	if got := f.Metadata["grpc_anomaly_lpm_too_large"]; got != "declared=1000 cap=64 captured=8" {
		t.Errorf("grpc_anomaly_lpm_too_large = %q, want %q", got, "declared=1000 cap=64 captured=8")
	}
	if got := f.Metadata["grpc_wire_length"]; got != "1000" {
		t.Errorf("grpc_wire_length = %q, want 1000 (declared)", got)
	}
	waitForStreamState(t, store, st.ID, "error", 5*time.Second)
}

// T9: Send case 3 — the client sends a prefix declaring 10 bytes, 4
// payload bytes, then ends the request body.
func TestGRPCLPMPartialAnomaly_SendTruncated(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upGot := make(chan int64, 1)
	upAddr := startRawH2Upstream(t, bodyCountingUpstream(upGot))

	ca, issuer := makeCA(t)
	proxyAddr, store := startGRPCMITMProxy(t, ctx, ca, issuer, pipelineOpts{
		extraGRPCOptionsFn: partialLPMOptFn(0),
	})

	tr := newTunnelH2Transport(proxyAddr, upAddr)
	defer tr.CloseIdleConnections()

	wire := append(lpmPrefixBytes(0, 10), []byte("wxyz")...)
	resp, err := tr.RoundTrip(newGRPCPost(ctx, t, upAddr, bytes.NewReader(wire)))
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("RoundTrip succeeded with status %d; want RST_STREAM INTERNAL_ERROR", resp.StatusCode)
	}
	// Forwarding characterization (passes before and after USK-1254).
	requireClientRSTInternal(t, err)
	requireUpstreamReadZero(t, upGot)

	st := firstGRPCStream(t, store, 5*time.Second)
	f := waitForAnomalyLPMFlow(t, store, st.ID, "send", "grpc_anomaly_lpm_truncated", 5*time.Second)
	if !bytes.Equal(f.RawBytes, wire) {
		t.Errorf("anomaly row RawBytes = %x, want %x", f.RawBytes, wire)
	}
	if got := f.Metadata["grpc_anomaly_lpm_truncated"]; got != "declared=10 observed=4" {
		t.Errorf("grpc_anomaly_lpm_truncated = %q, want %q", got, "declared=10 observed=4")
	}
	waitForStreamState(t, store, st.ID, "error", 5*time.Second)
}
