//go:build e2e

package grpcweb_test

// USK-898 smoke tier: the HTTP/2 gRPC-Web text (base64) recording contract
// runs on every PR (USK-1213). This file owns the base64-recording harness
// (pipelineOptsBase64, the h2 proxy, the base64 flow queries); the
// exhaustive-tier siblings in grpcweb_base64_recording_integration_test.go
// (HTTP/1.1 text, binary negative, per-stream cap, malformed base64, MCP
// parity, server-streaming shape) reuse it. See that file's header for the
// bug class and the e2e Subsystem Verification Checklist coverage.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	nethttp "net/http"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// pipelineOptsBase64 customises the test Pipeline + grpcweb wraps for
// the USK-898 tests. The struct is local to this file to avoid
// extending the shared pipelineOpts.
type pipelineOptsBase64 struct {
	// recordOpts are extra RecordStep Options layered onto the canonical
	// chain. Used to inject WithGRPCWebBase64MaxPerStream for the cap
	// test.
	recordOpts []pipeline.Option

	// installBase64Callback, when true, wires the grpcweb base64 record
	// callback (USK-898) on both the client-side and upstream-side
	// grpcweb wraps via session.GRPCWebBase64RecordOption.
	installBase64Callback bool
}

func buildPipelineBase64(store flow.Writer, opts pipelineOptsBase64) *pipeline.Pipeline {
	logger := slog.Default()
	recordOpts := []pipeline.Option{
		pipeline.WithWireEncoder(envelope.ProtocolGRPCWeb, grpcweb.EncodeWireBytes),
	}
	recordOpts = append(recordOpts, opts.recordOpts...)
	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewHTTPScopeStep(nil),
		pipeline.NewSafetyStep(nil, nil, nil, logger),
		pipeline.NewTransformStep(nil, nil, nil, nil),
		pipeline.NewInterceptStep(nil, nil, nil, nil, nil, nil, logger),
		pipeline.NewRecordStep(store, logger, recordOpts...),
	}
	return pipeline.New(steps...)
}

// startGRPCWebHTTP2ProxyBase64 mirrors the HTTP/1 harness for the h2
// path. Wires session.GRPCWebBase64RecordOption into both the client-
// side and upstream-side grpcweb wraps, matching the production wiring
// in internal/proxybuild/builder.go.
func startGRPCWebHTTP2ProxyBase64(
	t *testing.T,
	ctx context.Context,
	opts pipelineOptsBase64,
) (proxyAddr string, store *testStore, sessionDone <-chan struct{}) {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)
	store = &testStore{}
	done := make(chan struct{}, 16)

	bcfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, _, _ *envelope.TLSSnapshot, target string) {
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			t.Errorf("ClientTopmost is not *http2.Layer")
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)

		var wg sync.WaitGroup
		for {
			select {
			case <-cbCtx.Done():
				wg.Wait()
				return
			case streamCh, open := <-clientL.Channels():
				if !open {
					wg.Wait()
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					defer func() {
						select {
						case done <- struct{}{}:
						default:
						}
					}()

					p := buildPipelineBase64(store, opts)
					var grpcwebOpts []grpcweb.Option
					if opts.installBase64Callback {
						flowCtx := envelope.EnvelopeContext{TargetHost: target}
						grpcwebOpts = append(grpcwebOpts,
							session.GRPCWebBase64RecordOption(ctx, p, ch.StreamID(), flowCtx),
						)
					}

					dispatched, derr := connector.DispatchH2StreamWithOpts(
						cbCtx, ch, httpaggregator.RoleServer, clientLOpts,
						slog.Default(), nil, grpcwebOpts,
					)
					if derr != nil {
						_ = ch.Close()
						return
					}
					clientCh := dispatched

					session.RunSession(cbCtx, clientCh, func(dctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
						upStream, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						aggUp := httpaggregator.Wrap(upStream, httpaggregator.RoleClient, nil, upstreamLOpts)
						return grpcweb.Wrap(aggUp, grpcweb.RoleClient, grpcwebOpts...), nil
					}, p, session.SessionOptions{
						OnComplete: func(cctx context.Context, streamID string, err error) {
							state := "complete"
							if err != nil && !errors.Is(err, io.EOF) {
								state = "error"
							}
							if streamID != "" {
								_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{
									State:         state,
									FailureReason: session.ClassifyError(err),
								})
							}
						},
					})
				}(streamCh)
			}
		}
	}

	flCfg := connector.FullListenerConfig{
		Name: "grpcweb-h2-base64",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator: connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:   bcfg,
			OnStack: func(_ context.Context, s *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
				_ = s.Close()
			},
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       slog.Default(),
		}),
	}
	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx) //nolint:errcheck // test
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("h2 full listener not ready")
	}
	return fl.Addr(), store, done
}

// base64FlowsForStream returns flows in store filtered to streamID and
// wire_level=grpcweb-base64. Optionally filtered by direction when
// dir != "".
func base64FlowsForStream(store *testStore, streamID, dir string) []*flow.Flow {
	var out []*flow.Flow
	for _, f := range store.allFlows() {
		if f == nil || f.StreamID != streamID {
			continue
		}
		if f.WireLevel != flow.WireLevelGRPCWebBase64 {
			continue
		}
		if dir != "" && f.Direction != dir {
			continue
		}
		out = append(out, f)
	}
	return out
}

// waitForBase64Flows polls the store until at least n grpcweb-base64
// flows for streamID in dir are recorded, or until timeout. Failure
// prints diagnostic counts.
func waitForBase64Flows(t *testing.T, store *testStore, streamID, dir string, n int, timeout time.Duration) []*flow.Flow {
	t.Helper()
	deadline := time.Now().Add(timeout)
	var last []*flow.Flow
	for time.Now().Before(deadline) {
		last = base64FlowsForStream(store, streamID, dir)
		if len(last) >= n {
			return last
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("timeout: want %d %s grpcweb-base64 flows for stream %s; have %d", n, dir, streamID, len(last))
	return nil
}

// firstBase64Stream returns the first recorded Stream or fails the test.
func firstBase64Stream(t *testing.T, store *testStore, timeout time.Duration) *flow.Stream {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		streams := store.getStreams()
		if len(streams) > 0 {
			return streams[0]
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("no Stream recorded within timeout")
	return nil
}

// TestGRPCWebBase64Recording_HTTP2TextUnary covers the h2 path of the
// same record contract. The production wiring in
// internal/proxybuild/builder.go threads grpcWebBase64Opt through
// DispatchH2StreamFull / WrapH2UpstreamForDispatchFull; here we
// exercise the equivalent minimal harness via
// DispatchH2StreamWithOpts.
func TestGRPCWebBase64Recording_HTTP2TextUnary(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	respPayload := []byte("hello-h2-base64")
	upAddr, upShutdown := startGRPCWebHTTP2Upstream(t, func(_ *nethttp.Request) ([]byte, string) {
		body := buildGRPCWebResponseBody(respPayload, 0, "OK", true /* base64 */)
		return body, "application/grpc-web-text+proto"
	})
	defer upShutdown()

	proxyAddr, store, done := startGRPCWebHTTP2ProxyBase64(t, ctx, pipelineOptsBase64{
		installBase64Callback: true,
	})

	status, _, _ := sendGRPCWebHTTP2Request(t, proxyAddr, upAddr, []byte("ping-h2"), true /* base64 */)
	if status != 200 {
		t.Errorf("client status = %d, want 200", status)
	}

	// Wait for at least one stream completion.
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("timeout waiting for h2 session to complete")
	}

	st := firstBase64Stream(t, store, 5*time.Second)
	if st.Protocol != string(envelope.ProtocolGRPCWeb) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, string(envelope.ProtocolGRPCWeb))
	}

	// Receive side is the load-bearing case for h2: response body is
	// base64-encoded, so the receive base64 callback must fire.
	recvBase64 := waitForBase64Flows(t, store, st.ID, "receive", 1, 5*time.Second)
	if got := len(recvBase64); got != 1 {
		t.Errorf("h2 receive base64 count = %d, want 1", got)
	}
	if got := recvBase64[0].WireLevel; got != flow.WireLevelGRPCWebBase64 {
		t.Errorf("h2 receive base64 WireLevel = %q, want %q", got, flow.WireLevelGRPCWebBase64)
	}
}
