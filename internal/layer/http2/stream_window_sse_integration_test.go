//go:build e2e && !e2e_smoke

package http2_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	nethttp "net/http"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
	sserules "github.com/usk6666/yorishiro-proxy/internal/rules/sse"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// TestStreamWindow_HeldSSEEventDoesNotStallSharedUpstream (USK-1399
// acceptance 2): an SSE-over-h2 stream whose first event is held by an
// Intercept rule stops reading its upstream stream; the other stream on the
// same upstream h2 connection must still complete.
//
// Upstream: x/net http2 server. /sse flushes 64 events (one DATA frame
// each) and keeps the stream open; /fast answers immediately. Both requests
// go over one client connection, hence one CONNECT tunnel and one upstream
// h2 connection.
func TestStreamWindow_HeldSSEEventDoesNotStallSharedUpstream(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	flushed := make(chan struct{})
	stop := make(chan struct{})
	var stopOnce sync.Once
	stopUpstream := func() { stopOnce.Do(func() { close(stop) }) }
	defer stopUpstream()

	upAddr, _, _, upShutdown := startH2TLSUpstream(t, "sse-window-up",
		nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
			switch r.URL.Path {
			case "/sse":
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(nethttp.StatusOK)
				fl := w.(nethttp.Flusher)
				fl.Flush()
				for i := 0; i < 64; i++ {
					fmt.Fprintf(w, "data: event-%d\n\n", i)
					fl.Flush()
				}
				close(flushed)
				select {
				case <-r.Context().Done():
				case <-stop:
				}
			default:
				_, _ = w.Write([]byte("fast-ok"))
			}
		}))
	defer upShutdown()

	engine := sserules.NewInterceptEngine()
	rule, err := sserules.CompileInterceptRule("hold-first", "", "", "", "^event-0$", nil, nil, nil)
	if err != nil {
		t.Fatalf("compile rule: %v", err)
	}
	engine.AddRule(*rule)
	queue := common.NewHoldQueue()
	defer func() {
		for _, e := range queue.List() {
			_ = queue.Release(e.ID, &common.HoldAction{Type: common.ActionRelease})
		}
	}()

	proxyAddr := startH2MITMProxyWithSSEIntercept(t, ctx, engine, queue)
	cli := newMITMH2Client(proxyAddr, upAddr)
	defer cli.CloseIdleConnections()

	sseCtx, sseCancel := context.WithCancel(ctx)
	defer sseCancel()
	go func() {
		req, _ := nethttp.NewRequestWithContext(sseCtx, "GET", "https://"+upAddr+"/sse", nil)
		resp, rerr := cli.Do(req)
		if rerr != nil {
			return
		}
		defer resp.Body.Close()
		_, _ = io.Copy(io.Discard, resp.Body)
	}()

	select {
	case <-flushed:
	case <-time.After(10 * time.Second):
		t.Fatal("upstream did not flush the SSE events")
	}
	deadline := time.Now().Add(10 * time.Second)
	for len(queue.List()) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("first SSE event was not held by the intercept rule")
		}
		time.Sleep(20 * time.Millisecond)
	}

	fastCtx, fastCancel := context.WithTimeout(ctx, 10*time.Second)
	defer fastCancel()
	req, _ := nethttp.NewRequestWithContext(fastCtx, "GET", "https://"+upAddr+"/fast", nil)
	resp, err := cli.Do(req)
	if err != nil {
		t.Fatalf("GET /fast on the shared upstream connection: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if err != nil || string(body) != "fast-ok" {
		t.Fatalf("GET /fast body = %q, err = %v; want %q", body, err, "fast-ok")
	}
}

// startH2MITMProxyWithSSEIntercept is startH2MITMProxy with the upgrade-aware
// session (RunStackSessionExchange + UpgradeStep) so SSE responses swap to
// the per-event SSE relay, and an SSE InterceptStep driven by engine/queue.
func startH2MITMProxyWithSSEIntercept(t *testing.T, ctx context.Context, engine *sserules.InterceptEngine, queue *common.HoldQueue) string {
	t.Helper()
	store := &testStore{}
	p := pipeline.New(
		pipeline.NewHostScopeStep(nil),
		pipeline.NewInterceptStep(nil, nil, nil, engine, queue, nil, slog.Default()),
		pipeline.NewRecordStep(store, slog.Default()),
		session.NewUpgradeStep(),
	)
	sessOpts := session.SessionOptions{
		OnComplete: func(cctx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, session.ErrClientGoneAcked) {
				state = "error"
			}
			_ = store.UpdateStream(cctx, streamID, flow.StreamUpdate{State: state})
		},
	}

	onHTTP2Stack := func(cbCtx context.Context, stack *connector.ConnectionStack, upstreamH2 *intHTTP2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
		clientL, ok := stack.ClientTopmost().(*intHTTP2.Layer)
		if !ok {
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)
		var wg sync.WaitGroup
		defer wg.Wait()
		for {
			select {
			case <-cbCtx.Done():
				return
			case clientCh, ok := <-clientL.Channels():
				if !ok {
					return
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					aggCh, derr := connector.DispatchH2Stream(cbCtx, ch, httpaggregator.RoleServer, clientLOpts, slog.Default())
					if derr != nil {
						_ = ch.Close()
						return
					}
					dial := func(dctx context.Context, env *envelope.Envelope) (layer.Channel, error) {
						upCh, oerr := upstreamH2.OpenStream(dctx)
						if oerr != nil {
							return nil, oerr
						}
						var reqProto envelope.Protocol
						if env != nil {
							reqProto = env.Protocol
						}
						return connector.WrapH2UpstreamForDispatch(upCh, reqProto, upstreamLOpts, nil, nil), nil
					}
					_ = session.RunStackSessionExchange(cbCtx, stack, aggCh, dial, p, sessOpts)
				}(clientCh)
			}
		}
	}
	onStack := func(_ context.Context, s *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		_ = s.Close()
	}

	fl := connector.NewFullListener(connector.FullListenerConfig{
		Name: "h2-mitm-sse-window",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator:   connector.NewCONNECTNegotiator(slog.Default()),
			BuildCfg:     makeBuildCfg(t, nil),
			OnStack:      onStack,
			OnHTTP2Stack: onHTTP2Stack,
			Logger:       slog.Default(),
		}),
	})
	go fl.Start(ctx) //nolint:errcheck
	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("full listener not ready")
	}
	return fl.Addr()
}
