//go:build e2e

// Shared e2e helpers for HTTP/2 connector tests. Lives at smoke tier
// (//go:build e2e) so both smoke and exhaustive tests can consume them.
//
// Hosted helpers:
//   - newWSSOverH2TestTLSConfig: TLS config with self-signed leaf and
//     ALPN=[h2]; used by the wss-over-h2 and sse-over-h2 upstream
//     fixtures.
//   - startFullListenerProxyWithH2: FullListener + CONNECT handler with
//     both an HTTP/1.x OnStack and an HTTP/2 OnHTTP2Stack callback so the
//     per-stream upgrade orchestrators (runUpgradeWSOverH2 /
//     runUpgradeSSEOverH2) reach the live data path.
//
// Originally these helpers lived in wss_over_h2_integration_test.go at
// the exhaustive tier (e2e && !e2e_smoke). USK-888 moved them here so
// the new SSE-over-h2 happy-path test (//go:build e2e) compiles in the
// smoke tier without duplicating ~150 LOC of shared scaffolding.

package connector_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// newWSSOverH2TestTLSConfig builds a TLS config with a fresh self-signed
// leaf cert and ALPN=[h2]. Used by the upstream test fixtures and by the
// MITM-issued cert when the proxy MITMs the inner TLS handshake.
func newWSSOverH2TestTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-wss-over-h2"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"test-wss-over-h2"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{certDER}, PrivateKey: key}},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
	}
}

// startFullListenerProxyWithH2 starts a FullListener + CONNECT handler
// wired with both an OnStack callback (HTTP/1.x — copy of the helper in
// full_listener_integration_test.go) and an OnHTTP2Stack callback that
// mirrors proxybuild.buildOnHTTP2Stack: per-stream DispatchH2StreamWithOpts
// + session.RunStackSessionExchange so the upgrade-aware swap paths
// (runUpgradeWSOverH2 / runUpgradeSSEOverH2) reach the live data path.
// Returns (proxyAddr, store, wg).
func startFullListenerProxyWithH2(
	t *testing.T,
	ctx context.Context,
) (string, *testStore, *sync.WaitGroup) {
	t.Helper()

	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	issuer := cert.NewIssuer(ca)

	store := &testStore{}
	wg := &sync.WaitGroup{}

	buildCfg := &connector.BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             issuer,
		InsecureSkipVerify: true,
	}
	connectNeg := connector.NewCONNECTNegotiator(slog.Default())

	steps := []pipeline.Step{
		pipeline.NewHostScopeStep(nil),
		pipeline.NewRecordStep(store, slog.Default()),
		session.NewUpgradeStep(),
	}
	p := pipeline.New(steps...)

	sessOpts := session.SessionOptions{
		OnComplete: func(cbCtx context.Context, streamID string, err error) {
			if streamID == "" {
				return
			}
			// USK-903: ErrClientGoneAcked is a graceful terminal —
			// project state=complete + AppendTags["terminated_by"]
			// ="client" so SSE-over-h2 client-cancel records as
			// state=complete (matching H/1.1 symmetry) while
			// preserving the wire-observed cancellation as a
			// queryable attribution tag. Mirrors the production
			// proxybuild.buildOnCompleteFunc contract.
			clientGone := err != nil && errors.Is(err, session.ErrClientGoneAcked)
			state := "complete"
			if err != nil && !errors.Is(err, io.EOF) && !clientGone {
				state = "error"
			}
			upd := flow.StreamUpdate{
				State:         state,
				FailureReason: session.ClassifyError(err),
			}
			if clientGone {
				upd.AppendTags = map[string]string{
					"terminated_by": "client",
				}
			}
			_ = store.UpdateStream(cbCtx, streamID, upd)
		},
	}

	onStack := func(ctx context.Context, stack *connector.ConnectionStack, _, _ *envelope.TLSSnapshot, _ string) {
		defer wg.Done()
		defer stack.Close()
		clientCh := <-stack.ClientTopmost().Channels()
		_ = session.RunSession(ctx, clientCh, func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			return <-stack.UpstreamTopmost().Channels(), nil
		}, p, sessOpts)
	}

	onHTTP2Stack := func(ctx context.Context, stack *connector.ConnectionStack, upstreamH2 *http2.Layer, _, _ *envelope.TLSSnapshot, _ string) {
		defer wg.Done()
		clientL, ok := stack.ClientTopmost().(*http2.Layer)
		if !ok {
			return
		}
		clientLOpts := httpaggregator.OptionsFromLayer(clientL)
		upstreamLOpts := httpaggregator.OptionsFromLayer(upstreamH2)

		var streamWG sync.WaitGroup
		for {
			select {
			case <-ctx.Done():
				streamWG.Wait()
				return
			case clientCh, ok := <-clientL.Channels():
				if !ok {
					streamWG.Wait()
					return
				}
				streamWG.Add(1)
				go func(ch layer.Channel) {
					defer streamWG.Done()
					aggCh, derr := connector.DispatchH2Stream(ctx, ch, httpaggregator.RoleServer, clientLOpts, slog.Default())
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
					_ = session.RunStackSessionExchange(ctx, stack, aggCh, dial, p, sessOpts)
				}(clientCh)
			}
		}
	}

	flCfg := connector.FullListenerConfig{
		Name: "test-h2-helpers",
		Addr: "127.0.0.1:0",
		OnCONNECT: connector.NewCONNECTHandler(connector.CONNECTHandlerConfig{
			Negotiator:   connectNeg,
			BuildCfg:     buildCfg,
			OnStack:      onStack,
			OnHTTP2Stack: onHTTP2Stack,
		}),
	}

	fl := connector.NewFullListener(flCfg)
	go fl.Start(ctx)

	select {
	case <-fl.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for FullListener to be ready")
	}
	return fl.Addr(), store, wg
}
