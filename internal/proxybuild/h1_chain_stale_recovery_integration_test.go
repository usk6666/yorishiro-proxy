//go:build e2e && !e2e_smoke

package proxybuild

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// TestHTTP1StaleConnRecovery_AfterIdleClose simulates the live USK-998
// bug: an upstream HTTPS server closes its keep-alive connection during
// idle (matching the Apache / nginx Keep-Alive: timeout=N expiry); the
// proxy's parser goroutine parks on pendingNotify with pendingQ empty
// and never observes the FIN; the next request's Write hits EPIPE in
// the legacy code path.
//
// With USK-998's h1Chain + RedialUpstreamH1 wired into the dial
// closure, the next exchange's EnsureFresh detects the stale state
// via HealthCheck and transparently redials. The integration test
// asserts:
//
//  1. The first request succeeds.
//  2. The upstream then closes the keep-alive conn during idle.
//  3. EnsureFresh detects the stale state via HealthCheck.
//  4. A fresh dial succeeds; the second request lands on the new conn.
//  5. The chain's len(layers) advanced to 2 (original + redial step).
//  6. The fresh Layer's EnvelopeContext carries the redial label.
//
// This exercises the integration surface of HealthCheck → RedialUpstreamH1
// → h1Chain → Layer-construction-time options. The full proxybuild
// data-path stack (Pipeline / RecordStep / flow store) is exercised by
// the canonical mitm_integration_test.go harness; this test focuses on
// the staleness-recovery loop itself.
//
// The upstream is a real TLS listener (matching production CONNECT-MITM
// where the upstream-facing wire is always TLS); cfg uses
// InsecureSkipVerify for the self-signed test cert.
func TestHTTP1StaleConnRecovery_AfterIdleClose(t *testing.T) {
	cert := generateSelfSignedCert(t)
	tlsCfg := &tls.Config{Certificates: []tls.Certificate{cert}}

	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer ln.Close()

	var gotReqs atomic.Int32
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				_ = req.Body.Close()
				resp := "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: keep-alive\r\n\r\nOK"
				_, _ = c.Write([]byte(resp))
				gotReqs.Add(1)
				// Close eagerly to simulate Keep-Alive: timeout
				// expiry on the upstream side. The peer FIN is
				// invisible to the proxy's http1.Layer parser
				// (parked on pendingNotify); HealthCheck must
				// surface it on the next EnsureFresh.
				time.Sleep(50 * time.Millisecond)
			}(c)
		}
	}()

	target := ln.Addr().String()

	// BuildConfig with InsecureSkipVerify so the self-signed cert
	// passes the redial dial. We resolve per-host via a synthetic
	// PerHostTLS entry so RedialUpstreamH1's resolvePerHostTLS finds
	// the insecure-skip flag.
	cfg := buildTestBuildConfig(target)

	// Initial Layer is constructed by dialing once through the same
	// helper the chain uses on redial (so the test exercises real TLS
	// for both legs, matching the production CONNECT-MITM shape).
	envCtxTmpl := envelope.EnvelopeContext{
		ConnID:     "test-conn-998",
		TargetHost: target,
	}
	initial, err := dialInitialUpstream(t, target, cfg, envCtxTmpl)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}
	defer initial.Close()

	chain := newH1Chain(initial, target, cfg)
	defer chain.closeAll()

	// First exchange: HealthCheck on a freshly dialed conn returns
	// alive; EnsureFresh returns the initial Layer.
	got1, err := chain.EnsureFresh(context.Background())
	if err != nil {
		t.Fatalf("first EnsureFresh: %v", err)
	}
	if got1 != initial {
		t.Fatalf("first EnsureFresh returned a redial; expected the original Layer")
	}

	// Send the first request.
	if err := sendRequestAndDrain(got1, target); err != nil {
		t.Fatalf("first request: %v", err)
	}

	// Wait for the upstream to close (the server goroutine closes
	// after responding + a small sleep). Then a second EnsureFresh
	// must observe the stale state and redial.
	deadline := time.Now().Add(3 * time.Second)
	var got2 *http1.Layer
	for time.Now().Before(deadline) {
		got2, err = chain.EnsureFresh(context.Background())
		if err != nil {
			t.Fatalf("second EnsureFresh: %v", err)
		}
		if got2 != initial {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if got2 == initial {
		t.Fatal("second EnsureFresh never redialed; HealthCheck did not surface the idle FIN")
	}

	// Second request lands on the fresh Layer.
	if err := sendRequestAndDrain(got2, target); err != nil {
		t.Fatalf("second request on redialed Layer: %v", err)
	}

	if got := gotReqs.Load(); got < 2 {
		t.Fatalf("upstream got %d requests, want >= 2", got)
	}

	// Chain bookkeeping: the original + redial step both retained for
	// closeAll on CONNECT exit.
	if got := len(chain.layers); got != 2 {
		t.Errorf("chain.layers length = %d, want 2 (original + 1 redial)", got)
	}

	// EnvelopeContext continuity: the fresh Layer's template carries
	// the SAME ConnID as the stale (so the CONNECT's wire-log story
	// stays unified across redial steps — the redial-label suffix is
	// applied to the Layer's diagnostic streamID, not the envelope
	// ConnID; mirrors the h2 redial chain's wire-log shape).
	freshCtx := got2.EnvelopeContextTemplate()
	if freshCtx.ConnID != "test-conn-998" {
		t.Errorf("fresh Layer envCtx ConnID = %q, want %q (continuity)", freshCtx.ConnID, "test-conn-998")
	}
	if freshCtx.TargetHost != target {
		t.Errorf("fresh Layer TargetHost = %q, want %q", freshCtx.TargetHost, target)
	}
}

// dialInitialUpstream constructs the initial upstream Layer by going
// through the same dial path the redial uses — keeps the integration
// test honest (the test fails the same way the production redial would
// if RedialUpstreamH1 ever diverged).
//
// Test-only quirk: the bootstrap reuses RedialUpstreamH1, which stamps
// the produced Layer's streamID with the redial-label suffix
// (`/upstream-redial`). The test's assertions are scoped to the
// EnvelopeContext template (ConnID / TargetHost set via
// WithEnvelopeContext), not the streamID, so this does not affect
// correctness — but production callers should not use generation==0 on
// a real initial dial path; that branch is reserved for the chain's
// own bootstrap-via-redial pattern in this test harness.
func dialInitialUpstream(t *testing.T, target string, cfg *connector.BuildConfig, envCtxTmpl envelope.EnvelopeContext) (*http1.Layer, error) {
	t.Helper()
	stale := http1.New(nopConn{}, "stream-998-bootstrap", envelope.Receive,
		http1.WithEnvelopeContext(envCtxTmpl),
	)
	defer stale.Close()
	return connector.RedialUpstreamH1(context.Background(), target, stale, cfg, 0)
}

// buildTestBuildConfig returns a BuildConfig that lets the redial
// helper accept the test's self-signed TLS cert via the boot-time
// InsecureSkipVerify fallback.
func buildTestBuildConfig(_ string) *connector.BuildConfig {
	return &connector.BuildConfig{
		InsecureSkipVerify: true,
	}
}

// sendRequestAndDrain writes a minimal GET via the upstream Layer's
// per-exchange Channel and waits for the response Envelope to verify
// the round trip landed on the wire.
func sendRequestAndDrain(l *http1.Layer, target string) error {
	upCh := l.OpenExchange()
	if upCh == nil {
		return errors.New("OpenExchange returned nil")
	}

	reqMsg := &envelope.HTTPMessage{
		Method:    "GET",
		Scheme:    "https",
		Authority: target,
		Path:      "/",
		Headers: []envelope.KeyValue{
			{Name: "Host", Value: target},
			{Name: "User-Agent", Value: "usk-998-test"},
		},
	}
	reqEnv := &envelope.Envelope{
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Send,
		Message:   reqMsg,
	}
	if err := upCh.Send(context.Background(), reqEnv); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := upCh.Next(ctx)
	_ = upCh.Close()
	return err
}

// generateSelfSignedCert produces a throwaway ECDSA cert good enough
// for the in-process TLS listener used by this test.
func generateSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ECDSA generate: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"127.0.0.1"},
		IsCA:         true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	return tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
}

// nopConn is a placeholder net.Conn used so we can construct a stale
// *http1.Layer purely as a carrier for an EnvelopeContext template.
// The test never reads / writes through it; the bootstrap Layer is
// Closed immediately after RedialUpstreamH1 returns.
type nopConn struct{}

func (nopConn) Read([]byte) (int, error)         { return 0, errors.New("nopConn") }
func (nopConn) Write([]byte) (int, error)        { return 0, errors.New("nopConn") }
func (nopConn) Close() error                     { return nil }
func (nopConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (nopConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (nopConn) SetDeadline(time.Time) error      { return nil }
func (nopConn) SetReadDeadline(time.Time) error  { return nil }
func (nopConn) SetWriteDeadline(time.Time) error { return nil }
