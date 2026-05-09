//go:build e2e

// USK-784: HTTPS upstream TLS handshake failures must be recorded as a
// state="error" Stream so MITM diagnostic users can audit cert / chain
// misconfigurations through the proxy.
//
// Pre-USK-784 the proxy accepted CONNECT with `200 Connection Established`,
// then silently disconnected the client when the upstream TLS handshake
// rejected the cert. The flow store ended up with 0 records for that
// authority — the same observability gap USK-188 closed for WebSocket.
//
// Each test in this file:
//   - mints a local TLS server presenting a misconfigured cert
//     (expired or self-signed) — no real network is touched, so the
//     test runs hermetically;
//   - issues a CONNECT through a real BuildLiveStack proxy;
//   - confirms the connector's CONNECT path accepted the tunnel (200);
//   - confirms the inner TLS handshake failed at the proxy (Read/Write
//     error reported to the client);
//   - asserts a state="error" Stream was persisted with the CONNECT
//     authority in Tags["target"], the underlying error in Tags["error"],
//     and FailureReason="upstream_tls_error".
//
// Smoke tier (`//go:build e2e`, no `&& !e2e_smoke`) so the parity fix is
// in the merge gate and a regression in connect_handler.go's error path
// surfaces in per-PR CI rather than nightly.
package proxybuild_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// upstreamTLSErrorStore is a minimal flow.Writer test double scoped to
// this smoke test. The exhaustive sibling (onhttp1_integration_test.go)
// has a richer flowStoreCapture but lives under
// `e2e && !e2e_smoke`, so the symbol is invisible to this smoke file.
// Duplicate the small struct rather than dragging the smoke build into
// the exhaustive-only helper file.
type upstreamTLSErrorStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
}

func (s *upstreamTLSErrorStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *upstreamTLSErrorStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (s *upstreamTLSErrorStore) SaveFlow(_ context.Context, _ *flow.Flow) error {
	return nil
}

func (s *upstreamTLSErrorStore) Streams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

// TestProxybuild_CONNECT_UpstreamTLSHandshakeFailure_RecordsErrorFlow drives
// the USK-784 acceptance criteria end to end through BuildLiveStack:
//
//   - expired upstream cert → state="error" Stream recorded;
//   - self-signed upstream cert → state="error" Stream recorded;
//   - valid upstream cert → no state="error" Stream (regression guard).
//
// Each subtest stands up an isolated BuildLiveStack so the streams from
// one case do not leak into the next. Subtests run sequentially because
// the upstream listener accepts a single connection; a fresh listener per
// scenario keeps the wire shape predictable.
func TestProxybuild_CONNECT_UpstreamTLSHandshakeFailure_RecordsErrorFlow(t *testing.T) {
	cases := []struct {
		name               string
		certBuilder        func(t *testing.T) *tls.Config
		insecureSkipVerify bool
		wantErrFlow        bool
		errSubstring       string // substring expected in Tags["error"]
	}{
		{
			name:               "expired_cert",
			certBuilder:        expiredTLSConfig,
			insecureSkipVerify: false,
			wantErrFlow:        true,
			errSubstring:       "expired",
		},
		{
			name:               "self_signed_cert",
			certBuilder:        selfSignedTLSConfig,
			insecureSkipVerify: false,
			wantErrFlow:        true,
			// crypto/tls returns "x509: certificate signed by unknown
			// authority" for an unrecognised self-signed CA; assert on
			// "unknown authority".
			errSubstring: "unknown authority",
		},
		{
			// Regression guard: a self-signed cert PLUS InsecureSkipVerify
			// reproduces the canonical "valid HTTPS" path on the test
			// fixtures the rest of the suite already uses. The proxy
			// accepts the cert, the TLS MITM handshake completes, and no
			// state="error" Stream is recorded for the upstream-TLS path.
			name:               "valid_cert_regression_guard",
			certBuilder:        validTLSConfig,
			insecureSkipVerify: true,
			wantErrFlow:        false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			tlsCfg := tc.certBuilder(t)

			// Stand up the upstream TLS listener. We never need to read
			// past the handshake — for the failure cases the upstream's
			// TLS layer rejects the proxy's TLS verification before any
			// inner bytes flow; for the success case we accept and close
			// to avoid blocking on a phantom HTTP request the test never
			// sends. Either way the goroutine drains so nothing leaks.
			upstreamLn, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
			if err != nil {
				t.Fatalf("upstream tls listen: %v", err)
			}

			var serverWG sync.WaitGroup
			serverWG.Add(1)
			go func() {
				defer serverWG.Done()
				for {
					c, aerr := upstreamLn.Accept()
					if aerr != nil {
						return
					}
					// Force the TLS handshake to drive the proxy's
					// verification past the cert. We discard the result
					// — the failure cases will return an error here, the
					// success case may also short-circuit if the proxy
					// closes immediately. Best-effort.
					if tc, ok := c.(*tls.Conn); ok {
						_ = tc.Handshake()
					}
					_ = c.Close()
				}
			}()
			// Defer order matters: serverWG.Wait must run AFTER
			// upstreamLn.Close so the Accept loop unblocks. Defers run in
			// LIFO order, so push Wait first then Close.
			defer serverWG.Wait()
			defer upstreamLn.Close()

			target := upstreamLn.Addr().String()

			// Build the proxy stack. Failure cases run with
			// InsecureSkipVerify=false so upstream TLS verification
			// actually runs and rejects the misconfigured cert. The
			// regression case flips this to true so a healthy CONNECT
			// completes — proving the new error path does not fire on
			// the success branch.
			store := &upstreamTLSErrorStore{}
			ca := &cert.CA{}
			if err := ca.Generate(); err != nil {
				t.Fatalf("CA.Generate: %v", err)
			}
			deps := proxybuild.Deps{
				Logger:       testutil.DiscardLogger(),
				ListenerName: "usk-784-test",
				ListenAddr:   "127.0.0.1:0",
				FlowStore:    store,
				BuildConfig: &connector.BuildConfig{
					ProxyConfig:        &config.ProxyConfig{},
					Issuer:             cert.NewIssuer(ca),
					InsecureSkipVerify: tc.insecureSkipVerify,
				},
			}

			stack, err := proxybuild.BuildLiveStack(ctx, deps)
			if err != nil {
				t.Fatalf("BuildLiveStack: %v", err)
			}
			go func() { _ = stack.Listener.Start(ctx) }()
			select {
			case <-stack.Listener.Ready():
			case <-time.After(5 * time.Second):
				t.Fatal("listener not ready")
			}

			proxyAddr := stack.Listener.Addr()
			if proxyAddr == "" {
				t.Fatal("listener has no addr")
			}

			// Drive the CONNECT and TLS handshake through the proxy.
			gotErr := connectAndAttemptHandshake(t, proxyAddr, target)

			if tc.wantErrFlow {
				// The client must observe a TLS error or aborted
				// connection — the proxy disconnected because upstream
				// TLS failed.
				if gotErr == nil {
					t.Errorf("client TLS handshake unexpectedly succeeded; expected proxy to abort on upstream TLS failure")
				}
			}

			// Allow the OnUpstreamTLSError callback to drain into the
			// store. The recorder uses a context.Background-derived
			// 5-second timeout for the SaveStream call, but the callback
			// itself fires synchronously inside runTLSMITM — so a short
			// poll loop is enough.
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				if !tc.wantErrFlow {
					break
				}
				if findErrorStreamForTarget(store.Streams(), target) != nil {
					break
				}
				time.Sleep(50 * time.Millisecond)
			}

			errStream := findErrorStreamForTarget(store.Streams(), target)
			if !tc.wantErrFlow {
				if errStream != nil {
					t.Errorf("regression: state=\"error\" Stream recorded for valid upstream cert: %+v", errStream)
				}
				return
			}

			if errStream == nil {
				t.Fatalf("no state=\"error\" Stream recorded for target %q; streams=%+v",
					target, store.Streams())
			}

			// --- Acceptance criteria ---

			// 1. Stream State == "error".
			if errStream.State != "error" {
				t.Errorf("State = %q, want %q", errStream.State, "error")
			}

			// 2. Protocol classification surfaces this as HTTP-family
			// (CLAUDE.md MITM Principle #2: protocol-specific handling).
			if errStream.Protocol != "http" {
				t.Errorf("Protocol = %q, want %q", errStream.Protocol, "http")
			}

			// 3. Scheme = "https" — CONNECT + TLS MITM is the HTTPS data
			// path even when the inner TLS never completed.
			if errStream.Scheme != "https" {
				t.Errorf("Scheme = %q, want %q", errStream.Scheme, "https")
			}

			// 4. Target host preserved (CONNECT authority). The recorder
			// stores it in Tags["target"] AND ConnInfo.ServerAddr so the
			// audit record has redundant traceability.
			if errStream.Tags == nil || errStream.Tags["target"] != target {
				t.Errorf("Tags[\"target\"] = %q, want %q", errStream.Tags["target"], target)
			}
			if errStream.ConnInfo == nil || errStream.ConnInfo.ServerAddr != target {
				t.Errorf("ConnInfo.ServerAddr = %q, want %q",
					serverAddrOrEmpty(errStream.ConnInfo), target)
			}

			// 5. Error reason observable as a string.
			gotErrStr := ""
			if errStream.Tags != nil {
				gotErrStr = errStream.Tags["error"]
			}
			if gotErrStr == "" {
				t.Errorf("Tags[\"error\"] is empty; want non-empty error reason")
			}
			if tc.errSubstring != "" && !strings.Contains(gotErrStr, tc.errSubstring) {
				t.Errorf("Tags[\"error\"] = %q, want substring %q",
					gotErrStr, tc.errSubstring)
			}

			// 6. FailureReason classification.
			if errStream.FailureReason != "upstream_tls_error" {
				t.Errorf("FailureReason = %q, want %q",
					errStream.FailureReason, "upstream_tls_error")
			}
		})
	}
}

// connectAndAttemptHandshake performs CONNECT against the proxy then tries
// to complete a TLS handshake against the proxy's MITM cert. The proxy's
// CONNECT response is read first; if the proxy aborts BEFORE 200 the test
// fatals. The TLS handshake error (or success) is returned so callers
// distinguish "proxy never returned 200" from "proxy returned 200 then the
// upstream-TLS check failed".
func connectAndAttemptHandshake(t *testing.T, proxyAddr, target string) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// Proxy may close the underlying conn after the TLS error — make
	// the test driver close idempotently.
	defer func() { _ = conn.Close() }()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}

	// Read the CONNECT 200 line. The proxy's CONNECTNegotiator returns
	// `200 Connection Established` synchronously before the upstream TLS
	// dial happens — so even when upstream TLS will fail, we should
	// observe a 200 here. This proves the bug-class precondition: CONNECT
	// completed, then the upstream TLS verification failed.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 256)
	n, rerr := conn.Read(buf)
	if rerr != nil {
		t.Fatalf("read CONNECT response: %v", rerr)
	}
	connectResp := string(buf[:n])
	if !strings.Contains(connectResp, "200") {
		t.Fatalf("unexpected CONNECT response: %q (proxy did not accept tunnel)", connectResp)
	}
	_ = conn.SetReadDeadline(time.Time{})

	// Now attempt a TLS handshake against the MITM. We use
	// InsecureSkipVerify=true on the client because the proxy presents a
	// fresh per-host MITM cert signed by an ephemeral test CA. The
	// handshake will fail because the proxy aborts the inner TLS once
	// upstream verification fails — that is the bug we are recording.
	tlsClient := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // hermetic test proxy
		// A short handshake deadline keeps the test fast even when the
		// proxy keeps the conn open after upstream failure (it does not
		// today, but is implementation-specific).
	})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	herr := tlsClient.Handshake()
	_ = tlsClient.Close()
	return herr
}

// findErrorStreamForTarget scans streams for the first state="error"
// stream whose Tags["target"] matches the given authority. Returns nil
// when no such stream exists.
func findErrorStreamForTarget(streams []*flow.Stream, target string) *flow.Stream {
	for _, st := range streams {
		if st == nil {
			continue
		}
		if st.State != "error" {
			continue
		}
		if st.Tags != nil && st.Tags["target"] == target {
			return st
		}
		if st.ConnInfo != nil && st.ConnInfo.ServerAddr == target {
			return st
		}
	}
	return nil
}

// serverAddrOrEmpty returns ConnInfo.ServerAddr when non-nil; "" otherwise.
// Used to keep error message construction one-liner-friendly without
// repeated nil guards.
func serverAddrOrEmpty(ci *flow.ConnectionInfo) string {
	if ci == nil {
		return ""
	}
	return ci.ServerAddr
}

// ---------------------------------------------------------------------------
// TLS cert builders — hermetic test fixtures only.
// ---------------------------------------------------------------------------

// expiredTLSConfig mints a self-signed cert with NotAfter < NotBefore <
// time.Now() so crypto/tls's verifier rejects it as expired. The proxy's
// upstream TLS verification surfaces this as
// `x509: certificate has expired or is not yet valid` from the standard
// library.
func expiredTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "expired-upstream"},
		// Both timestamps in the past so the cert is expired regardless
		// of clock skew.
		NotBefore:   now.Add(-2 * time.Hour),
		NotAfter:    now.Add(-1 * time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:    []string{"127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}

// selfSignedTLSConfig mints a valid (non-expired) but self-signed cert.
// The proxy's verifier rejects it because the issuer chain does not lead
// to a trusted root, surfacing as
// `x509: certificate signed by unknown authority`.
func selfSignedTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "self-signed-upstream"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}

// validTLSConfig mints a cert anchored in a per-test root CA the proxy
// can trust at verification time. It is used by the regression guard to
// confirm that the new error-recording path does not fire for healthy
// upstreams. The CA + leaf material is returned as a single tls.Config —
// the regression test does NOT install the CA into the proxy's trust
// store today; instead it relies on InsecureSkipVerify=false flipping the
// path to the failure recorder ONLY when verification actually fails.
//
// However for the "valid cert" regression case, we simply set
// InsecureSkipVerify=true on the proxy via a per-test BuildConfig flip
// upstream of this helper — but this helper exists separately so the
// regression test still exercises a non-pathological cert (the failure
// modes ALL succeed at MITM if the proxy is told to skip verification,
// which is the exact "no error recorded" outcome we assert).
func validTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	// Reuse the simple in-test self-signed shape: NotAfter in the
	// future, valid SAN. The regression-guard subtest flips the proxy
	// back to InsecureSkipVerify=true via a separate code path so the
	// upstream cert is accepted.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "valid-upstream"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"127.0.0.1"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		Certificates: []tls.Certificate{{
			Certificate: [][]byte{certDER},
			PrivateKey:  key,
		}},
	}
}
