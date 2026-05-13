//go:build e2e

// USK-858: client-side TLS MITM handshake rejections (browser → proxy)
// must be recorded with FailureReason="client_tls_error" so MITM
// diagnostic users can distinguish them from upstream-side TLS failures
// (FailureReason="upstream_tls_error"). The canonical real-world
// trigger is Chromium pinning a known site (HSTS/HPKP, or an in-browser
// hardcoded cert) so the proxy's MITM cert is rejected with an
// unknown_certificate / bad_certificate TLS alert.
//
// This file is the symmetric mirror of upstream_tls_error_integration_test.go.
// Where that file misconfigures the upstream server's cert and asserts
// FailureReason="upstream_tls_error", this file misconfigures the
// client's TLS verifier (empty RootCAs) so the client rejects the
// proxy's MITM cert mid-handshake and asserts
// FailureReason="client_tls_error".
//
// The test runs hermetically: no real network is touched. The proxy is
// configured with RawPassthroughHosts so the client-side MITM handshake
// runs BEFORE the upstream dial — guaranteeing the failure surfaces on
// the client-side branch even when no upstream server is listening.
//
// Smoke tier (`//go:build e2e`, no `&& !e2e_smoke`) so the new taxonomy
// is in the merge gate and a regression in the recorder's branching
// surfaces in per-PR CI rather than nightly.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

// clientTLSErrorStore is a minimal flow.Writer test double. The
// upstream sibling integration test declares an identically-shaped type
// (upstreamTLSErrorStore) — we duplicate the struct rather than depend
// on a cross-file helper because both files share the same smoke build
// tag and Go requires unique type names per package even across files.
type clientTLSErrorStore struct {
	mu      sync.Mutex
	streams []*flow.Stream
}

func (s *clientTLSErrorStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.streams = append(s.streams, st)
	return nil
}

func (s *clientTLSErrorStore) UpdateStream(_ context.Context, _ string, _ flow.StreamUpdate) error {
	return nil
}

func (s *clientTLSErrorStore) SaveFlow(_ context.Context, _ *flow.Flow) error {
	return nil
}

func (s *clientTLSErrorStore) Streams() []*flow.Stream {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*flow.Stream, len(s.streams))
	copy(out, s.streams)
	return out
}

// TestProxybuild_CONNECT_ClientTLSMITMHandshakeFailure_RecordsClientTLSError
// drives the USK-858 acceptance criteria end to end through BuildLiveStack:
//
//   - the proxy issues a MITM cert signed by its ephemeral test CA;
//   - the client refuses to trust the cert (empty RootCAs pool) and aborts
//     with an unknown-authority alert; the proxy's tlslayer.Server reads
//     the alert and returns an error wrapped with
//     ErrClientTLSMITMHandshake;
//   - the recorder writes a state="error" Stream with
//     FailureReason="client_tls_error" (NOT upstream_tls_error);
//   - the CONNECT authority is preserved verbatim in Tags["target"] and
//     ConnInfo.ServerAddr.
//
// Raw passthrough mode routes the request through buildRawPassthroughStack
// so the client-side MITM handshake fires BEFORE any upstream dial — the
// failure cannot be confused with an upstream TLS error.
func TestProxybuild_CONNECT_ClientTLSMITMHandshakeFailure_RecordsClientTLSError(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Pick a target authority. We never connect to it — raw passthrough
	// will perform the client-side MITM handshake first and the test
	// aborts before any upstream dial. Use a literal IP:port to keep
	// the host extraction trivial.
	target := "127.0.0.1:1"

	// Stand up the proxy stack.
	store := &clientTLSErrorStore{}
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	deps := proxybuild.Deps{
		Logger:       testutil.DiscardLogger(),
		ListenerName: "usk-858-test",
		ListenAddr:   "127.0.0.1:0",
		FlowStore:    store,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig: &config.ProxyConfig{
				// Raw passthrough makes performClientMITM run before
				// any upstream dial — the failure must therefore
				// belong to the client-side branch.
				RawPassthroughHosts: []string{target},
			},
			Issuer: cert.NewIssuer(ca),
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

	// Drive the CONNECT and TLS handshake with an empty root-CA pool so
	// the client refuses to trust the proxy's freshly-minted MITM cert.
	gotErr := connectAndAttemptHandshakeWithEmptyRoots(t, proxyAddr, target)
	if gotErr == nil {
		t.Errorf("client TLS handshake unexpectedly succeeded; expected unknown-authority rejection")
	} else if !strings.Contains(gotErr.Error(), "unknown authority") &&
		!strings.Contains(gotErr.Error(), "certificate") {
		t.Errorf("client TLS handshake error = %q; want an unknown-authority / certificate-related rejection",
			gotErr.Error())
	}

	// Poll for the audit record (the recorder uses a background-derived
	// 5-second timeout for SaveStream but the callback itself fires
	// synchronously inside runTLSMITM).
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if findClientTLSErrorStream(store.Streams(), target) != nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	errStream := findClientTLSErrorStream(store.Streams(), target)
	if errStream == nil {
		t.Fatalf("no state=\"error\" Stream recorded for target %q; streams=%+v",
			target, store.Streams())
	}

	// --- Acceptance criteria ---

	// 1. Stream State == "error".
	if errStream.State != "error" {
		t.Errorf("State = %q, want %q", errStream.State, "error")
	}

	// 2. HTTP/HTTPS data path classification preserved for the
	// client-side path too — same justification as USK-784: no inner
	// negotiation completed so the protocol family is HTTP-with-HTTPS.
	if errStream.Protocol != "http" {
		t.Errorf("Protocol = %q, want %q", errStream.Protocol, "http")
	}
	if errStream.Scheme != "https" {
		t.Errorf("Scheme = %q, want %q", errStream.Scheme, "https")
	}

	// 3. CONNECT authority preserved verbatim in both surfaces.
	if errStream.Tags == nil || errStream.Tags["target"] != target {
		t.Errorf("Tags[\"target\"] = %q, want %q", errStream.Tags["target"], target)
	}
	if errStream.ConnInfo == nil || errStream.ConnInfo.ServerAddr != target {
		t.Errorf("ConnInfo.ServerAddr = %q, want %q",
			serverAddrOrEmptyClient(errStream.ConnInfo), target)
	}

	// 4. Underlying error string is preserved so MCP users can
	// disambiguate pinning-rejection from unknown_certificate without
	// re-parsing FailureReason. The Go stdlib surfaces these as
	// `tls: bad certificate` or `remote error: tls: <alert>` from
	// tlslayer.Server.
	gotErrStr := ""
	if errStream.Tags != nil {
		gotErrStr = errStream.Tags["error"]
	}
	if gotErrStr == "" {
		t.Errorf("Tags[\"error\"] is empty; want non-empty error reason")
	}
	// The wrapped sentinel is reflected in the error string so MCP grep
	// queries that ignore FailureReason (e.g. older clients) can still
	// distinguish the client-side path.
	if !strings.Contains(gotErrStr, "client TLS MITM handshake") {
		t.Errorf("Tags[\"error\"] = %q, want substring %q",
			gotErrStr, "client TLS MITM handshake")
	}

	// 5. FailureReason classification — the USK-858 contract.
	if errStream.FailureReason != "client_tls_error" {
		t.Errorf("FailureReason = %q, want %q (USK-858)",
			errStream.FailureReason, "client_tls_error")
	}
}

// connectAndAttemptHandshakeWithEmptyRoots sends CONNECT to the proxy
// and then performs a TLS handshake using an empty x509.NewCertPool() as
// RootCAs. The client therefore rejects the proxy's MITM cert and the
// handshake aborts with `x509: certificate signed by unknown authority`
// — the same shape Chromium produces when it pins a certificate the
// proxy MITM does not match (USK-856 reproducer).
//
// The function returns the TLS handshake error (or nil on the success
// path, which the test treats as a bug — the proxy should never present
// a trusted-by-default cert).
func connectAndAttemptHandshakeWithEmptyRoots(t *testing.T, proxyAddr, target string) error {
	t.Helper()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	// The proxy will close the conn after the failed TLS handshake; the
	// test driver closes idempotently so the defer is harmless.
	defer func() { _ = conn.Close() }()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}

	// Read the CONNECT 200 line synchronously. CONNECTNegotiator returns
	// `200 Connection Established` BEFORE the upstream stack build, so
	// even the client-side-MITM-failure path observes a 200 here.
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

	// Inner TLS handshake with an empty root pool — the client will
	// reject the proxy's MITM cert mid-handshake. ServerName matches the
	// CONNECT authority's host part so SNI is well-formed and the proxy
	// mints a per-host cert through MITMServerConfig.
	host, _, _ := net.SplitHostPort(target)
	tlsClient := tls.Client(conn, &tls.Config{
		ServerName: host,
		RootCAs:    x509.NewCertPool(),
		MinVersion: tls.VersionTLS12,
	})
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	herr := tlsClient.Handshake()
	_ = tlsClient.Close()
	return herr
}

// findClientTLSErrorStream is the client-side analogue of
// findErrorStreamForTarget in upstream_tls_error_integration_test.go.
// It scans for the first state="error" stream whose
// FailureReason=="client_tls_error" and whose Tags["target"] matches the
// given authority. Returns nil when no such stream exists.
//
// Asserting on FailureReason inside the find helper rather than the
// caller keeps the polling loop fail-fast on the upstream-side
// classification — if a regression silently routes the failure through
// the upstream branch the poll will time out cleanly rather than
// surfacing a misleading "stream found" success.
func findClientTLSErrorStream(streams []*flow.Stream, target string) *flow.Stream {
	for _, st := range streams {
		if st == nil {
			continue
		}
		if st.State != "error" {
			continue
		}
		if st.FailureReason != "client_tls_error" {
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

// serverAddrOrEmptyClient mirrors serverAddrOrEmpty in the upstream
// sibling test. Renamed to avoid the Go "redeclared in this block"
// error since both files compile under the same smoke build tag and
// belong to the same proxybuild_test package.
func serverAddrOrEmptyClient(ci *flow.ConnectionInfo) string {
	if ci == nil {
		return ""
	}
	return ci.ServerAddr
}
