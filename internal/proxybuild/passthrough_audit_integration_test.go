//go:build e2e && !e2e_smoke

// USK-790 / USK-845 / USK-1170 exhaustive tier for the TLS passthrough audit
// recorder: RecordScope filtering (out-of-scope suppressed, in-scope
// hostname match recorded) and the CONNECT / SOCKS5 handshake-latency
// regressions. The primary recording + latency guard and the shared helpers
// (passthroughAuditStore, startTLSEchoServer, startRecordedPassthroughProxy,
// assertTimedPassthroughHandshakeRecorded) live in the smoke-tier
// passthrough_audit_smoke_integration_test.go.
package proxybuild_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"strconv"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
	"github.com/usk6666/yorishiro-proxy/internal/testutil"
)

// TestProxybuild_TLSPassthrough_OutOfScope_NotRecorded verifies the
// recorder respects the RecordScope filter — passthrough connections to
// hosts outside the include list are NOT persisted.
func TestProxybuild_TLSPassthrough_OutOfScope_NotRecorded(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamCert, cleanup := startTLSEchoServer(t)
	defer cleanup()
	upstreamHost, _, _ := net.SplitHostPort(upstreamAddr)

	pl := connector.NewPassthroughList()
	pl.Add(upstreamHost)

	scope := flow.NewRecordScope()
	// Include only an unrelated hostname so passthrough host ends up
	// out-of-scope.
	scope.SetRules([]flow.ScopeRule{{Hostname: "other.example"}}, nil)

	store := newPassthroughAuditStore()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	deps := proxybuild.Deps{
		Logger:          testutil.DiscardLogger(),
		ListenerName:    "usk-790-out-of-scope",
		ListenAddr:      "127.0.0.1:0",
		FlowStore:       store,
		PassthroughList: pl,
		RecordScope:     scope,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig: &config.ProxyConfig{},
			Issuer:      cert.NewIssuer(ca),
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
		t.Fatal("listener never reported ready")
	}
	proxyAddr := stack.Listener.Addr()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}
	buf := make([]byte, 256)
	if _, rerr := conn.Read(buf); rerr != nil {
		t.Fatalf("read CONNECT: %v", rerr)
	}
	rootPool := x509.NewCertPool()
	rootPool.AddCert(upstreamCert)
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    rootPool,
		ServerName: "passthrough-meta-upstream",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("TLS handshake: %v", err)
	}
	_, _ = tlsConn.Write([]byte("ping"))
	rb := make([]byte, 4)
	_, _ = io.ReadFull(tlsConn, rb)
	_ = tlsConn.Close()
	_ = conn.Close()

	// Give the recorder a moment to NOT record anything.
	time.Sleep(500 * time.Millisecond)
	streams, flows := store.snapshot()
	if len(streams) != 0 {
		t.Errorf("RecordScope should suppress out-of-scope passthrough; got %d streams: %+v", len(streams), streams)
	}
	if len(flows) != 0 {
		t.Errorf("RecordScope should suppress out-of-scope passthrough; got %d flows", len(flows))
	}
}

// TestProxybuild_TLSPassthrough_InScope_HostnameMatch is the USK-845
// regression guard: with capture_scope.includes:[{hostname:"<upstream>"}]
// configured alongside tls_passthrough:["<upstream>"], the passthrough
// audit Stream / Flow MUST be persisted. The pre-fix bug seeded the
// scope envelope's Context.TargetHost from the dialed upstream IP, which
// short-circuited the matcher's SNI fallback. The fix plumbs the
// CONNECT target hostname onto PassthroughObservation.TargetHost so the
// matcher resolves the host correctly. Track F §F-1 (2026-05-13).
func TestProxybuild_TLSPassthrough_InScope_HostnameMatch(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamCert, cleanup := startTLSEchoServer(t)
	defer cleanup()
	upstreamHost, _, _ := net.SplitHostPort(upstreamAddr)

	pl := connector.NewPassthroughList()
	pl.Add(upstreamHost)

	// Include rule matches the target hostname — the CONNECT authority the
	// client sends is "127.0.0.1:<port>", so include "127.0.0.1" here.
	// What matters is that pre-fix this also failed (the matcher saw the
	// dialed IP without port handling baked in); post-fix the CONNECT
	// authority is plumbed cleanly.
	scope := flow.NewRecordScope()
	scope.SetRules([]flow.ScopeRule{{Hostname: upstreamHost}}, nil)

	store := newPassthroughAuditStore()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	deps := proxybuild.Deps{
		Logger:          testutil.DiscardLogger(),
		ListenerName:    "usk-845-in-scope",
		ListenAddr:      "127.0.0.1:0",
		FlowStore:       store,
		PassthroughList: pl,
		RecordScope:     scope,
		BuildConfig: &connector.BuildConfig{
			ProxyConfig: &config.ProxyConfig{},
			Issuer:      cert.NewIssuer(ca),
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
		t.Fatal("listener never reported ready")
	}
	proxyAddr := stack.Listener.Addr()

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}
	buf := make([]byte, 256)
	if _, rerr := conn.Read(buf); rerr != nil {
		t.Fatalf("read CONNECT: %v", rerr)
	}

	rootPool := x509.NewCertPool()
	rootPool.AddCert(upstreamCert)
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    rootPool,
		ServerName: "passthrough-meta-upstream",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through passthrough: %v", err)
	}
	payload := []byte("usk-845 in-scope hostname match")
	if _, werr := tlsConn.Write(payload); werr != nil {
		t.Fatalf("tlsConn.Write: %v", werr)
	}
	rb := make([]byte, len(payload))
	if _, rerr := io.ReadFull(tlsConn, rb); rerr != nil {
		t.Fatalf("tlsConn.Read: %v", rerr)
	}
	_ = tlsConn.Close()
	_ = conn.Close()

	// Wait for OnComplete to flush the audit records.
	deadline := time.Now().Add(3 * time.Second)
	var streams []*flow.Stream
	var flows []*flow.Flow
	for time.Now().Before(deadline) {
		streams, flows = store.snapshot()
		if len(streams) > 0 && len(flows) > 0 && streams[0].State == "complete" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(streams) != 1 {
		t.Fatalf("in-scope passthrough should record 1 Stream, got %d (%+v)", len(streams), streams)
	}
	st := streams[0]
	if st.Protocol != string(envelope.ProtocolTLSHandshake) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolTLSHandshake)
	}
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
	if len(flows) != 1 {
		t.Fatalf("in-scope passthrough should record 1 Flow, got %d", len(flows))
	}
	if flows[0].Metadata["sni"] != "passthrough-meta-upstream" {
		t.Errorf("Flow.Metadata[sni] = %q, want passthrough-meta-upstream", flows[0].Metadata["sni"])
	}
}

// TestProxybuild_TLSPassthrough_Recorded_CONNECT_HandshakeNotStalled is the
// USK-1170 regression: with recording enabled, the passthrough SNI peek
// must not hold the handshake for clientHelloPeekTimeout.
func TestProxybuild_TLSPassthrough_Recorded_CONNECT_HandshakeNotStalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyAddr, upstreamAddr, upstreamCert, store := startRecordedPassthroughProxy(ctx, t)

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}
	want := "HTTP/1.1 200 Connection Established\r\n\r\n"
	resp := make([]byte, len(want))
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, rerr := io.ReadFull(conn, resp); rerr != nil {
		t.Fatalf("read CONNECT response: %v", rerr)
	}
	if string(resp) != want {
		t.Fatalf("CONNECT response = %q", resp)
	}

	assertTimedPassthroughHandshakeRecorded(t, conn, upstreamCert, store)
}

// TestProxybuild_TLSPassthrough_Recorded_SOCKS5_HandshakeNotStalled is the
// SOCKS5 sibling of the CONNECT regression (socks5Passthrough shares the
// observed relay). USK-1170.
func TestProxybuild_TLSPassthrough_Recorded_SOCKS5_HandshakeNotStalled(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	proxyAddr, upstreamAddr, upstreamCert, store := startRecordedPassthroughProxy(ctx, t)
	upstreamHost, portStr, _ := net.SplitHostPort(upstreamAddr)
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	ip := net.ParseIP(upstreamHost).To4()
	if ip == nil {
		t.Fatalf("upstream host %q is not IPv4", upstreamHost)
	}

	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))

	// Greeting: VER=5, NMETHODS=1, METHOD=NO_AUTH.
	if _, werr := conn.Write([]byte{0x05, 0x01, 0x00}); werr != nil {
		t.Fatalf("write SOCKS5 greeting: %v", werr)
	}
	method := make([]byte, 2)
	if _, rerr := io.ReadFull(conn, method); rerr != nil {
		t.Fatalf("read SOCKS5 method selection: %v", rerr)
	}
	if method[0] != 0x05 || method[1] != 0x00 {
		t.Fatalf("SOCKS5 method selection = %x, want 0500", method)
	}
	// CONNECT: VER=5, CMD=1, RSV=0, ATYP=IPv4, ADDR, PORT.
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip...)
	req = append(req, byte(port>>8), byte(port))
	if _, werr := conn.Write(req); werr != nil {
		t.Fatalf("write SOCKS5 CONNECT: %v", werr)
	}
	// Reply with IPv4 BND.ADDR: 10 bytes.
	reply := make([]byte, 10)
	if _, rerr := io.ReadFull(conn, reply); rerr != nil {
		t.Fatalf("read SOCKS5 reply: %v", rerr)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("SOCKS5 reply = %x, want VER=05 REP=00", reply[:2])
	}

	assertTimedPassthroughHandshakeRecorded(t, conn, upstreamCert, store)
}
