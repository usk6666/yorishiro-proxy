//go:build e2e && !e2e_smoke

// USK-790: TLS passthrough must record a tls-handshake meta flow per
// connection so the audit trail surfaces "pinned host contacted" without
// violating the passthrough contract (no decryption, no inner-protocol
// introspection).
//
// This integration test stands up a real proxy stack via BuildLiveStack,
// adds an upstream host to the PassthroughList, drives a TLS handshake +
// echo exchange through the proxy, and asserts the flow store recorded:
//
//   - exactly one Stream with Protocol="tls-handshake", Scheme="https"
//     and State="complete" (or "error" for the failure case);
//   - a single send-direction Flow whose Metadata carries the SNI, both
//     byte counters non-zero on the success path, and the canonical
//     outcome value.
//
// Out-of-scope passthrough (record_scope filter rejects the host) is
// tested as a regression guard so the audit recorder does not over-record.
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
	"io"
	"math/big"
	"net"
	"strconv"
	"sync"
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

// passthroughAuditStore captures Stream + Flow writes for assertions.
type passthroughAuditStore struct {
	mu      sync.Mutex
	streams map[string]*flow.Stream
	flows   []*flow.Flow
}

func newPassthroughAuditStore() *passthroughAuditStore {
	return &passthroughAuditStore{streams: make(map[string]*flow.Stream)}
}

func (s *passthroughAuditStore) SaveStream(_ context.Context, st *flow.Stream) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *st
	if st.ConnInfo != nil {
		ci := *st.ConnInfo
		cp.ConnInfo = &ci
	}
	if st.Tags != nil {
		t := make(map[string]string, len(st.Tags))
		for k, v := range st.Tags {
			t[k] = v
		}
		cp.Tags = t
	}
	s.streams[st.ID] = &cp
	return nil
}

func (s *passthroughAuditStore) UpdateStream(_ context.Context, id string, upd flow.StreamUpdate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.streams[id]
	if !ok {
		return fmt.Errorf("stream %s not found for update", id)
	}
	if upd.State != "" {
		st.State = upd.State
	}
	if upd.FailureReason != "" {
		st.FailureReason = upd.FailureReason
	}
	if upd.Duration > 0 {
		st.Duration = upd.Duration
	}
	return nil
}

func (s *passthroughAuditStore) SaveFlow(_ context.Context, fl *flow.Flow) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *fl
	if fl.Metadata != nil {
		md := make(map[string]string, len(fl.Metadata))
		for k, v := range fl.Metadata {
			md[k] = v
		}
		cp.Metadata = md
	}
	s.flows = append(s.flows, &cp)
	return nil
}

func (s *passthroughAuditStore) snapshot() (streams []*flow.Stream, flows []*flow.Flow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, st := range s.streams {
		cp := *st
		streams = append(streams, &cp)
	}
	flows = append(flows, s.flows...)
	return streams, flows
}

// startTLSEchoServer launches a TLS echo server backed by a fresh
// self-signed certificate. The returned "127.0.0.1:port" address can be
// used as the passthrough target. The cert is returned so the test client
// can pin it.
func startTLSEchoServer(t *testing.T) (addr string, certPEM *x509.Certificate, cleanup func()) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "passthrough-meta-upstream"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"passthrough-meta-upstream"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatalf("tls listen: %v", err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				_, _ = io.Copy(c, c)
			}(conn)
		}
	}()
	cleanup = func() {
		_ = ln.Close()
		wg.Wait()
	}
	return ln.Addr().String(), parsed, cleanup
}

// TestProxybuild_TLSPassthrough_RecordsMetaFlow drives a real CONNECT +
// passthrough relay through BuildLiveStack and asserts the audit Stream +
// Flow are recorded with SNI, byte counters, and outcome.
func TestProxybuild_TLSPassthrough_RecordsMetaFlow(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstreamAddr, upstreamCert, cleanup := startTLSEchoServer(t)
	defer cleanup()
	upstreamHost, _, _ := net.SplitHostPort(upstreamAddr)

	pl := connector.NewPassthroughList()
	pl.Add(upstreamHost)

	store := newPassthroughAuditStore()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatalf("CA.Generate: %v", err)
	}
	deps := proxybuild.Deps{
		Logger:          testutil.DiscardLogger(),
		ListenerName:    "usk-790-test",
		ListenAddr:      "127.0.0.1:0",
		FlowStore:       store,
		PassthroughList: pl,
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

	// CONNECT through proxy.
	conn, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamAddr, upstreamAddr)
	if _, werr := conn.Write([]byte(connectReq)); werr != nil {
		t.Fatalf("write CONNECT: %v", werr)
	}
	// Drain CONNECT 200.
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read CONNECT response: %v", err)
	}
	if got := string(buf[:n]); got != "HTTP/1.1 200 Connection Established\r\n\r\n" {
		t.Fatalf("CONNECT response = %q", got)
	}

	// TLS handshake + echo exchange — this is what generates byte traffic
	// for the relay so the meta flow's byte counters land non-zero.
	rootPool := x509.NewCertPool()
	rootPool.AddCert(upstreamCert)
	tlsConn := tls.Client(conn, &tls.Config{
		RootCAs:    rootPool,
		ServerName: "passthrough-meta-upstream",
	})
	if err := tlsConn.Handshake(); err != nil {
		t.Fatalf("client TLS handshake through passthrough: %v", err)
	}
	payload := []byte("hello from passthrough audit test")
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
		if len(streams) > 0 && len(flows) > 0 {
			// Wait for State to settle to "complete".
			if streams[0].State == "complete" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}

	if len(streams) != 1 {
		t.Fatalf("expected 1 audit Stream, got %d (%+v)", len(streams), streams)
	}
	st := streams[0]
	if st.Protocol != string(envelope.ProtocolTLSHandshake) {
		t.Errorf("Stream.Protocol = %q, want %q", st.Protocol, envelope.ProtocolTLSHandshake)
	}
	if st.Scheme != "https" {
		t.Errorf("Stream.Scheme = %q, want https", st.Scheme)
	}
	if st.State != "complete" {
		t.Errorf("Stream.State = %q, want complete", st.State)
	}
	if st.Origin != flow.OriginProxy {
		t.Errorf("Stream.Origin = %q, want %q", st.Origin, flow.OriginProxy)
	}
	if st.Duration <= 0 {
		t.Errorf("Stream.Duration = %v, want positive", st.Duration)
	}
	if st.ConnInfo == nil || st.ConnInfo.ClientAddr == "" || st.ConnInfo.ServerAddr == "" {
		t.Errorf("Stream.ConnInfo missing addresses: %+v", st.ConnInfo)
	}

	if len(flows) != 1 {
		t.Fatalf("expected 1 audit Flow, got %d (%+v)", len(flows), flows)
	}
	fl := flows[0]
	if fl.StreamID != st.ID {
		t.Errorf("Flow.StreamID = %q, want %q", fl.StreamID, st.ID)
	}
	if fl.Direction != "send" {
		t.Errorf("Flow.Direction = %q, want send", fl.Direction)
	}
	if fl.Metadata["sni"] != "passthrough-meta-upstream" {
		t.Errorf("Flow.Metadata[sni] = %q, want passthrough-meta-upstream", fl.Metadata["sni"])
	}
	c2u, _ := strconv.ParseInt(fl.Metadata["bytes_client_to_upstream"], 10, 64)
	if c2u <= 0 {
		t.Errorf("Flow.Metadata[bytes_client_to_upstream] = %q, want positive integer", fl.Metadata["bytes_client_to_upstream"])
	}
	u2c, _ := strconv.ParseInt(fl.Metadata["bytes_upstream_to_client"], 10, 64)
	if u2c <= 0 {
		t.Errorf("Flow.Metadata[bytes_upstream_to_client] = %q, want positive integer", fl.Metadata["bytes_upstream_to_client"])
	}
	if fl.Metadata["outcome"] != envelope.TLSHandshakeOutcomeTunneled {
		t.Errorf("Flow.Metadata[outcome] = %q, want %q", fl.Metadata["outcome"], envelope.TLSHandshakeOutcomeTunneled)
	}
}

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
