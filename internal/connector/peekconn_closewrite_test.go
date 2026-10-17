package connector

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
	"math/big"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

// USK-1163: PeekConn embeds net.Conn, which hid the inner conn's CloseWrite.
// The plain-HTTP 414 reject path (layer/http1) and the TLS passthrough relay
// both type-assert CloseWrite, so on a PeekConn the half-close was silently
// skipped. These tests pin that PeekConn now forwards CloseWrite.

// tcpPair returns both ends of a real loopback TCP connection.
func tcpPair(t *testing.T) (dialed, accepted *net.TCPConn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	acceptCh := make(chan net.Conn, 1)
	acceptErr := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			acceptErr <- err
			return
		}
		acceptCh <- c
	}()

	d, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	select {
	case a := <-acceptCh:
		t.Cleanup(func() { a.Close() })
		t.Cleanup(func() { d.Close() })
		return d.(*net.TCPConn), a.(*net.TCPConn)
	case err := <-acceptErr:
		d.Close()
		t.Fatalf("accept: %v", err)
	case <-time.After(5 * time.Second):
		d.Close()
		t.Fatal("accept timed out")
	}
	return nil, nil
}

// readAllWithin reads conn to EOF under a deadline.
func readAllWithin(conn net.Conn, d time.Duration) ([]byte, error) {
	_ = conn.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	return io.ReadAll(conn)
}

// TestPeekConn_CloseWrite_TCP covers T1: CloseWrite on a PeekConn over
// loopback TCP sends FIN (the peer reads EOF) while the read side stays
// open, both for bytes already buffered by Peek and for bytes the peer
// sends after the half-close.
func TestPeekConn_CloseWrite_TCP(t *testing.T) {
	peer, inner := tcpPair(t)
	pc := NewPeekConn(inner)

	if _, err := peer.Write([]byte("peeked")); err != nil {
		t.Fatalf("peer write: %v", err)
	}
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if got, err := pc.Peek(len("peeked")); err != nil || string(got) != "peeked" {
		t.Fatalf("Peek = %q, %v; want %q", got, err, "peeked")
	}

	if _, err := pc.Write([]byte("bye")); err != nil {
		t.Fatalf("pc write: %v", err)
	}
	if err := pc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v, want nil on *net.TCPConn", err)
	}

	got, err := readAllWithin(peer, 2*time.Second)
	if err != nil {
		t.Fatalf("peer ReadAll: %v (want clean EOF after CloseWrite)", err)
	}
	if string(got) != "bye" {
		t.Fatalf("peer read %q, want %q", got, "bye")
	}

	// Read side is still open: buffered bytes first, then new bytes.
	if _, err := peer.Write([]byte("-later")); err != nil {
		t.Fatalf("peer write after half-close: %v", err)
	}
	if err := peer.CloseWrite(); err != nil {
		t.Fatalf("peer CloseWrite: %v", err)
	}
	rest, err := readAllWithin(pc, 5*time.Second)
	if err != nil {
		t.Fatalf("pc ReadAll after half-close: %v", err)
	}
	if string(rest) != "peeked-later" {
		t.Fatalf("pc read %q, want %q", rest, "peeked-later")
	}
}

// TestPeekConn_CloseWrite_Unsupported covers T2 (first half): an inner conn
// without half-close support (net.Pipe) yields errors.ErrUnsupported and
// leaves the connection fully usable in both directions.
func TestPeekConn_CloseWrite_Unsupported(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	pc := NewPeekConn(a)

	err := pc.CloseWrite()
	if err == nil || !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("CloseWrite = %v, want an error wrapping errors.ErrUnsupported", err)
	}

	go func() { _, _ = b.Write([]byte("x")) }()
	buf := make([]byte, 1)
	_ = pc.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(pc, buf); err != nil || buf[0] != 'x' {
		t.Fatalf("read after unsupported CloseWrite: %q, %v", buf, err)
	}
	go func() { _, _ = pc.Write([]byte("y")) }()
	_ = b.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(b, buf); err != nil || buf[0] != 'y' {
		t.Fatalf("write after unsupported CloseWrite: %q, %v", buf, err)
	}
}

// selfSignedServerConfig returns a throwaway TLS server config.
func selfSignedServerConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "peekconn-test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"peekconn-test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// TestPeekConn_CloseWrite_TLS covers T2 (second half): with an inner
// *tls.Conn, CloseWrite sends close_notify and the peer's Read returns
// io.EOF after the application data.
func TestPeekConn_CloseWrite_TLS(t *testing.T) {
	rawClient, rawServer := tcpPair(t)
	serverTLS := tls.Server(rawServer, selfSignedServerConfig(t))
	clientTLS := tls.Client(rawClient, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only self-signed peer
	defer serverTLS.Close()
	defer clientTLS.Close()

	hsErr := make(chan error, 1)
	go func() { hsErr <- clientTLS.Handshake() }()
	_ = serverTLS.SetDeadline(time.Now().Add(5 * time.Second))
	if err := serverTLS.Handshake(); err != nil {
		t.Fatalf("server handshake: %v", err)
	}
	if err := <-hsErr; err != nil {
		t.Fatalf("client handshake: %v", err)
	}
	_ = serverTLS.SetDeadline(time.Time{})

	pc := NewPeekConn(serverTLS)
	if _, err := pc.Write([]byte("tls-bye")); err != nil {
		t.Fatalf("pc write: %v", err)
	}
	if err := pc.CloseWrite(); err != nil {
		t.Errorf("CloseWrite: %v, want nil on *tls.Conn", err)
	}

	got, err := readAllWithin(clientTLS, 2*time.Second)
	if err != nil {
		t.Fatalf("client ReadAll: %v (want io.EOF via close_notify)", err)
	}
	if string(got) != "tls-bye" {
		t.Fatalf("client read %q, want %q", got, "tls-bye")
	}
}

// passthroughRig wires client ↔ [PeekConn | relay | raw TCP] ↔ upstream
// over real loopback TCP, matching how the TLS passthrough relay is fed:
// the client leg arrives as a *PeekConn from FullListener, the upstream leg
// is a plain dial.
type passthroughRig struct {
	client   *net.TCPConn
	upstream *net.TCPConn
	cancel   context.CancelFunc
	errCh    chan error
	aToB     *atomic.Int64
	bToA     *atomic.Int64
}

func newPassthroughRig(t *testing.T) *passthroughRig {
	t.Helper()
	client, proxyClient := tcpPair(t)
	proxyUpstream, upstream := tcpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &passthroughRig{
		client:   client,
		upstream: upstream,
		cancel:   cancel,
		errCh:    make(chan error, 1),
		aToB:     new(atomic.Int64),
		bToA:     new(atomic.Int64),
	}
	go func() {
		r.errCh <- relayBidirectionalCounted(ctx, NewPeekConn(proxyClient), proxyUpstream, r.aToB, r.bToA)
	}()
	return r
}

func (r *passthroughRig) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-r.errCh:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("relay did not return")
		return nil
	}
}

// TestRelayBidirectional_PeekConn_UpstreamHalfClose covers T4 (intended
// behaviour change of USK-1163): when upstream half-closes, the client
// receives upstream's bytes followed by EOF, while client→upstream stays
// open. Before USK-1163 the FIN was dropped (PeekConn hid CloseWrite) and
// the client hung until its own close.
func TestRelayBidirectional_PeekConn_UpstreamHalfClose(t *testing.T) {
	r := newPassthroughRig(t)

	if _, err := r.upstream.Write([]byte("from-upstream")); err != nil {
		t.Fatalf("upstream write: %v", err)
	}
	if err := r.upstream.CloseWrite(); err != nil {
		t.Fatalf("upstream CloseWrite: %v", err)
	}

	got, err := readAllWithin(r.client, 2*time.Second)
	if err != nil {
		t.Fatalf("client ReadAll: %v (want upstream FIN propagated to the client)", err)
	}
	if string(got) != "from-upstream" {
		t.Fatalf("client read %q, want %q", got, "from-upstream")
	}

	// client→upstream still flows after the client saw EOF.
	if _, err := r.client.Write([]byte("from-client")); err != nil {
		t.Fatalf("client write after EOF: %v", err)
	}
	if err := r.client.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	up, err := readAllWithin(r.upstream, 5*time.Second)
	if err != nil {
		t.Fatalf("upstream ReadAll: %v", err)
	}
	if string(up) != "from-client" {
		t.Fatalf("upstream read %q, want %q", up, "from-client")
	}

	if err := r.wait(t); err != nil {
		t.Fatalf("relay err = %v, want nil", err)
	}
	if r.aToB.Load() != int64(len("from-client")) || r.bToA.Load() != int64(len("from-upstream")) {
		t.Fatalf("byte counts aToB=%d bToA=%d, want %d/%d",
			r.aToB.Load(), r.bToA.Load(), len("from-client"), len("from-upstream"))
	}
}

// TestRelayBidirectional_PeekConn_ClientHalfClose covers T5
// (characterization, unchanged by USK-1163): a client half-close reaches
// upstream as EOF and upstream→client data still flows afterwards.
func TestRelayBidirectional_PeekConn_ClientHalfClose(t *testing.T) {
	r := newPassthroughRig(t)

	if _, err := r.client.Write([]byte("req")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	if err := r.client.CloseWrite(); err != nil {
		t.Fatalf("client CloseWrite: %v", err)
	}
	up, err := readAllWithin(r.upstream, 5*time.Second)
	if err != nil {
		t.Fatalf("upstream ReadAll: %v (want client FIN propagated upstream)", err)
	}
	if string(up) != "req" {
		t.Fatalf("upstream read %q, want %q", up, "req")
	}

	if _, err := r.upstream.Write([]byte("resp")); err != nil {
		t.Fatalf("upstream write after client half-close: %v", err)
	}
	buf := make([]byte, len("resp"))
	_ = r.client.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.ReadFull(r.client, buf); err != nil || string(buf) != "resp" {
		t.Fatalf("client read %q, %v; want %q", buf, err, "resp")
	}

	_ = r.upstream.Close()
	if err := r.wait(t); err != nil {
		t.Fatalf("relay err = %v, want nil", err)
	}
	if r.aToB.Load() != 3 || r.bToA.Load() != 4 {
		t.Fatalf("byte counts aToB=%d bToA=%d, want 3/4", r.aToB.Load(), r.bToA.Load())
	}
}

// TestRelayBidirectional_PeekConn_ContextCancel covers T5's teardown guard:
// cancelling ctx still tears the relay down and reports the cancellation.
func TestRelayBidirectional_PeekConn_ContextCancel(t *testing.T) {
	r := newPassthroughRig(t)
	r.cancel()
	if err := r.wait(t); err == nil {
		t.Fatal("relay err = nil after ctx cancel, want non-nil")
	}
}
