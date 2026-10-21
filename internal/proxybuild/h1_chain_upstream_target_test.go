package proxybuild

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// startSNIRecordingTLSUpstream starts a local TLS upstream that records the
// SNI of every ClientHello and holds each accepted connection open until the
// test ends. Returns the listener address and an accessor for the SNIs.
func startSNIRecordingTLSUpstream(t *testing.T) (addr string, snis func() []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "upstream.test"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"upstream.test"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var seen []string
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			mu.Lock()
			seen = append(seen, hello.ServerName)
			mu.Unlock()
			return nil, nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	var connsMu sync.Mutex
	var conns []net.Conn
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			connsMu.Lock()
			conns = append(conns, c)
			connsMu.Unlock()
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = c.(*tls.Conn).Handshake()
			}()
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		connsMu.Lock()
		for _, c := range conns {
			_ = c.Close()
		}
		connsMu.Unlock()
		wg.Wait()
	})
	return ln.Addr().String(), func() []string {
		mu.Lock()
		defer mu.Unlock()
		return slices.Clone(seen)
	}
}

// TestH1Chain_Redial_UpstreamTargetSplit is the proxybuild half of USK-1315
// test plan #10: a chain carrying a dial target / TLS authority split redials
// the dial target and sends the TLS authority's host as SNI.
func TestH1Chain_Redial_UpstreamTargetSplit(t *testing.T) {
	addr, snis := startSNIRecordingTLSUpstream(t)
	_, port, _ := net.SplitHostPort(addr)
	ut := connector.UpstreamTarget{Dial: addr, TLS: net.JoinHostPort("a.example", port)}

	_, server := testTCPPair(t)
	initial := http1.New(server, "stream-split", envelope.Receive,
		http1.WithScheme("https"),
		http1.WithEnvelopeContext(envelope.EnvelopeContext{ConnID: "c1", TargetHost: ut.Dial}),
	)
	cfg := &connector.BuildConfig{InsecureSkipVerify: true}
	chain := newH1Chain(initial, ut, cfg, nil, nil)
	defer chain.closeAll()

	if _, err := chain.Redial(context.Background()); err != nil {
		t.Fatalf("Redial: %v (a.example is unresolvable — a dial of the TLS host would fail here)", err)
	}
	if got := snis(); !slices.Equal(got, []string{"a.example"}) {
		t.Errorf("redial SNIs = %q, want [\"a.example\"] (the TLS authority's host)", got)
	}
}
