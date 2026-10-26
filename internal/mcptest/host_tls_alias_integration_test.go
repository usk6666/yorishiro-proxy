//go:build e2e && !e2e_smoke

// USK-1384: per-host TLS settings (host_tls in the -config file) apply to a
// CONNECT authority that respells the entry's host — a trailing dot or an
// IPv4-mapped IPv6 literal — exactly as they apply to the entry's own
// spelling. Both the startup-time resolver and the runtime registry are
// built from the same host_tls map by mcpserver, so this drives the
// production config → runtime wiring. The fold is comparison-only: the
// recorded flow keeps the authority as the client wrote it.
package mcptest_test

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
)

// hostTLSAliasHosts are the CONNECT hosts each test drives: the entry's own
// spelling (control) and two respellings that dial the same loopback
// upstream.
var hostTLSAliasHosts = []string{"localhost", "localhost.", "::ffff:127.0.0.1"}

// hostTLSAliasPKI holds a server CA + leaf (SAN localhost, 127.0.0.1) and a
// client CA + client cert, with the PEM files the config refers to.
type hostTLSAliasPKI struct {
	leaf           tls.Certificate
	serverCAPath   string
	clientCAs      *x509.CertPool
	clientCertPath string
	clientKeyPath  string
}

func newHostTLSAliasPKI(t *testing.T) hostTLSAliasPKI {
	t.Helper()
	dir := t.TempDir()
	newCA := func(cn string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: cn},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().Add(time.Hour),
			IsCA:                  true,
			BasicConstraintsValid: true,
			KeyUsage:              x509.KeyUsageCertSign,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c, key, der
	}
	issue := func(ca *x509.Certificate, caKey *ecdsa.PrivateKey, tmpl *x509.Certificate) ([]byte, *ecdsa.PrivateKey) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		tmpl.SerialNumber = big.NewInt(time.Now().UnixNano())
		tmpl.NotBefore = time.Now().Add(-time.Hour)
		tmpl.NotAfter = time.Now().Add(time.Hour)
		tmpl.KeyUsage = x509.KeyUsageDigitalSignature
		der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return der, key
	}
	writePEM := func(name, typ string, der []byte) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, pem.EncodeToMemory(&pem.Block{Type: typ, Bytes: der}), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	serverCA, serverCAKey, serverCADER := newCA("host_tls alias server CA")
	leafDER, leafKey := issue(serverCA, serverCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "localhost"},
		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	clientCA, clientCAKey, _ := newCA("host_tls alias client CA")
	clientDER, clientKey := issue(clientCA, clientCAKey, &x509.Certificate{
		Subject:     pkix.Name{CommonName: "host_tls alias client"},
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	clientKeyDER, err := x509.MarshalECPrivateKey(clientKey)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(clientCA)
	return hostTLSAliasPKI{
		leaf:           tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		serverCAPath:   writePEM("server-ca.pem", "CERTIFICATE", serverCADER),
		clientCAs:      pool,
		clientCertPath: writePEM("client.pem", "CERTIFICATE", clientDER),
		clientKeyPath:  writePEM("client-key.pem", "EC PRIVATE KEY", clientKeyDER),
	}
}

// hostTLSAliasUpstream is a loopback HTTP/1.1-over-TLS upstream that
// answers every request with 200 and counts the client certificates the
// proxy presented on the last handshake.
type hostTLSAliasUpstream struct {
	port      string
	peerCerts atomic.Int64
	requests  atomic.Int64
}

func startHostTLSAliasUpstream(t *testing.T, pki hostTLSAliasPKI, requireClientCert bool) *hostTLSAliasUpstream {
	t.Helper()
	cfg := &tls.Config{
		Certificates: []tls.Certificate{pki.leaf},
		NextProtos:   []string{"http/1.1"},
		MinVersion:   tls.VersionTLS12,
	}
	if requireClientCert {
		cfg.ClientAuth = tls.RequireAndVerifyClientCert
		cfg.ClientCAs = pki.clientCAs
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	u := &hostTLSAliasUpstream{}
	_, u.port, _ = net.SplitHostPort(ln.Addr().String())
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = c.SetDeadline(time.Now().Add(10 * time.Second))
				tc := c.(*tls.Conn)
				if tc.Handshake() != nil {
					return
				}
				u.peerCerts.Store(int64(len(tc.ConnectionState().PeerCertificates)))
				req, rerr := http.ReadRequest(bufio.NewReader(tc))
				if rerr != nil {
					return
				}
				_, _ = io.Copy(io.Discard, req.Body)
				u.requests.Add(1)
				_, _ = io.WriteString(tc, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
			}(c)
		}
	}()
	return u
}

// connectTLSGet sends CONNECT authority through the proxy, completes a TLS
// handshake with the MITM leaf and issues GET path. It returns the status
// code, or an error describing where the exchange broke.
func connectTLSGet(t *testing.T, proxyAddr, host, authority, path string) (int, error) {
	t.Helper()
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := io.WriteString(c, "CONNECT "+authority+" HTTP/1.1\r\nHost: "+authority+"\r\n\r\n"); err != nil {
		return 0, fmt.Errorf("write CONNECT: %w", err)
	}
	br := bufio.NewReader(c)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		return 0, fmt.Errorf("read CONNECT reply: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("CONNECT reply %d", resp.StatusCode)
	}
	sni := host
	if net.ParseIP(host) != nil {
		sni = ""
	}
	tc := tls.Client(c, &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, //nolint:gosec // test: the MITM leaf is not what is under test
		NextProtos:         []string{"http/1.1"},
	})
	if err := tc.Handshake(); err != nil {
		return 0, fmt.Errorf("client TLS handshake through the proxy: %w", err)
	}
	if _, err := io.WriteString(tc, "GET "+path+" HTTP/1.1\r\nHost: "+authority+"\r\nConnection: close\r\n\r\n"); err != nil {
		return 0, fmt.Errorf("write GET: %w", err)
	}
	r, err := http.ReadResponse(bufio.NewReader(tc), nil)
	if err != nil {
		return 0, fmt.Errorf("read GET response: %w", err)
	}
	_ = r.Body.Close()
	return r.StatusCode, nil
}

// hostTLSAliasConfig renders a -config document with one host_tls entry per
// host, each carrying the given fields.
func hostTLSAliasConfig(t *testing.T, entry map[string]any, hosts ...string) string {
	t.Helper()
	m := map[string]any{}
	for _, h := range hosts {
		m[h] = entry
	}
	b, err := json.Marshal(map[string]any{"host_tls": m})
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// assertAliasFlowRecorded checks that the flow for path was recorded as a
// complete https 200 exchange with the verified test upstream, and that the
// recorded request keeps the authority exactly as the client wrote it (the
// fold is comparison-only).
func assertAliasFlowRecorded(t *testing.T, h *mcptest.Harness, path, authority, upstreamPort string) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		res := h.MustOK(t, "query", map[string]any{
			"resource": "flows",
			"filter":   map[string]any{"url_pattern": path, "state": "complete"},
		})
		flows, _ := res.Decoded["flows"].([]any)
		if len(flows) == 1 {
			f, _ := flows[0].(map[string]any)
			id, _ := f["id"].(string)
			d := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": id, "include_bodies": false}).Decoded
			if d["scheme"] != "https" {
				t.Errorf("flow scheme = %v, want https", d["scheme"])
			}
			if code, _ := d["response_status_code"].(float64); code != 200 {
				t.Errorf("flow response_status_code = %v, want 200", d["response_status_code"])
			}
			if u, _ := d["url"].(string); u != "https://"+authority+path {
				t.Errorf("flow url = %q, want %q (authority as written)", u, "https://"+authority+path)
			}
			hdrs, _ := d["request_headers"].(map[string]any)
			if hv, _ := hdrs["Host"].([]any); len(hv) != 1 || hv[0] != authority {
				t.Errorf("recorded Host header = %v, want [%s] verbatim", hdrs["Host"], authority)
			}
			ci, _ := d["conn_info"].(map[string]any)
			if sa, _ := ci["server_addr"].(string); !strings.HasSuffix(sa, ":"+upstreamPort) {
				t.Errorf("conn_info.server_addr = %q, want the upstream port %s", sa, upstreamPort)
			}
			if subj := ci["tls_server_cert_subject"]; subj != "CN=localhost" {
				t.Errorf("conn_info.tls_server_cert_subject = %v, want CN=localhost (the test upstream)", subj)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("query(flows, url_pattern=%s, state=complete) = %d flows, want 1: %s", path, len(flows), res.Text)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestE2E_HostTLSAlias_CABundleForRespelledCONNECT: upstream verification is
// enforced (-insecure=false) and the upstream leaf chains only to the
// per-host ca_bundle, so a CONNECT succeeds only when the entry applies.
func TestE2E_HostTLSAlias_CABundleForRespelledCONNECT(t *testing.T) {
	pki := newHostTLSAliasPKI(t)
	up := startHostTLSAliasUpstream(t, pki, false)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: hostTLSAliasConfig(t, map[string]any{"ca_bundle": pki.serverCAPath}, "localhost", "127.0.0.1"),
		ExtraArgs:  []string{"-insecure=false"},
	})
	proxyAddr := startProxy(t, h)

	for i, host := range hostTLSAliasHosts {
		t.Run(host, func(t *testing.T) {
			authority := net.JoinHostPort(host, up.port)
			path := fmt.Sprintf("/host-tls-alias-ca-%d", i)
			code, err := connectTLSGet(t, proxyAddr, host, authority, path)
			if err != nil || code != http.StatusOK {
				t.Fatalf("CONNECT %s: status=%d err=%v, want 200 (the per-host ca_bundle must verify the upstream)", authority, code, err)
			}
			assertAliasFlowRecorded(t, h, path, authority, up.port)
		})
	}
}

// TestE2E_HostTLSAlias_ClientCertForRespelledCONNECT: the upstream requires
// a client certificate signed by the client CA; only the per-host
// client_cert / client_key provide one.
func TestE2E_HostTLSAlias_ClientCertForRespelledCONNECT(t *testing.T) {
	pki := newHostTLSAliasPKI(t)
	up := startHostTLSAliasUpstream(t, pki, true)
	h := mcptest.StartHarness(t, mcptest.HarnessOptions{
		ConfigJSON: hostTLSAliasConfig(t, map[string]any{
			"client_cert": pki.clientCertPath,
			"client_key":  pki.clientKeyPath,
		}, "localhost", "127.0.0.1"),
	})
	proxyAddr := startProxy(t, h)

	for i, host := range hostTLSAliasHosts {
		t.Run(host, func(t *testing.T) {
			before := up.requests.Load()
			authority := net.JoinHostPort(host, up.port)
			path := fmt.Sprintf("/host-tls-alias-mtls-%d", i)
			code, err := connectTLSGet(t, proxyAddr, host, authority, path)
			if err != nil || code != http.StatusOK {
				t.Fatalf("CONNECT %s: status=%d err=%v, want 200 (the per-host client cert must be presented)", authority, code, err)
			}
			if got := up.requests.Load() - before; got != 1 {
				t.Errorf("upstream requests = %d, want 1", got)
			}
			if n := up.peerCerts.Load(); n != 1 {
				t.Errorf("upstream saw %d client certificates, want 1", n)
			}
			assertAliasFlowRecorded(t, h, path, authority, up.port)
		})
	}
}
