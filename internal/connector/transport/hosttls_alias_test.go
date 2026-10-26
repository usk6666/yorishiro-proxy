package transport

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// USK-1384: per-host TLS entries are compared in the dial-equivalent host
// form (hostcanon.FoldDialEquivalent), on both the registration and the
// lookup side. Only the comparison key is folded: ServerName, SNI and the
// dial target stay as written.

// TestHostTLSRegistry_Lookup_DialEquivalentSpellings: a respelled server
// name that dials the same destination finds the entry instead of falling
// back to the global config.
func TestHostTLSRegistry_Lookup_DialEquivalentSpellings(t *testing.T) {
	global := &HostTLSConfig{}
	localhost := &HostTLSConfig{}
	v4 := &HostTLSConfig{}
	v6 := &HostTLSConfig{}
	wild := &HostTLSConfig{}

	reg := NewHostTLSRegistry()
	reg.SetGlobal(global)
	reg.Set("localhost", localhost)
	reg.Set("127.0.0.1", v4)
	reg.Set("::1", v6)
	reg.Set("*.example.com", wild)

	tests := []struct {
		name string
		want *HostTLSConfig
	}{
		{"localhost.", localhost},
		{"LOCALHOST.", localhost},
		{"::ffff:127.0.0.1", v4},
		{"[::ffff:127.0.0.1]", v4},
		{"0:0::ffff:7f00:1", v4},
		{"::ffff:127.0.0.1%lo", v4},
		{"0:0::1", v6},
		{"[::1]", v6},
		{"api.example.com.", wild},
		{"API.Example.COM.", wild},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := reg.Lookup(tt.name); got != tt.want {
				t.Errorf("Lookup(%q) = %p, want the per-host entry %p (global %p)", tt.name, got, tt.want, global)
			}
		})
	}
}

// TestHostTLSRegistry_Set_DialEquivalentSpellings: the registration side is
// folded too, Remove takes any equivalent spelling, and Hosts reports the
// pattern as entered.
func TestHostTLSRegistry_Set_DialEquivalentSpellings(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		lookup  string
	}{
		{"case and trailing dot", "LocalHost.", "localhost"},
		{"bracketed IPv6", "[::1]", "::1"},
		{"IPv4-mapped IPv6", "::ffff:10.0.0.5", "10.0.0.5"},
		{"wildcard case and trailing dot", "*.Example.COM.", "api.example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			global := &HostTLSConfig{}
			entry := &HostTLSConfig{}
			reg := NewHostTLSRegistry()
			reg.SetGlobal(global)
			reg.Set(tt.pattern, entry)

			if got := reg.Lookup(tt.lookup); got != entry {
				t.Errorf("Set(%q); Lookup(%q) = %p, want the entry %p (global %p)", tt.pattern, tt.lookup, got, entry, global)
			}
			hosts := reg.Hosts()
			if hosts[tt.pattern] != entry || len(hosts) != 1 {
				t.Errorf("Hosts() = %v, want exactly {%q: entry} (the pattern as entered)", hosts, tt.pattern)
			}
		})
	}

	t.Run("Remove with an equivalent spelling", func(t *testing.T) {
		global := &HostTLSConfig{}
		reg := NewHostTLSRegistry()
		reg.SetGlobal(global)
		reg.Set("localhost", &HostTLSConfig{})
		reg.Remove("localhost.")
		if got := reg.Lookup("localhost"); got != global {
			t.Errorf("after Remove(\"localhost.\"), Lookup(\"localhost\") = %p, want global %p", got, global)
		}
		if n := len(reg.Hosts()); n != 0 {
			t.Errorf("after Remove(\"localhost.\"), Hosts() has %d entries, want 0", n)
		}
	})
}

// TestHostTLSRegistry_Lookup_NonEquivalentSpellingsMiss is the negative
// control: spellings that do not dial the same destination (legacy inet_aton
// IPv4 forms, which Go's pure resolver rejects or sends to DNS; two trailing
// dots; IPv4-compatible IPv6) and wildcard depths outside the one-level
// grammar keep falling back to the global config.
//
// "[127.0.0.1]" is the bare bracketed form: the live path never passes it,
// because extractHost (net.SplitHostPort) already strips the brackets of
// "[127.0.0.1]:443", and that authority dials 127.0.0.1. As a bare host it
// is a LegacyIPv4Spelling and is compared as written.
func TestHostTLSRegistry_Lookup_NonEquivalentSpellingsMiss(t *testing.T) {
	global := &HostTLSConfig{}
	reg := NewHostTLSRegistry()
	reg.SetGlobal(global)
	reg.Set("127.0.0.1", &HostTLSConfig{})
	reg.Set("localhost", &HostTLSConfig{})
	reg.Set("*.example.com", &HostTLSConfig{})

	for _, name := range []string{
		"127.1",
		"0x7f.0.0.1",
		"2130706433",
		"0177.0.0.1",
		"127.0.0.1.",
		"[127.0.0.1]",
		"::127.0.0.1",
		"localhost..",
		"a.b.example.com",
		"example.com",
	} {
		t.Run(name, func(t *testing.T) {
			if got := reg.Lookup(name); got != global {
				t.Errorf("Lookup(%q) = %p, want global %p (not a dial-equivalent spelling of any entry)", name, got, global)
			}
		})
	}
}

// hostTLSAliasPKI is a CA and a leaf signed by it whose SANs cover
// localhost and 127.0.0.1, with the CA written as a PEM bundle.
type hostTLSAliasPKI struct {
	leaf   tls.Certificate
	caPath string
}

func newHostTLSAliasPKI(t *testing.T) hostTLSAliasPKI {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "host_tls alias test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caPath := filepath.Join(t.TempDir(), "alias-ca.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o600); err != nil {
		t.Fatal(err)
	}
	return hostTLSAliasPKI{
		leaf:   tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey},
		caPath: caPath,
	}
}

// TestTLSTransports_TLSConnect_PerHostCAForRespelledServerName: the MCP-side
// transports (resend / reflection) apply the per-host ca_bundle when the
// server name respells the entry's host. Verification is enforced
// (InsecureSkipVerify false), so only the per-host RootCAs let the handshake
// succeed.
func TestTLSTransports_TLSConnect_PerHostCAForRespelledServerName(t *testing.T) {
	pki := newHostTLSAliasPKI(t)
	reg := NewHostTLSRegistry()
	reg.Set("localhost", &HostTLSConfig{CABundlePath: pki.caPath})
	reg.Set("127.0.0.1", &HostTLSConfig{CABundlePath: pki.caPath})

	transports := map[string]TLSTransport{
		"standard": &StandardTransport{HostTLS: reg, NextProtos: []string{"http/1.1"}},
		"utls":     &UTLSTransport{Profile: ProfileChrome, HostTLS: reg, NextProtos: []string{"http/1.1"}},
	}
	for tname, tr := range transports {
		for _, sni := range []string{"localhost.", "::ffff:127.0.0.1"} {
			t.Run(tname+"/"+sni, func(t *testing.T) {
				ln := startTLSServer(t, pki.leaf, []string{"http/1.1"})
				defer ln.Close()
				conn, err := net.Dial("tcp", ln.Addr().String())
				if err != nil {
					t.Fatal(err)
				}
				defer conn.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				tlsConn, _, err := tr.TLSConnect(ctx, conn, sni)
				if err != nil {
					t.Fatalf("TLSConnect(sni=%q) = %v, want success via the per-host ca_bundle", sni, err)
				}
				_ = tlsConn.Close()
			})
		}
	}
}
