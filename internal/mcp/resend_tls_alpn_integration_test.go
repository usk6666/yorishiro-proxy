//go:build e2e && !e2e_smoke

package mcp

// resend_tls_alpn_integration_test.go — USK-717 / USK-718 acceptance gate
// for resend_http and resend_raw against HTTPS upstreams.
//
// Pre-USK-717 the resend TLS dial path discarded the ALPN result from
// transport.TLSConnect and always wrapped the post-handshake conn in an
// http1.New Layer. Combined with StandardTransport offering ["h2","http/1.1"]
// and uTLS Chrome offering an h2-capable ClientHello, any modern HTTPS
// upstream that selected h2 caused the resend request to be silently
// reinterpreted as a malformed HTTP/2 connection preface — the wire failed
// with EOF / parse error / timeout, never reaching application code.
//
// Pre-USK-718 resend_raw built a naked tls.Config and bypassed the
// configured TLSTransport entirely, so any uTLS fingerprint was silently
// dropped.
//
// The fix clones the configured TLSTransport with NextProtos=["http/1.1"]
// for the single TLS handshake performed by resend_http / resend_ws /
// resend_raw, and routes resend_raw through the same TLSTransport that
// the other resend tools use.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// startResendHTTPSEcho stands up an HTTPS server that offers BOTH h2 and
// http/1.1 in ALPN. Returns the negotiated ALPN of the most recent accepted
// connection via the getter. Pre-USK-717 the resend path would have ended
// up on h2 here and failed at the http1.New Layer.
func startResendHTTPSEcho(t *testing.T) (*httptest.Server, func() string) {
	t.Helper()
	var lastALPN atomic.Pointer[string]

	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		if r.TLS != nil {
			p := r.TLS.NegotiatedProtocol
			lastALPN.Store(&p)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"path":  r.URL.Path,
			"proto": r.Proto,
		})
	}))
	srv.EnableHTTP2 = true
	srv.TLS = &tls.Config{
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv, func() string {
		if p := lastALPN.Load(); p != nil {
			return *p
		}
		return ""
	}
}

// setupResendHTTPSSession boots an MCP server pre-wired with the supplied
// TLSTransport and an in-memory pluginv2 Engine. The transport is the
// surface USK-717 / USK-718 fix and is the only knob the test varies.
// Returns the client session and the underlying flow.Store so resend_raw
// tests can seed a recorded RawMessage.
func setupResendHTTPSSession(t *testing.T, tlsTransport transport.TLSTransport) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	engine := pluginv2.NewEngine(nil)

	ctx := context.Background()
	srv := newServer(ctx, nil, store, nil,
		WithPluginv2Engine(engine),
		WithTLSTransport(tlsTransport),
	)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })

	client := gomcp.NewClient(&gomcp.Implementation{Name: "resend-tls-alpn-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })

	return cs, store
}

// TestResendHTTP_HTTPS_StandardTransport_NegotiatesHTTP11 covers USK-717
// against an HTTPS server that offers ["h2","http/1.1"] using a
// StandardTransport. Pre-fix this would silently negotiate h2 (the default
// NextProtos for StandardTransport is ["h2","http/1.1"]) and the request
// would fail at the http1 Layer — the fix forces http/1.1 ALPN at the
// resend dial site.
func TestResendHTTP_HTTPS_StandardTransport_NegotiatesHTTP11(t *testing.T) {
	echo, getALPN := startResendHTTPSEcho(t)
	authority := echo.Listener.Addr().String()

	cs, _ := setupResendHTTPSSession(t, &transport.StandardTransport{InsecureSkipVerify: true})

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "https",
		"authority": authority,
		"path":      "/ping",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("resend_http over HTTPS failed (USK-717 regression): %s", extractTextContent(res))
	}

	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
	if alpn := getALPN(); alpn != "http/1.1" {
		t.Errorf("server-side negotiated ALPN = %q, want http/1.1", alpn)
	}
}

// TestResendHTTP_HTTPS_UTLSChrome_NegotiatesHTTP11 covers the production
// shape: proxy_start forces uTLS Chrome by default. Chrome's ClientHello
// includes h2 in ALPN, so pre-USK-717 a naive resend would silently end
// up on an h2 connection and fail. The fix preserves the rest of the
// Chrome fingerprint while pinning ALPN to http/1.1 at the resend site.
func TestResendHTTP_HTTPS_UTLSChrome_NegotiatesHTTP11(t *testing.T) {
	echo, getALPN := startResendHTTPSEcho(t)
	authority := echo.Listener.Addr().String()

	cs, _ := setupResendHTTPSSession(t, &transport.UTLSTransport{
		Profile:            transport.ProfileChrome,
		InsecureSkipVerify: true,
	})

	res := callResendHTTP(t, cs, map[string]any{
		"method":    "GET",
		"scheme":    "https",
		"authority": authority,
		"path":      "/ping",
		"headers": []map[string]any{
			{"name": "Host", "value": authority},
		},
		"timeout_ms": 5000,
	})
	if res.IsError {
		t.Fatalf("resend_http with uTLS Chrome over HTTPS failed (USK-717 regression): %s", extractTextContent(res))
	}

	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", out.StatusCode)
	}
	if alpn := getALPN(); alpn != "http/1.1" {
		t.Errorf("server-side negotiated ALPN = %q, want http/1.1", alpn)
	}
}

// TestResendRaw_HTTPS_RoutesViaTLSTransport covers USK-718. Wires a
// recording TLSTransport that wraps a StandardTransport and increments a
// counter on every TLSConnect call. Pre-fix resend_raw built a naked
// tls.Config and bypassed the transport entirely, so the counter would
// stay at zero. Post-fix resend_raw goes through the configured transport
// and the counter increments.
func TestResendRaw_HTTPS_RoutesViaTLSTransport(t *testing.T) {
	// Plain TLS listener (no HTTP) so the dial succeeds and the recording
	// transport's TLSConnect is exercised. We don't drive a full request
	// through — the assertion is "the configured TLSTransport handled the
	// handshake", proven by the recorder counter.
	cert := alpnTestCert(t, "127.0.0.1")
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				for {
					if _, rerr := c.Read(buf); rerr != nil {
						return
					}
				}
			}(c)
		}
	}()

	rec := &recordingTLSTransport{
		inner: &transport.StandardTransport{InsecureSkipVerify: true},
	}
	cs, store := setupResendHTTPSSession(t, rec)

	original := []byte("GET /seed HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
	streamID := seedRawStream(t, store, original)

	addr := ln.Addr().String()
	res, err := cs.CallTool(context.Background(), &gomcp.CallToolParams{
		Name: "resend_raw",
		Arguments: map[string]any{
			"flow_id":              streamID,
			"target_addr":          addr,
			"use_tls":              true,
			"sni":                  "127.0.0.1",
			"insecure_skip_verify": true,
			"timeout_ms":           1500,
		},
	})
	if err != nil {
		t.Fatalf("CallTool resend_raw: %v", err)
	}
	// The dial may legitimately time out (server reads forever) — what
	// matters is whether the configured TLSTransport was consulted.
	_ = res

	if got := atomic.LoadInt32(&rec.calls); got == 0 {
		t.Fatal("recordingTLSTransport.TLSConnect was never called — resend_raw bypassed the configured transport (USK-718 regression)")
	}
	if rec.lastSNI != "127.0.0.1" {
		t.Errorf("recorded SNI = %q, want 127.0.0.1", rec.lastSNI)
	}
}

// recordingTLSTransport delegates to inner and increments calls every
// time TLSConnect runs. Used to prove resend_raw consults the configured
// TLSTransport (USK-718).
type recordingTLSTransport struct {
	inner   transport.TLSTransport
	calls   int32
	lastSNI string
}

func (r *recordingTLSTransport) TLSConnect(ctx context.Context, conn net.Conn, serverName string) (net.Conn, string, error) {
	atomic.AddInt32(&r.calls, 1)
	r.lastSNI = serverName
	if r.inner == nil {
		return nil, "", errors.New("recordingTLSTransport: nil inner")
	}
	return r.inner.TLSConnect(ctx, conn, serverName)
}

// alpnTestCert produces a self-signed certificate for the supplied
// hostname. Local copy mirrors newResendRawTestTLSConfig in
// resend_raw_integration_test.go without dragging in its full helper.
func alpnTestCert(t *testing.T, hostname string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: hostname},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{hostname},
		IPAddresses:  []net.IP{net.ParseIP(hostname)},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}
