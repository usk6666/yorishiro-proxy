package connector

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/cert"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector/testutil"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestMITMAdvertiseFromUpstreamPick covers the single-element / nil
// contract of the sniff-first advertise helper (USK-997, Resolved
// Decision #15).
func TestMITMAdvertiseFromUpstreamPick(t *testing.T) {
	tests := []struct {
		name     string
		upstream string
		want     []string
	}{
		{"h2 → [h2]", "h2", []string{"h2"}},
		{"http/1.1 → [http/1.1]", "http/1.1", []string{"http/1.1"}},
		{"empty → nil (no ALPN ext at all)", "", nil},
		{"unknown → [unknown]", "spdy/3.1", []string{"spdy/3.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := mitmAdvertiseFromUpstreamPick(tt.upstream)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("mitmAdvertiseFromUpstreamPick(%q) = %v, want %v",
					tt.upstream, got, tt.want)
			}
		})
	}
}

// TestALPNListContains covers the linear-search helper used by the H2
// pool fast path to decide whether the sniffed client offer permits the
// cached h2 Layer.
func TestALPNListContains(t *testing.T) {
	tests := []struct {
		name     string
		offers   []string
		protocol string
		want     bool
	}{
		{"nil offers / empty protocol", nil, "h2", false},
		{"empty offers", []string{}, "h2", false},
		{"hit head", []string{"h2", "http/1.1"}, "h2", true},
		{"hit tail", []string{"http/1.1", "h2"}, "h2", true},
		{"miss", []string{"http/1.1"}, "h2", false},
		{"case-exact (no fold)", []string{"H2"}, "h2", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := alpnListContains(tt.offers, tt.protocol); got != tt.want {
				t.Errorf("alpnListContains(%v, %q) = %v, want %v",
					tt.offers, tt.protocol, got, tt.want)
			}
		})
	}
}

// TestPeekClientHelloSNIAndALPN_NotPeekConn covers the non-PeekConn
// branch: callers that pass a plain net.Conn get a fail-soft empty
// return, never a panic. Sibling of peekClientHelloSNI's contract.
func TestPeekClientHelloSNIAndALPN_NotPeekConn(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	peeked := peekClientHelloSNIAndALPN(a)
	if peeked.SNI != "" || peeked.ALPN != nil {
		t.Errorf("non-PeekConn: got (%q, %v), want (\"\", nil)", peeked.SNI, peeked.ALPN)
	}
}

// TestPeekClientHelloSNIAndALPN_ClosedPeekConn covers the "peek read
// fails immediately" branch (EOF before any bytes arrive). Documented
// as a Debug-logged fail-soft path.
func TestPeekClientHelloSNIAndALPN_ClosedPeekConn(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)
	_ = b.Close() // peer close → peek sees EOF
	_ = a.Close()

	peeked := peekClientHelloSNIAndALPN(pc)
	if peeked.SNI != "" || peeked.ALPN != nil {
		t.Errorf("closed conn: got (%q, %v), want (\"\", nil)", peeked.SNI, peeked.ALPN)
	}
}

// TestPeekClientHelloSNIAndALPN_NonTLSBytes covers a non-handshake
// first byte: should swallow errNotClientHello silently and return
// ("", nil).
func TestPeekClientHelloSNIAndALPN_NonTLSBytes(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)
	defer a.Close()

	go func() {
		// Send plain HTTP/1.x bytes (first byte is 0x47 'G', not 0x16).
		_, _ = b.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\n\r\n"))
	}()

	peeked := peekClientHelloSNIAndALPN(pc)
	if peeked.SNI != "" || peeked.ALPN != nil {
		t.Errorf("non-TLS bytes: got (%q, %v), want (\"\", nil)", peeked.SNI, peeked.ALPN)
	}
	_ = b.Close()
}

// TestPeekClientHelloSNIAndALPN_ValidClientHello covers the happy path:
// a real TLS ClientHello with SNI + ALPN extensions is parsed and both
// fields are populated. Uses a tls.Client goroutine to produce the
// ClientHello over a net.Pipe so we don't have to hand-assemble the
// bytes.
func TestPeekClientHelloSNIAndALPN_ValidClientHello(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)

	wantSNI := "test.example.com"
	wantALPN := []string{"h2", "http/1.1"}

	go func() {
		// tls.Client writes its ClientHello on the first read attempt.
		// Triggering Handshake from this goroutine writes the bytes
		// to the pipe; the handshake itself will then block because the
		// peer (a / pc) never replies, but that's fine — we only need
		// the ClientHello bytes to land in pc's buffer.
		conn := tls.Client(b, &tls.Config{
			ServerName:         wantSNI,
			NextProtos:         wantALPN,
			InsecureSkipVerify: true, //nolint:gosec // test
		})
		_ = conn.HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	peeked := peekClientHelloSNIAndALPN(pc)
	if peeked.SNI != wantSNI {
		t.Errorf("sni = %q, want %q", peeked.SNI, wantSNI)
	}
	if !reflect.DeepEqual(peeked.ALPN, wantALPN) {
		t.Errorf("alpn = %v, want %v", peeked.ALPN, wantALPN)
	}
	// USK-1015: a real ClientHello yields non-empty JA3/JA4.
	if peeked.ClientJA3 == "" || peeked.ClientJA4 == "" {
		t.Errorf("expected non-empty fingerprints, got ja3=%q ja4=%q", peeked.ClientJA3, peeked.ClientJA4)
	}

	_ = a.Close()
	_ = b.Close()
}

// TestPeekClientHelloSNIAndALPN_SNIOnlyNoALPN covers the partial-success
// branch where a client sends SNI but no ALPN extension. sni is
// populated; alpn is nil. The proxy then falls back for the ALPN axis
// only.
func TestPeekClientHelloSNIAndALPN_SNIOnlyNoALPN(t *testing.T) {
	a, b := net.Pipe()
	pc := NewPeekConn(a)

	wantSNI := "no-alpn.example.com"

	go func() {
		conn := tls.Client(b, &tls.Config{
			ServerName:         wantSNI,
			InsecureSkipVerify: true, //nolint:gosec // test
			// NextProtos intentionally unset → ClientHello omits the
			// ALPN extension entirely.
		})
		_ = conn.HandshakeContext(context.Background())
		_ = conn.Close()
	}()

	peeked := peekClientHelloSNIAndALPN(pc)
	if peeked.SNI != wantSNI {
		t.Errorf("sni = %q, want %q", peeked.SNI, wantSNI)
	}
	if peeked.ALPN != nil {
		t.Errorf("alpn = %v, want nil (no extension)", peeked.ALPN)
	}

	_ = a.Close()
	_ = b.Close()
}

// TestBuildSniffFirstStack_StandardBrowserShape exercises the happy
// path: client offered [h2, http/1.1], upstream picks h2 (the spec
// behaviour). Sniff-first must thread the upstream pick into the MITM
// advertise so the client also speaks h2; the resulting stack must
// route via h2.
func TestBuildSniffFirstStack_StandardBrowserShape(t *testing.T) {
	upstreamLn, _ := startHTTPSEchoWithALPN(t, []string{"h2", "http/1.1"})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	stack, _, upstreamSnap := runBuildConnectionStackSniffFirst(t, target, []string{"h2", "http/1.1"})
	defer stack.Close()

	if upstreamSnap == nil || upstreamSnap.ALPN != "h2" {
		t.Fatalf("upstream ALPN = %q, want h2 (standard browser shape regression)",
			alpnOrEmpty(upstreamSnap))
	}
	if stack.UpstreamH2Layer() == nil {
		t.Error("h2 route expected (UpstreamH2Layer is nil)")
	}
}

// TestBuildSniffFirstStack_RFC7301Violation_Demo1NextcloudRegression is
// the USK-995 reproducer. Upstream emulates demo1.nextcloud.com nginx
// returning http/1.1 even for a solo-h2 ALPN offer (RFC 7301 §3.2
// violation). Sniff-first must:
//
//   - Dial upstream with [h2, http/1.1] (client's offer);
//   - Observe upstream's wrong pick http/1.1;
//   - Advertise [http/1.1] to the MITM client;
//   - Route the resulting stack as http1 (not h2 — would crash with
//     invalid client preface, the original USK-995 symptom).
//
// Pre-USK-997 the proxy advertised what *it* thought was right
// ([h2,http/1.1]), the client picked h2, upstream had returned
// http/1.1 → mismatch dance ad nauseam → curl 0-byte timeout.
func TestBuildSniffFirstStack_RFC7301Violation_Demo1NextcloudRegression(t *testing.T) {
	upstream := testutil.StartRFC7301NonCompliantUpstream(t, func(conn net.Conn) {
		defer conn.Close()
		// Minimal HTTP/1.x echo: read until \r\n\r\n, respond 200.
		buf := make([]byte, 4096)
		for n := 0; n < len(buf); {
			nn, err := conn.Read(buf[n:])
			if err != nil {
				return
			}
			n += nn
			if bytes.Contains(buf[:n], []byte("\r\n\r\n")) {
				break
			}
		}
		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\nrfc-7301"))
	})
	defer upstream.Close()

	stack, _, upstreamSnap := runBuildConnectionStackSniffFirst(t, upstream.Addr, []string{"h2", "http/1.1"})
	defer stack.Close()

	if upstreamSnap == nil || upstreamSnap.ALPN != "http/1.1" {
		t.Fatalf("upstream ALPN = %q, want http/1.1 (RFC 7301 violator)",
			alpnOrEmpty(upstreamSnap))
	}
	if stack.UpstreamH2Layer() != nil {
		t.Error("expected non-h2 route (RFC 7301 violation upstream returned http/1.1)")
	}
	if stack.UpstreamTopmost() == nil {
		t.Error("expected upstream layer for http/1.1 route")
	}
}

// TestBuildSniffFirstStack_H1OnlyClient is the negative-control h1
// scenario: client offers only [http/1.1], upstream supports both.
// Sniff-first must:
//
//   - Dial upstream with [http/1.1] only;
//   - Receive http/1.1 back;
//   - Advertise [http/1.1] to the client;
//   - Route as http1 end-to-end (no h2 leak).
func TestBuildSniffFirstStack_H1OnlyClient(t *testing.T) {
	upstreamLn, _ := startHTTPSEchoWithALPN(t, []string{"h2", "http/1.1"})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	stack, _, upstreamSnap := runBuildConnectionStackSniffFirst(t, target, []string{"http/1.1"})
	defer stack.Close()

	if upstreamSnap == nil || upstreamSnap.ALPN != "http/1.1" {
		t.Fatalf("upstream ALPN = %q, want http/1.1 (h1-only client)",
			alpnOrEmpty(upstreamSnap))
	}
	if stack.UpstreamH2Layer() != nil {
		t.Error("h1-only client should not produce h2 route")
	}
}

// TestBuildSniffFirstStack_CachesUpstreamPick verifies that the
// sniff-first branch writes the learned upstream ALPN into the cache,
// so the legacy fallback path benefits from the warmed entry (Resolved
// Decision #13).
func TestBuildSniffFirstStack_CachesUpstreamPick(t *testing.T) {
	upstreamLn, _ := startHTTPSEchoWithALPN(t, []string{"h2", "http/1.1"})
	defer upstreamLn.Close()
	target := upstreamLn.Addr().String()

	cache := NewALPNCache(DefaultALPNCacheSize, DefaultALPNCacheTTL)
	buildCfg := newSniffFirstBuildCfg(t)
	buildCfg.ALPNCache = cache

	stack, _, _ := runBuildConnectionStackSniffFirstWithCfg(t, target, []string{"h2", "http/1.1"}, buildCfg)
	defer stack.Close()

	entry, ok := cache.Get(ALPNCacheKeyFromConfig(target, buildCfg))
	if !ok {
		t.Fatal("cache entry missing after sniff-first run")
	}
	if entry.Protocol != "h2" {
		t.Errorf("cache.Protocol = %q, want h2", entry.Protocol)
	}
}

// ---- Helpers ----

// snapshotShim exposes the TLSSnapshot.ALPN value via a tiny wrapper
// so the helpers below can return a simple struct without callers
// depending on the envelope package type surface.
type snapshotShim struct{ ALPN string }

// alpnOrEmpty extracts ALPN from a snapshotShim or returns empty.
func alpnOrEmpty(s *snapshotShim) string {
	if s == nil {
		return ""
	}
	return s.ALPN
}

// runBuildConnectionStackSniffFirst is the canonical harness: it
// creates a real BuildConfig, drives BuildConnectionStack with a
// ClientHelloPeek carrying the given ALPN list, and the test client
// performs a TLS handshake offering the same ALPN. The returned stack
// (must be Close()'d) plus both snapshots let the caller assert on
// the ALPN choice + dispatch route.
func runBuildConnectionStackSniffFirst(
	t *testing.T,
	target string,
	clientALPN []string,
) (stack *ConnectionStack, clientSnap, upstreamSnap *snapshotShim) {
	t.Helper()
	buildCfg := newSniffFirstBuildCfg(t)
	return runBuildConnectionStackSniffFirstWithCfg(t, target, clientALPN, buildCfg)
}

// runBuildConnectionStackSniffFirstWithCfg is the variant that accepts
// a pre-built BuildConfig so tests can pre-inject an ALPNCache or
// other knobs. Returns the stack plus a snapshotShim for upstream
// (the assertion surface used by the tests above).
//
// Drives the client TLS handshake on a dedicated goroutine; when the
// negotiated client-facing ALPN is h2 the helper also drives a
// ClientRole http2.Layer over the inner TLS conn so the proxy's
// ServerRole preface in buildH2Stack can complete without deadlock.
func runBuildConnectionStackSniffFirstWithCfg(
	t *testing.T,
	target string,
	clientALPN []string,
	buildCfg *BuildConfig,
) (stack *ConnectionStack, clientSnap, upstreamSnap *snapshotShim) {
	t.Helper()

	clientLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer clientLn.Close()

	type buildResult struct {
		stack        *ConnectionStack
		clientALPN   string
		upstreamALPN string
		err          error
	}
	resultCh := make(chan buildResult, 1)

	go func() {
		serverConn, accErr := clientLn.Accept()
		if accErr != nil {
			resultCh <- buildResult{err: accErr}
			return
		}
		// Wrap in PeekConn so peekClientHelloSNIAndALPN can hook.
		pc := NewPeekConn(serverConn)
		// Drive the sniff manually here (we're calling
		// BuildConnectionStack directly, not via runTLSMITM).
		peeked := peekClientHelloSNIAndALPN(pc)
		s, cs, us, bErr := BuildConnectionStack(context.Background(), pc, target, buildCfg, peeked)
		var cALPN, uALPN string
		if cs != nil {
			cALPN = cs.ALPN
		}
		if us != nil {
			uALPN = us.ALPN
		}
		resultCh <- buildResult{stack: s, clientALPN: cALPN, upstreamALPN: uALPN, err: bErr}
	}()

	clientConn, err := net.Dial("tcp", clientLn.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = clientConn.Close() })

	host, _, _ := net.SplitHostPort(target)

	clientTLS := tls.Client(clientConn, &tls.Config{
		ServerName:         host,
		NextProtos:         clientALPN,
		InsecureSkipVerify: true, //nolint:gosec // test
	})
	if hsErr := clientTLS.Handshake(); hsErr != nil {
		t.Fatalf("client TLS handshake: %v", hsErr)
	}
	t.Cleanup(func() { _ = clientTLS.Close() })

	// When the negotiated ALPN is h2 the proxy's ServerRole h2 preface
	// (inside buildH2Stack) blocks waiting for our client preface. Run a
	// ClientRole http2.Layer so the preface exchange completes — the
	// pattern used in TestBuildConnectionStack_H2MITMStack.
	negotiated := clientTLS.ConnectionState().NegotiatedProtocol
	if negotiated == ALPNProtocolH2 {
		clientH2, h2Err := http2.New(clientTLS, "sniff-first-test-client", http2.ClientRole,
			http2.WithScheme("https"),
		)
		if h2Err != nil {
			t.Fatalf("client http2.New: %v", h2Err)
		}
		t.Cleanup(func() { _ = clientH2.Close() })
	}

	select {
	case r := <-resultCh:
		if r.err != nil {
			t.Fatalf("BuildConnectionStack: %v", r.err)
		}
		// Verify the client actually saw an ALPN that makes sense.
		if r.clientALPN != "" && !sliceContains(clientALPN, r.clientALPN) {
			t.Errorf("client picked ALPN %q not in offered set %v", r.clientALPN, clientALPN)
		}
		return r.stack, &snapshotShim{ALPN: r.clientALPN}, &snapshotShim{ALPN: r.upstreamALPN}
	case <-time.After(10 * time.Second):
		t.Fatal("BuildConnectionStack timed out")
		return nil, nil, nil
	}
}

func sliceContains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}

func newSniffFirstBuildCfg(t *testing.T) *BuildConfig {
	t.Helper()
	ca := &cert.CA{}
	if err := ca.Generate(); err != nil {
		t.Fatal(err)
	}
	return &BuildConfig{
		ProxyConfig:        &config.ProxyConfig{},
		Issuer:             cert.NewIssuer(ca),
		InsecureSkipVerify: true,
	}
}

// startHTTPSEchoWithALPN starts a tls.Listen-backed server that
// advertises nextProtos and serves a minimal HTTP/1.x echo. Returns
// (listener, ALPN-picks recorder). Used by the standard-browser and
// h1-only-client tests.
func startHTTPSEchoWithALPN(t *testing.T, nextProtos []string) (net.Listener, func() []string) {
	t.Helper()
	tlsCfg, err := newSelfSignedTLSConfig("test.example.com")
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg.NextProtos = nextProtos
	ln, err := tls.Listen("tcp", "127.0.0.1:0", tlsCfg)
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var picks []string
	go func() {
		for {
			conn, accErr := ln.Accept()
			if accErr != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if tc, ok := c.(*tls.Conn); ok {
					_ = tc.SetReadDeadline(time.Now().Add(5 * time.Second))
					if hsErr := tc.HandshakeContext(context.Background()); hsErr != nil {
						return
					}
					_ = tc.SetReadDeadline(time.Time{})
					mu.Lock()
					picks = append(picks, tc.ConnectionState().NegotiatedProtocol)
					mu.Unlock()
				}
				br := bufio.NewReader(c)
				_, _ = readRequestBytes(br)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"))
			}(conn)
		}
	}()

	return ln, func() []string {
		mu.Lock()
		defer mu.Unlock()
		out := make([]string, len(picks))
		copy(out, picks)
		return out
	}
}

// readRequestBytes reads bytes until \r\n\r\n or EOF, returning what was
// read. Used only for cleanly draining the test HTTP/1.x handshake.
func readRequestBytes(br *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := br.ReadString('\n')
		buf.WriteString(line)
		if err != nil {
			if errors.Is(err, io.EOF) && buf.Len() > 0 {
				return buf.Bytes(), nil
			}
			return buf.Bytes(), err
		}
		if strings.TrimRight(line, "\r\n") == "" {
			return buf.Bytes(), nil
		}
	}
}
