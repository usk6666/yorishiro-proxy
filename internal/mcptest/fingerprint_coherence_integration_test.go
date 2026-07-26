//go:build e2e && !e2e_smoke

// Package mcptest_test holds USK-1011's capstone verification for the M47
// Firefox Fingerprint Fidelity milestone: when tls_fingerprint=firefox is
// selected, the fingerprint the UPSTREAM observes coming FROM THE PROXY must
// be Firefox-coherent on BOTH axes —
//
//   - TLS: the proxy→upstream ClientHello's JA4 equals a uTLS
//     HelloFirefox_Auto reference (exact), and its cipher set matches
//     (structural, order-independent — the "JA3 structural" check per the
//     design review's U1: uTLS may shuffle extensions per handshake, so an
//     exact JA3 wire-order hash would be flaky, whereas JA4's sorted form is
//     shuffle- and GREASE-immune and therefore deterministic).
//   - HTTP/2: the proxy's upstream SETTINGS (wire order + values), the
//     stream-0 WINDOW_UPDATE increment, and the request pseudo-header order
//     match the Firefox FF120 goldens (USK-1007).
//
// The chrome sub-test asserts the Chrome-shape baseline (both axes) and the
// none sub-test asserts the standard-TLS / not-a-browser baseline, so an
// accidental profile bleed (e.g. "none" silently dialing Firefox) is caught
// as a regression rather than passing silently.
//
// Wiring: this drives a real HTTP/2 data-plane request through the proxy via
// a CONNECT tunnel + client-offered ALPN h2, so the MITM'd upstream leg
// negotiates h2 and the capture upstream (mcptest UpstreamProto="capture")
// records the proxy's real on-wire ClientHello + H2 frames. It runs in the
// exhaustive (non-smoke) e2e tier.
package mcptest_test

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"sort"
	"strings"
	"testing"
	"time"

	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/mcptest"
	"github.com/usk6666/yorishiro-proxy/internal/tlsfingerprint"
)

// fpH2Shape is the expected HTTP/2 send-shape for one browser profile.
type fpH2Shape struct {
	settings   []frame.Setting
	connWindow uint32
	pseudo     []string
}

// firefoxH2Shape pins the Firefox FF120 goldens (USK-1007): SETTINGS
// 1:65536, 2:0, 4:131072, 5:16384 in wire order (no MAX_CONCURRENT_STREAMS),
// a stream-0 WINDOW_UPDATE increment of 12517377, and pseudo-header order
// :method :path :authority :scheme.
var firefoxH2Shape = fpH2Shape{
	settings: []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: 65536},
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingInitialWindowSize, Value: 131072},
		{ID: frame.SettingMaxFrameSize, Value: 16384},
	},
	connWindow: 12517377,
	pseudo:     []string{":method", ":path", ":authority", ":scheme"},
}

// defaultH2Shape is the proxy's historical (Chrome-ish) baseline that every
// non-firefox profile — including "none" — resolves to via
// resolveH2Fingerprint: SETTINGS 1:4096, 2:0, 3:500, 4:16777216, 5:16384
// (MAX_CONCURRENT_STREAMS present), a 16 MiB - 65535 connection-window bump,
// and pseudo-header order :method :scheme :authority :path.
//
// It is named "default", not "chrome", because it is the proxy's own
// pre-USK-1007 send-shape rather than a real Chrome 120 capture; the chrome
// sub-test asserts it as a baseline, and the none sub-test asserts it because
// a profile claiming no browser identity has nothing to be coherent with.
var defaultH2Shape = fpH2Shape{
	settings: []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: 4096},
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingMaxConcurrentStreams, Value: 500},
		{ID: frame.SettingInitialWindowSize, Value: 16777216},
		{ID: frame.SettingMaxFrameSize, Value: 16384},
	},
	connWindow: 16777216 - 65535, // 16711681
	pseudo:     []string{":method", ":scheme", ":authority", ":path"},
}

// fpDataPlaneALPN is the ALPN offer list the data-plane client presents to
// the proxy. The MITM sniff-first path (USK-997) forwards it byte-identical
// to the upstream leg, so the offline uTLS reference must use the same list
// to produce a matching JA4.
var fpDataPlaneALPN = []string{"h2", "http/1.1"}

// TestE2E_FingerprintCoherence_UpstreamShape is the USK-1011 capstone. For
// each profile it drives one h2 request through the proxy and asserts the
// upstream-observed TLS + H2 fingerprint coherence, plus the recording
// outcomes (Stream/Flow/env.Raw) per the e2e Subsystem Verification
// Checklist.
func TestE2E_FingerprintCoherence_UpstreamShape(t *testing.T) {
	cases := []struct {
		name        string
		fingerprint string
		helloID     *utls.ClientHelloID // nil for "none" (standard crypto/tls)
		wantH2      fpH2Shape
	}{
		{"firefox", "firefox", &utls.HelloFirefox_Auto, firefoxH2Shape},
		{"chrome", "chrome", &utls.HelloChrome_Auto, defaultH2Shape},
		// USK-1021 regression: proxy_start used to install the raw "none"
		// sentinel as the live-dial override instead of resolving it to ""
		// (standard TLS) at the dial seam, so the MITM upstream dial failed
		// with `unsupported uTLS profile "none"`. Do NOT weaken the
		// assertions (MITM-diagnostic test philosophy).
		{"none", "none", nil, defaultH2Shape},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			// ResolveTLSFingerprint defaults unset → firefox, so every
			// sub-test MUST set -tls-fingerprint explicitly.
			h := mcptest.StartHarness(t, mcptest.HarnessOptions{
				TLSFingerprint: tc.fingerprint,
				UpstreamProto:  "capture",
			})
			if h.UpstreamCapture == nil {
				t.Fatal("UpstreamCapture is nil; harness wiring regressed")
			}

			startRes := h.MustOK(t, "proxy_start", map[string]any{"listen_addr": "127.0.0.1:0"})
			proxyAddr, _ := startRes.Decoded["listen_addr"].(string)
			if proxyAddr == "" {
				t.Fatalf("proxy_start: missing listen_addr in result: %s", startRes.Text)
			}

			// The capture listens on 127.0.0.1:PORT; address it as
			// localhost:PORT so the proxy sends a DNS-name SNI (matching
			// the reference build) rather than an IP literal (which
			// suppresses the SNI extension entirely).
			_, port, err := net.SplitHostPort(h.UpstreamCapture.Addr())
			if err != nil {
				t.Fatalf("split capture addr %q: %v", h.UpstreamCapture.Addr(), err)
			}
			const serverName = "localhost"
			connectTarget := net.JoinHostPort(serverName, port)
			path := "/fingerprint-" + tc.name
			url := "https://" + connectTarget + path

			// Drive one h2 request through the proxy.
			client := fpH2ClientThroughProxy(proxyAddr, connectTarget, serverName)
			resp, err := client.Get(url)
			if err != nil {
				snap := h.UpstreamCapture.Snapshot()
				t.Fatalf("h2-over-CONNECT GET failed: %v (upstream ALPN observed=%q)", err, snap.ALPN)
			}
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != gohttp.StatusOK {
				t.Errorf("status = %d, want 200", resp.StatusCode)
			}
			if !strings.Contains(string(body), "fingerprint-coherence-ok") {
				t.Errorf("body = %q, want contains %q", string(body), "fingerprint-coherence-ok")
			}

			captured := h.UpstreamCapture.WaitH2(10 * time.Second)
			snap := h.UpstreamCapture.Snapshot()

			// ALPN guard (design review U3): the capture advertises h2
			// ONLY; if the upstream leg did not negotiate h2 the H2
			// assertions would have nothing to check, so fail loudly
			// rather than silently skip.
			if snap.ALPN != "h2" {
				t.Fatalf("upstream leg ALPN = %q, want %q — the proxy did not offer/negotiate h2 upstream",
					snap.ALPN, "h2")
			}
			if !captured {
				t.Fatalf("did not capture full H2 shape within deadline: settings=%v window=%d pseudo=%v",
					snap.Settings, snap.ConnWindowIncrement, snap.PseudoOrder)
			}

			assertTLSCoherence(t, tc.name, tc.helloID, serverName, snap.ClientHelloRecord)
			assertH2Coherence(t, tc.wantH2, snap)
			assertRecording(t, h, path)
		})
	}
}

// assertTLSCoherence checks the proxy→upstream ClientHello fingerprint.
//
// For a browser profile: JA4 must equal the uTLS reference exactly, and the
// GREASE-stripped cipher set must match (order-independent — the structural
// stand-in for JA3, which is flaky under uTLS extension shuffle). For "none"
// (helloID nil): the ClientHello must be a standard crypto/tls hello — no
// GREASE ciphers, and a JA4 distinct from both browser references.
func assertTLSCoherence(t *testing.T, profile string, helloID *utls.ClientHelloID, serverName string, observed []byte) {
	t.Helper()
	if len(observed) == 0 {
		t.Fatal("no ClientHello record captured")
	}
	obsJA3, obsJA4 := tlsfingerprint.Compute(observed)
	if obsJA3 == "" || obsJA4 == "" {
		t.Fatalf("observed ClientHello produced empty fingerprints: ja3=%q ja4=%q", obsJA3, obsJA4)
	}

	if helloID != nil {
		refRecord := fpReferenceHello(t, *helloID, serverName, fpDataPlaneALPN)
		_, refJA4 := tlsfingerprint.Compute(refRecord)
		if refJA4 == "" {
			t.Fatal("reference ClientHello produced empty JA4")
		}
		// JA4: exact (sorted ciphers + sorted extensions + metadata →
		// shuffle- and GREASE-immune).
		if obsJA4 != refJA4 {
			t.Errorf("%s JA4 mismatch:\n observed = %q\n reference= %q", profile, obsJA4, refJA4)
		}
		// JA3 structural: cipher-set membership, order-independent.
		obsCiphers := fpCipherSet(observed)
		refCiphers := fpCipherSet(refRecord)
		if !fpUint16SliceEqual(obsCiphers, refCiphers) {
			t.Errorf("%s cipher set mismatch (structural JA3):\n observed = %v\n reference= %v",
				profile, obsCiphers, refCiphers)
		}
		return
	}

	// "none": standard crypto/tls. Assert it is NOT a browser fingerprint.
	_, ffJA4 := tlsfingerprint.Compute(fpReferenceHello(t, utls.HelloFirefox_Auto, serverName, fpDataPlaneALPN))
	_, chJA4 := tlsfingerprint.Compute(fpReferenceHello(t, utls.HelloChrome_Auto, serverName, fpDataPlaneALPN))
	if obsJA4 == ffJA4 {
		t.Errorf("none JA4 == firefox reference JA4 (%q); tls_fingerprint=none must NOT dial a browser profile", obsJA4)
	}
	if obsJA4 == chJA4 {
		t.Errorf("none JA4 == chrome reference JA4 (%q); tls_fingerprint=none must NOT dial a browser profile", obsJA4)
	}
	// Standard crypto/tls never emits GREASE (RFC 8701) — the "not a
	// browser" signal.
	if greased := fpGREASECiphers(observed); len(greased) > 0 {
		t.Errorf("none ClientHello contains GREASE ciphers %v; standard crypto/tls must not emit GREASE", greased)
	}
}

// assertH2Coherence checks the proxy's upstream HTTP/2 send-shape against the
// expected profile goldens.
func assertH2Coherence(t *testing.T, want fpH2Shape, snap mcptest.CaptureResult) {
	t.Helper()
	fpAssertSettingsEqual(t, snap.Settings, want.settings)
	if snap.ConnWindowIncrement != want.connWindow {
		t.Errorf("conn WINDOW_UPDATE increment = %d, want %d", snap.ConnWindowIncrement, want.connWindow)
	}
	if !fpStringSliceEqual(snap.PseudoOrder, want.pseudo) {
		t.Errorf("pseudo-header order = %v, want %v", snap.PseudoOrder, want.pseudo)
	}
}

// assertRecording verifies the Subsystem Checklist recording outcomes: the
// flow records with Protocol=http, Scheme=https, State=complete, and a
// non-empty raw_request (env.Raw preserved end-to-end through the MCP
// boundary — the L4-capable principle).
func assertRecording(t *testing.T, h *mcptest.Harness, pathSubstring string) {
	t.Helper()
	flow := fpWaitForFlow(t, h, pathSubstring, 5*time.Second)
	if flow.Protocol != "http" {
		t.Errorf("flow.protocol = %q, want %q", flow.Protocol, "http")
	}
	if flow.Scheme != "https" {
		t.Errorf("flow.scheme = %q, want %q", flow.Scheme, "https")
	}
	if flow.State != "complete" {
		t.Errorf("flow.state = %q, want %q", flow.State, "complete")
	}
	fpAssertRawRequestNonEmpty(t, h, flow.ID)
}

// ---------------------------------------------------------------------------
// TLS reference + fingerprint helpers
// ---------------------------------------------------------------------------

// fpReferenceHello builds a uTLS ClientHello for helloID with its ALPN
// extension overridden to alpn, mirroring exactly what the proxy's uTLS
// transport does (BuildHandshakeState → replace ALPNExtension →
// MarshalClientHello). It returns the full TLS record (5-byte header
// prepended) ready for tlsfingerprint.Compute.
func fpReferenceHello(t *testing.T, helloID utls.ClientHelloID, serverName string, alpn []string) []byte {
	t.Helper()
	c1, c2 := net.Pipe()
	t.Cleanup(func() { _ = c1.Close(); _ = c2.Close() })

	u := utls.UClient(c1, &utls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12}, helloID)
	if err := u.BuildHandshakeState(); err != nil {
		t.Fatalf("uTLS BuildHandshakeState: %v", err)
	}
	for _, ext := range u.Extensions {
		if a, ok := ext.(*utls.ALPNExtension); ok {
			a.AlpnProtocols = append([]string(nil), alpn...)
			break
		}
	}
	if err := u.MarshalClientHello(); err != nil {
		t.Fatalf("uTLS MarshalClientHello: %v", err)
	}
	raw := u.HandshakeState.Hello.Raw
	if len(raw) == 0 {
		t.Fatal("empty reference ClientHello raw")
	}
	rec := []byte{0x16, 0x03, 0x01, byte(len(raw) >> 8), byte(len(raw))}
	return append(rec, raw...)
}

// fpCipherSet extracts the GREASE-stripped, ascending-sorted cipher suite
// list from a raw ClientHello record. Fail-soft: returns nil on any
// truncation.
func fpCipherSet(record []byte) []uint16 {
	// record header(5) + handshake header(4) + client_version(2) +
	// random(32) = 43, then session_id (1-byte len + id), then
	// cipher_suites (2-byte len + list).
	const fixed = 5 + 4 + 2 + 32
	if len(record) < fixed+1 {
		return nil
	}
	idx := fixed
	sidLen := int(record[idx])
	idx++
	idx += sidLen
	if idx+2 > len(record) {
		return nil
	}
	clen := int(record[idx])<<8 | int(record[idx+1])
	idx += 2
	if clen%2 != 0 || idx+clen > len(record) {
		return nil
	}
	var out []uint16
	for i := 0; i < clen; i += 2 {
		c := uint16(record[idx+i])<<8 | uint16(record[idx+i+1])
		if fpIsGREASE(c) {
			continue
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// fpGREASECiphers returns the GREASE cipher values present in a raw
// ClientHello record (for the "none" not-a-browser assertion).
func fpGREASECiphers(record []byte) []uint16 {
	const fixed = 5 + 4 + 2 + 32
	if len(record) < fixed+1 {
		return nil
	}
	idx := fixed
	sidLen := int(record[idx])
	idx++
	idx += sidLen
	if idx+2 > len(record) {
		return nil
	}
	clen := int(record[idx])<<8 | int(record[idx+1])
	idx += 2
	if clen%2 != 0 || idx+clen > len(record) {
		return nil
	}
	var out []uint16
	for i := 0; i < clen; i += 2 {
		c := uint16(record[idx+i])<<8 | uint16(record[idx+i+1])
		if fpIsGREASE(c) {
			out = append(out, c)
		}
	}
	return out
}

// fpIsGREASE reports whether v is an RFC 8701 GREASE value (0x?A?A with equal
// bytes).
func fpIsGREASE(v uint16) bool {
	hi := byte(v >> 8)
	lo := byte(v)
	return hi == lo && lo&0x0f == 0x0a
}

// ---------------------------------------------------------------------------
// Data-plane client (CONNECT tunnel → TLS(h2) → HTTP/2)
// ---------------------------------------------------------------------------

// fpH2ClientThroughProxy builds an http.Client that tunnels an HTTP/2
// request through the proxy: CONNECT to connectTarget, then a TLS handshake
// (ALPN h2 first) so the proxy MITMs the leg and negotiates h2 with the
// capture upstream. InsecureSkipVerify accepts the proxy's ephemeral-CA MITM
// leaf.
func fpH2ClientThroughProxy(proxyAddr, connectTarget, serverName string) *gohttp.Client {
	tr := &http2.Transport{
		DialTLS: func(_, _ string, _ *tls.Config) (net.Conn, error) {
			raw, err := fpDialCONNECTTunnel(proxyAddr, connectTarget)
			if err != nil {
				return nil, err
			}
			tconn := tls.Client(raw, &tls.Config{
				ServerName:         serverName,
				NextProtos:         fpDataPlaneALPN,
				InsecureSkipVerify: true, //nolint:gosec // test data-plane client trusts the proxy MITM leaf
			})
			if err := tconn.Handshake(); err != nil {
				_ = raw.Close()
				return nil, fmt.Errorf("data-plane TLS handshake: %w", err)
			}
			if got := tconn.ConnectionState().NegotiatedProtocol; got != "h2" {
				_ = tconn.Close()
				return nil, fmt.Errorf("client-proxy leg negotiated ALPN %q, want h2", got)
			}
			return tconn, nil
		},
	}
	return &gohttp.Client{Transport: tr, Timeout: 30 * time.Second}
}

// fpDialCONNECTTunnel opens a CONNECT tunnel to proxyAddr for target and
// returns the post-200 raw connection. Uniquely named to avoid colliding
// with connect_modes_smoke's dialCONNECTTunnel (both compile into the same
// package under -tags e2e).
func fpDialCONNECTTunnel(proxyAddr, target string) (net.Conn, error) {
	c, err := net.DialTimeout("tcp", proxyAddr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	req := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
	if _, err := c.Write([]byte(req)); err != nil {
		_ = c.Close()
		return nil, err
	}
	br := bufio.NewReader(c)
	line, err := br.ReadString('\n')
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	if !strings.Contains(line, "200") {
		_ = c.Close()
		return nil, fmt.Errorf("CONNECT failed: %s", line)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil {
			_ = c.Close()
			return nil, err
		}
		if l == "\r\n" || l == "\n" {
			break
		}
	}
	if br.Buffered() > 0 {
		_ = c.Close()
		return nil, fmt.Errorf("unexpected buffered bytes after CONNECT response")
	}
	return c, nil
}

// ---------------------------------------------------------------------------
// Recording query helpers
// ---------------------------------------------------------------------------

// fpFlowEntry is the subset of query("flows") we read. Uniquely named to
// avoid colliding with connect_modes_smoke's connectModeFlow.
type fpFlowEntry struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Scheme   string `json:"scheme"`
	State    string `json:"state"`
	URL      string `json:"url"`
}

// fpWaitForFlow polls query("flows") until a completed flow whose URL
// contains pathSubstring appears, or the timeout elapses.
func fpWaitForFlow(t *testing.T, h *mcptest.Harness, pathSubstring string, timeout time.Duration) fpFlowEntry {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		res := h.MustOK(t, "query", map[string]any{"resource": "flows"})
		var parsed struct {
			Flows []fpFlowEntry `json:"flows"`
		}
		if err := json.Unmarshal([]byte(res.Text), &parsed); err != nil {
			t.Fatalf("decode query(flows): %v (text=%q)", err, res.Text)
		}
		for _, f := range parsed.Flows {
			if strings.Contains(f.URL, pathSubstring) && f.State == "complete" {
				return f
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no completed flow with URL containing %q within %v; flows=%+v",
				pathSubstring, timeout, parsed.Flows)
		}
		time.Sleep(30 * time.Millisecond)
	}
}

// fpAssertRawRequestNonEmpty asserts query("flow", id) returns a non-empty,
// base64-decodable raw_request — proof env.Raw survived to the MCP boundary
// unmodified (L4-capable principle; fingerprinting must not touch env.Raw).
func fpAssertRawRequestNonEmpty(t *testing.T, h *mcptest.Harness, flowID string) {
	t.Helper()
	res := h.MustOK(t, "query", map[string]any{"resource": "flow", "id": flowID})
	rawB64, _ := res.Decoded["raw_request"].(string)
	if rawB64 == "" {
		t.Errorf("flow %s raw_request is empty (L4-capable principle violated); response=%s", flowID, res.Text)
		return
	}
	decoded, err := base64.StdEncoding.DecodeString(rawB64)
	if err != nil {
		t.Errorf("flow %s raw_request is not valid base64: %v", flowID, err)
		return
	}
	if len(decoded) == 0 {
		t.Errorf("flow %s raw_request decoded to zero bytes (L4-capable principle violated)", flowID)
	}
}

// ---------------------------------------------------------------------------
// Small assertion helpers
// ---------------------------------------------------------------------------

func fpAssertSettingsEqual(t *testing.T, got, want []frame.Setting) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("SETTINGS length = %d, want %d\n got=%+v\nwant=%+v", len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].ID != want[i].ID || got[i].Value != want[i].Value {
			t.Fatalf("SETTINGS[%d] = {ID:%d Value:%d}, want {ID:%d Value:%d}\n got=%+v\nwant=%+v",
				i, got[i].ID, got[i].Value, want[i].ID, want[i].Value, got, want)
		}
	}
}

func fpStringSliceEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func fpUint16SliceEqual(a, b []uint16) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
