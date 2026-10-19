//go:build e2e && !e2e_smoke

package mcp

// resend_http_h2_integration_test.go — USK-1198 acceptance gate.
//
// Before USK-1198, resend_http / fuzz_http pinned TLS ALPN to http/1.1 and
// always drove an internal/layer/http1 Layer, so an HTTP/2-recorded flow was
// silently re-sent as HTTP/1.1 (GitHub issue 137 verification on v0.20.0).
// These tests drive the real MCP tool against upstreams that observe the
// protocol server-side: a raw x/net Framer upstream that only speaks HTTP/2
// (and records the HPACK field list, the client SETTINGS and the ClientHello
// shape), net/http upstreams that report r.Proto, and an h2c upstream.

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"

	"github.com/usk6666/yorishiro-proxy/internal/connector/transport"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// ---------------------------------------------------------------------------
// Upstream fixtures
// ---------------------------------------------------------------------------

// rawH2Request is one request observed by rawH2Upstream.
type rawH2Request struct {
	alpn     string
	hello    string // "chrome-utls" | "firefox-utls" | "standard"
	settings []http2.Setting
	fields   []hpack.HeaderField
}

func (r rawH2Request) field(name string) (string, bool) {
	for _, f := range r.fields {
		if f.Name == name {
			return f.Value, true
		}
	}
	return "", false
}

// rawH2Upstream is a TLS listener that offers ALPN "h2" only and speaks
// nothing but HTTP/2 (x/net Framer + HPACK): a connection that does not
// open with the HTTP/2 client preface is dropped without a response. It
// records, per request, the negotiated ALPN, a ClientHello verdict, the
// client's SETTINGS frame and the decoded request header block in wire
// order — which is how a test sees that no synthetic host header was sent
// and that :authority is the recorded authority.
type rawH2Upstream struct {
	ln net.Listener

	mu       sync.Mutex
	requests []rawH2Request
	conns    int
	got      chan struct{}
}

// clientHelloVerdict classifies a ClientHello: GREASE in cipher_suites
// (RFC 8701) is the uTLS Chrome tell; the FFDHE groups 256/257 in
// supported_groups are the uTLS Firefox tell. Go's crypto/tls emits
// neither.
func clientHelloVerdict(hello *tls.ClientHelloInfo) string {
	for _, cs := range hello.CipherSuites {
		if byte(cs>>8) == byte(cs) && byte(cs)&0x0F == 0x0A {
			return "chrome-utls"
		}
	}
	for _, g := range hello.SupportedCurves {
		if g == 256 || g == 257 {
			return "firefox-utls"
		}
	}
	return "standard"
}

func startRawH2Upstream(t *testing.T) *rawH2Upstream {
	t.Helper()
	u := &rawH2Upstream{got: make(chan struct{}, 16)}
	cert := alpnTestCert(t, "127.0.0.1")
	var lastHello atomic.Pointer[string]
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2"},
		MinVersion:   tls.VersionTLS12,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			v := clientHelloVerdict(hello)
			lastHello.Store(&v)
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	u.ln = ln
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, aerr := ln.Accept()
			if aerr != nil {
				return
			}
			go u.serve(c.(*tls.Conn), &lastHello)
		}
	}()
	return u
}

func (u *rawH2Upstream) addr() string { return u.ln.Addr().String() }

func (u *rawH2Upstream) serve(c *tls.Conn, lastHello *atomic.Pointer[string]) {
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))
	if err := c.Handshake(); err != nil {
		return
	}
	u.mu.Lock()
	u.conns++
	u.mu.Unlock()
	req := rawH2Request{alpn: c.ConnectionState().NegotiatedProtocol, hello: "standard"}
	if v := lastHello.Load(); v != nil {
		req.hello = *v
	}

	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(c, preface); err != nil || string(preface) != http2.ClientPreface {
		return // not HTTP/2: an h2-only server has nothing to say
	}
	fr := http2.NewFramer(c, c)
	if err := fr.WriteSettings(); err != nil {
		return
	}
	dec := hpack.NewDecoder(4096, func(f hpack.HeaderField) { req.fields = append(req.fields, f) })
	respond := func(streamID uint32) {
		u.mu.Lock()
		u.requests = append(u.requests, req)
		u.mu.Unlock()
		select {
		case u.got <- struct{}{}:
		default:
		}
		var hb bytes.Buffer
		enc := hpack.NewEncoder(&hb)
		_ = enc.WriteField(hpack.HeaderField{Name: ":status", Value: "200"})
		_ = enc.WriteField(hpack.HeaderField{Name: "content-type", Value: "text/plain"})
		_ = fr.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: hb.Bytes(), EndHeaders: true})
		_ = fr.WriteData(streamID, true, []byte("h2-only-ok"))
	}
	for {
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		switch f := f.(type) {
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			if req.settings == nil {
				_ = f.ForeachSetting(func(s http2.Setting) error {
					req.settings = append(req.settings, s)
					return nil
				})
			}
			_ = fr.WriteSettingsAck()
		case *http2.PingFrame:
			if !f.IsAck() {
				_ = fr.WritePing(true, f.Data)
			}
		case *http2.HeadersFrame:
			if _, err := dec.Write(f.HeaderBlockFragment()); err != nil {
				return
			}
			if f.StreamEnded() {
				respond(f.StreamID)
			}
		case *http2.DataFrame:
			if f.StreamEnded() {
				respond(f.StreamID)
			}
		}
	}
}

func (u *rawH2Upstream) waitRequest(t *testing.T, n int, timeout time.Duration) rawH2Request {
	t.Helper()
	deadline := time.After(timeout)
	for {
		u.mu.Lock()
		if len(u.requests) >= n {
			r := u.requests[n-1]
			u.mu.Unlock()
			return r
		}
		conns := u.conns
		u.mu.Unlock()
		select {
		case <-u.got:
		case <-deadline:
			t.Fatalf("h2-only upstream saw fewer than %d HTTP/2 requests within %v (%d TLS connections accepted)", n, timeout, conns)
		}
	}
}

// protoRecorder is a net/http upstream handler that records r.Proto per
// request — the server-side observation of the protocol the resend used.
type protoRecorder struct {
	mu     sync.Mutex
	protos []string
	hosts  []string
}

func (p *protoRecorder) handler(earlyHints bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		p.mu.Lock()
		p.protos = append(p.protos, r.Proto)
		p.hosts = append(p.hosts, r.Host)
		p.mu.Unlock()
		if earlyHints {
			w.Header().Set("Link", "</style.css>; rel=preload; as=style")
			w.WriteHeader(http.StatusEarlyHints)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, "proto-ok")
	})
}

func (p *protoRecorder) snapshot() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.protos...)
}

// startProtoTLSUpstream starts an httptest TLS server whose ALPN offer is
// nextProtos; h2 handling is enabled iff nextProtos contains "h2".
func startProtoTLSUpstream(t *testing.T, nextProtos []string, earlyHints bool) (*httptest.Server, *protoRecorder) {
	t.Helper()
	rec := &protoRecorder{}
	srv := httptest.NewUnstartedServer(rec.handler(earlyHints))
	for _, p := range nextProtos {
		if p == "h2" {
			srv.EnableHTTP2 = true
		}
	}
	srv.TLS = &tls.Config{NextProtos: nextProtos, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	return srv, rec
}

// ---------------------------------------------------------------------------
// Session / store helpers
// ---------------------------------------------------------------------------

// setupResendHTTPVersionSession boots an MCP server with tlsTransport and,
// when fingerprint != "", a fingerprint setter that currentTLSFingerprint
// consults (the h2 Layer shapes SETTINGS from it, USK-1007).
func setupResendHTTPVersionSession(t *testing.T, tlsTransport transport.TLSTransport, fingerprint string) (*gomcp.ClientSession, flow.Store) {
	t.Helper()
	store := newTestStore(t)
	ctx := context.Background()
	opts := []ServerOption{
		WithPluginv2Engine(pluginv2.NewEngine(nil)),
		WithTLSTransport(tlsTransport),
	}
	if fingerprint != "" {
		opts = append(opts, WithTLSFingerprintSetter(&mockTLSFingerprintSetter{profile: fingerprint, transport: tlsTransport}))
	}
	srv := newServer(ctx, nil, store, nil, opts...)
	ct, st := gomcp.NewInMemoryTransports()
	ss, err := srv.server.Connect(ctx, st, nil)
	if err != nil {
		t.Fatalf("server connect: %v", err)
	}
	t.Cleanup(func() { ss.Close() })
	client := gomcp.NewClient(&gomcp.Implementation{Name: "usk1198-test", Version: "v0.0.1"}, nil)
	cs, err := client.Connect(ctx, ct, nil)
	if err != nil {
		t.Fatalf("client connect: %v", err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs, store
}

// flowVersions returns the http_version of the semantic send and receive
// Flows recorded under streamID (receive = the last receive Flow).
func flowVersions(t *testing.T, store flow.Store, streamID string) (send, recv string, recvStatuses []int) {
	t.Helper()
	flows, err := store.GetFlows(context.Background(), streamID, flow.FlowListOptions{WireLevel: flow.WireLevelSemantic})
	if err != nil {
		t.Fatalf("GetFlows(%s): %v", streamID, err)
	}
	for _, f := range flows {
		switch f.Direction {
		case "send":
			if send == "" {
				send = f.HTTPVersion
			}
		case "receive":
			recv = f.HTTPVersion
			recvStatuses = append(recvStatuses, f.StatusCode)
		}
	}
	return send, recv, recvStatuses
}

// resendStream returns the single Origin=resend Stream in store.
func resendStream(t *testing.T, store flow.Store) *flow.Stream {
	t.Helper()
	streams, err := store.ListStreams(context.Background(), flow.StreamListOptions{})
	if err != nil {
		t.Fatalf("ListStreams: %v", err)
	}
	for _, s := range streams {
		if s.Origin == flow.OriginResend {
			return s
		}
	}
	t.Fatalf("no Origin=resend Stream recorded (%d streams total)", len(streams))
	return nil
}

// h2RecordedHeaders is the header shape the live HTTP/2 recorder stores:
// lowercase names, no pseudo-headers, no host (RFC 9113 §8.2.1, §8.3.1).
func h2RecordedHeaders() map[string][]string {
	return map[string][]string{
		"user-agent": {"curl/8.5.0"},
		"accept":     {"*/*"},
	}
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestResendHTTP_H2Flow_H2OnlyUpstream covers AC "an h2-recorded flow can
// be resent to an upstream whose ALPN is h2-only" plus the wire shape of
// the HTTP/2 request: :authority / :scheme / :path come from the recorded
// flow and no synthetic host header is added. Both new Flows record "h2".
func TestResendHTTP_H2Flow_H2OnlyUpstream(t *testing.T) {
	up := startRawH2Upstream(t)
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+up.addr()+"/h2only?x=1", "h2", h2RecordedHeaders())

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
	if res.IsError {
		t.Fatalf("resend_http of an h2 flow to an h2-only upstream failed: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 || out.Body != "h2-only-ok" {
		t.Errorf("result = %d %q, want 200 %q", out.StatusCode, out.Body, "h2-only-ok")
	}

	req := up.waitRequest(t, 1, 5*time.Second)
	if req.alpn != "h2" {
		t.Errorf("negotiated ALPN = %q, want h2", req.alpn)
	}
	for name, want := range map[string]string{
		":method":    "GET",
		":scheme":    "https",
		":authority": up.addr(),
		":path":      "/h2only?x=1",
		"user-agent": "curl/8.5.0",
	} {
		if got, ok := req.field(name); !ok || got != want {
			t.Errorf("upstream field %s = %q (present=%v), want %q", name, got, ok, want)
		}
	}
	if v, ok := req.field("host"); ok {
		t.Errorf("upstream saw a synthetic host header %q; HTTP/2 carries the target in :authority only", v)
	}

	send, recv, _ := flowVersions(t, store, out.StreamID)
	if send != "h2" || recv != "h2" {
		t.Errorf("recorded http_version send=%q receive=%q, want h2/h2", send, recv)
	}
}

// TestResendHTTP_H2Flow_UTLSProfiles covers AC "h2 resend works with uTLS
// fingerprints (chrome / firefox)" — the combination USK-717 broke. The
// upstream checks that the ClientHello really was the uTLS profile, that
// the connection is HTTP/2, and that the HTTP/2 SETTINGS follow the
// configured fingerprint (Firefox advertises a 131072-byte stream window;
// the default shape a 16 MiB one).
func TestResendHTTP_H2Flow_UTLSProfiles(t *testing.T) {
	cases := []struct {
		name        string
		profile     transport.BrowserProfile
		wantHello   string
		wantInitWin uint32
	}{
		{name: "chrome", profile: transport.ProfileChrome, wantHello: "chrome-utls", wantInitWin: 16 << 20},
		{name: "firefox", profile: transport.ProfileFirefox, wantHello: "firefox-utls", wantInitWin: 131072},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			up := startRawH2Upstream(t)
			cs, store := setupResendHTTPVersionSession(t, &transport.UTLSTransport{Profile: tc.profile, InsecureSkipVerify: true}, tc.name)
			flowID := saveVersionedHTTPFlow(t, store, "https://"+up.addr()+"/utls", "h2", h2RecordedHeaders())

			res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
			if res.IsError {
				t.Fatalf("resend_http with uTLS %s failed: %s", tc.name, extractTextContent(res))
			}
			req := up.waitRequest(t, 1, 5*time.Second)
			if req.alpn != "h2" {
				t.Errorf("negotiated ALPN = %q, want h2", req.alpn)
			}
			if req.hello != tc.wantHello {
				t.Errorf("ClientHello verdict = %q, want %q", req.hello, tc.wantHello)
			}
			var initWin uint32
			for _, s := range req.settings {
				if s.ID == http2.SettingInitialWindowSize {
					initWin = s.Val
				}
			}
			if initWin != tc.wantInitWin {
				t.Errorf("client SETTINGS_INITIAL_WINDOW_SIZE = %d, want %d (settings %v)", initWin, tc.wantInitWin, req.settings)
			}
		})
	}
}

// TestResendHTTP_H2Flow_UpstreamRefusesH2_Errors pins the no-silent-fallback
// rule: an upstream that does not negotiate h2 fails the resend with an
// error naming the negotiated ALPN, the Stream ends in state "error", and
// no request reaches the upstream.
func TestResendHTTP_H2Flow_UpstreamRefusesH2_Errors(t *testing.T) {
	srv, rec := startProtoTLSUpstream(t, []string{"http/1.1"}, false)
	authority := srv.Listener.Addr().String()
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+authority+"/refuse", "h2", h2RecordedHeaders())

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
	if !res.IsError {
		t.Fatalf("resend_http of an h2 flow to an http/1.1-only upstream succeeded; want an error (upstream saw %v)", rec.snapshot())
	}
	msg := extractTextContent(res)
	if !strings.Contains(msg, `"http/1.1"`) || !strings.Contains(msg, "h2") || !strings.Contains(msg, "http_version") {
		t.Errorf("error = %q, want it to name the negotiated ALPN \"http/1.1\", h2, and the http_version override", msg)
	}
	if got := rec.snapshot(); len(got) != 0 {
		t.Errorf("upstream received %v; want no request after the ALPN mismatch", got)
	}
	if st := resendStream(t, store); st.State != "error" {
		t.Errorf("resend Stream.State = %q, want error", st.State)
	}
}

// TestResendHTTP_H2Flow_ExplicitHTTP11Override covers the explicit
// downgrade: http_version "http/1.1" on an h2 flow sends HTTP/1.1 and the
// new Flows record it.
func TestResendHTTP_H2Flow_ExplicitHTTP11Override(t *testing.T) {
	srv, rec := startProtoTLSUpstream(t, []string{"http/1.1"}, false)
	authority := srv.Listener.Addr().String()
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+authority+"/downgrade", "h2", h2RecordedHeaders())

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "http_version": "http/1.1", "timeout_ms": 5000})
	if res.IsError {
		t.Fatalf("resend_http http_version=http/1.1 failed: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if got := rec.snapshot(); len(got) != 1 || got[0] != "HTTP/1.1" {
		t.Errorf("upstream protos = %v, want [HTTP/1.1]", got)
	}
	send, recv, _ := flowVersions(t, store, out.StreamID)
	if send != "http/1.1" || recv != "http/1.1" {
		t.Errorf("recorded http_version send=%q receive=%q, want http/1.1/http/1.1", send, recv)
	}
}

// TestResendHTTP_H1Flow_StaysHTTP11 is the USK-717 guard for flow_id
// resends: an HTTP/1.1-recorded flow against an upstream offering
// ["h2","http/1.1"] still negotiates http/1.1, and the new Send Flow now
// records "http/1.1" (it used to record "").
func TestResendHTTP_H1Flow_StaysHTTP11(t *testing.T) {
	for _, tc := range []struct {
		name string
		tr   transport.TLSTransport
	}{
		{"standard", &transport.StandardTransport{InsecureSkipVerify: true}},
		{"utls_chrome", &transport.UTLSTransport{Profile: transport.ProfileChrome, InsecureSkipVerify: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv, rec := startProtoTLSUpstream(t, []string{"h2", "http/1.1"}, false)
			authority := srv.Listener.Addr().String()
			cs, store := setupResendHTTPVersionSession(t, tc.tr, "")
			flowID := saveVersionedHTTPFlow(t, store, "https://"+authority+"/h1", "http/1.1", map[string][]string{"User-Agent": {"curl/8.5.0"}})

			res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
			if res.IsError {
				t.Fatalf("resend_http of an h1 flow failed: %s", extractTextContent(res))
			}
			var out resendHTTPResult
			decodeStructuredResult(t, res, &out)
			if got := rec.snapshot(); len(got) != 1 || got[0] != "HTTP/1.1" {
				t.Errorf("upstream protos = %v, want [HTTP/1.1]", got)
			}
			send, recv, _ := flowVersions(t, store, out.StreamID)
			if send != "http/1.1" || recv != "http/1.1" {
				t.Errorf("recorded http_version send=%q receive=%q, want http/1.1/http/1.1", send, recv)
			}
		})
	}
}

// TestResendHTTP_H2CFlow_PriorKnowledge covers h2c: an h2c-recorded flow is
// re-sent over cleartext HTTP/2 with prior knowledge (RFC 9113 §3.3) and
// both new Flows record "h2c".
func TestResendHTTP_H2CFlow_PriorKnowledge(t *testing.T) {
	rec := &protoRecorder{}
	srv := httptest.NewUnstartedServer(rec.handler(false))
	srv.Config.Protocols = new(http.Protocols)
	srv.Config.Protocols.SetHTTP1(true)
	srv.Config.Protocols.SetUnencryptedHTTP2(true)
	srv.Start()
	t.Cleanup(srv.Close)
	authority := srv.Listener.Addr().String()
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "http://"+authority+"/h2c", "h2c", h2RecordedHeaders())

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
	if res.IsError {
		t.Fatalf("resend_http of an h2c flow failed: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if got := rec.snapshot(); len(got) != 1 || got[0] != "HTTP/2.0" {
		t.Errorf("upstream protos = %v, want [HTTP/2.0]", got)
	}
	send, recv, _ := flowVersions(t, store, out.StreamID)
	if send != "h2c" || recv != "h2c" {
		t.Errorf("recorded http_version send=%q receive=%q, want h2c/h2c", send, recv)
	}
}

// TestResendHTTP_H2Flow_EarlyHintsThenFinal covers 1xx handling: a 103
// Early Hints ahead of the 200 is recorded as its own receive Flow and the
// tool reports the final status, not the interim one.
func TestResendHTTP_H2Flow_EarlyHintsThenFinal(t *testing.T) {
	srv, rec := startProtoTLSUpstream(t, []string{"h2", "http/1.1"}, true)
	authority := srv.Listener.Addr().String()
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+authority+"/hints", "h2", h2RecordedHeaders())

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
	if res.IsError {
		t.Fatalf("resend_http failed: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 || out.Body != "proto-ok" {
		t.Errorf("result = %d %q, want the final 200 %q", out.StatusCode, out.Body, "proto-ok")
	}
	if got := rec.snapshot(); len(got) != 1 || got[0] != "HTTP/2.0" {
		t.Errorf("upstream protos = %v, want [HTTP/2.0]", got)
	}
	_, _, statuses := flowVersions(t, store, out.StreamID)
	if len(statuses) != 2 || statuses[0] != 103 || statuses[1] != 200 {
		t.Errorf("recorded receive statuses = %v, want [103 200]", statuses)
	}
}

// TestResendHTTP_H1Flow_EarlyHintsThenFinal is the HTTP/1.1 twin of
// TestResendHTTP_H2Flow_EarlyHintsThenFinal: the 1xx loop is shared, so an
// h1 resend must also report the final 200 (not the 103) and record both
// responses as receive Flows in wire order.
func TestResendHTTP_H1Flow_EarlyHintsThenFinal(t *testing.T) {
	srv, rec := startProtoTLSUpstream(t, []string{"http/1.1"}, true)
	authority := srv.Listener.Addr().String()
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+authority+"/hints", "http/1.1", map[string][]string{"User-Agent": {"curl/8.5.0"}})

	res := callResendHTTP(t, cs, map[string]any{"flow_id": flowID, "timeout_ms": 5000})
	if res.IsError {
		t.Fatalf("resend_http failed: %s", extractTextContent(res))
	}
	var out resendHTTPResult
	decodeStructuredResult(t, res, &out)
	if out.StatusCode != 200 || out.Body != "proto-ok" {
		t.Errorf("result = %d %q, want the final 200 %q", out.StatusCode, out.Body, "proto-ok")
	}
	if got := rec.snapshot(); len(got) != 1 || got[0] != "HTTP/1.1" {
		t.Errorf("upstream protos = %v, want [HTTP/1.1]", got)
	}
	send, recv, statuses := flowVersions(t, store, out.StreamID)
	if len(statuses) != 2 || statuses[0] != 103 || statuses[1] != 200 {
		t.Errorf("recorded receive statuses = %v, want [103 200]", statuses)
	}
	if send != "http/1.1" || recv != "http/1.1" {
		t.Errorf("recorded http_version send=%q receive=%q, want http/1.1/http/1.1", send, recv)
	}
}

// TestFuzzHTTP_H2Flow_VariantsSentOverHTTP2 covers AC "fuzz_http variants
// based on an h2 flow are sent over HTTP/2": every variant reaches the
// h2-only upstream as HTTP/2 and every variant Send Flow records "h2".
func TestFuzzHTTP_H2Flow_VariantsSentOverHTTP2(t *testing.T) {
	up := startRawH2Upstream(t)
	cs, store := setupResendHTTPVersionSession(t, &transport.StandardTransport{InsecureSkipVerify: true}, "")
	flowID := saveVersionedHTTPFlow(t, store, "https://"+up.addr()+"/base", "h2", h2RecordedHeaders())

	out := callFuzzHTTP(t, cs, map[string]any{
		"flow_id":    flowID,
		"timeout_ms": 5000,
		"positions": []map[string]any{
			{"path": "path", "payloads": []string{"/v0", "/v1"}},
		},
	})
	if out.CompletedVariants != 2 {
		t.Fatalf("completed_variants = %d, want 2 (variants %+v)", out.CompletedVariants, out.Variants)
	}
	for i, v := range out.Variants {
		if v.Error != "" || v.StatusCode != 200 {
			t.Errorf("variant %d: status=%d error=%q, want 200 and no error", i, v.StatusCode, v.Error)
		}
		send, _, _ := flowVersions(t, store, v.StreamID)
		if send != "h2" {
			t.Errorf("variant %d send http_version = %q, want h2", i, send)
		}
	}
	for i, want := range []string{"/v0", "/v1"} {
		req := up.waitRequest(t, i+1, 5*time.Second)
		if got, _ := req.field(":path"); got != want {
			t.Errorf("request %d :path = %q, want %q", i+1, got, want)
		}
		if _, ok := req.field("host"); ok {
			t.Errorf("request %d carried a synthetic host header", i+1)
		}
	}
}
