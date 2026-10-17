package proxybuild

import (
	"context"
	"errors"
	"io"
	"net"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// USK-1165: a tcp_forward h2 connection owns exactly one upstream Layer
// (chain[0], built by connector.BuildConnectionStackWithTarget). These unit
// tests pin the per-stream upstream selector (forwardH2Upstream.open) to the
// same redial / one-shot Refused retry semantics as the CONNECT path
// (openUpstreamStreamWithRetry, USK-991 / USK-993), and the forward mint
// (newForwardH2Mint) to the connection shape conn #1 had.

// TestForwardH2Upstream_RefusedTriggersOneRetry: the first OpenStream on the
// forward connection's upstream Layer is refused before HEADERS (the Layer
// went stale between selection and OpenStream). The selector must redial once
// and return the channel opened on the fresh Layer — the same contract as
// TestOpenUpstreamStreamWithRetry_RefusedTriggersRetry for CONNECT.
func TestForwardH2Upstream_RefusedTriggersOneRetry(t *testing.T) {
	chain0, chain0Peer := dialPeerH2Layer(t)
	defer chain0.Close()
	defer chain0Peer.Close()
	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	// chain[0] goes stale so the retry's selection redials.
	_ = chain0Peer.Close()
	awaitShutdown(t, chain0)

	var redials atomic.Int32
	redial := func(_ context.Context, _ string, _ *http2.Layer, _ int) (*http2.Layer, error) {
		redials.Add(1)
		return fresh, nil
	}
	stub := stubChannel{streamID: 3}
	var opens atomic.Int32
	openFn := func(_ context.Context, l *http2.Layer) (layer.Channel, error) {
		if opens.Add(1) == 1 {
			return nil, &layer.StreamError{Code: layer.ErrorRefused, Reason: "GOAWAY received"}
		}
		if l != fresh {
			t.Errorf("retry OpenStream on %p, want fresh %p", l, fresh)
		}
		return stub, nil
	}

	u := &forwardH2Upstream{
		target:     "127.0.0.1:9",
		chain0:     chain0,
		chain:      newRedialChain(nil),
		redial:     redial,
		openStream: openFn,
		logger:     silentLogger(),
	}
	gotL, gotCh, err := u.open(context.Background())
	if err != nil {
		t.Fatalf("open: %v (OpenStream calls=%d, redials=%d); want the Refused first attempt retried on a fresh Layer",
			err, opens.Load(), redials.Load())
	}
	if gotL != fresh {
		t.Errorf("open returned Layer %p, want fresh %p", gotL, fresh)
	}
	if gotCh != stub {
		t.Errorf("open returned channel %v, want the fresh Layer's channel", gotCh)
	}
	if n := opens.Load(); n != 2 {
		t.Errorf("OpenStream calls = %d, want 2 (one retry)", n)
	}
	if n := redials.Load(); n != 1 {
		t.Errorf("redials = %d, want 1", n)
	}
}

// TestForwardH2Upstream_StaleChain0RedialsBeforeOpen: after upstream GOAWAY
// the forward connection's chain[0] is stale; a new stream must be opened on
// a freshly dialed Layer, not refused on chain[0].
func TestForwardH2Upstream_StaleChain0RedialsBeforeOpen(t *testing.T) {
	chain0, chain0Peer := dialPeerH2Layer(t)
	defer chain0.Close()
	defer chain0Peer.Close()
	fresh, freshPeer := dialPeerH2Layer(t)
	defer fresh.Close()
	defer freshPeer.Close()

	injectGoAwayFromPeer(t, chain0Peer, 1, 0)
	awaitGoAwayClosed(t, chain0)

	var redials atomic.Int32
	redial := func(_ context.Context, _ string, stale *http2.Layer, gen int) (*http2.Layer, error) {
		redials.Add(1)
		if stale != chain0 {
			t.Errorf("redial stale = %p, want chain[0] %p", stale, chain0)
		}
		if gen != 1 {
			t.Errorf("redial generation = %d, want 1", gen)
		}
		return fresh, nil
	}
	u := &forwardH2Upstream{
		target:     "127.0.0.1:9",
		chain0:     chain0,
		chain:      newRedialChain(nil),
		redial:     redial,
		openStream: http2OpenStream,
		logger:     silentLogger(),
	}
	gotL, ch, err := u.open(context.Background())
	if err != nil {
		t.Fatalf("open after chain[0] GOAWAY: %v; want a stream on a redialed Layer", err)
	}
	defer ch.Close()
	if gotL != fresh {
		t.Errorf("open returned Layer %p, want fresh %p", gotL, fresh)
	}
	if n := redials.Load(); n != 1 {
		t.Errorf("redials = %d, want 1", n)
	}
}

// TestForwardH2Upstream_NonRefusedPassesThrough: a non-Refused OpenStream
// error is returned verbatim with no retry and no redial.
func TestForwardH2Upstream_NonRefusedPassesThrough(t *testing.T) {
	chain0, chain0Peer := dialPeerH2Layer(t)
	defer chain0.Close()
	defer chain0Peer.Close()

	sentinel := errors.New("boom")
	var opens, redials atomic.Int32
	u := &forwardH2Upstream{
		target: "127.0.0.1:9",
		chain0: chain0,
		chain:  newRedialChain(nil),
		redial: func(context.Context, string, *http2.Layer, int) (*http2.Layer, error) {
			redials.Add(1)
			return nil, errors.New("unexpected redial")
		},
		openStream: func(context.Context, *http2.Layer) (layer.Channel, error) {
			opens.Add(1)
			return nil, sentinel
		},
		logger: silentLogger(),
	}
	if _, _, err := u.open(context.Background()); !errors.Is(err, sentinel) {
		t.Fatalf("open err = %v, want %v", err, sentinel)
	}
	if opens.Load() != 1 || redials.Load() != 0 {
		t.Errorf("OpenStream calls = %d, redials = %d; want 1 and 0", opens.Load(), redials.Load())
	}
}

// peerSettings reads the client preface and the first frame (SETTINGS) a
// ClientRole Layer writes on its conn and returns the settings in wire
// order. The peer keeps draining afterwards so the Layer's writer never
// blocks on the pipe.
func peerSettings(t *testing.T, peer net.Conn) <-chan []xhttp2.Setting {
	t.Helper()
	out := make(chan []xhttp2.Setting, 1)
	go func() {
		defer close(out)
		buf := make([]byte, len(xhttp2.ClientPreface))
		if _, err := io.ReadFull(peer, buf); err != nil {
			return
		}
		fr := xhttp2.NewFramer(io.Discard, peer)
		f, err := fr.ReadFrame()
		if err != nil {
			return
		}
		sf, ok := f.(*xhttp2.SettingsFrame)
		if !ok {
			return
		}
		var got []xhttp2.Setting
		_ = sf.ForeachSetting(func(s xhttp2.Setting) error {
			got = append(got, s)
			return nil
		})
		out <- got
		_, _ = io.Copy(io.Discard, peer)
	}()
	return out
}

func recvSettings(t *testing.T, ch <-chan []xhttp2.Setting) []xhttp2.Setting {
	t.Helper()
	select {
	case s, ok := <-ch:
		if !ok {
			t.Fatal("peer did not read a SETTINGS frame")
		}
		return s
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for SETTINGS")
	}
	return nil
}

// referenceUpstreamSettings returns the SETTINGS a conn-#1-shaped upstream
// Layer (http2.New ClientRole + the configured fingerprint, as
// buildTargetOverrideH2CStack builds it) sends.
func referenceUpstreamSettings(t *testing.T, fingerprint string) []xhttp2.Setting {
	t.Helper()
	c, p := net.Pipe()
	defer p.Close()
	ch := peerSettings(t, p)
	l, err := http2.New(c, "reference", http2.ClientRole, http2.WithH2Fingerprint(fingerprint))
	if err != nil {
		t.Fatalf("reference http2.New: %v", err)
	}
	defer l.Close()
	return recvSettings(t, ch)
}

// TestNewForwardH2Mint_PreservesConnShape: the Layer a forward redial mints
// keeps conn #1's identity (ConnID / TargetHost from the template), stamps
// the NEW dial's upstream TLS snapshot (nil for h2c), sends the same
// SETTINGS fingerprint conn #1 sent, and wires the GOAWAY observer.
func TestNewForwardH2Mint_PreservesConnShape(t *testing.T) {
	cases := []struct {
		name        string
		fingerprint string
		snap        *envelope.TLSSnapshot
	}{
		{name: "h2c_default_fingerprint"},
		{name: "upstream_tls_firefox_fingerprint", fingerprint: "firefox",
			snap: &envelope.TLSSnapshot{SNI: "localhost", ALPN: "h2"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &connector.BuildConfig{ProxyConfig: &config.ProxyConfig{}, TLSFingerprint: tc.fingerprint}
			want := referenceUpstreamSettings(t, cfg.EffectiveTLSFingerprint())

			cliConn, peer := net.Pipe()
			defer peer.Close()
			settingsCh := peerSettings(t, peer)
			var dials atomic.Int32
			dial := func(context.Context) (net.Conn, *envelope.TLSSnapshot, error) {
				dials.Add(1)
				return cliConn, tc.snap, nil
			}
			tmpl := envelope.EnvelopeContext{
				ConnID:     "conn-1",
				TargetHost: "127.0.0.1:8443",
				TLS:        &envelope.TLSSnapshot{SNI: "stale-snapshot"},
			}
			mint := newForwardH2Mint(dial, tmpl, "http", cfg)

			var goAways atomic.Int32
			fresh, err := mint(context.Background(), "127.0.0.1:8443", nil, 1, func() { goAways.Add(1) })
			if err != nil {
				t.Fatalf("mint: %v", err)
			}
			defer fresh.Close()
			if dials.Load() != 1 {
				t.Errorf("dials = %d, want 1", dials.Load())
			}

			got := fresh.EnvelopeContextTemplate()
			if got.ConnID != tmpl.ConnID || got.TargetHost != tmpl.TargetHost {
				t.Errorf("template ConnID/TargetHost = %q/%q, want %q/%q",
					got.ConnID, got.TargetHost, tmpl.ConnID, tmpl.TargetHost)
			}
			if got.TLS != tc.snap {
				t.Errorf("template TLS = %+v, want the fresh dial's snapshot %+v", got.TLS, tc.snap)
			}
			if gotSettings := recvSettings(t, settingsCh); !reflect.DeepEqual(gotSettings, want) {
				t.Errorf("redialed SETTINGS = %v, want conn #1 shape %v", gotSettings, want)
			}
		})
	}
}

// TestNewForwardH2Mint_DialErrorPropagates: a failed forward dial surfaces
// as a mint error (selectUpstreamForDial then falls back to the stale Layer
// and the stream is refused, USK-1157).
func TestNewForwardH2Mint_DialErrorPropagates(t *testing.T) {
	sentinel := errors.New("dial refused")
	mint := newForwardH2Mint(func(context.Context) (net.Conn, *envelope.TLSSnapshot, error) {
		return nil, nil, sentinel
	}, envelope.EnvelopeContext{ConnID: "c"}, "http", &connector.BuildConfig{ProxyConfig: &config.ProxyConfig{}})
	if _, err := mint(context.Background(), "t", nil, 1, nil); !errors.Is(err, sentinel) {
		t.Fatalf("mint err = %v, want wrapping %v", err, sentinel)
	}
}

// TestForwardUpstreamH2Layer_FiresGoAwayObserver: the exported connector
// helper both the initial forward stack build and the forward redial use
// wires onGoAway as the Layer's GOAWAY observer (the pre-warm wake source).
func TestForwardUpstreamH2Layer_FiresGoAwayObserver(t *testing.T) {
	cliConn, peer := net.Pipe()
	defer peer.Close()
	go func() {
		buf := make([]byte, len(xhttp2.ClientPreface))
		if _, err := io.ReadFull(peer, buf); err != nil {
			return
		}
		go func() { _, _ = io.Copy(io.Discard, peer) }()
	}()
	fired := make(chan struct{}, 1)
	l, err := connector.NewForwardUpstreamH2Layer(cliConn, "conn-1/upstream", "http",
		envelope.EnvelopeContext{ConnID: "conn-1"}, &connector.BuildConfig{ProxyConfig: &config.ProxyConfig{}},
		func() {
			select {
			case fired <- struct{}{}:
			default:
			}
		})
	if err != nil {
		t.Fatalf("NewForwardUpstreamH2Layer: %v", err)
	}
	defer l.Close()
	injectGoAwayFromPeer(t, peer, 0, 0)
	select {
	case <-fired:
	case <-time.After(3 * time.Second):
		t.Fatal("GOAWAY observer did not fire")
	}
}
