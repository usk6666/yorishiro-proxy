//go:build e2e && !e2e_smoke

package connector_test

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// ---------------------------------------------------------------------------
// USK-871: SETTINGS_ENABLE_CONNECT_PROTOCOL upstream-sniff coverage
//
// The fix reverses the construction order in BuildPlainH2CStack /
// buildH2Stack: upstream ClientRole is established first, the proxy waits
// for the upstream's initial SETTINGS frame, and the value of
// SETTINGS_ENABLE_CONNECT_PROTOCOL (RFC 8441 §3) is then mirrored into the
// proxy's client-facing ServerRole advertise. Pool-hit fast-paths skip
// the wait because peer SETTINGS were already observed at pool-insertion
// time.
//
// These integration tests use BuildPlainH2CStack as the entry point —
// it accepts a pre-dialed upstream net.Conn, which lets the test substitute
// a controllable fake upstream driven via raw HTTP/2 frames over a TCP
// loopback pipe. Using a real http2.Layer (ServerRole) as the fake
// upstream would also work, but the lower-level frame.Reader/Writer is
// preferred so the test can deliberately omit or delay the SETTINGS frame.
// ---------------------------------------------------------------------------

// fakeH2Upstream owns the upstream side of an h2 connection: it speaks the
// minimal SETTINGS-exchange dance needed to let buildH2Stack complete its
// upstream-sniff, then otherwise idles.
type fakeH2Upstream struct {
	conn net.Conn
	rd   *frame.Reader
	wr   *frame.Writer
}

func newFakeH2Upstream(t *testing.T, conn net.Conn) *fakeH2Upstream {
	t.Helper()
	return &fakeH2Upstream{
		conn: conn,
		rd:   frame.NewReader(conn),
		wr:   frame.NewWriter(conn),
	}
}

// readClientPreface drains the 24-byte HTTP/2 client preface that
// http2.New writes synchronously inside its runPreface() call.
func (u *fakeH2Upstream) readClientPreface(t *testing.T) {
	t.Helper()
	buf := make([]byte, 24)
	if _, err := io.ReadFull(u.conn, buf); err != nil {
		t.Fatalf("fakeH2Upstream: read client preface: %v", err)
	}
	if string(buf) != http2.ClientPreface {
		t.Fatalf("fakeH2Upstream: preface mismatch: %q", buf)
	}
}

// sendInitialSettings writes our initial SETTINGS frame.
func (u *fakeH2Upstream) sendInitialSettings(t *testing.T, params []frame.Setting) {
	t.Helper()
	if err := u.wr.WriteSettings(params); err != nil {
		t.Fatalf("fakeH2Upstream: write SETTINGS: %v", err)
	}
}

// drainUntilSettingsAck reads frames until our SETTINGS frame is acked by
// the proxy. The proxy emits SETTINGS-ACK after applying our SETTINGS, so
// observing the ACK guarantees the proxy has already woken up its
// WaitPeerSettings() caller.
func (u *fakeH2Upstream) drainUntilSettingsAck(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := u.rd.ReadFrame()
		if err != nil {
			t.Fatalf("fakeH2Upstream: read frame: %v", err)
		}
		if f.Header.Type == frame.TypeSettings && f.Header.Flags.Has(frame.FlagAck) {
			return
		}
	}
	t.Fatalf("fakeH2Upstream: did not see SETTINGS-ACK")
}

// proxyServerSidePeer owns the client side of the proxy connection: it
// drains the proxy's preface + initial SETTINGS so we can assert exactly
// which settings the proxy chose to advertise.
type proxyServerSidePeer struct {
	conn net.Conn
	rd   *frame.Reader
	wr   *frame.Writer
}

func newProxyServerSidePeer(t *testing.T, conn net.Conn) *proxyServerSidePeer {
	t.Helper()
	p := &proxyServerSidePeer{
		conn: conn,
		rd:   frame.NewReader(conn),
		wr:   frame.NewWriter(conn),
	}
	// The proxy's ServerRole http2.New runs runPreface() synchronously,
	// which BLOCKS until it reads our (client's) 24-byte preface. We must
	// send the preface from a goroutine context that does not also try to
	// block on http2.New return — but BuildPlainH2CStack invokes http2.New
	// for the ServerRole only AFTER it has finished the upstream-sniff
	// wait. So we ship the preface upfront here in a background goroutine
	// — http2.New will read it the moment it reaches runPreface().
	go func() {
		_, _ = p.conn.Write([]byte(http2.ClientPreface))
	}()
	return p
}

// readInitialServerSettings reads frames until the very first non-ACK
// SETTINGS frame from the proxy is observed and returns its parameters.
func (p *proxyServerSidePeer) readInitialServerSettings(t *testing.T) []frame.Setting {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("proxyServerSidePeer: read frame: %v", err)
		}
		if f.Header.Type != frame.TypeSettings {
			continue
		}
		if f.Header.Flags.Has(frame.FlagAck) {
			continue
		}
		params, perr := f.SettingsParams()
		if perr != nil {
			t.Fatalf("proxyServerSidePeer: SettingsParams: %v", perr)
		}
		return params
	}
	t.Fatalf("proxyServerSidePeer: did not see initial SETTINGS")
	return nil
}

func hasEnableConnectProtocol(params []frame.Setting) (uint32, bool) {
	for _, s := range params {
		if s.ID == frame.SettingEnableConnectProtocol {
			return s.Value, true
		}
	}
	return 0, false
}

// TestH2_EnableConnectProtocol_MirroredFromUpstream_Zero verifies the
// USK-871 invariant end-to-end: when the upstream omits
// SETTINGS_ENABLE_CONNECT_PROTOCOL (i.e. does not advertise extended
// CONNECT support per RFC 8441), the proxy's client-facing ServerRole
// must also omit the setting.
//
// Failure scenario reproduced (pre-fix): browser observes the proxy's
// ENABLE_CONNECT_PROTOCOL=1, attempts RFC 8441 extended CONNECT for WS,
// upstream returns PROTOCOL_ERROR / stream reset, WS handshake fails.
func TestH2_EnableConnectProtocol_MirroredFromUpstream_Zero(t *testing.T) {
	// Set up: a TCP pipe pair on each side — one for the proxy's
	// client-facing connection, one for the upstream.
	clientLeft, clientRight := net.Pipe()
	defer clientLeft.Close()
	defer clientRight.Close()
	upstreamLeft, upstreamRight := net.Pipe()
	defer upstreamLeft.Close()
	defer upstreamRight.Close()

	// Build the proxy stack in a goroutine. BuildPlainH2CStack reverses
	// the construction order (USK-871): it first wraps the upstream conn
	// in http2.New(ClientRole), then waits for the upstream peer
	// SETTINGS, then constructs http2.New(ServerRole) with the mirrored
	// WithEnableConnectProtocol value.
	cfg := &connector.BuildConfig{}
	stackCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := connector.BuildPlainH2CStack(ctx, clientRight, upstreamRight, "echo.example.com:80", cfg)
		stackCh <- err
	}()

	// Fake upstream: speak the SETTINGS dance without advertising
	// SETTINGS_ENABLE_CONNECT_PROTOCOL.
	upstream := newFakeH2Upstream(t, upstreamLeft)
	upstream.readClientPreface(t)
	// Send our initial SETTINGS without the ENABLE_CONNECT_PROTOCOL
	// setting. Per RFC 8441 §3 + RFC 9113 §6.5.2, an omitted setting is
	// the default 0.
	upstream.sendInitialSettings(t, []frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 100},
	})

	// Fake client (browser): drain proxy's preface + initial SETTINGS
	// frame.
	clientPeer := newProxyServerSidePeer(t, clientLeft)
	params := clientPeer.readInitialServerSettings(t)

	if v, ok := hasEnableConnectProtocol(params); ok {
		t.Fatalf("proxy advertised ENABLE_CONNECT_PROTOCOL=%d; want omitted (upstream did not advertise it). params=%+v",
			v, params)
	}

	// Drain the SETTINGS-ACK we owe the proxy so the proxy can settle.
	upstream.drainUntilSettingsAck(t)

	// Stack build should complete without error.
	if err := waitWithTimeout(stackCh, 5*time.Second); err != nil {
		t.Fatalf("BuildPlainH2CStack: %v", err)
	}
}

// TestH2_EnableConnectProtocol_MirroredFromUpstream_One verifies the
// positive complement: when the upstream DOES advertise
// SETTINGS_ENABLE_CONNECT_PROTOCOL=1, the proxy's client-facing
// ServerRole must propagate the value (preserving USK-764 behaviour for
// upstreams that legitimately support extended CONNECT).
func TestH2_EnableConnectProtocol_MirroredFromUpstream_One(t *testing.T) {
	clientLeft, clientRight := net.Pipe()
	defer clientLeft.Close()
	defer clientRight.Close()
	upstreamLeft, upstreamRight := net.Pipe()
	defer upstreamLeft.Close()
	defer upstreamRight.Close()

	cfg := &connector.BuildConfig{}
	stackCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := connector.BuildPlainH2CStack(ctx, clientRight, upstreamRight, "echo.example.com:80", cfg)
		stackCh <- err
	}()

	upstream := newFakeH2Upstream(t, upstreamLeft)
	upstream.readClientPreface(t)
	upstream.sendInitialSettings(t, []frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 100},
		{ID: frame.SettingEnableConnectProtocol, Value: 1},
	})

	clientPeer := newProxyServerSidePeer(t, clientLeft)
	params := clientPeer.readInitialServerSettings(t)

	v, ok := hasEnableConnectProtocol(params)
	if !ok {
		t.Fatalf("proxy did not advertise ENABLE_CONNECT_PROTOCOL; want value 1 mirrored from upstream. params=%+v", params)
	}
	if v != 1 {
		t.Errorf("proxy advertised ENABLE_CONNECT_PROTOCOL=%d, want 1", v)
	}

	upstream.drainUntilSettingsAck(t)

	if err := waitWithTimeout(stackCh, 5*time.Second); err != nil {
		t.Fatalf("BuildPlainH2CStack: %v", err)
	}
}

// TestH2_EnableConnectProtocol_TimeoutFallback verifies that when the
// upstream completes the HTTP/2 preface but never sends its initial
// SETTINGS frame, the proxy falls back (after a hard-coded 5s ceiling) to
// advertising ENABLE_CONNECT_PROTOCOL=1 — the pre-USK-871 unconditional
// default. This is the fail-open path so existing clients that depend on
// extended CONNECT keep working when the upstream is slow / misbehaving.
//
// The test uses ctx.WithTimeout(<5s) and asserts that buildH2Stack's wait
// honours the parent context: even though the internal timeout is 5s, the
// caller's earlier cancel takes precedence.
func TestH2_EnableConnectProtocol_TimeoutFallback(t *testing.T) {
	clientLeft, clientRight := net.Pipe()
	defer clientLeft.Close()
	defer clientRight.Close()
	upstreamLeft, upstreamRight := net.Pipe()
	defer upstreamLeft.Close()
	defer upstreamRight.Close()

	// Use a context with a deadline shorter than the hard-coded internal
	// 5s timeout so the test does not have to wait the full ceiling.
	cfg := &connector.BuildConfig{}
	stackCh := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
		defer cancel()
		_, err := connector.BuildPlainH2CStack(ctx, clientRight, upstreamRight, "slow.example.com:80", cfg)
		stackCh <- err
	}()

	// Fake upstream: drain the preface but DO NOT send SETTINGS.
	upstream := newFakeH2Upstream(t, upstreamLeft)
	upstream.readClientPreface(t)
	// Intentionally NOT sending SETTINGS — the proxy's WaitPeerSettings
	// will time out via the parent context.

	// The proxy still constructs its ServerRole after the timeout,
	// falling back to advertising ENABLE_CONNECT_PROTOCOL=1.
	clientPeer := newProxyServerSidePeer(t, clientLeft)
	params := clientPeer.readInitialServerSettings(t)

	v, ok := hasEnableConnectProtocol(params)
	if !ok {
		t.Fatalf("proxy did not advertise ENABLE_CONNECT_PROTOCOL after timeout-fallback; expected fail-open value 1. params=%+v", params)
	}
	if v != 1 {
		t.Errorf("timeout-fallback ENABLE_CONNECT_PROTOCOL = %d, want 1", v)
	}

	if err := waitWithTimeout(stackCh, 5*time.Second); err != nil {
		t.Fatalf("BuildPlainH2CStack (timeout-fallback): %v", err)
	}
}

// waitWithTimeout returns the value from ch or fails on timeout.
func waitWithTimeout(ch <-chan error, d time.Duration) error {
	select {
	case err := <-ch:
		return err
	case <-time.After(d):
		return errors.New("build did not complete within timeout")
	}
}
