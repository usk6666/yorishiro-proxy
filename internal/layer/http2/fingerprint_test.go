package http2

import (
	"context"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// chromeConnWindowIncrement is the default (Chrome-shaped) stream-0
// WINDOW_UPDATE increment: 16 MiB - 65535.
const chromeConnWindowIncrement = uint32(defaultLargeConnWindow - defaultConnectionWindowSize)

// TestResolveH2Fingerprint verifies that only "firefox" on a ClientRole
// Layer resolves to the Firefox shape; every other profile and every
// ServerRole Layer resolves to the default (USK-1007 U1/U2).
func TestResolveH2Fingerprint(t *testing.T) {
	tests := []struct {
		name    string
		profile string
		role    Role
		want    H2Fingerprint
	}{
		{"firefox_client", "firefox", ClientRole, H2FingerprintFirefox},
		{"firefox_mixed_case_client", "FireFox", ClientRole, H2FingerprintFirefox},
		{"firefox_padded_client", "  firefox  ", ClientRole, H2FingerprintFirefox},
		{"firefox_server_ignored", "firefox", ServerRole, H2FingerprintDefault},
		{"chrome_client", "chrome", ClientRole, H2FingerprintDefault},
		{"edge_client", "edge", ClientRole, H2FingerprintDefault},
		{"safari_client", "safari", ClientRole, H2FingerprintDefault},
		{"random_client", "random", ClientRole, H2FingerprintDefault},
		{"none_client", "none", ClientRole, H2FingerprintDefault},
		{"empty_client", "", ClientRole, H2FingerprintDefault},
		{"unknown_client", "brave", ClientRole, H2FingerprintDefault},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := resolveH2Fingerprint(tt.profile, tt.role); got != tt.want {
				t.Errorf("resolveH2Fingerprint(%q, %v) = %d, want %d", tt.profile, tt.role, got, tt.want)
			}
		})
	}
}

// TestFirefoxSettingsFrame_GoldenOrder pins the Firefox SETTINGS wire order
// and values against the FF120 capture: HEADER_TABLE_SIZE=65536,
// ENABLE_PUSH=0, INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384, with
// MAX_CONCURRENT_STREAMS dropped.
func TestFirefoxSettingsFrame_GoldenOrder(t *testing.T) {
	got := firefoxSettingsFrame(firefoxClientSettings())
	want := []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: 65536},
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingInitialWindowSize, Value: 131072},
		{ID: frame.SettingMaxFrameSize, Value: 16384},
	}
	assertSettingsEqual(t, got, want)

	// MAX_CONCURRENT_STREAMS must never appear.
	if _, ok := findSetting(got, frame.SettingMaxConcurrentStreams); ok {
		t.Errorf("firefoxSettingsFrame emitted MAX_CONCURRENT_STREAMS, want absent: %+v", got)
	}
}

// TestFirefoxSettingsFrame_MaxHeaderListSizeConditional confirms the
// conditional-emission contract carries over: MAX_HEADER_LIST_SIZE is
// appended only when explicitly non-zero (e.g. the gRPC WithMaxHeaderListSize
// path), never in the pure Firefox shape.
func TestFirefoxSettingsFrame_MaxHeaderListSizeConditional(t *testing.T) {
	s := firefoxClientSettings()
	s.MaxHeaderListSize = 262144
	got := firefoxSettingsFrame(s)
	v, ok := findSetting(got, frame.SettingMaxHeaderListSize)
	if !ok || v != 262144 {
		t.Fatalf("MAX_HEADER_LIST_SIZE = (%d, %v), want (262144, true); got %+v", v, ok, got)
	}
	// It must be appended last, after MAX_FRAME_SIZE.
	if got[len(got)-1].ID != frame.SettingMaxHeaderListSize {
		t.Errorf("MAX_HEADER_LIST_SIZE not emitted last: %+v", got)
	}
}

// TestConnWindowIncrement verifies the fingerprint-selected stream-0
// WINDOW_UPDATE increment.
func TestConnWindowIncrement(t *testing.T) {
	if got := connWindowIncrement(H2FingerprintFirefox); got != firefoxConnWindowIncrement {
		t.Errorf("connWindowIncrement(firefox) = %d, want %d", got, firefoxConnWindowIncrement)
	}
	if got := connWindowIncrement(H2FingerprintDefault); got != chromeConnWindowIncrement {
		t.Errorf("connWindowIncrement(default) = %d, want %d", got, chromeConnWindowIncrement)
	}
}

// TestDefaultLocalSettings verifies the fingerprint-selected local SETTINGS
// applied when no WithInitialSettings override is supplied.
func TestDefaultLocalSettings(t *testing.T) {
	ff := defaultLocalSettings(H2FingerprintFirefox)
	if ff.HeaderTableSize != firefoxHeaderTableSize ||
		ff.InitialWindowSize != firefoxInitialWindowSize ||
		ff.MaxFrameSize != firefoxMaxFrameSize {
		t.Errorf("defaultLocalSettings(firefox) = %+v, want firefox values", ff)
	}

	def := defaultLocalSettings(H2FingerprintDefault)
	if def.InitialWindowSize != defaultLargeStreamWindow {
		t.Errorf("defaultLocalSettings(default) InitialWindowSize = %d, want %d (16 MiB)",
			def.InitialWindowSize, defaultLargeStreamWindow)
	}
	if def.HeaderTableSize != defaultHeaderTableSize {
		t.Errorf("defaultLocalSettings(default) HeaderTableSize = %d, want %d",
			def.HeaderTableSize, defaultHeaderTableSize)
	}
}

// TestLayer_ClientRole_FirefoxSettings_Wire drives the full New() boot with
// WithH2Fingerprint("firefox") and asserts the wire SETTINGS frame's exact
// order+values and the conn-level WINDOW_UPDATE increment (12517377).
func TestLayer_ClientRole_FirefoxSettings_Wire(t *testing.T) {
	_, peer, cleanup := startClientLayer(t, WithH2Fingerprint("firefox"))
	defer cleanup()

	params, inc := readInitialSettingsAndConnWindow(t, peer)

	want := []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: 65536},
		{ID: frame.SettingEnablePush, Value: 0},
		{ID: frame.SettingInitialWindowSize, Value: 131072},
		{ID: frame.SettingMaxFrameSize, Value: 16384},
	}
	assertSettingsEqual(t, params, want)

	if _, ok := findSetting(params, frame.SettingMaxConcurrentStreams); ok {
		t.Errorf("firefox ClientRole SETTINGS contains MAX_CONCURRENT_STREAMS, want absent: %+v", params)
	}
	if inc != firefoxConnWindowIncrement {
		t.Errorf("firefox conn WINDOW_UPDATE increment = %d, want %d", inc, firefoxConnWindowIncrement)
	}
}

// TestLayer_ClientRole_DefaultSettings_NoRegression locks the pre-USK-1007
// Chrome-shaped ClientRole wire output for the unset and explicit-"chrome"
// cases. Any drift here is a backward-compat break.
func TestLayer_ClientRole_DefaultSettings_NoRegression(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
	}{
		{"unset", nil},
		{"chrome", []Option{WithH2Fingerprint("chrome")}},
		{"unknown_profile", []Option{WithH2Fingerprint("brave")}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, peer, cleanup := startClientLayer(t, tc.opts...)
			defer cleanup()

			params, inc := readInitialSettingsAndConnWindow(t, peer)
			want := []frame.Setting{
				{ID: frame.SettingHeaderTableSize, Value: defaultHeaderTableSize},
				{ID: frame.SettingEnablePush, Value: 0},
				{ID: frame.SettingMaxConcurrentStreams, Value: defaultMaxConcurrentStreams},
				{ID: frame.SettingInitialWindowSize, Value: defaultLargeStreamWindow},
				{ID: frame.SettingMaxFrameSize, Value: defaultMaxFrameSize},
			}
			assertSettingsEqual(t, params, want)
			if inc != chromeConnWindowIncrement {
				t.Errorf("default conn WINDOW_UPDATE increment = %d, want %d", inc, chromeConnWindowIncrement)
			}
		})
	}
}

// TestLayer_ServerRole_FirefoxIgnored verifies WithH2Fingerprint("firefox")
// has no effect on a ServerRole (client-facing) Layer — browser fingerprinting
// concerns the upstream send-shape only.
func TestLayer_ServerRole_FirefoxIgnored(t *testing.T) {
	_, peer, cleanup := startServerLayer(t, WithH2Fingerprint("firefox"))
	defer cleanup()

	params := readInitialSettings(t, peer)
	// ServerRole omits ENABLE_PUSH (RFC 9113 §7.2.2, USK-825) and advertises
	// the default header table size — not the Firefox 65536.
	v, ok := findSetting(params, frame.SettingHeaderTableSize)
	if !ok || v != defaultHeaderTableSize {
		t.Errorf("ServerRole HEADER_TABLE_SIZE = (%d, %v), want (%d, true) — firefox must not apply",
			v, ok, defaultHeaderTableSize)
	}
	if _, ok := findSetting(params, frame.SettingEnablePush); ok {
		t.Errorf("ServerRole SETTINGS contains ENABLE_PUSH, want absent (firefox must not apply): %+v", params)
	}
}

// TestAppendRequestPseudoHeaders_Order verifies the pseudo-header order the
// wire encoder produces for each fingerprint via the exported
// BuildHeaderFieldsFromEventWithFingerprint, including the backward-compatible
// 2-arg default, the empty-:authority case, and extended-CONNECT :protocol.
func TestAppendRequestPseudoHeaders_Order(t *testing.T) {
	base := &H2HeadersEvent{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/x"}
	env := &envelope.Envelope{Direction: envelope.Send}

	t.Run("firefox_order", func(t *testing.T) {
		fields := BuildHeaderFieldsFromEventWithFingerprint(env, base, H2FingerprintFirefox)
		assertPseudoOrder(t, fields, []string{":method", ":path", ":authority", ":scheme"})
	})
	t.Run("default_order", func(t *testing.T) {
		fields := BuildHeaderFieldsFromEventWithFingerprint(env, base, H2FingerprintDefault)
		assertPseudoOrder(t, fields, []string{":method", ":scheme", ":authority", ":path"})
	})
	t.Run("backward_compat_2arg_is_default", func(t *testing.T) {
		fields := BuildHeaderFieldsFromEvent(env, base)
		assertPseudoOrder(t, fields, []string{":method", ":scheme", ":authority", ":path"})
	})
	t.Run("firefox_empty_authority", func(t *testing.T) {
		evt := &H2HeadersEvent{Method: "GET", Scheme: "https", Path: "/"}
		fields := BuildHeaderFieldsFromEventWithFingerprint(env, evt, H2FingerprintFirefox)
		assertPseudoOrder(t, fields, []string{":method", ":path", ":scheme"})
	})
	t.Run("firefox_extended_connect_protocol_last", func(t *testing.T) {
		evt := &H2HeadersEvent{Method: "CONNECT", Scheme: "https", Authority: "example.com", Path: "/", ConnectProtocol: "websocket"}
		fields := BuildHeaderFieldsFromEventWithFingerprint(env, evt, H2FingerprintFirefox)
		assertPseudoOrder(t, fields, []string{":method", ":path", ":authority", ":scheme", ":protocol"})
	})
}

// TestLayer_Firefox_NativeSend_PseudoOrder is the end-to-end wire assertion:
// a firefox ClientRole Layer's native send path (sendHeadersEvent →
// c.layer.h2Fingerprint) must place the request pseudo-headers on the wire in
// Firefox order. The default (chrome) counterpart proves no regression.
func TestLayer_Firefox_NativeSend_PseudoOrder(t *testing.T) {
	cases := []struct {
		name string
		opts []Option
		want []string
	}{
		{"firefox", []Option{WithH2Fingerprint("firefox")}, []string{":method", ":path", ":authority", ":scheme"}},
		{"default", nil, []string{":method", ":scheme", ":authority", ":path"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, peer, cleanup := startClientLayer(t, tc.opts...)
			defer cleanup()
			peer.consumePeerSettings(t)

			ch, err := l.OpenStream(context.Background())
			if err != nil {
				t.Fatalf("OpenStream: %v", err)
			}
			go func() {
				_ = ch.Send(context.Background(), &envelope.Envelope{
					Direction: envelope.Send,
					Message: &H2HeadersEvent{
						Method: "GET", Scheme: "https", Authority: "example.com", Path: "/p",
						EndStream: true,
					},
				})
			}()

			fields := readHeadersFields(t, peer)
			got := pseudoNames(fields)
			assertStringSliceEqual(t, got, tc.want)
		})
	}
}

// --- helpers ---

func assertSettingsEqual(t *testing.T, got, want []frame.Setting) {
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

// readInitialSettingsAndConnWindow drains frames until it has captured the
// first non-ACK SETTINGS params and the first stream-0 WINDOW_UPDATE
// increment, returning both.
func readInitialSettingsAndConnWindow(t *testing.T, p *h2Peer) ([]frame.Setting, uint32) {
	t.Helper()
	var params []frame.Setting
	var inc uint32
	haveSettings := false
	haveWU := false
	deadline := time.Now().Add(2 * time.Second)
	for (!haveSettings || !haveWU) && time.Now().Before(deadline) {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read peer setup: %v", err)
		}
		switch f.Header.Type {
		case frame.TypeSettings:
			if f.Header.Flags.Has(frame.FlagAck) {
				continue
			}
			sp, perr := f.SettingsParams()
			if perr != nil {
				t.Fatalf("SettingsParams: %v", perr)
			}
			params = sp
			haveSettings = true
		case frame.TypeWindowUpdate:
			if f.Header.StreamID != 0 {
				continue
			}
			v, werr := f.WindowUpdateIncrement()
			if werr != nil {
				t.Fatalf("WindowUpdateIncrement: %v", werr)
			}
			inc = v
			haveWU = true
		}
	}
	if !haveSettings || !haveWU {
		t.Fatalf("did not observe both SETTINGS and conn WINDOW_UPDATE within deadline (settings=%v, wu=%v)",
			haveSettings, haveWU)
	}
	return params, inc
}

// readHeadersFields reads frames from the peer until the first HEADERS frame,
// then HPACK-decodes its block. A 65536-byte decoder table is used so the
// firefox layer's larger encoder table never trips a table-size-update limit.
func readHeadersFields(t *testing.T, p *h2Peer) []hpack.HeaderField {
	t.Helper()
	dec := hpack.NewDecoder(65536)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read HEADERS: %v", err)
		}
		if f.Header.Type != frame.TypeHeaders {
			continue
		}
		block, berr := f.HeaderBlockFragment()
		if berr != nil {
			t.Fatalf("HeaderBlockFragment: %v", berr)
		}
		fields, derr := dec.Decode(block)
		if derr != nil {
			t.Fatalf("hpack decode: %v", derr)
		}
		return fields
	}
	t.Fatal("did not observe HEADERS within deadline")
	return nil
}

// pseudoNames returns the names of the leading pseudo-header fields (":"
// prefix) in wire order.
func pseudoNames(fields []hpack.HeaderField) []string {
	var out []string
	for _, f := range fields {
		if len(f.Name) == 0 || f.Name[0] != ':' {
			break
		}
		out = append(out, f.Name)
	}
	return out
}

func assertPseudoOrder(t *testing.T, fields []hpack.HeaderField, want []string) {
	t.Helper()
	assertStringSliceEqual(t, pseudoNames(fields), want)
}

func assertStringSliceEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("pseudo-header order = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("pseudo-header order = %v, want %v", got, want)
		}
	}
}
