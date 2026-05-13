package http2

import (
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// readInitialSettings drains frames from the peer until the very first
// non-ACK SETTINGS frame is observed and returns its parameters. The
// USK-764 advertisement assertions only care about the initial SETTINGS;
// any subsequent WINDOW_UPDATE / SETTINGS-ACK is ignored.
func readInitialSettings(t *testing.T, p *h2Peer) []frame.Setting {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f, err := p.rd.ReadFrame()
		if err != nil {
			t.Fatalf("read peer setup: %v", err)
		}
		if f.Header.Type != frame.TypeSettings {
			continue
		}
		if f.Header.Flags.Has(frame.FlagAck) {
			continue
		}
		params, perr := f.SettingsParams()
		if perr != nil {
			t.Fatalf("SettingsParams: %v", perr)
		}
		return params
	}
	t.Fatal("did not see initial SETTINGS within deadline")
	return nil
}

// findSetting returns (value, true) if id appears in params, else (0, false).
func findSetting(params []frame.Setting, id frame.SettingID) (uint32, bool) {
	for _, s := range params {
		if s.ID == id {
			return s.Value, true
		}
	}
	return 0, false
}

// TestLayer_ServerRole_AdvertisesEnableConnectProtocol verifies that a
// ServerRole Layer's initial SETTINGS frame contains
// SETTINGS_ENABLE_CONNECT_PROTOCOL = 1 by default (RFC 8441 §3).
func TestLayer_ServerRole_AdvertisesEnableConnectProtocol(t *testing.T) {
	_, peer, cleanup := startServerLayer(t)
	defer cleanup()

	params := readInitialSettings(t, peer)
	v, ok := findSetting(params, frame.SettingEnableConnectProtocol)
	if !ok {
		t.Fatalf("ServerRole initial SETTINGS missing ENABLE_CONNECT_PROTOCOL; got %+v", params)
	}
	if v != 1 {
		t.Errorf("ENABLE_CONNECT_PROTOCOL = %d, want 1", v)
	}
}

// TestLayer_ClientRole_DoesNotAdvertiseEnableConnectProtocol verifies that
// a ClientRole Layer's initial SETTINGS frame does NOT include
// SETTINGS_ENABLE_CONNECT_PROTOCOL. RFC 8441 §3 reserves the advertisement
// for servers; clients have no business announcing it.
func TestLayer_ClientRole_DoesNotAdvertiseEnableConnectProtocol(t *testing.T) {
	_, peer, cleanup := startClientLayer(t)
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingEnableConnectProtocol); ok {
		t.Fatalf("ClientRole initial SETTINGS unexpectedly advertised ENABLE_CONNECT_PROTOCOL=%d; full params=%+v", v, params)
	}
}

// TestLayer_ServerRole_WithEnableConnectProtocolFalse_Suppresses verifies
// that WithEnableConnectProtocol(false) on a ServerRole suppresses the
// 0x08 advertisement entirely (used by tests / future config flags to
// keep the proxy invisible to RFC 8441-aware clients).
func TestLayer_ServerRole_WithEnableConnectProtocolFalse_Suppresses(t *testing.T) {
	_, peer, cleanup := startServerLayer(t, WithEnableConnectProtocol(false))
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingEnableConnectProtocol); ok {
		t.Fatalf("WithEnableConnectProtocol(false) leaked ENABLE_CONNECT_PROTOCOL=%d to wire; params=%+v", v, params)
	}
}

// TestLayer_ClientRole_WithEnableConnectProtocolTrue_Advertises verifies
// the explicit option overrides the role default. Useful for diagnostic
// configurations that need to mirror a server's advertisement on the
// client side.
func TestLayer_ClientRole_WithEnableConnectProtocolTrue_Advertises(t *testing.T) {
	_, peer, cleanup := startClientLayer(t, WithEnableConnectProtocol(true))
	defer cleanup()

	params := readInitialSettings(t, peer)
	v, ok := findSetting(params, frame.SettingEnableConnectProtocol)
	if !ok {
		t.Fatalf("WithEnableConnectProtocol(true) on ClientRole did not advertise; params=%+v", params)
	}
	if v != 1 {
		t.Errorf("ENABLE_CONNECT_PROTOCOL = %d, want 1", v)
	}
}

// TestLayer_ServerRole_MirrorsPeerEnableConnectProtocol_Zero verifies the
// USK-871 invariant at the Layer surface: when buildH2Stack mirrors an
// upstream peer that does NOT advertise SETTINGS_ENABLE_CONNECT_PROTOCOL
// (i.e. value defaults to 0), the proxy ServerRole must omit the setting
// from its initial SETTINGS frame. WithEnableConnectProtocol(false) is
// the option the connector threads through after sniffing the upstream.
func TestLayer_ServerRole_MirrorsPeerEnableConnectProtocol_Zero(t *testing.T) {
	_, peer, cleanup := startServerLayer(t, WithEnableConnectProtocol(false))
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingEnableConnectProtocol); ok {
		t.Fatalf("ServerRole mirrored upstream-0 but advertised ENABLE_CONNECT_PROTOCOL=%d; params=%+v", v, params)
	}
}

// TestLayer_ServerRole_MirrorsPeerEnableConnectProtocol_One verifies the
// USK-871 invariant at the Layer surface: when buildH2Stack mirrors an
// upstream peer that DOES advertise SETTINGS_ENABLE_CONNECT_PROTOCOL=1,
// the proxy ServerRole must advertise value 1 too. This preserves the
// USK-764 behaviour for upstreams that legitimately support extended
// CONNECT.
func TestLayer_ServerRole_MirrorsPeerEnableConnectProtocol_One(t *testing.T) {
	_, peer, cleanup := startServerLayer(t, WithEnableConnectProtocol(true))
	defer cleanup()

	params := readInitialSettings(t, peer)
	v, ok := findSetting(params, frame.SettingEnableConnectProtocol)
	if !ok {
		t.Fatalf("ServerRole mirrored upstream-1 but did not advertise ENABLE_CONNECT_PROTOCOL; params=%+v", params)
	}
	if v != 1 {
		t.Errorf("ENABLE_CONNECT_PROTOCOL = %d, want 1", v)
	}
}
