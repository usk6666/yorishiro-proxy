package http2

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// TestLayer_DefaultMaxHeaderListSize_Omitted verifies that when the
// caller does not configure SETTINGS_MAX_HEADER_LIST_SIZE, the setting
// is absent from the initial SETTINGS frame.
//
// RFC 9113 §6.5.2 specifies the default for MAX_HEADER_LIST_SIZE as
// "unlimited", represented on the wire by omitting the setting. Emitting
// the setting with value 0 advertises a hard zero limit; grpc-go clients
// interpret that as "any header byte violates the server limit" and
// reject every RPC. The pre-fix behaviour unconditionally emitted the
// field, so the default-constructed Settings struct (zero value) leaked
// MAX_HEADER_LIST_SIZE=0 onto the wire and broke gRPC clients talking
// through the proxy.
func TestLayer_DefaultMaxHeaderListSize_Omitted(t *testing.T) {
	_, peer, cleanup := startServerLayer(t)
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingMaxHeaderListSize); ok {
		t.Fatalf("default initial SETTINGS unexpectedly advertised MAX_HEADER_LIST_SIZE=%d; full params=%+v", v, params)
	}
}

// TestLayer_WithInitialSettings_MaxHeaderListSizeNonzero_Advertises
// verifies that a non-zero MaxHeaderListSize supplied through
// WithInitialSettings is emitted on the initial SETTINGS frame.
//
// Note: WithMaxHeaderListSize (per-field option) configures only the
// HPACK *decoder* limit and does not influence wire advertisement —
// wire emission is exclusively driven by Settings.MaxHeaderListSize on
// the WithInitialSettings path. The gRPC layer test exercises both
// dimensions together (settings.MaxHeaderListSize for the wire +
// WithMaxHeaderListSize for the decoder).
func TestLayer_WithInitialSettings_MaxHeaderListSizeNonzero_Advertises(t *testing.T) {
	const want uint32 = 16384
	custom := Settings{
		HeaderTableSize:      4096,
		EnablePush:           0,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    65535,
		MaxFrameSize:         16384,
		MaxHeaderListSize:    want,
	}

	_, peer, cleanup := startServerLayer(t, WithInitialSettings(custom))
	defer cleanup()

	params := readInitialSettings(t, peer)
	v, ok := findSetting(params, frame.SettingMaxHeaderListSize)
	if !ok {
		t.Fatalf("WithInitialSettings did not advertise MAX_HEADER_LIST_SIZE; params=%+v", params)
	}
	if v != want {
		t.Errorf("MAX_HEADER_LIST_SIZE = %d, want %d", v, want)
	}
}

// TestLayer_WithInitialSettings_MaxHeaderListSizeZero_Omitted covers the
// WithInitialSettings path: even when a fully-populated Settings struct
// is supplied with MaxHeaderListSize left at zero, the zero value must
// still be elided from the wire (RFC 9113 §6.5.2 default = unlimited).
//
// This guards against a regression where the conditional emission was
// applied only on the role-default path.
func TestLayer_WithInitialSettings_MaxHeaderListSizeZero_Omitted(t *testing.T) {
	custom := Settings{
		HeaderTableSize:      4096,
		EnablePush:           0,
		MaxConcurrentStreams: 100,
		InitialWindowSize:    65535,
		MaxFrameSize:         16384,
		// MaxHeaderListSize: 0 (default)
	}

	_, peer, cleanup := startServerLayer(t, WithInitialSettings(custom))
	defer cleanup()

	params := readInitialSettings(t, peer)
	if v, ok := findSetting(params, frame.SettingMaxHeaderListSize); ok {
		t.Fatalf("WithInitialSettings(MaxHeaderListSize=0) leaked MAX_HEADER_LIST_SIZE=%d to wire; params=%+v", v, params)
	}
}
