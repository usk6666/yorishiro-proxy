package http2

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// H2Fingerprint selects the browser-shaped HTTP/2 send-fingerprint a
// ClientRole (upstream) Layer presents to the peer. Cloudflare / Akamai and
// similar anti-bot frontends fingerprint the *HTTP/2* behaviour of a client
// (SETTINGS values + order, the connection-level WINDOW_UPDATE increment, and
// the request pseudo-header order) in addition to the TLS ClientHello. For a
// MITM proxy to present a coherent browser identity, the proxy's own upstream
// H2 shape must match the browser it claims to be via tls_fingerprint.
//
// Only H2FingerprintFirefox diverges from the historical (Chrome-ish) shape;
// every other value — including chrome / edge / safari / random / none / unset
// — resolves to H2FingerprintDefault and keeps the pre-USK-1007 wire output
// byte-for-byte. See docs/rfc/envelope.md §3.4.
type H2Fingerprint int

const (
	// H2FingerprintDefault is the historical Chrome-shaped ClientRole H2
	// send-fingerprint. It is the fallback for every profile except
	// "firefox" and for every ServerRole Layer.
	H2FingerprintDefault H2Fingerprint = iota
	// H2FingerprintFirefox emits a Firefox-shaped ClientRole H2
	// send-fingerprint (SETTINGS, WINDOW_UPDATE increment, pseudo-header
	// order). Applies to the upstream (ClientRole) send-shape only.
	H2FingerprintFirefox
)

// Firefox HTTP/2 wire constants.
//
// Pinned against a Firefox 120 capture (coherent with the uTLS Firefox_120
// ClientHello selected by tls_fingerprint=firefox, USK-1014). The Akamai
// passive-HTTP/2 fingerprint for this shape is:
//
//	1:65536;2:0;4:131072;5:16384|12517377|0|m,p,a,s
//
// decoded as SETTINGS HEADER_TABLE_SIZE=65536, ENABLE_PUSH=0,
// INITIAL_WINDOW_SIZE=131072, MAX_FRAME_SIZE=16384 (in that wire order;
// MAX_CONCURRENT_STREAMS and MAX_HEADER_LIST_SIZE are not sent); a stream-0
// WINDOW_UPDATE increment of 12517377; no PRIORITY tree (deferred, USK-1018);
// and request pseudo-header order :method :path :authority :scheme.
const (
	firefoxHeaderTableSize   uint32 = 65536
	firefoxInitialWindowSize uint32 = 131072
	firefoxMaxFrameSize      uint32 = 16384

	// firefoxConnWindowIncrement is the stream-0 WINDOW_UPDATE increment
	// Firefox sends immediately after its SETTINGS frame, raising the
	// connection-level receive window from the RFC 9113 default of 65535 to
	// 12 MiB (12582912). 12582912 - 65535 = 12517377.
	firefoxConnWindowIncrement uint32 = 12517377
)

// resolveH2Fingerprint maps a tls_fingerprint profile string to the H2
// send-fingerprint the Layer should present. Firefox shaping applies to the
// upstream (ClientRole) send-shape only; ServerRole (client-facing) Layers
// always use the default shape. Unknown / empty profiles fall back to the
// default with no error (mirrors the uTLS layer's fallback, USK-1007 U2).
func resolveH2Fingerprint(profile string, role Role) H2Fingerprint {
	if role != ClientRole {
		return H2FingerprintDefault
	}
	switch strings.ToLower(strings.TrimSpace(profile)) {
	case "firefox":
		return H2FingerprintFirefox
	default:
		return H2FingerprintDefault
	}
}

// firefoxClientSettings returns the local SETTINGS a Firefox-shaped
// ClientRole Layer applies (and therefore both advertises on the wire and
// enforces for receive-side flow control). Unlike the default ClientRole
// path — which advertises a 16 MiB stream window — Firefox advertises a
// 131072-byte stream window, so the local settings must match to keep the
// flow-control accounting coherent with what the wire announced.
//
// EnablePush is left 0 here; applyEnablePushDefault re-affirms it for
// ClientRole per RFC 9113 §6.5.2. MaxConcurrentStreams / MaxHeaderListSize
// are intentionally left 0 so firefoxSettingsFrame omits them from the wire.
func firefoxClientSettings() Settings {
	return Settings{
		HeaderTableSize:   firefoxHeaderTableSize,
		EnablePush:        0,
		InitialWindowSize: firefoxInitialWindowSize,
		MaxFrameSize:      firefoxMaxFrameSize,
	}
}

// firefoxSettingsFrame serializes s into the Firefox SETTINGS wire order:
// HEADER_TABLE_SIZE (0x1), ENABLE_PUSH (0x2), INITIAL_WINDOW_SIZE (0x4),
// MAX_FRAME_SIZE (0x5). MAX_CONCURRENT_STREAMS is dropped entirely (Firefox
// does not advertise it). MAX_HEADER_LIST_SIZE is emitted only when a caller
// explicitly set a non-zero value (the pure Firefox shape leaves it 0 and
// therefore off the wire), preserving the same conditional-emission contract
// settingsToFrame applies for the default shape (e.g. the gRPC layer's
// WithMaxHeaderListSize).
func firefoxSettingsFrame(s Settings) []frame.Setting {
	out := []frame.Setting{
		{ID: frame.SettingHeaderTableSize, Value: s.HeaderTableSize},
		{ID: frame.SettingEnablePush, Value: s.EnablePush},
		{ID: frame.SettingInitialWindowSize, Value: s.InitialWindowSize},
		{ID: frame.SettingMaxFrameSize, Value: s.MaxFrameSize},
	}
	if s.MaxHeaderListSize != 0 {
		out = append(out, frame.Setting{
			ID:    frame.SettingMaxHeaderListSize,
			Value: s.MaxHeaderListSize,
		})
	}
	return out
}

// defaultLocalSettings returns the local SETTINGS a Layer applies when the
// caller did not supply an explicit WithInitialSettings override, selected by
// fingerprint. The default (Chrome-shaped) path advertises a 16 MiB stream
// window; the Firefox path advertises Firefox's 131072-byte window.
func defaultLocalSettings(fp H2Fingerprint) Settings {
	if fp == H2FingerprintFirefox {
		return firefoxClientSettings()
	}
	def := DefaultSettings()
	def.InitialWindowSize = defaultLargeStreamWindow
	return def
}

// connWindowIncrement returns the stream-0 WINDOW_UPDATE increment sent after
// the preface SETTINGS, selected by fingerprint. Default raises the
// connection window to 16 MiB; Firefox raises it to 12 MiB.
func connWindowIncrement(fp H2Fingerprint) uint32 {
	if fp == H2FingerprintFirefox {
		return firefoxConnWindowIncrement
	}
	return uint32(defaultLargeConnWindow - defaultConnectionWindowSize)
}
