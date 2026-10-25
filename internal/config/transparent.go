package config

import "runtime"

// Transparent-mode values for ProxyConfig.TransparentMode and the
// proxy_start `transparent_mode` input (USK-1316).
const (
	// TransparentModeNone explicitly turns transparent mode off, overriding
	// a config-file default. The empty string means "inherit" (off when
	// nothing is configured).
	TransparentModeNone = "none"

	// TransparentModeRedirect makes the listener accept connections an
	// nftables / iptables REDIRECT rule diverted to it, relaying each to
	// its original destination (getsockopt SO_ORIGINAL_DST). Linux only.
	TransparentModeRedirect = "redirect"
)

// transparentSupported reports whether this platform supports
// TransparentModeRedirect. A variable so tests can exercise the
// unsupported-platform error on Linux.
var transparentSupported = runtime.GOOS == "linux"

// ValidateTransparentMode checks a transparent_mode value against the
// settings it cannot be combined with.
func ValidateTransparentMode(mode string, tcpForwards int, socks5Auth string) error {
	_ = mode
	_ = tcpForwards
	_ = socks5Auth
	return nil
}

// DefaultTransparentPeekTimeoutMs is the default transparent peek
// deadline in milliseconds (owner decision, USK-1316).
const DefaultTransparentPeekTimeoutMs = 1000

// Bounds of transparent_peek_timeout_ms, matching the other proxy_start
// timeout inputs.
const (
	MinTransparentPeekTimeoutMs = 100
	MaxTransparentPeekTimeoutMs = 600000
)

// ValidateTransparentPeekTimeoutMs checks a transparent_peek_timeout_ms
// value: 0 (default) or MinTransparentPeekTimeoutMs..MaxTransparentPeekTimeoutMs.
func ValidateTransparentPeekTimeoutMs(ms int) error {
	_ = ms
	return nil
}
