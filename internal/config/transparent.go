package config

import (
	"errors"
	"fmt"
	"runtime"
)

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
// tcpForwards is the number of configured tcp_forwards entries. Values
// are case-sensitive. "redirect" is refused on a platform without
// REDIRECT support (the error wraps errors.ErrUnsupported), together with
// tcp_forwards (a forward has a fixed target; a transparent listener
// takes each connection's own), and with socks5_auth=password (a
// transparent listener never speaks SOCKS5, so the setting would silently
// do nothing).
func ValidateTransparentMode(mode string, tcpForwards int, socks5Auth string) error {
	switch mode {
	case "", TransparentModeNone:
		return nil
	case TransparentModeRedirect:
	default:
		return fmt.Errorf("transparent_mode %q is not valid: use %q or %q", mode, TransparentModeNone, TransparentModeRedirect)
	}
	if !transparentSupported {
		return fmt.Errorf("transparent_mode %q requires Linux (getsockopt SO_ORIGINAL_DST): %w", mode, errors.ErrUnsupported)
	}
	if tcpForwards > 0 {
		return fmt.Errorf("transparent_mode %q cannot be combined with tcp_forwards", mode)
	}
	if socks5Auth == "password" {
		return fmt.Errorf("transparent_mode %q cannot be combined with socks5_auth=password (a transparent listener does not accept SOCKS5)", mode)
	}
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
	if ms == 0 {
		return nil
	}
	if ms < MinTransparentPeekTimeoutMs || ms > MaxTransparentPeekTimeoutMs {
		return fmt.Errorf("transparent_peek_timeout_ms must be between %d and %d, got %d", MinTransparentPeekTimeoutMs, MaxTransparentPeekTimeoutMs, ms)
	}
	return nil
}
