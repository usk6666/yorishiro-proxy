package config

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// ValidateListenAddr validates a proxy listener bind address ("host:port").
//
// Accepted hosts are IP literals of any scope — loopback, unspecified
// (0.0.0.0 / ::), private, public, link-local with a zone — and the literal
// "localhost". Other host names are rejected so the bound interface never
// depends on DNS resolution, and legacy IPv4 spellings ("127.1",
// "0x7f.0.0.1", "2130706433") are rejected by netip's strict parser. An
// empty host is rejected: binding every interface must be spelled out as
// 0.0.0.0 or [::].
//
// The port must be a decimal 0..65535; service names ("http") are rejected
// so the bound port is exactly what the operator wrote. Port 0 requests a
// kernel-assigned ephemeral port.
//
// Non-loopback addresses make the proxy reachable by any host that can
// route to them, with no client authentication. Access control for such a
// deployment is the network side (e.g. nftables) plus the TargetScope
// Policy.
func ValidateListenAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid listen_addr %q: %w", addr, err)
	}
	if host == "" {
		return fmt.Errorf("invalid listen_addr %q: host must be specified; write 0.0.0.0 or [::] explicitly to listen on all interfaces (e.g. 127.0.0.1:8080, 0.0.0.0:8080)", addr)
	}
	if host != "localhost" {
		if _, err := netip.ParseAddr(host); err != nil {
			return fmt.Errorf("invalid listen_addr %q: host must be an IP literal or \"localhost\" (host names are not resolved)", addr)
		}
	}
	if err := validateListenPort(port); err != nil {
		return fmt.Errorf("invalid listen_addr %q: %w", addr, err)
	}
	return nil
}

// validateListenPort accepts a plain decimal port 0..65535 (no sign, no
// service name).
func validateListenPort(port string) error {
	if port == "" || len(port) > 5 {
		return fmt.Errorf("port must be a decimal number 0-65535")
	}
	for _, c := range port {
		if c < '0' || c > '9' {
			return fmt.Errorf("port must be a decimal number 0-65535")
		}
	}
	if n, err := strconv.Atoi(port); err != nil || n > 65535 {
		return fmt.Errorf("port must be a decimal number 0-65535")
	}
	return nil
}
