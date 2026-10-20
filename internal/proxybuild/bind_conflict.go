package proxybuild

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

// fallbackForwardBindHost is the forward bind host used when the parent
// listener's bound address cannot be read (the parent was stopped
// concurrently; StartTCPForwardsNamed discards the forward in that case).
const fallbackForwardBindHost = "127.0.0.1"

// bindAddrsOverlap reports whether two host:port bind addresses contend
// for the same socket: their ports are equal and non-zero, and their hosts
// are equal or either host is the unspecified address (0.0.0.0 / ::).
//
// The rule is deliberately conservative. "0.0.0.0:p" vs "[::1]:p" is
// reported as overlapping even though a v4-only wildcard does not cover
// ::1 — an accepted false positive that keeps the rule independent of the
// platform's IPV6_V6ONLY default. The literal "localhost" (accepted by
// config.ValidateListenAddr and resolved by net.Listen) overlaps every
// loopback address. Port 0 asks the kernel for a fresh ephemeral port, so
// it never overlaps anything.
func bindAddrsOverlap(a, b string) bool {
	aHost, aPort, err := net.SplitHostPort(a)
	if err != nil {
		return false
	}
	bHost, bPort, err := net.SplitHostPort(b)
	if err != nil {
		return false
	}
	ap, err := strconv.Atoi(aPort)
	if err != nil || ap == 0 {
		return false
	}
	bp, err := strconv.Atoi(bPort)
	if err != nil || bp != ap {
		return false
	}
	return bindHostsOverlap(aHost, bHost)
}

// bindHostsOverlap is the host half of bindAddrsOverlap.
func bindHostsOverlap(a, b string) bool {
	if isUnspecifiedHost(a) || isUnspecifiedHost(b) {
		return true
	}
	if a == "localhost" || b == "localhost" {
		return isLoopbackHost(a) && isLoopbackHost(b)
	}
	aa, errA := netip.ParseAddr(a)
	bb, errB := netip.ParseAddr(b)
	if errA != nil || errB != nil {
		return a == b
	}
	return aa.Unmap() == bb.Unmap()
}

func isUnspecifiedHost(h string) bool {
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.IsUnspecified()
}

func isLoopbackHost(h string) bool {
	if h == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(h)
	return err == nil && ip.Unmap().IsLoopback()
}

// isNonLoopbackBind reports whether a bound listener address (as returned
// by net.Listener.Addr().String()) is reachable beyond the loopback
// interface. Unparseable hosts report false: a bound listener always
// reports an IP literal.
func isNonLoopbackBind(boundAddr string) bool {
	host, _, err := net.SplitHostPort(boundAddr)
	if err != nil {
		return false
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return !ip.Unmap().IsLoopback()
}

// checkBindConflictLocked returns an error wrapping ErrBindConflict when
// addr overlaps the bound address of any running listener or TCP forward
// under this Manager. Caller must hold m.mu.
//
// The registry only holds sockets that are already bound, so the check is
// exact for StartNamed (which holds m.mu across its bind). A forward is
// registered just after its bind, outside m.mu; a concurrent start that
// races into that window falls through to the kernel's own EADDRINUSE.
func (m *Manager) checkBindConflictLocked(addr string) error {
	for name, entry := range m.listeners {
		if bindAddrsOverlap(addr, entry.listenAddr) {
			return fmt.Errorf("%w: %s overlaps listener %q bound on %s", ErrBindConflict, addr, name, entry.listenAddr)
		}
		for port, fwd := range entry.tcpForwards {
			if bindAddrsOverlap(addr, fwd.addr) {
				return fmt.Errorf("%w: %s overlaps tcp forward %s of listener %q bound on %s", ErrBindConflict, addr, port, name, fwd.addr)
			}
		}
	}
	return nil
}

// forwardBindHostLocked returns the host a TCP forward of the named parent
// listener binds on: the parent's bound host (USK-1125), so a forward is
// exposed exactly as widely as its parent. Caller must hold m.mu.
func (m *Manager) forwardBindHostLocked(parentListenerName string) string {
	entry, ok := m.listeners[parentListenerName]
	if !ok {
		return fallbackForwardBindHost
	}
	host, _, err := net.SplitHostPort(entry.listenAddr)
	if err != nil || host == "" {
		return fallbackForwardBindHost
	}
	return host
}
