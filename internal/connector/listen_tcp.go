package connector

import (
	"net"
	"net/netip"
)

// ListenTCP binds a TCP listener on addr for the proxy data path (the
// FullListener and TCP forward listeners).
//
// An IPv4 literal host is bound with network "tcp4". Go's
// net.Listen("tcp", "0.0.0.0:p") opens a dual-stack socket, which would also
// expose the listener on every IPv6 address — wider than the operator
// wrote, and invisible to IPv4-only firewall rules (USK-1125). Every other
// host (IPv6 literals, "localhost") keeps network "tcp", so "[::]" stays the
// platform's dual-stack wildcard and "localhost" resolves as before.
func ListenTCP(addr string) (net.Listener, error) {
	return net.Listen(listenNetwork(addr), addr)
}

// listenNetwork returns "tcp4" for an IPv4-literal host and "tcp" otherwise.
// An unparseable addr also yields "tcp" so net.Listen reports its own error.
func listenNetwork(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp"
	}
	if ip, err := netip.ParseAddr(host); err == nil && ip.Is4() {
		return "tcp4"
	}
	return "tcp"
}
