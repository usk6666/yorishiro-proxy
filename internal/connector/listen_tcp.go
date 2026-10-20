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
//
// An IPv4-mapped IPv6 literal ("[::ffff:0.0.0.0]", "[::ffff:127.0.0.1]")
// is the IPv4 address it maps and is bound as that IPv4 literal with
// "tcp4"; with "tcp", Go would turn the mapped wildcard into the dual-stack
// "[::]" socket.
func ListenTCP(addr string) (net.Listener, error) {
	network, bindAddr := listenTarget(addr)
	return net.Listen(network, bindAddr)
}

// listenNetwork returns "tcp4" for an IPv4-literal host (including an
// IPv4-mapped IPv6 literal) and "tcp" otherwise.
func listenNetwork(addr string) string {
	network, _ := listenTarget(addr)
	return network
}

// listenTarget returns the network and address net.Listen is called with.
// An IPv4 or IPv4-mapped literal host yields "tcp4" and the unmapped IPv4
// host; every other addr (including an unparseable one, so net.Listen
// reports its own error) is returned unchanged with "tcp".
func listenTarget(addr string) (network, bindAddr string) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "tcp", addr
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return "tcp", addr
	}
	if ip = ip.Unmap(); ip.Is4() {
		return "tcp4", net.JoinHostPort(ip.String(), port)
	}
	return "tcp", addr
}
