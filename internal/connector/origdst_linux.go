//go:build linux

package connector

import (
	"errors"
	"net"
	"net/netip"
	"syscall"
)

const transparentSupported = true

// platformOriginalDst is the Linux REDIRECT resolver.
func platformOriginalDst(conn net.Conn) (netip.AddrPort, error) {
	_ = conn
	return netip.AddrPort{}, errors.New("not implemented")
}

// decodeOrigDst4 decodes a sockaddr_in returned by SO_ORIGINAL_DST.
func decodeOrigDst4(b [16]byte) netip.AddrPort {
	_ = b
	return netip.AddrPort{}
}

// decodeOrigDst6 decodes a sockaddr_in6 returned by IP6T_SO_ORIGINAL_DST.
func decodeOrigDst6(sa syscall.RawSockaddrInet6) netip.AddrPort {
	_ = sa
	return netip.AddrPort{}
}
