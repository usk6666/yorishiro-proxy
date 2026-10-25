//go:build linux

package connector

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
)

const transparentSupported = true

// Netfilter getsockopt option numbers (linux/netfilter_ipv4.h,
// linux/netfilter_ipv6/ip6_tables.h). Both are 80.
const (
	soOriginalDst     = 80 // SO_ORIGINAL_DST, level SOL_IP
	ip6tSoOriginalDst = 80 // IP6T_SO_ORIGINAL_DST, level SOL_IPV6
)

// platformOriginalDst is the Linux REDIRECT resolver: getsockopt
// SO_ORIGINAL_DST for an IPv4 (or IPv4-mapped, dual-stack) connection,
// IP6T_SO_ORIGINAL_DST for IPv6. The standard library has no typed
// wrapper for these options, so the result is read through the
// getsockopt wrappers whose buffer is at least as large as the
// sockaddr the kernel writes: IPv6Mreq (20 bytes ≥ sockaddr_in) and
// IPv6MTUInfo (32 bytes, starting with a sockaddr_in6).
func platformOriginalDst(conn net.Conn) (netip.AddrPort, error) {
	if pc, ok := conn.(*PeekConn); ok {
		conn = pc.Conn
	}
	sc, ok := conn.(syscall.Conn)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("connector: SO_ORIGINAL_DST: %T has no file descriptor", conn)
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("connector: SO_ORIGINAL_DST: %w", err)
	}
	local, ok := addrPortOf(conn.LocalAddr())
	if !ok {
		return netip.AddrPort{}, errors.New("connector: SO_ORIGINAL_DST: no local address")
	}
	v4 := local.Addr().Is4()

	var (
		dst  netip.AddrPort
		gerr error
	)
	cerr := raw.Control(func(fd uintptr) {
		if v4 {
			var mreq *syscall.IPv6Mreq
			mreq, gerr = syscall.GetsockoptIPv6Mreq(int(fd), syscall.SOL_IP, soOriginalDst)
			if gerr == nil {
				dst = decodeOrigDst4(mreq.Multiaddr)
			}
			return
		}
		var info *syscall.IPv6MTUInfo
		info, gerr = syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.SOL_IPV6, ip6tSoOriginalDst)
		if gerr == nil {
			dst = decodeOrigDst6(info.Addr)
		}
	})
	if cerr != nil {
		return netip.AddrPort{}, fmt.Errorf("connector: SO_ORIGINAL_DST: %w", cerr)
	}
	if gerr != nil {
		return netip.AddrPort{}, fmt.Errorf("connector: SO_ORIGINAL_DST: %w", gerr)
	}
	return dst, nil
}

// decodeOrigDst4 decodes a sockaddr_in returned by SO_ORIGINAL_DST:
// family (host order), port (network order), address.
func decodeOrigDst4(b [16]byte) netip.AddrPort {
	if binary.NativeEndian.Uint16(b[0:2]) != syscall.AF_INET {
		return netip.AddrPort{}
	}
	port := binary.BigEndian.Uint16(b[2:4])
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte(b[4:8])), port)
}

// decodeOrigDst6 decodes a sockaddr_in6 returned by IP6T_SO_ORIGINAL_DST.
// sin6_port holds the port in network byte order.
func decodeOrigDst6(sa syscall.RawSockaddrInet6) netip.AddrPort {
	if sa.Family != syscall.AF_INET6 {
		return netip.AddrPort{}
	}
	var p [2]byte
	binary.NativeEndian.PutUint16(p[:], sa.Port)
	return netip.AddrPortFrom(netip.AddrFrom16(sa.Addr), binary.BigEndian.Uint16(p[:]))
}
