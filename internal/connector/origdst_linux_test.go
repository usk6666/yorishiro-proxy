//go:build linux

package connector

import (
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"testing"
)

// T1 (USK-1316): the real getsockopt(SO_ORIGINAL_DST) on a connection no
// REDIRECT rule touched. With nf_conntrack loaded Linux reports the
// connection's own local address (IPv4); without it, or for IPv6, it
// fails (ENOENT). Either way transparent admission must reject the
// connection: a direct client must never be relayed to the proxy itself.

func TestPlatformOriginalDst_NonNATedConnection(t *testing.T) {
	tests := []struct {
		name       string
		listenAddr string
		dialHost   string
	}{
		{name: "IPv4 loopback listener", listenAddr: "127.0.0.1:0", dialHost: "127.0.0.1"},
		{name: "IPv4 wildcard listener", listenAddr: "0.0.0.0:0", dialHost: "127.0.0.1"},
		{name: "dual-stack wildcard listener, IPv4 client", listenAddr: "[::]:0", dialHost: "127.0.0.1"},
		{name: "IPv6 loopback listener", listenAddr: "[::1]:0", dialHost: "::1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ln, err := ListenTCP(tc.listenAddr)
			if err != nil {
				t.Skipf("listen %s: %v", tc.listenAddr, err)
			}
			defer ln.Close()
			_, port, _ := net.SplitHostPort(ln.Addr().String())

			// 1. The resolver itself.
			done := make(chan net.Conn, 1)
			go func() {
				c, err := ln.Accept()
				if err != nil {
					close(done)
					return
				}
				done <- c
			}()
			client, err := net.Dial("tcp", net.JoinHostPort(tc.dialHost, port))
			if err != nil {
				t.Skipf("dial %s: %v", tc.dialHost, err)
			}
			defer client.Close()
			server, ok := <-done
			if !ok {
				t.Fatal("accept failed")
			}
			defer server.Close()

			dst, rerr := PlatformOriginalDstResolver().OriginalDst(server)
			local := netip.MustParseAddrPort(server.LocalAddr().String())
			local = netip.AddrPortFrom(local.Addr().Unmap(), local.Port())
			if rerr == nil && dst != local {
				t.Fatalf("OriginalDst = %v on a non-NATed connection, want an error or the local address %v", dst, local)
			}
			if _, err := resolveTransparentDst(PlatformOriginalDstResolver(), server); err == nil {
				t.Fatalf("resolveTransparentDst admitted a non-NATed connection (OriginalDst = %v, %v)", dst, rerr)
			}
		})
	}
}

// TestFullListener_Transparent_PlatformResolverRejectsDirectClient drives
// the FullListener with the real resolver: a client dialing the listener
// directly is closed without a handler call.
func TestFullListener_Transparent_PlatformResolverRejectsDirectClient(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:0", "0.0.0.0:0"} {
		t.Run(addr, func(t *testing.T) {
			probe := &transparentProbe{}
			fl, logs := startTransparentTestListener(t, addr, PlatformOriginalDstResolver(), probe)
			conn := dialPort(t, fl)
			expectClosedWithoutResponse(t, conn)
			waitLog(t, logs, "level=WARN", "remote_addr="+conn.LocalAddr().String())
			if n, _, _ := probe.snapshot(); n != 0 {
				t.Errorf("handler invoked %d times, want 0", n)
			}
		})
	}
}

// TestDecodeOrigDst covers the sockaddr decoding of both getsockopt
// results: the port is big-endian on the wire.
func TestDecodeOrigDst(t *testing.T) {
	var in4 [16]byte
	binary.NativeEndian.PutUint16(in4[0:2], syscall.AF_INET)
	binary.BigEndian.PutUint16(in4[2:4], 8080)
	copy(in4[4:8], []byte{192, 0, 2, 10})
	if got, want := decodeOrigDst4(in4), netip.MustParseAddrPort("192.0.2.10:8080"); got != want {
		t.Errorf("decodeOrigDst4 = %v, want %v", got, want)
	}

	var sa syscall.RawSockaddrInet6
	sa.Family = syscall.AF_INET6
	var p [2]byte
	binary.BigEndian.PutUint16(p[:], 443)
	sa.Port = binary.NativeEndian.Uint16(p[:])
	sa.Addr = netip.MustParseAddr("2001:db8::1").As16()
	if got, want := decodeOrigDst6(sa), netip.MustParseAddrPort("[2001:db8::1]:443"); got != want {
		t.Errorf("decodeOrigDst6 = %v, want %v", got, want)
	}
}
