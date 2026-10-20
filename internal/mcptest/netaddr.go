package mcptest

import (
	"net"
	"testing"
)

// NonLoopbackIPv4 returns an IPv4 address assigned to an up, non-loopback
// interface of the test host that a listener can actually bind. Link-local
// addresses are skipped (their reachability depends on the interface). The
// test is skipped when no such address exists or when the environment
// refuses a wildcard bind — sandboxed runners commonly have only lo.
func NonLoopbackIPv4(t testing.TB) string {
	t.Helper()
	if ln, err := net.Listen("tcp", "0.0.0.0:0"); err != nil {
		t.Skipf("cannot bind 0.0.0.0 in this environment: %v", err)
	} else {
		_ = ln.Close()
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		t.Skipf("no non-loopback IPv4 address bindable in this environment: list interfaces: %v", err)
	}
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil || ip4.IsLoopback() || ip4.IsLinkLocalUnicast() {
				continue
			}
			ln, err := net.Listen("tcp", net.JoinHostPort(ip4.String(), "0"))
			if err != nil {
				continue
			}
			_ = ln.Close()
			return ip4.String()
		}
	}
	t.Skip("no non-loopback IPv4 address bindable in this environment")
	return ""
}
