//go:build !linux

package connector

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
)

const transparentSupported = false

// platformOriginalDst reports that REDIRECT transparent mode needs Linux
// (getsockopt SO_ORIGINAL_DST is a netfilter interface).
func platformOriginalDst(net.Conn) (netip.AddrPort, error) {
	return netip.AddrPort{}, fmt.Errorf("connector: transparent mode (SO_ORIGINAL_DST) requires Linux: %w", errors.ErrUnsupported)
}
