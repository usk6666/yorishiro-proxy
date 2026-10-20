package connector

import "net"

// ListenTCP binds a TCP listener on addr.
func ListenTCP(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
