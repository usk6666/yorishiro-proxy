package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strconv"
)

// SOCKS5 command codes (RFC 1928, Section 4).
const (
	cmdConnect      = 0x01
	cmdBind         = 0x02
	cmdUDPAssociate = 0x03
)

// SOCKS5 address types (RFC 1928, Section 4).
const (
	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04
)

// SOCKS5 reply codes (RFC 1928, Section 6).
const (
	replySuccess              = 0x00
	replyGeneralFailure       = 0x01
	replyConnectionNotAllowed = 0x02
	replyNetworkUnreachable   = 0x03
	replyHostUnreachable      = 0x04
	replyConnectionRefused    = 0x05
	replyTTLExpired           = 0x06
	replyCommandNotSupported  = 0x07
	replyAddrTypeNotSupported = 0x08
)

// handleRequest reads the SOCKS5 request from the client and returns the
// target address as "host:port". Only the CONNECT command is supported.
//
// Request format (RFC 1928, Section 4):
//
//	+----+-----+-------+------+----------+----------+
//	|VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func (h *Handler) handleRequest(conn net.Conn) (string, error) {
	// Read fixed header: VER, CMD, RSV, ATYP.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}

	if header[0] != socks5Version {
		_ = writeReply(conn, replyGeneralFailure, nil)
		return "", fmt.Errorf("unsupported SOCKS version in request: %d", header[0])
	}

	cmd := header[1]
	atyp := header[3]

	// Only CONNECT is supported.
	if cmd != cmdConnect {
		_ = writeReply(conn, replyCommandNotSupported, nil)
		return "", fmt.Errorf("unsupported command: %d", cmd)
	}

	// Parse destination address.
	host, err := readAddress(conn, atyp)
	if err != nil {
		_ = writeReply(conn, replyAddrTypeNotSupported, nil)
		return "", fmt.Errorf("read address: %w", err)
	}

	// Read destination port (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readAddress reads the destination address from the SOCKS5 request based on
// the address type.
func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		return net.IP(addr).String(), nil

	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return "", fmt.Errorf("read domain length: %w", err)
		}
		domainLen := int(lenBuf[0])
		if domainLen == 0 {
			return "", fmt.Errorf("empty domain name")
		}
		domain := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domain); err != nil {
			return "", fmt.Errorf("read domain: %w", err)
		}
		return string(domain), nil

	case atypIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		return net.IP(addr).String(), nil

	default:
		return "", fmt.Errorf("unsupported address type: %d", atyp)
	}
}

// writeReply sends a SOCKS5 reply to the client.
//
// Reply format (RFC 1928, Section 6):
//
//	+----+-----+-------+------+----------+----------+
//	|VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
//	+----+-----+-------+------+----------+----------+
//	| 1  |  1  | X'00' |  1   | Variable |    2     |
//	+----+-----+-------+------+----------+----------+
func writeReply(conn net.Conn, rep byte, bindAddr net.Addr) error {
	var atyp byte
	var addr []byte
	var port uint16

	if bindAddr != nil {
		if tcpAddr, ok := bindAddr.(*net.TCPAddr); ok {
			port = uint16(tcpAddr.Port)
			if ip4 := tcpAddr.IP.To4(); ip4 != nil {
				atyp = atypIPv4
				addr = ip4
			} else if ip6 := tcpAddr.IP.To16(); ip6 != nil {
				atyp = atypIPv6
				addr = ip6
			}
		}
	}

	// Default to IPv4 0.0.0.0:0 if no address is available.
	if addr == nil {
		atyp = atypIPv4
		addr = []byte{0, 0, 0, 0}
	}

	reply := make([]byte, 0, 4+len(addr)+2)
	reply = append(reply, socks5Version, rep, 0x00, atyp)
	reply = append(reply, addr...)
	reply = append(reply, byte(port>>8), byte(port))

	_, err := conn.Write(reply)
	return err
}

// parseHostPort splits a host:port string into hostname and port number.
func parseHostPort(target string) (string, int, error) {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return "", 0, fmt.Errorf("split host port: %w", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return "", 0, fmt.Errorf("parse port: %w", err)
	}
	return host, port, nil
}
