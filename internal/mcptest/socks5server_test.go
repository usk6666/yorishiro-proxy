//go:build e2e

package mcptest_test

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// placeholderSOCKS5Listener wraps a plain loopback TCP listener used by
// USK-725's SOCKS5 wiring tests as a stand-in for a real SOCKS5 server.
// It performs no RFC 1928 / RFC 1929 handshake, accepts no
// authentication, and never reads bytes off the accepted sockets — its
// sole purpose is to expose a reachable Addr() so the URL the test hands
// to proxy_start is syntactically valid and points at a real loopback
// port. The full SOCKS5 fixture (handshake-capable; see socks5Server
// below) lives behind USK-734's transit assertion. Acceptance-only
// scenarios (the URL is parsed and stored, no traffic flows) keep using
// this placeholder.
type placeholderSOCKS5Listener struct {
	listener net.Listener
	closed   atomic.Bool
}

// startPlaceholderSOCKS5Listener returns the address of a TCP listener
// used as a placeholder for acceptance-only scenarios — the proxy never
// attempts a SOCKS5 handshake against it. Tests that drive traffic
// through SOCKS5 use startSOCKS5Server instead.
func startPlaceholderSOCKS5Listener(t *testing.T) *placeholderSOCKS5Listener {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5 placeholder: %v", err)
	}

	s := &placeholderSOCKS5Listener{listener: ln}
	t.Cleanup(s.Close)
	return s
}

// Addr returns the host:port the listener is bound to.
func (s *placeholderSOCKS5Listener) Addr() string {
	return s.listener.Addr().String()
}

// Close stops the listener. Idempotent.
func (s *placeholderSOCKS5Listener) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.listener.Close()
}

// socks5Server is a minimal RFC 1928 + RFC 1929 SOCKS5 server used by
// USK-734's transit-assertion test. It accepts the username/password
// auth method (when configured) and CONNECT requests, then bridges
// bytes between the client and the requested target.
//
// Scope: just enough to verify yorishiro-proxy's upstream-SOCKS5 client
// path. Not a production SOCKS5 implementation — only IPv4 and DOMAIN
// address types are supported, and only the CONNECT command is honoured.
// Other variants are rejected at the SOCKS5 reply layer so test
// assertions on auth/transit failures stay narrowly-scoped.
type socks5Server struct {
	listener net.Listener
	username string
	password string

	// requireAuth toggles RFC 1929 user/pass auth. When false the server
	// advertises method 0x00 (no auth) only.
	requireAuth bool

	// connections counts the number of accepted client connections that
	// completed a SUCCESSFUL CONNECT (i.e. transited the server). Reads
	// are atomic so the test goroutine can poll without locking.
	connections atomic.Int32

	// authFailures counts auth attempts that failed with bad creds.
	authFailures atomic.Int32

	// lastTarget is the most recent CONNECT target string ("host:port")
	// the server bridged to. Empty when no CONNECT has happened.
	mu         sync.Mutex
	lastTarget string

	closed atomic.Bool
	wg     sync.WaitGroup
}

// startSOCKS5Server launches a minimal SOCKS5 server on a loopback
// ephemeral port. When username/password are non-empty, RFC 1929 auth
// is required and the server rejects mismatched credentials with reply
// 0xFF. Empty username + password disables auth.
//
// The server is torn down via t.Cleanup. The accept goroutine drains on
// listener.Close; per-conn goroutines are bounded by handler completion
// or context cancel.
func startSOCKS5Server(t *testing.T, username, password string) *socks5Server {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen socks5 server: %v", err)
	}

	s := &socks5Server{
		listener:    ln,
		username:    username,
		password:    password,
		requireAuth: username != "" || password != "",
	}
	t.Cleanup(s.Close)

	s.wg.Add(1)
	go s.acceptLoop()
	return s
}

// Addr returns host:port the server is bound to.
func (s *socks5Server) Addr() string {
	return s.listener.Addr().String()
}

// Connections returns the number of successful CONNECT bridges.
func (s *socks5Server) Connections() int32 {
	return s.connections.Load()
}

// AuthFailures returns the number of bad-creds rejections.
func (s *socks5Server) AuthFailures() int32 {
	return s.authFailures.Load()
}

// LastTarget returns the most recently bridged target string.
func (s *socks5Server) LastTarget() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastTarget
}

// Close stops the server. Idempotent. Blocks until in-flight handlers
// drain (bounded by their own conn deadlines).
func (s *socks5Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	_ = s.listener.Close()
	s.wg.Wait()
}

func (s *socks5Server) acceptLoop() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || s.closed.Load() {
				return
			}
			// Don't surface errors via t.Errorf from inside the
			// goroutine — t.Errorf is not safe across goroutines after
			// the parent test exits. Log and bail.
			log.Printf("socks5: accept error: %v", err)
			return
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handle(c)
		}(conn)
	}
}

// handle runs the per-connection SOCKS5 negotiation + bridge.
func (s *socks5Server) handle(c net.Conn) {
	// Bound the handshake; bytes copied during the bridge phase use
	// no deadline (handlers stay alive until either side EOFs).
	_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))

	// --- Greeting (RFC 1928 §3) ---
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return
	}
	if header[0] != 0x05 {
		return // not SOCKS5
	}
	nmethods := int(header[1])
	methods := make([]byte, nmethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	// --- Method selection ---
	wantMethod := byte(0x00) // no auth
	if s.requireAuth {
		wantMethod = 0x02 // user/pass
	}
	supported := false
	for _, m := range methods {
		if m == wantMethod {
			supported = true
			break
		}
	}
	if !supported {
		_, _ = c.Write([]byte{0x05, 0xFF})
		return
	}
	if _, err := c.Write([]byte{0x05, wantMethod}); err != nil {
		return
	}

	// --- Sub-negotiation: RFC 1929 user/pass when required ---
	if s.requireAuth {
		ok, err := s.readAndCheckAuth(c)
		if err != nil {
			return
		}
		if !ok {
			s.authFailures.Add(1)
			_, _ = c.Write([]byte{0x01, 0x01}) // failure
			return
		}
		if _, err := c.Write([]byte{0x01, 0x00}); err != nil {
			return
		}
	}

	// --- Request: VER=0x05, CMD, RSV=0x00, ATYP, DST.ADDR, DST.PORT ---
	reqHdr := make([]byte, 4)
	if _, err := io.ReadFull(c, reqHdr); err != nil {
		return
	}
	if reqHdr[0] != 0x05 {
		return
	}
	if reqHdr[1] != 0x01 { // CONNECT only
		s.replyError(c, 0x07) // command not supported
		return
	}

	host, err := s.readDestination(c, reqHdr[3])
	if err != nil {
		s.replyError(c, 0x08) // address type not supported
		return
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, portBuf); err != nil {
		return
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(host, strconv.Itoa(int(port)))

	// Clear the handshake deadline before the bridge phase so long-lived
	// CONNECT tunnels (the proxy keeping the upstream conn open) are not
	// torn down mid-flight.
	_ = c.SetReadDeadline(time.Time{})

	// Dial upstream and reply.
	upstream, err := net.DialTimeout("tcp", target, 5*time.Second)
	if err != nil {
		s.replyError(c, 0x05) // connection refused (general)
		return
	}
	defer upstream.Close()

	// Reply: succeeded; BND.ADDR/BND.PORT echo our local view.
	if err := s.replySuccess(c, upstream); err != nil {
		return
	}

	s.connections.Add(1)
	s.mu.Lock()
	s.lastTarget = target
	s.mu.Unlock()

	// --- Bridge bytes both directions until either side EOFs/errors ---
	bridge(c, upstream)
}

// readAndCheckAuth reads an RFC 1929 sub-negotiation block and returns
// (ok, err). ok indicates the credentials matched the server's
// configured user/pass.
func (s *socks5Server) readAndCheckAuth(c net.Conn) (bool, error) {
	verBuf := make([]byte, 2)
	if _, err := io.ReadFull(c, verBuf); err != nil {
		return false, err
	}
	if verBuf[0] != 0x01 { // sub-negotiation version
		return false, fmt.Errorf("unsupported auth version %d", verBuf[0])
	}
	ulen := int(verBuf[1])
	user := make([]byte, ulen)
	if _, err := io.ReadFull(c, user); err != nil {
		return false, err
	}
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(c, plenBuf); err != nil {
		return false, err
	}
	plen := int(plenBuf[0])
	pass := make([]byte, plen)
	if _, err := io.ReadFull(c, pass); err != nil {
		return false, err
	}
	return string(user) == s.username && string(pass) == s.password, nil
}

// readDestination decodes the SOCKS5 request DST.ADDR for the given
// ATYP. Only IPv4 (0x01) and DOMAIN (0x03) are supported — the proxy's
// upstream-SOCKS5 client only emits these forms.
func (s *socks5Server) readDestination(c net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03: // DOMAIN
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c, lenBuf); err != nil {
			return "", err
		}
		dlen := int(lenBuf[0])
		buf := make([]byte, dlen)
		if _, err := io.ReadFull(c, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	default:
		return "", fmt.Errorf("unsupported atyp %d", atyp)
	}
}

// replyError writes a SOCKS5 reply with the given REP code, IPv4
// 0.0.0.0:0 BND fields. Used for non-success paths.
func (s *socks5Server) replyError(c net.Conn, rep byte) {
	_, _ = c.Write([]byte{0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
}

// replySuccess writes a SOCKS5 success reply, encoding the local
// address of the upstream conn in the BND fields.
func (s *socks5Server) replySuccess(c net.Conn, upstream net.Conn) error {
	local := upstream.LocalAddr().(*net.TCPAddr)
	ip4 := local.IP.To4()
	if ip4 == nil {
		ip4 = []byte{0, 0, 0, 0}
	}
	reply := make([]byte, 0, 10)
	reply = append(reply, 0x05, 0x00, 0x00, 0x01)
	reply = append(reply, ip4...)
	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(local.Port))
	reply = append(reply, portBuf...)
	_, err := c.Write(reply)
	return err
}

// bridge copies bytes between a and b until either direction errors. It
// closes the half-direction on EOF rather than the whole conn, so a
// graceful FIN from one side does not abort an in-flight response on
// the other. Defers come from the parent.
func bridge(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(b, a)
		if cw, ok := b.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(a, b)
		if cw, ok := a.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
	}()
	wg.Wait()
}

// closeWriter is implemented by *net.TCPConn (CloseWrite). The bridge
// uses it to issue a half-close on EOF so the peer's pending read can
// drain naturally. Defined as an interface so the type switch is
// readable.
type closeWriter interface {
	CloseWrite() error
}
