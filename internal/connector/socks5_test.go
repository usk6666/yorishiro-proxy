package connector

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"
)

// socks5TestRig runs a single Negotiate call over a net.Pipe and exposes the
// "client side" so tests can drive wire bytes in both directions.
type socks5TestRig struct {
	t         *testing.T
	neg       *SOCKS5Negotiator
	ctx       context.Context
	client    net.Conn
	proxy     net.Conn
	pc        *PeekConn
	done      chan struct{}
	retCtx    context.Context
	retTarget string
	retErr    error
}

func newSOCKS5TestRig(t *testing.T, neg *SOCKS5Negotiator) *socks5TestRig {
	t.Helper()
	client, proxySide := net.Pipe()
	pc := NewPeekConn(proxySide)
	return &socks5TestRig{
		t:      t,
		neg:    neg,
		ctx:    context.Background(),
		client: client,
		proxy:  proxySide,
		pc:     pc,
		done:   make(chan struct{}),
	}
}

// start launches Negotiate in a goroutine.
func (r *socks5TestRig) start() {
	go func() {
		defer close(r.done)
		r.retCtx, r.retTarget, r.retErr = r.neg.Negotiate(r.ctx, r.pc)
	}()
}

// writeClient sends bytes from the "client" to the proxy-side negotiator.
func (r *socks5TestRig) writeClient(b []byte) {
	r.t.Helper()
	if _, err := r.client.Write(b); err != nil {
		r.t.Fatalf("writeClient: %v", err)
	}
}

// readClient reads up to n bytes from the client side.
func (r *socks5TestRig) readClient(n int) []byte {
	r.t.Helper()
	buf := make([]byte, n)
	_ = r.client.SetReadDeadline(time.Now().Add(2 * time.Second))
	read, err := io.ReadFull(r.client, buf)
	if err != nil && read == 0 {
		r.t.Fatalf("readClient: %v", err)
	}
	return buf[:read]
}

// closeAll tears down both pipe ends.
func (r *socks5TestRig) closeAll() {
	_ = r.client.Close()
	_ = r.proxy.Close()
}

// waitDone waits for Negotiate to return.
func (r *socks5TestRig) waitDone(d time.Duration) {
	r.t.Helper()
	select {
	case <-r.done:
	case <-time.After(d):
		r.t.Fatalf("Negotiate did not complete within %v", d)
	}
}

// --- wire helpers ---------------------------------------------------------

// buildMethodGreeting packs a client method selection greeting.
func buildMethodGreeting(methods ...byte) []byte {
	out := []byte{socks5Version, byte(len(methods))}
	return append(out, methods...)
}

// buildAuthSub packs a username/password sub-negotiation message.
func buildAuthSub(user, pass string) []byte {
	out := []byte{socks5AuthSubVersion, byte(len(user))}
	out = append(out, []byte(user)...)
	out = append(out, byte(len(pass)))
	out = append(out, []byte(pass)...)
	return out
}

// buildConnectIPv4 packs a CONNECT request with an IPv4 destination.
func buildConnectIPv4(ip [4]byte, port uint16) []byte {
	out := []byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv4}
	out = append(out, ip[:]...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(out, portBytes...)
}

// buildConnectDomain packs a CONNECT request with a DOMAIN destination.
func buildConnectDomain(domain string, port uint16) []byte {
	out := []byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, byte(len(domain))}
	out = append(out, []byte(domain)...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(out, portBytes...)
}

// buildConnectIPv6 packs a CONNECT request with an IPv6 destination.
func buildConnectIPv6(ip [16]byte, port uint16) []byte {
	out := []byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPIPv6}
	out = append(out, ip[:]...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(out, portBytes...)
}

// buildRequest allows tests to craft arbitrary CMD / ATYP combinations.
func buildRequest(cmd, atyp byte, addr []byte, port uint16) []byte {
	out := []byte{socks5Version, cmd, 0x00, atyp}
	out = append(out, addr...)
	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, port)
	return append(out, portBytes...)
}

// --- method negotiation ---------------------------------------------------

func TestSOCKS5Negotiator_MethodNoAuth(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectIPv4([4]byte{1, 2, 3, 4}, 443))
	}()

	sel := rig.readClient(2)
	if sel[0] != socks5Version || sel[1] != socks5MethodNoAuth {
		t.Errorf("method selection = %v, want [0x05 0x00]", sel)
	}
	reply := rig.readClient(10)
	if reply[1] != socks5ReplySuccess {
		t.Errorf("reply REP = 0x%02x, want 0x00 success", reply[1])
	}

	rig.waitDone(2 * time.Second)
	if rig.retErr != nil {
		t.Fatalf("Negotiate error: %v", rig.retErr)
	}
	if rig.retTarget != "1.2.3.4:443" {
		t.Errorf("target = %q, want 1.2.3.4:443", rig.retTarget)
	}
	if SOCKS5TargetFromContext(rig.retCtx) != "1.2.3.4:443" {
		t.Errorf("ctx target = %q", SOCKS5TargetFromContext(rig.retCtx))
	}
	if SOCKS5AuthMethodFromContext(rig.retCtx) != socks5AuthMethodNone {
		t.Errorf("ctx auth_method = %q, want none", SOCKS5AuthMethodFromContext(rig.retCtx))
	}
}

func TestSOCKS5Negotiator_MethodUserPassPreferred(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"alice": "pw"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		// Offer both — negotiator should prefer username/password when
		// an authenticator is configured.
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth, socks5MethodUsernamePassword))
		rig.writeClient(buildAuthSub("alice", "pw"))
		rig.writeClient(buildConnectDomain("example.com", 443))
	}()

	sel := rig.readClient(2)
	if sel[1] != socks5MethodUsernamePassword {
		t.Errorf("method selection = 0x%02x, want 0x02", sel[1])
	}
	authResp := rig.readClient(2)
	if authResp[1] != socks5AuthSuccess {
		t.Errorf("auth STATUS = 0x%02x, want 0x00", authResp[1])
	}
	reply := rig.readClient(10)
	if reply[1] != socks5ReplySuccess {
		t.Errorf("reply REP = 0x%02x", reply[1])
	}

	rig.waitDone(2 * time.Second)
	if rig.retErr != nil {
		t.Fatalf("Negotiate error: %v", rig.retErr)
	}
	if rig.retTarget != "example.com:443" {
		t.Errorf("target = %q", rig.retTarget)
	}
	if SOCKS5AuthUserFromContext(rig.retCtx) != "alice" {
		t.Errorf("ctx auth user = %q", SOCKS5AuthUserFromContext(rig.retCtx))
	}
	if SOCKS5AuthMethodFromContext(rig.retCtx) != socks5AuthMethodUsernamePassword {
		t.Errorf("ctx auth method = %q", SOCKS5AuthMethodFromContext(rig.retCtx))
	}
}

func TestSOCKS5Negotiator_MethodNoAcceptable(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"a": "b"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		// Only NO_AUTH; authenticator required → 0xFF
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
	}()

	sel := rig.readClient(2)
	if sel[1] != socks5MethodNoAcceptable {
		t.Errorf("method = 0x%02x, want 0xFF", sel[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5NoAcceptableMethods) {
		t.Errorf("err = %v, want ErrSOCKS5NoAcceptableMethods", rig.retErr)
	}
}

func TestSOCKS5Negotiator_MethodNMethodsZero(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() { rig.writeClient([]byte{socks5Version, 0x00}) }()

	sel := rig.readClient(2)
	if sel[1] != socks5MethodNoAcceptable {
		t.Errorf("method = 0x%02x", sel[1])
	}
	rig.waitDone(2 * time.Second)
	if rig.retErr == nil {
		t.Fatal("expected error for NMETHODS=0")
	}
}

// --- authentication -------------------------------------------------------

func TestSOCKS5Negotiator_AuthWrongPassword(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"alice": "correct"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
		rig.writeClient(buildAuthSub("alice", "wrong"))
	}()

	_ = rig.readClient(2) // method sel
	authResp := rig.readClient(2)
	if authResp[1] != socks5AuthFailure {
		t.Errorf("STATUS = 0x%02x", authResp[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5AuthFailed) {
		t.Errorf("err = %v, want ErrSOCKS5AuthFailed", rig.retErr)
	}
}

func TestSOCKS5Negotiator_AuthEmptyUsername(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"alice": "pw"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
		// VER=0x01, ULEN=0 → rejected.
		rig.writeClient([]byte{socks5AuthSubVersion, 0x00})
	}()

	_ = rig.readClient(2) // method sel
	authResp := rig.readClient(2)
	if authResp[1] != socks5AuthFailure {
		t.Errorf("STATUS = 0x%02x", authResp[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5AuthFailed) {
		t.Errorf("err = %v", rig.retErr)
	}
}

func TestSOCKS5Negotiator_AuthEmptyPassword(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"alice": "pw"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
		// VER=0x01, ULEN=5, "alice", PLEN=0.
		msg := []byte{socks5AuthSubVersion, 5, 'a', 'l', 'i', 'c', 'e', 0}
		rig.writeClient(msg)
	}()

	_ = rig.readClient(2)
	authResp := rig.readClient(2)
	if authResp[1] != socks5AuthFailure {
		t.Errorf("STATUS = 0x%02x", authResp[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5AuthFailed) {
		t.Errorf("err = %v", rig.retErr)
	}
}

func TestSOCKS5Negotiator_AuthUnsupportedSubVersion(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"a": "b"})

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
		// Wrong sub-neg version.
		rig.writeClient([]byte{0x02, 1, 'a', 1, 'b'})
	}()

	_ = rig.readClient(2)
	authResp := rig.readClient(2)
	if authResp[1] != socks5AuthFailure {
		t.Errorf("STATUS = 0x%02x", authResp[1])
	}
	rig.waitDone(2 * time.Second)
	if rig.retErr == nil {
		t.Fatal("expected error for bad sub-version")
	}
}

// --- request parsing ------------------------------------------------------

func TestSOCKS5Negotiator_ATYPIPv6(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	var ip6 [16]byte
	ip6[15] = 1 // ::1
	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectIPv6(ip6, 443))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplySuccess {
		t.Errorf("reply REP = 0x%02x", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if rig.retErr != nil {
		t.Fatalf("Negotiate: %v", rig.retErr)
	}
	if rig.retTarget != "[::1]:443" {
		t.Errorf("target = %q, want [::1]:443", rig.retTarget)
	}
}

func TestSOCKS5Negotiator_ATYPDomainZeroLen(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		// VER, CMD=CONNECT, RSV, ATYP=DOMAIN, LEN=0, then PORT(2 bytes).
		rig.writeClient([]byte{socks5Version, socks5CmdConnect, 0x00, socks5ATYPDomain, 0x00, 0, 0})
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyGeneralFailure {
		t.Errorf("reply REP = 0x%02x, want 0x01 general failure", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if rig.retErr == nil {
		t.Fatal("expected error for empty domain")
	}
}

func TestSOCKS5Negotiator_ATYPUnknown(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildRequest(socks5CmdConnect, 0x05, nil, 0))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyAddrTypeNotSupported {
		t.Errorf("reply REP = 0x%02x, want 0x08", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5UnsupportedAddrType) {
		t.Errorf("err = %v", rig.retErr)
	}
}

func TestSOCKS5Negotiator_CMDBind(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildRequest(socks5CmdBind, socks5ATYPIPv4, []byte{0, 0, 0, 0}, 0))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyCommandNotSupported {
		t.Errorf("reply REP = 0x%02x, want 0x07", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5UnsupportedCommand) {
		t.Errorf("err = %v", rig.retErr)
	}
}

func TestSOCKS5Negotiator_CMDUDPAssociate(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildRequest(socks5CmdUDPAssociate, socks5ATYPIPv4, []byte{0, 0, 0, 0}, 0))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyCommandNotSupported {
		t.Errorf("reply REP = 0x%02x, want 0x07", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5UnsupportedCommand) {
		t.Errorf("err = %v", rig.retErr)
	}
}

// --- policy checks --------------------------------------------------------

func TestSOCKS5Negotiator_ScopeBlocked(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	scope := NewTargetScope()
	scope.SetPolicyRules(nil, []TargetRule{{Hostname: "blocked.example"}})
	neg.Scope = scope

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectDomain("blocked.example", 443))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyConnectionNotAllowed {
		t.Errorf("reply REP = 0x%02x, want 0x02", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5BlockedByScope) {
		t.Errorf("err = %v, want ErrSOCKS5BlockedByScope", rig.retErr)
	}
}

func TestSOCKS5Negotiator_RateLimitBlocked(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 0.0001})
	// Warm bucket: the first call consumes the initial token.
	_ = rl.Check("example.com")
	neg.RateLimiter = rl

	rig := newSOCKS5TestRig(t, neg)
	defer rig.closeAll()
	rig.start()

	go func() {
		rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
		rig.writeClient(buildConnectDomain("example.com", 443))
	}()

	_ = rig.readClient(2)
	reply := rig.readClient(10)
	if reply[1] != socks5ReplyConnectionNotAllowed {
		t.Errorf("reply REP = 0x%02x, want 0x02", reply[1])
	}
	rig.waitDone(2 * time.Second)
	if !errors.Is(rig.retErr, ErrSOCKS5BlockedByRateLimit) {
		t.Errorf("err = %v", rig.retErr)
	}
}

// --- per-listener authenticator override ----------------------------------

func TestSOCKS5Negotiator_PerListenerAuthOverride(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.Authenticator = NewStaticAuthenticator(map[string]string{"default": "default-pw"})
	neg.ListenerAuthOverride = map[string]Authenticator{
		"special": NewStaticAuthenticator(map[string]string{"special": "special-pw"}),
	}

	// Case 1: listener "special" — the override credentials must be used.
	t.Run("override listener", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "special")
		defer rig.closeAll()
		rig.start()

		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("special", "special-pw"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()

		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
		if rig.retErr != nil {
			t.Fatalf("Negotiate: %v", rig.retErr)
		}
		if SOCKS5AuthUserFromContext(rig.retCtx) != "special" {
			t.Errorf("user = %q", SOCKS5AuthUserFromContext(rig.retCtx))
		}
	})

	// Case 2: listener "special" rejects the default credentials.
	t.Run("override rejects default creds", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "special")
		defer rig.closeAll()
		rig.start()

		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("default", "default-pw"))
		}()

		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthFailure {
			t.Errorf("STATUS = 0x%02x, want failure", authResp[1])
		}
		rig.waitDone(2 * time.Second)
		if !errors.Is(rig.retErr, ErrSOCKS5AuthFailed) {
			t.Errorf("err = %v", rig.retErr)
		}
	})

	// Case 3: unknown listener falls back to the default authenticator.
	t.Run("unknown listener uses default", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "other")
		defer rig.closeAll()
		rig.start()

		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("default", "default-pw"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()

		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
		if rig.retErr != nil {
			t.Fatalf("Negotiate: %v", rig.retErr)
		}
		if SOCKS5AuthUserFromContext(rig.retCtx) != "default" {
			t.Errorf("user = %q", SOCKS5AuthUserFromContext(rig.retCtx))
		}
	})
}

// --- StaticAuthenticator table tests --------------------------------------

func TestStaticAuthenticator(t *testing.T) {
	a := NewStaticAuthenticator(map[string]string{"alice": "p1", "bob": "p2"})

	cases := []struct {
		user, pass string
		want       bool
	}{
		{"alice", "p1", true},
		{"alice", "wrong", false},
		{"bob", "p2", true},
		{"carol", "p3", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := a.Authenticate(c.user, c.pass); got != c.want {
			t.Errorf("Authenticate(%q,%q) = %v, want %v", c.user, c.pass, got, c.want)
		}
	}

	// Zero value (nil map) rejects everything.
	var zero StaticAuthenticator
	if zero.Authenticate("alice", "p1") {
		t.Error("zero StaticAuthenticator accepted credentials")
	}
	// Nil receiver is safe.
	var nilA *StaticAuthenticator
	if nilA.Authenticate("alice", "p1") {
		t.Error("nil StaticAuthenticator accepted credentials")
	}
}

// --- runtime auth mutate (USK-770) ----------------------------------------

// TestSOCKS5Negotiator_SetAuthenticator_RuntimeMutate exercises the
// SetAuthenticator path used by the MCP proxy_start / configure tools to
// install a global authenticator without listener restart. The first
// handshake runs with NO_AUTH; SetAuthenticator is then called and the
// second handshake exercises USERNAME_PASSWORD against the new credentials.
func TestSOCKS5Negotiator_SetAuthenticator_RuntimeMutate(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())

	// Phase 1: no authenticator installed — NO_AUTH must succeed.
	t.Run("phase_no_auth", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
			rig.writeClient(buildConnectIPv4([4]byte{127, 0, 0, 1}, 80))
		}()
		methodResp := rig.readClient(2)
		if methodResp[1] != socks5MethodNoAuth {
			t.Errorf("method = 0x%02x, want NO_AUTH", methodResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
		if rig.retErr != nil {
			t.Fatalf("Negotiate: %v", rig.retErr)
		}
	})

	// Phase 2: install an authenticator at runtime — handshake must
	// switch to USERNAME_PASSWORD.
	neg.SetAuthenticator(NewStaticAuthenticator(map[string]string{"u": "p"}))

	t.Run("phase_password_after_set", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		defer rig.closeAll()
		rig.start()
		go func() {
			// Client offers both methods; negotiator must pick UP.
			rig.writeClient(buildMethodGreeting(socks5MethodNoAuth, socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("u", "p"))
			rig.writeClient(buildConnectIPv4([4]byte{127, 0, 0, 1}, 80))
		}()
		methodResp := rig.readClient(2)
		if methodResp[1] != socks5MethodUsernamePassword {
			t.Errorf("method = 0x%02x, want USERNAME_PASSWORD", methodResp[1])
		}
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("auth STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
		if rig.retErr != nil {
			t.Fatalf("Negotiate: %v", rig.retErr)
		}
	})

	// Phase 3: clear the authenticator at runtime — handshake reverts.
	neg.SetAuthenticator(nil)

	t.Run("phase_no_auth_after_clear", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
			rig.writeClient(buildConnectIPv4([4]byte{127, 0, 0, 1}, 80))
		}()
		methodResp := rig.readClient(2)
		if methodResp[1] != socks5MethodNoAuth {
			t.Errorf("method = 0x%02x, want NO_AUTH (auth cleared)", methodResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
		if rig.retErr != nil {
			t.Fatalf("Negotiate: %v", rig.retErr)
		}
	})
}

// TestSOCKS5Negotiator_SetListenerAuth_RuntimeMutate verifies the
// per-listener override mutators preserve USK-242 multi-listener semantics:
// (1) installing override A then swapping to B applies B for the next
// handshake on that listener; (2) ClearListenerAuth falls back to the
// global authenticator; (3) other listeners are unaffected.
func TestSOCKS5Negotiator_SetListenerAuth_RuntimeMutate(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.SetAuthenticator(NewStaticAuthenticator(map[string]string{"global": "global-pw"}))

	// Install override A on listener "alpha".
	neg.SetListenerAuth("alpha", NewStaticAuthenticator(map[string]string{"alpha-A": "pw-A"}))

	t.Run("override_A_active", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "alpha")
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("alpha-A", "pw-A"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()
		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("override A: STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
	})

	// Swap to override B on the same listener.
	neg.SetListenerAuth("alpha", NewStaticAuthenticator(map[string]string{"alpha-B": "pw-B"}))

	t.Run("override_B_replaces_A", func(t *testing.T) {
		// New B credentials accepted.
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "alpha")
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("alpha-B", "pw-B"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()
		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("override B: STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
	})

	t.Run("old_A_rejected_after_swap", func(t *testing.T) {
		// Old A credentials must now fail.
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "alpha")
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("alpha-A", "pw-A"))
		}()
		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthFailure {
			t.Errorf("old override A creds STATUS = 0x%02x, want failure", authResp[1])
		}
		rig.waitDone(2 * time.Second)
		if !errors.Is(rig.retErr, ErrSOCKS5AuthFailed) {
			t.Errorf("err = %v, want ErrSOCKS5AuthFailed", rig.retErr)
		}
	})

	// Clear the override and confirm the global authenticator takes over
	// for handshakes on this listener.
	neg.ClearListenerAuth("alpha")

	t.Run("clear_falls_through_to_global", func(t *testing.T) {
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "alpha")
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("global", "global-pw"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()
		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("global fallback: STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
	})

	t.Run("other_listener_unaffected", func(t *testing.T) {
		// Independent listener "beta" never had an override installed, so
		// it always saw the global authenticator. Confirm USK-242
		// independence under runtime mutate.
		rig := newSOCKS5TestRig(t, neg)
		rig.ctx = ContextWithListenerName(context.Background(), "beta")
		defer rig.closeAll()
		rig.start()
		go func() {
			rig.writeClient(buildMethodGreeting(socks5MethodUsernamePassword))
			rig.writeClient(buildAuthSub("global", "global-pw"))
			rig.writeClient(buildConnectDomain("example.com", 443))
		}()
		_ = rig.readClient(2)
		authResp := rig.readClient(2)
		if authResp[1] != socks5AuthSuccess {
			t.Errorf("listener beta: STATUS = 0x%02x", authResp[1])
		}
		_ = rig.readClient(10)
		rig.waitDone(2 * time.Second)
	})
}

// TestSOCKS5Negotiator_AuthMutate_RaceFree exercises concurrent reads
// (authenticatorFor via in-flight handshakes) racing against writes
// (SetAuthenticator / SetListenerAuth / ClearListenerAuth from the MCP
// control plane). The -race detector is the assertion: the test passes
// when no data race is reported.
func TestSOCKS5Negotiator_AuthMutate_RaceFree(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	neg.SetAuthenticator(NewStaticAuthenticator(map[string]string{"u": "p"}))

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Reader goroutines call authenticatorFor (the handshake-time read
	// path) directly to maximise contention.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			listener := fmt.Sprintf("listener-%d", id%2)
			for {
				select {
				case <-stop:
					return
				default:
					_ = neg.authenticatorFor(listener)
					_ = neg.HasAnyAuthenticator()
				}
			}
		}(i)
	}

	// Writer goroutines mutate auth state aggressively.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			auth := NewStaticAuthenticator(map[string]string{"u": fmt.Sprintf("pw-%d", id)})
			listener := fmt.Sprintf("listener-%d", id%2)
			for j := 0; j < 200; j++ {
				select {
				case <-stop:
					return
				default:
					switch j % 3 {
					case 0:
						neg.SetAuthenticator(auth)
					case 1:
						neg.SetListenerAuth(listener, auth)
					case 2:
						neg.ClearListenerAuth(listener)
					}
				}
			}
		}(i)
	}

	// Let readers and writers race for a short window then signal stop.
	time.Sleep(150 * time.Millisecond)
	close(stop)
	wg.Wait()

	// HasAnyAuthenticator should still return true (global auth installed
	// at the start; clear-listener does not touch it).
	if !neg.HasAnyAuthenticator() {
		t.Error("HasAnyAuthenticator() = false, want true")
	}
}

// TestSOCKS5Negotiator_HasAnyAuthenticator covers the predicate the MCP
// `query resource=status` tool consumes via the socks5AuthQuerier
// extension to surface `socks5_enabled` (USK-770).
func TestSOCKS5Negotiator_HasAnyAuthenticator(t *testing.T) {
	neg := NewSOCKS5Negotiator(newTestLogger())
	if neg.HasAnyAuthenticator() {
		t.Error("fresh negotiator: HasAnyAuthenticator() = true, want false")
	}

	// Per-listener-only is enough.
	neg.SetListenerAuth("L1", NewStaticAuthenticator(map[string]string{"u": "p"}))
	if !neg.HasAnyAuthenticator() {
		t.Error("after SetListenerAuth: HasAnyAuthenticator() = false")
	}
	neg.ClearListenerAuth("L1")
	if neg.HasAnyAuthenticator() {
		t.Error("after ClearListenerAuth: HasAnyAuthenticator() = true")
	}

	// Global only.
	neg.SetAuthenticator(NewStaticAuthenticator(map[string]string{"u": "p"}))
	if !neg.HasAnyAuthenticator() {
		t.Error("after SetAuthenticator: HasAnyAuthenticator() = false")
	}
	neg.SetAuthenticator(nil)
	if neg.HasAnyAuthenticator() {
		t.Error("after SetAuthenticator(nil): HasAnyAuthenticator() = true")
	}
}
