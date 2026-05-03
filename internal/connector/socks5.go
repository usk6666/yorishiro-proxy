// socks5.go implements the SOCKS5 negotiator (RFC 1928 + RFC 1929).
//
// Responsibility: handshake, authentication, CONNECT command parsing, and
// target validation against the scope/rate-limit policies. Once Negotiate
// returns, the raw post-handshake tunnel is handed off to NewSOCKS5Handler
// (socks5_handler.go) which builds the ConnectionStack and dispatches the
// resulting Layer pair.
package connector

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"time"
)

// SOCKS5 protocol constants (RFC 1928 + RFC 1929).
const (
	socks5Version byte = 0x05

	// Authentication methods.
	socks5MethodNoAuth           byte = 0x00
	socks5MethodUsernamePassword byte = 0x02
	socks5MethodNoAcceptable     byte = 0xFF

	// RFC 1929 username/password sub-negotiation.
	socks5AuthSubVersion byte = 0x01
	socks5AuthSuccess    byte = 0x00
	socks5AuthFailure    byte = 0x01

	// Commands.
	socks5CmdConnect      byte = 0x01
	socks5CmdBind         byte = 0x02
	socks5CmdUDPAssociate byte = 0x03

	// Address types.
	socks5ATYPIPv4   byte = 0x01
	socks5ATYPDomain byte = 0x03
	socks5ATYPIPv6   byte = 0x04

	// Reply codes.
	socks5ReplySuccess              byte = 0x00
	socks5ReplyGeneralFailure       byte = 0x01
	socks5ReplyConnectionNotAllowed byte = 0x02
	socks5ReplyCommandNotSupported  byte = 0x07
	socks5ReplyAddrTypeNotSupported byte = 0x08
)

// Auth method labels exposed via context / plugin hook data.
const (
	socks5AuthMethodNone             = "none"
	socks5AuthMethodUsernamePassword = "username_password"
)

// socks5HandshakeTimeout bounds the entire SOCKS5 handshake phase so a
// lingering client cannot stall a negotiator goroutine.
const socks5HandshakeTimeout = 30 * time.Second

// Sentinel errors returned to the caller so integration glue can identify
// denial paths without string matching. The negotiator is still responsible
// for sending the correct SOCKS5 reply before returning any of these.
var (
	// ErrSOCKS5BlockedByScope is returned when TargetScope denied the target.
	ErrSOCKS5BlockedByScope = errors.New("connector: SOCKS5 target blocked by scope")

	// ErrSOCKS5BlockedByRateLimit is returned when the rate limiter denied the target.
	ErrSOCKS5BlockedByRateLimit = errors.New("connector: SOCKS5 target blocked by rate limit")

	// ErrSOCKS5UnsupportedCommand is returned for BIND / UDP ASSOCIATE.
	ErrSOCKS5UnsupportedCommand = errors.New("connector: SOCKS5 command not supported")

	// ErrSOCKS5UnsupportedAddrType is returned for ATYP values we do not recognize.
	ErrSOCKS5UnsupportedAddrType = errors.New("connector: SOCKS5 address type not supported")

	// ErrSOCKS5AuthFailed is returned when RFC 1929 sub-negotiation fails.
	ErrSOCKS5AuthFailed = errors.New("connector: SOCKS5 authentication failed")

	// ErrSOCKS5NoAcceptableMethods is returned when the client does not
	// offer a method we can honor.
	ErrSOCKS5NoAcceptableMethods = errors.New("connector: SOCKS5 no acceptable auth methods")
)

// Authenticator validates username/password credentials for SOCKS5
// USERNAME_PASSWORD authentication (RFC 1929). Implementations must be safe
// for concurrent use.
type Authenticator interface {
	// Authenticate returns true if the given credentials are valid.
	Authenticate(username, password string) bool
}

// StaticAuthenticator is an in-memory Authenticator backed by a fixed
// username → password map. The zero value rejects every authentication.
type StaticAuthenticator struct {
	credentials map[string]string
}

// NewStaticAuthenticator constructs a StaticAuthenticator from the given
// credentials map. A nil or empty map is allowed; it produces an
// authenticator that rejects every login.
func NewStaticAuthenticator(creds map[string]string) *StaticAuthenticator {
	clone := make(map[string]string, len(creds))
	for k, v := range creds {
		clone[k] = v
	}
	return &StaticAuthenticator{credentials: clone}
}

// Authenticate implements Authenticator. The password comparison uses
// crypto/subtle.ConstantTimeCompare to avoid a timing side-channel on the
// password byte length / contents (CWE-208). A user-existence side-channel
// still exists via the map lookup, but RFC 1929 transmits credentials in
// plaintext over TCP so this is a defense-in-depth measure, not a primary
// mitigation.
func (s *StaticAuthenticator) Authenticate(username, password string) bool {
	if s == nil || len(s.credentials) == 0 {
		return false
	}
	expected, ok := s.credentials[username]
	if !ok {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(expected), []byte(password)) == 1
}

// SOCKS5Negotiator drives the SOCKS5 handshake (RFC 1928 method negotiation,
// optional RFC 1929 sub-negotiation, CONNECT command parsing, scope / rate
// limit checks, and the success reply). After a successful Negotiate the raw
// post-handshake connection is handed to NewSOCKS5Handler (socks5_handler.go)
// which builds the ConnectionStack.
//
// All fields are optional except where noted. The zero value is usable and
// behaves as "accept NO_AUTH, no policy enforcement".
type SOCKS5Negotiator struct {
	// Authenticator is the default RFC 1929 authenticator. When non-nil, the
	// negotiator prefers USERNAME_PASSWORD over NO_AUTH during method
	// selection. When nil (and no per-listener override matches), only
	// NO_AUTH is accepted.
	Authenticator Authenticator

	// ListenerAuthOverride maps listener names to per-listener
	// authenticators. Consulted via ListenerNameFromContext; falls back to
	// Authenticator when the listener name has no entry.
	ListenerAuthOverride map[string]Authenticator

	// Scope enforces target allow/deny rules before the SOCKS5 reply is
	// sent. Nil disables the check.
	Scope *TargetScope

	// RateLimiter is consulted before the SOCKS5 reply is sent. Nil
	// disables rate limiting.
	RateLimiter *RateLimiter

	// Logger is used for handler-wide diagnostics. A per-connection logger
	// is still pulled out of the context when present.
	Logger *slog.Logger
}

// NewSOCKS5Negotiator returns a negotiator configured with the given logger.
// A nil logger is replaced with slog.Default(). Additional fields can be set
// directly on the returned value before handing it to SOCKS5Handler.
func NewSOCKS5Negotiator(logger *slog.Logger) *SOCKS5Negotiator {
	if logger == nil {
		logger = slog.Default()
	}
	return &SOCKS5Negotiator{Logger: logger}
}

// Negotiate drives the SOCKS5 handshake on conn. On success it returns an
// enriched ctx (carrying the authenticated username / auth method / target
// so downstream hooks can observe it) and the parsed "host:port" target.
//
// Negotiate does NOT close conn. The caller (NewSOCKS5Handler) is responsible
// for handing conn to BuildConnectionStack, which owns it from that point on.
//
// Error paths:
//
//   - Malformed wire data during method negotiation returns an error without
//     a SOCKS5 reply (handshake state is undefined).
//   - Unsupported method set returns METHOD=0xFF then an error.
//   - Failed authentication writes STATUS=0x01 then returns ErrSOCKS5AuthFailed.
//   - Unsupported CMD returns REP=0x07 then ErrSOCKS5UnsupportedCommand.
//   - Unsupported ATYP returns REP=0x08 then ErrSOCKS5UnsupportedAddrType.
//   - TargetScope denial returns REP=0x02 then ErrSOCKS5BlockedByScope.
//   - RateLimit denial returns REP=0x02 then ErrSOCKS5BlockedByRateLimit.
func (n *SOCKS5Negotiator) Negotiate(ctx context.Context, conn net.Conn) (context.Context, string, error) {
	if conn == nil {
		return ctx, "", fmt.Errorf("connector: SOCKS5Negotiator.Negotiate: nil conn")
	}

	// Slowloris protection: bound the entire handshake. Deadline is cleared
	// before we return so the caller's tunnel deadlines remain authoritative.
	deadline := time.Now().Add(socks5HandshakeTimeout)
	_ = conn.SetDeadline(deadline)
	defer func() { _ = conn.SetDeadline(time.Time{}) }()

	// Step 1: method negotiation.
	authMethodName, authUser, err := n.negotiateMethod(ctx, conn)
	if err != nil {
		return ctx, "", fmt.Errorf("socks5: method negotiation: %w", err)
	}

	// Step 2: request parsing.
	target, err := n.readRequest(conn)
	if err != nil {
		return ctx, "", fmt.Errorf("socks5: request: %w", err)
	}

	// Step 3: TargetScope check. Performed inline because SOCKS5 needs to
	// send REP=0x02 BEFORE any tunnel bytes — a downstream check at
	// BuildConnectionStack time cannot meet that requirement.
	//
	// Scheme is passed as "" because at handshake time SOCKS5 does not know
	// the tunneled protocol. Scope rules that are restricted by Schemes
	// (e.g. Schemes: ["https"]) will not match here.
	if n.Scope != nil && n.Scope.HasRules() {
		host, portStr, splitErr := net.SplitHostPort(target)
		port := 0
		if splitErr == nil {
			if p, perr := strconv.Atoi(portStr); perr == nil {
				port = p
			}
		}
		allowed, reason := n.Scope.CheckTarget("", host, port, "")
		if !allowed {
			n.logger(ctx).Info("socks5 target blocked by scope",
				"target", target, "reason", reason)
			_ = writeSOCKS5Reply(conn, socks5ReplyConnectionNotAllowed)
			return ctx, target, ErrSOCKS5BlockedByScope
		}
	}

	// Step 4: RateLimit check.
	if n.RateLimiter != nil && n.RateLimiter.HasLimits() {
		host, _, splitErr := net.SplitHostPort(target)
		if splitErr != nil {
			host = target
		}
		if denial := n.RateLimiter.Check(host); denial != nil {
			n.logger(ctx).Info("socks5 target blocked by rate limit",
				"target", target, "type", denial.LimitType)
			_ = writeSOCKS5Reply(conn, socks5ReplyConnectionNotAllowed)
			return ctx, target, ErrSOCKS5BlockedByRateLimit
		}
	}

	// Enrich ctx so downstream hooks / tags can observe the SOCKS5
	// metadata. Done before the plugin dispatch so the hook can observe
	// the same values via context helpers if it prefers.
	ctx = ContextWithSOCKS5Target(ctx, target)
	ctx = ContextWithSOCKS5AuthMethod(ctx, authMethodName)
	if authUser != "" {
		ctx = ContextWithSOCKS5AuthUser(ctx, authUser)
	}

	// Step 5: success reply.
	if err := writeSOCKS5Reply(conn, socks5ReplySuccess); err != nil {
		return ctx, "", fmt.Errorf("socks5: write success reply: %w", err)
	}

	n.logger(ctx).Debug("socks5 handshake complete",
		"target", target, "auth_method", authMethodName)

	return ctx, target, nil
}

// negotiateMethod runs RFC 1928 method negotiation and, if USERNAME_PASSWORD
// was chosen, the RFC 1929 sub-negotiation. It returns the auth method name
// (for context / plugin hook) and the authenticated username (empty for
// NO_AUTH).
func (n *SOCKS5Negotiator) negotiateMethod(ctx context.Context, conn net.Conn) (string, string, error) {
	// Read VER + NMETHODS.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", "", fmt.Errorf("read method header: %w", err)
	}
	if header[0] != socks5Version {
		return "", "", fmt.Errorf("unexpected version byte: 0x%02x", header[0])
	}
	nMethods := int(header[1])
	if nMethods == 0 {
		// Spec violation: NMETHODS must be >= 1. Reply with no-acceptable
		// before closing so well-behaved clients see a defined state.
		_, _ = conn.Write([]byte{socks5Version, socks5MethodNoAcceptable})
		return "", "", fmt.Errorf("zero methods offered")
	}
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", "", fmt.Errorf("read methods: %w", err)
	}

	// Pick the authenticator for this listener (falls back to default).
	listenerName := ListenerNameFromContext(ctx)
	auth := n.authenticatorFor(listenerName)

	// Select method. With an authenticator configured we require
	// USERNAME_PASSWORD; otherwise we accept NO_AUTH.
	selected := socks5MethodNoAcceptable
	hasNoAuth := false
	hasUserPass := false
	for _, m := range methods {
		switch m {
		case socks5MethodNoAuth:
			hasNoAuth = true
		case socks5MethodUsernamePassword:
			hasUserPass = true
		}
	}
	if auth != nil {
		if hasUserPass {
			selected = socks5MethodUsernamePassword
		}
	} else if hasNoAuth {
		selected = socks5MethodNoAuth
	}

	// Send method selection.
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return "", "", fmt.Errorf("write method selection: %w", err)
	}

	if selected == socks5MethodNoAcceptable {
		return "", "", ErrSOCKS5NoAcceptableMethods
	}
	if selected == socks5MethodNoAuth {
		return socks5AuthMethodNone, "", nil
	}

	// USERNAME_PASSWORD sub-negotiation. auth is guaranteed non-nil here
	// (we only picked USERNAME_PASSWORD when an authenticator was
	// configured).
	user, err := n.subNegotiateUserPass(conn, auth)
	if err != nil {
		return "", "", err
	}
	return socks5AuthMethodUsernamePassword, user, nil
}

// subNegotiateUserPass performs the RFC 1929 sub-negotiation and returns the
// authenticated username on success.
func (n *SOCKS5Negotiator) subNegotiateUserPass(conn net.Conn, auth Authenticator) (string, error) {
	// VER (0x01) + ULEN.
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return "", fmt.Errorf("read auth header: %w", err)
	}
	if head[0] != socks5AuthSubVersion {
		// Reply failure so clients see a defined state before the close.
		_, _ = conn.Write([]byte{socks5AuthSubVersion, socks5AuthFailure})
		return "", fmt.Errorf("unsupported auth sub-version: 0x%02x", head[0])
	}
	ulen := int(head[1])
	if ulen == 0 {
		_, _ = conn.Write([]byte{socks5AuthSubVersion, socks5AuthFailure})
		return "", fmt.Errorf("%w: empty username", ErrSOCKS5AuthFailed)
	}
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return "", fmt.Errorf("read username: %w", err)
	}

	// PLEN.
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return "", fmt.Errorf("read password length: %w", err)
	}
	plen := int(plenBuf[0])
	if plen == 0 {
		_, _ = conn.Write([]byte{socks5AuthSubVersion, socks5AuthFailure})
		return "", fmt.Errorf("%w: empty password", ErrSOCKS5AuthFailed)
	}
	password := make([]byte, plen)
	if _, err := io.ReadFull(conn, password); err != nil {
		return "", fmt.Errorf("read password: %w", err)
	}

	if !auth.Authenticate(string(username), string(password)) {
		_, _ = conn.Write([]byte{socks5AuthSubVersion, socks5AuthFailure})
		return "", ErrSOCKS5AuthFailed
	}

	if _, err := conn.Write([]byte{socks5AuthSubVersion, socks5AuthSuccess}); err != nil {
		return "", fmt.Errorf("write auth success: %w", err)
	}
	return string(username), nil
}

// readRequest reads the SOCKS5 request and returns the canonical "host:port"
// target. On unsupported CMD / ATYP it sends the appropriate reply before
// returning a sentinel error.
func (n *SOCKS5Negotiator) readRequest(conn net.Conn) (string, error) {
	// Fixed header: VER, CMD, RSV, ATYP.
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", fmt.Errorf("read request header: %w", err)
	}
	if header[0] != socks5Version {
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return "", fmt.Errorf("unexpected request version: 0x%02x", header[0])
	}

	cmd := header[1]
	if cmd != socks5CmdConnect {
		_ = writeSOCKS5Reply(conn, socks5ReplyCommandNotSupported)
		return "", fmt.Errorf("%w: 0x%02x", ErrSOCKS5UnsupportedCommand, cmd)
	}

	atyp := header[3]
	host, err := readSOCKS5Address(conn, atyp)
	if err != nil {
		// Distinguish "unknown ATYP" (REP=0x08) from "malformed bytes".
		if errors.Is(err, ErrSOCKS5UnsupportedAddrType) {
			_ = writeSOCKS5Reply(conn, socks5ReplyAddrTypeNotSupported)
			return "", err
		}
		_ = writeSOCKS5Reply(conn, socks5ReplyGeneralFailure)
		return "", fmt.Errorf("read address: %w", err)
	}

	// DST.PORT (2 bytes, big-endian).
	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return "", fmt.Errorf("read port: %w", err)
	}
	port := binary.BigEndian.Uint16(portBuf)

	return net.JoinHostPort(host, strconv.Itoa(int(port))), nil
}

// readSOCKS5Address decodes the DST.ADDR field for the given ATYP. A zero
// length DOMAINNAME is rejected as REP=0x01 (general failure) — unknown ATYP
// returns ErrSOCKS5UnsupportedAddrType so the caller can emit REP=0x08.
func readSOCKS5Address(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case socks5ATYPIPv4:
		addr := make([]byte, 4)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv4: %w", err)
		}
		return net.IP(addr).String(), nil
	case socks5ATYPDomain:
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
	case socks5ATYPIPv6:
		addr := make([]byte, 16)
		if _, err := io.ReadFull(conn, addr); err != nil {
			return "", fmt.Errorf("read IPv6: %w", err)
		}
		return net.IP(addr).String(), nil
	default:
		return "", fmt.Errorf("%w: 0x%02x", ErrSOCKS5UnsupportedAddrType, atyp)
	}
}

// writeSOCKS5Reply emits a SOCKS5 reply with the given REP code and
// BND.ADDR / BND.PORT = 0.0.0.0:0. We do not echo the actual upstream bind
// address because the upstream dial has not yet happened, and most clients
// do not inspect BND.* for non-BIND flows.
func writeSOCKS5Reply(conn net.Conn, rep byte) error {
	reply := []byte{
		socks5Version,
		rep,
		0x00,           // RSV
		socks5ATYPIPv4, // ATYP = IPv4
		0, 0, 0, 0,     // BND.ADDR = 0.0.0.0
		0, 0, // BND.PORT = 0
	}
	_, err := conn.Write(reply)
	return err
}

// authenticatorFor returns the authenticator for the given listener name,
// falling back to the default. Must be called WITHOUT holding any lock; the
// negotiator's fields are immutable after construction so no synchronization
// is needed here.
func (n *SOCKS5Negotiator) authenticatorFor(listenerName string) Authenticator {
	if listenerName != "" && n.ListenerAuthOverride != nil {
		if auth, ok := n.ListenerAuthOverride[listenerName]; ok {
			return auth
		}
	}
	return n.Authenticator
}

// logger returns the best logger for a given ctx, falling back to the
// negotiator's own logger and finally slog.Default().
func (n *SOCKS5Negotiator) logger(ctx context.Context) *slog.Logger {
	if l := LoggerFromContext(ctx, n.Logger); l != nil {
		return l
	}
	return slog.Default()
}
