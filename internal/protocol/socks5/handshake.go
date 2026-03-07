package socks5

import (
	"fmt"
	"io"
	"net"
)

// SOCKS5 authentication methods (RFC 1928, Section 3).
const (
	methodNoAuth           = 0x00
	methodUsernamePassword = 0x02
	methodNoAcceptable     = 0xFF
)

// Username/Password authentication version (RFC 1929).
const authVersion = 0x01

// Authentication status codes (RFC 1929).
const (
	authSuccess = 0x00
	authFailure = 0x01
)

// negotiateMethod reads the client's method selection message and responds
// with the chosen authentication method.
//
// Client greeting format (RFC 1928, Section 3):
//
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1 to 255 |
//	+----+----------+----------+
func (h *Handler) negotiateMethod(conn net.Conn) (byte, error) {
	// Read version and number of methods.
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return 0, fmt.Errorf("read method header: %w", err)
	}

	if header[0] != socks5Version {
		return 0, fmt.Errorf("unsupported SOCKS version: %d", header[0])
	}

	nMethods := int(header[1])
	if nMethods == 0 {
		_, _ = conn.Write([]byte{socks5Version, methodNoAcceptable})
		return 0, fmt.Errorf("client offered zero methods")
	}

	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return 0, fmt.Errorf("read methods: %w", err)
	}

	// Select method based on handler configuration.
	selected := h.selectMethod(methods)

	// Send method selection response.
	if _, err := conn.Write([]byte{socks5Version, selected}); err != nil {
		return 0, fmt.Errorf("write method selection: %w", err)
	}

	if selected == methodNoAcceptable {
		return 0, fmt.Errorf("no acceptable authentication method")
	}

	return selected, nil
}

// selectMethod chooses the best authentication method from the client's offering.
// If an authenticator is configured, USERNAME/PASSWORD is preferred.
// Otherwise, NO AUTH is selected if offered.
func (h *Handler) selectMethod(methods []byte) byte {
	hasNoAuth := false
	hasUserPass := false

	for _, m := range methods {
		switch m {
		case methodNoAuth:
			hasNoAuth = true
		case methodUsernamePassword:
			hasUserPass = true
		}
	}

	// If auth is required, prefer USERNAME/PASSWORD.
	if h.getAuth() != nil {
		if hasUserPass {
			return methodUsernamePassword
		}
		// Auth is required but client doesn't offer it.
		return methodNoAcceptable
	}

	// No auth configured, accept NO AUTH.
	if hasNoAuth {
		return methodNoAuth
	}

	return methodNoAcceptable
}

// authenticateUserPass performs USERNAME/PASSWORD sub-negotiation (RFC 1929).
//
// Sub-negotiation format:
//
//	+----+------+----------+------+----------+
//	|VER | ULEN |  UNAME   | PLEN |  PASSWD  |
//	+----+------+----------+------+----------+
//	| 1  |  1   | 1 to 255 |  1   | 1 to 255 |
//	+----+------+----------+------+----------+
func (h *Handler) authenticateUserPass(conn net.Conn) error {
	// Read auth version.
	verBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, verBuf); err != nil {
		return fmt.Errorf("read auth version: %w", err)
	}
	if verBuf[0] != authVersion {
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return fmt.Errorf("unsupported auth version: %d", verBuf[0])
	}

	// Read username.
	ulenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, ulenBuf); err != nil {
		return fmt.Errorf("read username length: %w", err)
	}
	ulen := int(ulenBuf[0])
	if ulen == 0 {
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return fmt.Errorf("empty username")
	}
	username := make([]byte, ulen)
	if _, err := io.ReadFull(conn, username); err != nil {
		return fmt.Errorf("read username: %w", err)
	}

	// Read password.
	plenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, plenBuf); err != nil {
		return fmt.Errorf("read password length: %w", err)
	}
	plen := int(plenBuf[0])
	password := make([]byte, plen)
	if plen > 0 {
		if _, err := io.ReadFull(conn, password); err != nil {
			return fmt.Errorf("read password: %w", err)
		}
	}

	// Validate credentials.
	auth := h.getAuth()
	if auth == nil || !auth.Authenticate(string(username), string(password)) {
		_, _ = conn.Write([]byte{authVersion, authFailure})
		return fmt.Errorf("authentication failed for user %q", string(username))
	}

	// Send success response.
	if _, err := conn.Write([]byte{authVersion, authSuccess}); err != nil {
		return fmt.Errorf("write auth success: %w", err)
	}

	return nil
}
