package mcp

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
)

// tokenBytes is the number of random bytes used to generate a Bearer token.
// The resulting hex-encoded token will be twice this length (64 characters).
const tokenBytes = 32

// BearerAuthMiddleware returns an http.Handler that validates Bearer token
// authentication on incoming requests. Requests with a valid
// "Authorization: Bearer <token>" header are passed to next; all others
// receive a 401 Unauthorized response.
//
// Token comparison uses crypto/subtle.ConstantTimeCompare to prevent
// timing side-channel attacks.
func BearerAuthMiddleware(next http.Handler, token string) http.Handler {
	tokenBuf := []byte(token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			slog.Warn("MCP HTTP auth: missing Authorization header",
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Expect "Bearer <token>" format.
		const prefix = "Bearer "
		if !strings.HasPrefix(authHeader, prefix) {
			slog.Warn("MCP HTTP auth: invalid Authorization scheme",
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		provided := authHeader[len(prefix):]
		if subtle.ConstantTimeCompare([]byte(provided), tokenBuf) != 1 {
			slog.Warn("MCP HTTP auth: invalid token",
				"remote_addr", r.RemoteAddr)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// GenerateToken creates a cryptographically random hex-encoded token.
// It returns a 64-character hex string derived from 32 random bytes.
func GenerateToken() (string, error) {
	buf := make([]byte, tokenBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("generate auth token: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
