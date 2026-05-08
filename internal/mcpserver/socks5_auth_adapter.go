// socks5_auth_adapter.go bridges the MCP control-plane socks5AuthSetter
// interface (internal/mcp/server.go) to the live data-path SOCKS5Negotiator
// (internal/connector). This is the USK-770 wiring that re-establishes the
// MCP → SOCKS5 auth path that the USK-690 rewire left dangling.
//
// The adapter holds a reference to the process-singleton negotiator created
// once by Run(). Each MCP `proxy_start socks5_auth=...` /
// `configure socks5_auth=...` call lands here and is forwarded to the
// negotiator's thread-safe mutators. Per-listener calls (USK-242 multi-
// listener semantics) carry the listener name; global calls do not.
package mcpserver

import (
	"log/slog"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// socks5AuthAdapter implements internal/mcp's socks5AuthSetter interface.
// It is the *only* writer of SOCKS5Negotiator's auth state from the MCP
// control plane; the connector keeps direct field assignment available for
// initialization-time use only.
type socks5AuthAdapter struct {
	neg    *connector.SOCKS5Negotiator
	logger *slog.Logger
}

// newSOCKS5AuthAdapter constructs an adapter bound to neg. neg must be
// non-nil; the call site is responsible for that invariant (constructed
// alongside the manager in mcpserver.assembleLiveManager). A nil logger
// falls back to slog.Default() so adapter call sites do not have to
// thread a logger through their own code paths.
func newSOCKS5AuthAdapter(neg *connector.SOCKS5Negotiator, logger *slog.Logger) *socks5AuthAdapter {
	if logger == nil {
		logger = slog.Default()
	}
	return &socks5AuthAdapter{neg: neg, logger: logger}
}

// SetPasswordAuth installs a username/password authenticator as the global
// default for every listener that lacks an explicit per-listener override.
// Mirrors the legacy SOCKS5Handler.SetPasswordAuth semantics that the MCP
// proxy_start tool depended on before USK-690.
//
// Logs a single Info line announcing the install. The username is logged
// (so operators can audit which credential is active); the password is
// never logged.
func (a *socks5AuthAdapter) SetPasswordAuth(username, password string) {
	a.neg.SetAuthenticator(connector.NewStaticAuthenticator(map[string]string{
		username: password,
	}))
	a.logger.Info("socks5 auth installed", "scope", "global", "username", username)
}

// ClearAuth removes the global authenticator, restoring NO_AUTH behaviour
// for listeners that have no per-listener override. Per-listener overrides
// are not affected — those are managed via ClearAuthForListener.
func (a *socks5AuthAdapter) ClearAuth() {
	a.neg.SetAuthenticator(nil)
	a.logger.Info("socks5 auth cleared", "scope", "global")
}

// SetPasswordAuthForListener installs a per-listener authenticator scoped to
// listenerName. The listener name must match the value carried by
// connector.ContextWithListenerName at handshake time (the FullListener
// configures this from FullListenerConfig.Name). USK-242 semantics: a
// per-listener authenticator does NOT bleed across listeners — only handshakes
// arriving on the named listener consult this entry.
//
// Logs a single Info line announcing the install (listener + username);
// the password is never logged.
func (a *socks5AuthAdapter) SetPasswordAuthForListener(listenerName, username, password string) {
	a.neg.SetListenerAuth(listenerName, connector.NewStaticAuthenticator(map[string]string{
		username: password,
	}))
	a.logger.Info("socks5 auth installed", "scope", "listener", "listener", listenerName, "username", username)
}

// ClearAuthForListener removes the per-listener authenticator entry for
// listenerName. Subsequent handshakes for that listener fall back to the
// global authenticator (or NO_AUTH when none is set).
func (a *socks5AuthAdapter) ClearAuthForListener(listenerName string) {
	a.neg.ClearListenerAuth(listenerName)
	a.logger.Info("socks5 auth cleared", "scope", "listener", "listener", listenerName)
}

// HasAnyAuth reports whether the underlying negotiator has at least one
// authenticator configured (global or per-listener). Surfaced for the MCP
// `query resource=status` tool's `socks5_enabled` field so the user-visible
// status reflects the actual runtime auth state rather than a static
// "is the wire-up present" flag.
func (a *socks5AuthAdapter) HasAnyAuth() bool {
	return a.neg.HasAnyAuthenticator()
}
