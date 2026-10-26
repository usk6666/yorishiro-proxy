package mcpserver

import (
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// bootRequestTimeout resolves the static request-head bound handed to
// proxybuild.Deps.RequestTimeout from the config file's request_timeout_ms
// (USK-1186): connector.DefaultRequestHeaderTimeout when omitted, 0 when
// disabled (the Manager's disabled state is what turns the deadlines off;
// 0 here only keeps a stale static value from leaking into a fallback),
// otherwise the configured value.
func bootRequestTimeout(proxyCfg *config.ProxyConfig) time.Duration {
	if proxyCfg == nil || proxyCfg.RequestTimeoutMs == nil {
		return connector.DefaultRequestHeaderTimeout
	}
	return time.Duration(*proxyCfg.RequestTimeoutMs) * time.Millisecond
}

// applyBootClientTimeouts seeds the Manager's client-side timeout state from
// the config file's request_timeout_ms / client_idle_timeout_ms (USK-1186),
// with the same meaning as the MCP proxy_start / configure inputs: omitted
// keeps the default, 0 disables the bound, a value sets it. Listeners
// started later inherit the state through Manager.StartNamed. The values
// are validated by ProxyConfig.Validate at load time.
//
// This is boot state only: an explicit MCP configure / proxy_start value
// replaces it, and nothing re-applies the file afterwards (a SIGHUP reload
// validates the file but applies only its policy section).
func applyBootClientTimeouts(mgr *proxybuild.Manager, proxyCfg *config.ProxyConfig) {
	var requestMs, idleMs *int
	if proxyCfg != nil {
		requestMs, idleMs = proxyCfg.RequestTimeoutMs, proxyCfg.ClientIdleTimeoutMs
	}
	switch {
	case requestMs == nil:
		mgr.SetRequestTimeout(connector.DefaultRequestHeaderTimeout)
	case *requestMs == 0:
		mgr.DisableRequestTimeout()
	default:
		mgr.SetRequestTimeout(time.Duration(*requestMs) * time.Millisecond)
	}
	// Omitted idle needs no seed: BuildConfig falls back to
	// connector.DefaultClientIdleTimeout.
	switch {
	case idleMs == nil:
	case *idleMs == 0:
		mgr.DisableClientIdleTimeout()
	default:
		mgr.SetClientIdleTimeout(time.Duration(*idleMs) * time.Millisecond)
	}
}
