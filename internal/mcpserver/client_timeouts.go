package mcpserver

import (
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/proxybuild"
)

// bootRequestTimeout resolves the static request-head bound handed to
// proxybuild.Deps.RequestTimeout from the config file's request_timeout_ms
// (USK-1186).
func bootRequestTimeout(proxyCfg *config.ProxyConfig) time.Duration {
	return connector.DefaultRequestHeaderTimeout
}

// applyBootClientTimeouts seeds the Manager's client-side timeout state from
// the config file's request_timeout_ms / client_idle_timeout_ms (USK-1186).
func applyBootClientTimeouts(mgr *proxybuild.Manager, proxyCfg *config.ProxyConfig) {
	mgr.SetRequestTimeout(connector.DefaultRequestHeaderTimeout)
}
