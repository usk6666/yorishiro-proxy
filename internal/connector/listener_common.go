package connector

import (
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

// DefaultPeekTimeout is the maximum time a listener waits for the client's
// initial bytes before protocol detection. It protects against Slowloris-style
// stalls without being so short that real clients on slow links fail.
const DefaultPeekTimeout = 30 * time.Second

// DefaultMaxConnections is the concurrent-connection cap a listener applies
// when none is configured. It aliases config.DefaultMaxConnections, the
// single definition (see internal/config/limits.go for how it was sized).
// Operators can override via FullListenerConfig or at runtime.
const DefaultMaxConnections = config.DefaultMaxConnections

// hookTimeout is the maximum time allowed for lifecycle hook dispatches
// (pluginv2 connection.on_connect / tls.on_handshake / socks5.on_connect).
// Lifecycle hooks are observe-only, so a short timeout prevents slow plugins
// from blocking connection acceptance.
const hookTimeout = 5 * time.Second

// DefaultListenerName is the name of the listener started without an
// explicit name. It mirrors proxybuild.DefaultListenerName; the
// multi-listener lifecycle itself lives in proxybuild.Manager.
const DefaultListenerName = "default"
