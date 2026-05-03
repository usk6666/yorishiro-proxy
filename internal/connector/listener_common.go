package connector

import (
	"errors"
	"time"
)

// DefaultPeekTimeout is the maximum time a listener waits for the client's
// initial bytes before protocol detection. It protects against Slowloris-style
// stalls without being so short that real clients on slow links fail.
const DefaultPeekTimeout = 30 * time.Second

// DefaultMaxConnections limits concurrent connections to bound worst-case
// memory footprint. Operators can override via FullListenerConfig or at
// runtime.
const DefaultMaxConnections = 128

// hookTimeout is the maximum time allowed for lifecycle hook dispatches
// (pluginv2 connection.on_connect / tls.on_handshake / socks5.on_connect).
// Lifecycle hooks are observe-only, so a short timeout prevents slow plugins
// from blocking connection acceptance.
const hookTimeout = 5 * time.Second

// shutdownTimeout bounds Coordinator.StopNamed / StopAll waits for an
// individual listener to drain.
const shutdownTimeout = 30 * time.Second

// DefaultListenerName is the name assigned when the caller does not pass an
// explicit name to Coordinator.StartNamed.
const DefaultListenerName = "default"

var (
	// ErrListenerExists is returned by Coordinator.StartNamed when the given
	// name is already running.
	ErrListenerExists = errors.New("connector: listener with this name already exists")

	// ErrListenerNotFound is returned by Coordinator.StopNamed when no
	// listener has the given name.
	ErrListenerNotFound = errors.New("connector: listener not found")
)

// ListenerStatus describes a single running listener. It is returned by
// Coordinator.ListenerStatuses so callers can build a status view without
// touching FullListener internals.
type ListenerStatus struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}
