package proxybuild

import "errors"

// ErrAlreadyRunning is returned when Start is called for the default
// listener while it is already running. Mirrors proxy.ErrAlreadyRunning so
// MCP error matching works after the USK-690 swap.
var ErrAlreadyRunning = errors.New("proxybuild: default listener is already running")

// ErrNotRunning is returned when Stop is called for the default listener
// while it is not running.
var ErrNotRunning = errors.New("proxybuild: default listener is not running")

// ErrListenerExists is returned by StartNamed when a listener with the
// requested non-default name already exists.
var ErrListenerExists = errors.New("proxybuild: listener with this name already exists")

// ErrListenerNotFound is returned by StopNamed when the requested
// non-default listener name does not exist.
var ErrListenerNotFound = errors.New("proxybuild: listener not found")

// ErrTCPForwardsNotSupported is returned by the stub TCP forward methods.
// Real TCP forward support is owned by USK-690 (or a follow-up issue).
var ErrTCPForwardsNotSupported = errors.New("proxybuild: tcp forward listeners not yet supported")
