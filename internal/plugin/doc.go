// Package plugin provides a Starlark-based plugin engine for extending
// yorishiro-proxy behavior through user-defined scripts.
//
// Plugins are loaded from .star files and register hook functions that are
// called at specific points in the proxy pipeline. Each hook receives a
// protocol-specific context dict and returns an Action that controls
// whether the proxy should continue, drop the connection, or respond
// directly.
//
// The engine supports multiple plugins executed in registration order,
// with configurable error handling (skip or abort) per plugin.
package plugin
