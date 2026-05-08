package connector

import (
	"fmt"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/pool"
)

// ConnectionStack is a per-connection runtime object representing the layer
// stack for both the client side and the upstream side. It is held by the
// Connector while the connection is alive and owned by Session for the
// duration of RunSession.
//
// The stack is mutable: WebSocket Upgrade is expressed as
// ReplaceClientTop(wsLayer). Session observes the current topmost channel
// at the start of each iteration.
//
// See RFC-001 section 3.4.
type ConnectionStack struct {
	ConnID string

	mu       sync.Mutex
	client   sideStack
	upstream sideStack

	// streamSubStacks holds per-stream Layer overlays installed by protocol
	// upgrades that affect a single h2 stream — currently only RFC 8441
	// extended CONNECT → WebSocket-over-h2 (USK-765 / RFC-001 §3.4.1).
	// Empty by default; the connection-level Topmost is the source of
	// truth when no entry is registered for a streamID.
	//
	// Map key is envelope.StreamID (the same string returned by
	// layer.Channel.StreamID()). Values are stream-scoped Layer pairs
	// that own the per-stream byte triple obtained via
	// http2.Layer.DetachStream(streamID).
	//
	// All reads / writes happen under mu (RFC-001 §3.4.1 goroutine-
	// safety MUST). The map itself is never exposed; callers interact
	// only via RegisterStreamSubStack / *ForStream / ReleaseStreamSubStack.
	streamSubStacks map[string]*sideSubStack

	// upstreamH2 is the pooled upstream HTTP/2 Layer when the stack was built
	// for the "h2" ALPN route. It is owned by the Pool (not the stack) and
	// MUST NOT be closed by ConnectionStack.Close(). Callers obtain it via
	// UpstreamH2Layer and are responsible for returning it to the pool via
	// Pool.Put once the handler exits. Nil on non-h2 routes.
	upstreamH2 *http2.Layer

	// poolKey is the PoolKey under which upstreamH2 was obtained. Zero value
	// when upstreamH2 is nil.
	poolKey pool.PoolKey
}

// sideSubStack pairs the stream-scoped client and upstream Layer overlays
// installed by a per-stream upgrade. The pair is closed together when the
// stream reaches its terminal state.
//
// See RFC-001 §3.4.1.
type sideSubStack struct {
	Client   layer.Layer // e.g. ws.Layer in h2 mode (RoleServer)
	Upstream layer.Layer // e.g. ws.Layer in h2 mode (RoleClient)
}

type sideStack struct {
	layers  []layer.Layer // bottom-up order
	topmost layer.Layer
}

// NewConnectionStack creates a new empty ConnectionStack with the given
// connection identifier.
func NewConnectionStack(connID string) *ConnectionStack {
	return &ConnectionStack{ConnID: connID}
}

// PushClient adds a new top layer to the client side and makes it the
// current topmost.
func (s *ConnectionStack) PushClient(l layer.Layer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.client.layers = append(s.client.layers, l)
	s.client.topmost = l
}

// PushUpstream adds a new top layer to the upstream side and makes it the
// current topmost.
func (s *ConnectionStack) PushUpstream(l layer.Layer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstream.layers = append(s.upstream.layers, l)
	s.upstream.topmost = l
}

// ReplaceClientTop atomically swaps the topmost client layer and returns
// the old one. Used for protocol upgrades (e.g., HTTP/1 -> WebSocket).
// The caller is responsible for closing the old layer if needed.
func (s *ConnectionStack) ReplaceClientTop(l layer.Layer) (old layer.Layer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = s.client.topmost
	if len(s.client.layers) > 0 {
		s.client.layers[len(s.client.layers)-1] = l
	} else {
		s.client.layers = append(s.client.layers, l)
	}
	s.client.topmost = l
	return old
}

// ReplaceUpstreamTop atomically swaps the topmost upstream layer and returns
// the old one. Used for protocol upgrades (e.g., HTTP/1 -> WebSocket).
// The caller is responsible for closing the old layer if needed.
func (s *ConnectionStack) ReplaceUpstreamTop(l layer.Layer) (old layer.Layer) {
	s.mu.Lock()
	defer s.mu.Unlock()
	old = s.upstream.topmost
	if len(s.upstream.layers) > 0 {
		s.upstream.layers[len(s.upstream.layers)-1] = l
	} else {
		s.upstream.layers = append(s.upstream.layers, l)
	}
	s.upstream.topmost = l
	return old
}

// ClientTopmost returns the current topmost client layer, or nil if empty.
func (s *ConnectionStack) ClientTopmost() layer.Layer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client.topmost
}

// UpstreamTopmost returns the current topmost upstream layer, or nil if empty.
func (s *ConnectionStack) UpstreamTopmost() layer.Layer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstream.topmost
}

// RegisterStreamSubStack installs a per-stream Layer pair on streamID.
// The connection-level Layers are unchanged; sibling streams remain on the
// connection-level chain (RFC-001 §3.4.1 multiplex-isolation MUST).
//
// Single-writer invariant: registration MUST happen exactly once per
// streamID, on the same goroutine that observed the trigger envelope (the
// extended CONNECT 2xx response). Re-registration on the same id is a
// programming error and returns an error without mutating state.
//
// streamID must be non-empty; client and upstream must both be non-nil.
// The caller retains responsibility for the eventual lifecycle release —
// see ReleaseStreamSubStack.
func (s *ConnectionStack) RegisterStreamSubStack(streamID string, client, upstream layer.Layer) error {
	if streamID == "" {
		return fmt.Errorf("connection stack: RegisterStreamSubStack requires non-empty streamID")
	}
	if client == nil || upstream == nil {
		return fmt.Errorf("connection stack: RegisterStreamSubStack requires non-nil client and upstream layers (streamID=%q)", streamID)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streamSubStacks == nil {
		s.streamSubStacks = make(map[string]*sideSubStack)
	}
	if _, exists := s.streamSubStacks[streamID]; exists {
		return fmt.Errorf("connection stack: sub-stack already registered for streamID=%q", streamID)
	}
	s.streamSubStacks[streamID] = &sideSubStack{Client: client, Upstream: upstream}
	return nil
}

// ReleaseStreamSubStack removes the per-stream Layer pair for streamID and
// closes both Layers. Subsequent *ForStream lookups fall back to the
// connection-level Topmost (RFC-001 §3.4.1 lifetime MUST).
//
// Idempotent: a release for an unknown streamID is a no-op and returns nil.
// The first non-nil close error is reported; subsequent close errors are
// dropped (callers that want all errors should call Close manually before
// release).
func (s *ConnectionStack) ReleaseStreamSubStack(streamID string) error {
	s.mu.Lock()
	sub, ok := s.streamSubStacks[streamID]
	if ok {
		delete(s.streamSubStacks, streamID)
	}
	s.mu.Unlock()
	if !ok || sub == nil {
		return nil
	}
	var firstErr error
	if sub.Client != nil {
		if err := sub.Client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if sub.Upstream != nil {
		if err := sub.Upstream.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if firstErr != nil {
		return fmt.Errorf("connection stack: release sub-stack for streamID=%q: %w", streamID, firstErr)
	}
	return nil
}

// ClientTopmostForStream returns the per-stream client Layer if a sub-stack
// is registered for streamID; otherwise it falls back to the connection-
// level ClientTopmost (RFC-001 §3.4.1 fallback MUST).
//
// Pipeline / Session per-stream channel iteration MUST consult this method
// (or UpstreamTopmostForStream) rather than ClientTopmost() directly when
// the streamID may have been swapped.
func (s *ConnectionStack) ClientTopmostForStream(streamID string) layer.Layer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID != "" {
		if sub, ok := s.streamSubStacks[streamID]; ok && sub != nil && sub.Client != nil {
			return sub.Client
		}
	}
	return s.client.topmost
}

// UpstreamTopmostForStream is the upstream-side counterpart of
// ClientTopmostForStream.
func (s *ConnectionStack) UpstreamTopmostForStream(streamID string) layer.Layer {
	s.mu.Lock()
	defer s.mu.Unlock()
	if streamID != "" {
		if sub, ok := s.streamSubStacks[streamID]; ok && sub != nil && sub.Upstream != nil {
			return sub.Upstream
		}
	}
	return s.upstream.topmost
}

// HasStreamSubStack reports whether a per-stream overlay is registered for
// streamID. Test-only / diagnostic helper.
func (s *ConnectionStack) HasStreamSubStack(streamID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streamSubStacks == nil {
		return false
	}
	_, ok := s.streamSubStacks[streamID]
	return ok
}

// UpstreamH2Layer returns the pooled upstream HTTP/2 Layer when the stack was
// built for the "h2" ALPN route. Returns nil on non-h2 routes.
//
// The returned Layer is owned by the connection pool; callers MUST return it
// via Pool.Put (or Pool.Evict on failure) once the handler exits.
// ConnectionStack.Close does NOT close this Layer — pool lifecycle is
// independent of stack lifecycle.
func (s *ConnectionStack) UpstreamH2Layer() *http2.Layer {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstreamH2
}

// PoolKey returns the pool.PoolKey under which UpstreamH2Layer was obtained.
// Returns the zero value when UpstreamH2Layer is nil.
func (s *ConnectionStack) PoolKey() pool.PoolKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.poolKey
}

// setUpstreamH2 stores the pooled upstream HTTP/2 Layer and its pool key.
// Intended for use by stack_builder.go only.
func (s *ConnectionStack) setUpstreamH2(l *http2.Layer, key pool.PoolKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.upstreamH2 = l
	s.poolKey = key
}

// Close closes all layers in both stacks in reverse order (top to bottom).
// Errors are collected; the first error is returned.
//
// Close does NOT close upstreamH2 — that Layer is owned by the connection
// pool and has an independent lifecycle. Callers are responsible for
// returning it via Pool.Put before or after Close.
//
// Any per-stream sub-stacks still registered at Close time are also closed
// (defensive cascade — production code releases sub-stacks at h2 stream
// terminal transition, but a Close path that bypasses that release MUST
// not leak Layer resources).
func (s *ConnectionStack) Close() error {
	s.mu.Lock()
	subs := s.streamSubStacks
	s.streamSubStacks = nil
	defer s.mu.Unlock()

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Drain still-registered sub-stacks first; their per-stream byte
	// triples are scoped above the connection-level Layers below them.
	for _, sub := range subs {
		if sub == nil {
			continue
		}
		if sub.Client != nil {
			record(sub.Client.Close())
		}
		if sub.Upstream != nil {
			record(sub.Upstream.Close())
		}
	}

	// Close top-to-bottom (reverse of push order)
	for i := len(s.client.layers) - 1; i >= 0; i-- {
		record(s.client.layers[i].Close())
	}
	for i := len(s.upstream.layers) - 1; i >= 0; i-- {
		record(s.upstream.layers[i].Close())
	}

	s.client = sideStack{}
	s.upstream = sideStack{}
	// Intentionally NOT clearing upstreamH2 / poolKey: the pool owns the
	// Layer and the handler is still responsible for Pool.Put using poolKey.

	if firstErr != nil {
		return fmt.Errorf("connection stack close: %w", firstErr)
	}
	return nil
}
