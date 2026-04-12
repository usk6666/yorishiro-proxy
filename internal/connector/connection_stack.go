package connector

import (
	"fmt"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
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

// Close closes all layers in both stacks in reverse order (top to bottom).
// Errors are collected; the first error is returned.
func (s *ConnectionStack) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var firstErr error
	record := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
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

	if firstErr != nil {
		return fmt.Errorf("connection stack close: %w", firstErr)
	}
	return nil
}
