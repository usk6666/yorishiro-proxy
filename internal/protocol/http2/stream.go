package http2

import (
	"fmt"
	"sync"
)

// StreamState represents the state of an HTTP/2 stream per RFC 9113 Section 5.1.
type StreamState uint8

const (
	// StateIdle is the initial state of a stream.
	StateIdle StreamState = iota
	// StateReservedLocal means a PUSH_PROMISE has been sent.
	StateReservedLocal
	// StateReservedRemote means a PUSH_PROMISE has been received.
	StateReservedRemote
	// StateOpen means the stream is open for sending and receiving frames.
	StateOpen
	// StateHalfClosedLocal means the local side has sent END_STREAM.
	StateHalfClosedLocal
	// StateHalfClosedRemote means the remote side has sent END_STREAM.
	StateHalfClosedRemote
	// StateClosed means the stream is fully closed.
	StateClosed
)

// String returns the human-readable name of the stream state.
func (s StreamState) String() string {
	switch s {
	case StateIdle:
		return "idle"
	case StateReservedLocal:
		return "reserved (local)"
	case StateReservedRemote:
		return "reserved (remote)"
	case StateOpen:
		return "open"
	case StateHalfClosedLocal:
		return "half-closed (local)"
	case StateHalfClosedRemote:
		return "half-closed (remote)"
	case StateClosed:
		return "closed"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(s))
	}
}

// Stream represents the state of a single HTTP/2 stream.
type Stream struct {
	// ID is the stream identifier.
	ID uint32
	// State is the current stream state.
	State StreamState
	// SendWindow is the remaining flow control window for sending data.
	SendWindow int32
	// RecvWindow is the remaining flow control window for receiving data.
	RecvWindow int32
}

// StreamMap manages concurrent access to a collection of HTTP/2 streams.
// It is safe for concurrent use.
type StreamMap struct {
	mu      sync.Mutex
	streams map[uint32]*Stream

	// initialSendWindow is the initial window size for new streams' send window.
	// Updated when the peer's SETTINGS_INITIAL_WINDOW_SIZE changes.
	initialSendWindow int32
	// initialRecvWindow is the initial window size for new streams' receive window.
	// This is the local SETTINGS_INITIAL_WINDOW_SIZE value.
	initialRecvWindow int32

	// lastPeerStreamID tracks the highest stream ID initiated by the peer.
	lastPeerStreamID uint32
}

// NewStreamMap creates a new StreamMap with the given initial window sizes.
func NewStreamMap(initialSendWindow, initialRecvWindow int32) *StreamMap {
	return &StreamMap{
		streams:           make(map[uint32]*Stream),
		initialSendWindow: initialSendWindow,
		initialRecvWindow: initialRecvWindow,
	}
}

// Get returns the stream with the given ID, or nil if not found.
func (sm *StreamMap) Get(id uint32) *Stream {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.streams[id]
}

// GetOrCreate returns the stream with the given ID, creating it in idle
// state if it does not exist.
func (sm *StreamMap) GetOrCreate(id uint32) *Stream {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		s = &Stream{
			ID:         id,
			State:      StateIdle,
			SendWindow: sm.initialSendWindow,
			RecvWindow: sm.initialRecvWindow,
		}
		sm.streams[id] = s
	}
	return s
}

// Transition attempts to transition a stream's state based on the event.
// It returns an error if the transition is invalid per RFC 9113 Section 5.1.
//
// The caller must not hold sm's lock.
func (sm *StreamMap) Transition(id uint32, event StreamEvent) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.streams[id]
	if !ok {
		s = &Stream{
			ID:         id,
			State:      StateIdle,
			SendWindow: sm.initialSendWindow,
			RecvWindow: sm.initialRecvWindow,
		}
		sm.streams[id] = s
	}

	newState, err := nextState(s.State, event)
	if err != nil {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   fmt.Sprintf("invalid transition from %s on %s", s.State, event),
		}
	}
	s.State = newState
	return nil
}

// UpdateInitialSendWindow adjusts all open/half-closed streams' send windows
// when the peer's SETTINGS_INITIAL_WINDOW_SIZE changes.
// Per RFC 9113 Section 6.9.2, the difference is applied to all active streams.
// Returns an error if any stream's window would overflow the maximum (2^31-1).
func (sm *StreamMap) UpdateInitialSendWindow(newSize int32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	delta := newSize - sm.initialSendWindow

	// Pre-check: verify no active stream would overflow before applying changes.
	for _, s := range sm.streams {
		if s.State == StateOpen || s.State == StateHalfClosedLocal || s.State == StateHalfClosedRemote {
			newWindow := int64(s.SendWindow) + int64(delta)
			if newWindow > maxWindowSize {
				return &ConnError{
					Code:   ErrCodeFlowControl,
					Reason: fmt.Sprintf("SETTINGS_INITIAL_WINDOW_SIZE change would overflow stream %d send window: current=%d, delta=%d, max=%d", s.ID, s.SendWindow, delta, maxWindowSize),
				}
			}
		}
	}

	sm.initialSendWindow = newSize
	for _, s := range sm.streams {
		if s.State == StateOpen || s.State == StateHalfClosedLocal || s.State == StateHalfClosedRemote {
			s.SendWindow += delta
		}
	}
	return nil
}

// SetInitialRecvWindow updates the initial receive window size for new streams.
func (sm *StreamMap) SetInitialRecvWindow(size int32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.initialRecvWindow = size
}

// Count returns the number of streams in the given state.
func (sm *StreamMap) Count(state StreamState) int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	n := 0
	for _, s := range sm.streams {
		if s.State == state {
			n++
		}
	}
	return n
}

// ActiveCount returns the number of streams that are open or half-closed.
func (sm *StreamMap) ActiveCount() int {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	n := 0
	for _, s := range sm.streams {
		if s.State == StateOpen || s.State == StateHalfClosedLocal || s.State == StateHalfClosedRemote {
			n++
		}
	}
	return n
}

// LastPeerStreamID returns the highest stream ID initiated by the peer.
func (sm *StreamMap) LastPeerStreamID() uint32 {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	return sm.lastPeerStreamID
}

// SetLastPeerStreamID updates the highest stream ID initiated by the peer.
func (sm *StreamMap) SetLastPeerStreamID(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if id > sm.lastPeerStreamID {
		sm.lastPeerStreamID = id
	}
}

// ConsumeSendWindow decrements the send window of the given stream by n bytes.
// Returns an error if the window would go below zero.
func (sm *StreamMap) ConsumeSendWindow(id uint32, n int32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   "stream does not exist",
		}
	}
	if s.SendWindow < n {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeFlowControl,
			Reason:   fmt.Sprintf("send window exhausted: window=%d, requested=%d", s.SendWindow, n),
		}
	}
	s.SendWindow -= n
	return nil
}

// ConsumeRecvWindow decrements the receive window of the given stream by n bytes.
// Returns an error if the window would go below zero.
func (sm *StreamMap) ConsumeRecvWindow(id uint32, n int32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   "stream does not exist",
		}
	}
	if s.RecvWindow < n {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeFlowControl,
			Reason:   fmt.Sprintf("receive window exhausted: window=%d, received=%d", s.RecvWindow, n),
		}
	}
	s.RecvWindow -= n
	return nil
}

// IncrementSendWindow adds the given increment to the stream's send window.
// Returns an error if the resulting window exceeds the maximum (2^31-1).
func (sm *StreamMap) IncrementSendWindow(id uint32, inc uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   "stream does not exist",
		}
	}
	newWindow := int64(s.SendWindow) + int64(inc)
	if newWindow > maxWindowSize {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeFlowControl,
			Reason:   fmt.Sprintf("send window overflow: current=%d, increment=%d, max=%d", s.SendWindow, inc, maxWindowSize),
		}
	}
	s.SendWindow = int32(newWindow)
	return nil
}

// IncrementRecvWindow adds the given increment to the stream's receive window.
// Returns an error if the resulting window exceeds the maximum (2^31-1).
func (sm *StreamMap) IncrementRecvWindow(id uint32, inc uint32) error {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   "stream does not exist",
		}
	}
	newWindow := int64(s.RecvWindow) + int64(inc)
	if newWindow > maxWindowSize {
		return &StreamError{
			StreamID: id,
			Code:     ErrCodeFlowControl,
			Reason:   fmt.Sprintf("receive window overflow: current=%d, increment=%d, max=%d", s.RecvWindow, inc, maxWindowSize),
		}
	}
	s.RecvWindow = int32(newWindow)
	return nil
}

// StreamEvent represents an event that causes a stream state transition.
type StreamEvent uint8

const (
	// EventSendHeaders means HEADERS frame sent (without END_STREAM).
	EventSendHeaders StreamEvent = iota
	// EventRecvHeaders means HEADERS frame received (without END_STREAM).
	EventRecvHeaders
	// EventSendEndStream means END_STREAM flag sent (on HEADERS or DATA).
	EventSendEndStream
	// EventRecvEndStream means END_STREAM flag received (on HEADERS or DATA).
	EventRecvEndStream
	// EventSendRST means RST_STREAM sent.
	EventSendRST
	// EventRecvRST means RST_STREAM received.
	EventRecvRST
	// EventSendPushPromise means PUSH_PROMISE sent (for reserved streams).
	EventSendPushPromise
	// EventRecvPushPromise means PUSH_PROMISE received (for reserved streams).
	EventRecvPushPromise
)

// String returns the human-readable name of the stream event.
func (e StreamEvent) String() string {
	switch e {
	case EventSendHeaders:
		return "send_headers"
	case EventRecvHeaders:
		return "recv_headers"
	case EventSendEndStream:
		return "send_end_stream"
	case EventRecvEndStream:
		return "recv_end_stream"
	case EventSendRST:
		return "send_rst"
	case EventRecvRST:
		return "recv_rst"
	case EventSendPushPromise:
		return "send_push_promise"
	case EventRecvPushPromise:
		return "recv_push_promise"
	default:
		return fmt.Sprintf("unknown(%d)", uint8(e))
	}
}

// stateTransitionKey is a composite key for the state transition table.
type stateTransitionKey struct {
	state StreamState
	event StreamEvent
}

// stateTransitions is a lookup table for valid stream state transitions
// per RFC 9113 Section 5.1.
var stateTransitions = map[stateTransitionKey]StreamState{
	// idle transitions
	{StateIdle, EventSendHeaders}:     StateOpen,
	{StateIdle, EventRecvHeaders}:     StateOpen,
	{StateIdle, EventSendPushPromise}: StateReservedLocal,
	{StateIdle, EventRecvPushPromise}: StateReservedRemote,

	// reserved (local) transitions
	{StateReservedLocal, EventSendHeaders}: StateHalfClosedRemote,
	{StateReservedLocal, EventSendRST}:     StateClosed,
	{StateReservedLocal, EventRecvRST}:     StateClosed,

	// reserved (remote) transitions
	{StateReservedRemote, EventRecvHeaders}: StateHalfClosedLocal,
	{StateReservedRemote, EventSendRST}:     StateClosed,
	{StateReservedRemote, EventRecvRST}:     StateClosed,

	// open transitions
	{StateOpen, EventSendEndStream}: StateHalfClosedLocal,
	{StateOpen, EventRecvEndStream}: StateHalfClosedRemote,
	{StateOpen, EventSendRST}:       StateClosed,
	{StateOpen, EventRecvRST}:       StateClosed,

	// half-closed (local) transitions
	{StateHalfClosedLocal, EventRecvEndStream}: StateClosed,
	{StateHalfClosedLocal, EventSendRST}:       StateClosed,
	{StateHalfClosedLocal, EventRecvRST}:       StateClosed,

	// half-closed (remote) transitions
	{StateHalfClosedRemote, EventSendEndStream}: StateClosed,
	{StateHalfClosedRemote, EventSendRST}:       StateClosed,
	{StateHalfClosedRemote, EventRecvRST}:       StateClosed,
}

// nextState computes the next stream state given the current state and event.
// Returns an error if the transition is not valid per RFC 9113 Section 5.1.
func nextState(current StreamState, event StreamEvent) (StreamState, error) {
	key := stateTransitionKey{state: current, event: event}
	if next, ok := stateTransitions[key]; ok {
		return next, nil
	}
	return current, fmt.Errorf("invalid state transition: %s + %s", current, event)
}
