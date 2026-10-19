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

	// highestID is the highest stream id that has ever had an entry (or was
	// marked seen via MarkSeen), indexed by id parity (odd = client-
	// initiated, even = server-initiated). Streams leave the map once closed
	// (USK-1144), so an absent id at or below its parity's high-water mark
	// is closed rather than idle (RFC 9113 §5.1.1: ids are never reused).
	highestID [2]uint32

	// localReset / localResetRing remember the most recent stream ids this
	// endpoint closed by sending RST_STREAM (NoteLocalReset), so a HEADERS
	// the peer had already queued on such a stream is ignored as RFC 9113
	// §5.1 requires rather than taken for stream-id reuse. Bounded by
	// maxLocalResetIDs (oldest evicted first) so a flood of refused or
	// cancelled streams cannot grow it.
	localReset     map[uint32]struct{}
	localResetRing []uint32
	localResetNext int
}

// maxLocalResetIDs bounds the locally-reset id set. It is above twice the
// default SETTINGS_MAX_CONCURRENT_STREAMS, so every stream that can be open
// at once fits with room to spare; a peer that sends HEADERS on a reset
// stream after over this many later resets gets the stream-id-reuse
// connection error.
const maxLocalResetIDs = 1024

// NewStreamMap creates a new StreamMap with the given initial window sizes.
func NewStreamMap(initialSendWindow, initialRecvWindow int32) *StreamMap {
	return &StreamMap{
		streams:           make(map[uint32]*Stream),
		initialSendWindow: initialSendWindow,
		initialRecvWindow: initialRecvWindow,
	}
}

// Get returns the stream with the given ID, or nil if not found.
// The returned *Stream is not protected by StreamMap's mutex. Callers must ensure
// that concurrent modifications to Stream fields are synchronized externally.
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
		sm.noteIDLocked(id)
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
		sm.noteIDLocked(id)
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

// TransitionExisting is Transition for an event that can only apply to a
// stream that already exists (END_STREAM, RST_STREAM). Unlike Transition it
// never creates an entry: a stream that is absent — never opened (e.g. one
// refused with RST_STREAM before it was registered) or already removed —
// is left alone and (false, nil) is returned. closed reports whether the
// stream is in the closed state afterwards; the caller then retires it
// (USK-1144).
func (sm *StreamMap) TransitionExisting(id uint32, event StreamEvent) (closed bool, err error) {
	sm.mu.Lock()
	defer sm.mu.Unlock()

	s, ok := sm.streams[id]
	if !ok {
		return false, nil
	}
	newState, nerr := nextState(s.State, event)
	if nerr != nil {
		return s.State == StateClosed, &StreamError{
			StreamID: id,
			Code:     ErrCodeProtocol,
			Reason:   fmt.Sprintf("invalid transition from %s on %s", s.State, event),
		}
	}
	s.State = newState
	return newState == StateClosed, nil
}

// Remove deletes the stream's entry. The id stays accounted for in its
// parity's high-water mark, so IsClosed reports it as closed afterwards.
func (sm *StreamMap) Remove(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.streams, id)
}

// RemoveIfClosed deletes the stream's entry if it is in the closed state and
// reports whether it did.
func (sm *StreamMap) RemoveIfClosed(id uint32) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok || s.State != StateClosed {
		return false
	}
	delete(sm.streams, id)
	return true
}

// MarkSeen records id as used without creating an entry. Used for a peer
// stream refused before it was registered (RST_STREAM(REFUSED_STREAM)): the
// stream is closed from the moment it is refused (RFC 9113 §5.1), so a later
// frame on it is a frame on a closed stream, not a new stream.
func (sm *StreamMap) MarkSeen(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.noteIDLocked(id)
}

// NoteLocalReset records that this endpoint closed id by sending
// RST_STREAM. It must be called before the stream's entry is removed, so
// that whenever IsClosed reports the id closed, WasLocallyReset already
// reflects it.
func (sm *StreamMap) NoteLocalReset(id uint32) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, ok := sm.localReset[id]; ok {
		return
	}
	if sm.localReset == nil {
		sm.localReset = make(map[uint32]struct{})
	}
	if len(sm.localResetRing) < maxLocalResetIDs {
		sm.localResetRing = append(sm.localResetRing, id)
	} else {
		delete(sm.localReset, sm.localResetRing[sm.localResetNext])
		sm.localResetRing[sm.localResetNext] = id
		sm.localResetNext = (sm.localResetNext + 1) % maxLocalResetIDs
	}
	sm.localReset[id] = struct{}{}
}

// WasLocallyReset reports whether id is among the most recent streams this
// endpoint closed by sending RST_STREAM (see NoteLocalReset).
func (sm *StreamMap) WasLocallyReset(id uint32) bool {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	_, ok := sm.localReset[id]
	return ok
}

// IsClosed reports whether id refers to a stream that was used on this
// connection and has since been removed: it has no entry, and an id of the
// same parity at least as high has been used. Stream 0 is never closed.
func (sm *StreamMap) IsClosed(id uint32) bool {
	if id == 0 {
		return false
	}
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if _, ok := sm.streams[id]; ok {
		return false
	}
	return id <= sm.highestID[id%2]
}

// noteIDLocked raises id's parity high-water mark. Caller holds sm.mu.
func (sm *StreamMap) noteIDLocked(id uint32) {
	if id > sm.highestID[id%2] {
		sm.highestID[id%2] = id
	}
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

// GetSendWindow returns the send window of the given stream.
// Returns 0 and false if the stream does not exist.
func (sm *StreamMap) GetSendWindow(id uint32) (int32, bool) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	s, ok := sm.streams[id]
	if !ok {
		return 0, false
	}
	return s.SendWindow, true
}

// ConsumeSendWindow decrements the send window of the given stream by n bytes.
// Returns an error if n is not positive or the window would go below zero.
func (sm *StreamMap) ConsumeSendWindow(id uint32, n int32) error {
	if n <= 0 {
		return fmt.Errorf("consume send window: n must be positive, got %d", n)
	}
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
// Returns an error if n is not positive or the window would go below zero.
func (sm *StreamMap) ConsumeRecvWindow(id uint32, n int32) error {
	if n <= 0 {
		return fmt.Errorf("consume recv window: n must be positive, got %d", n)
	}
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
