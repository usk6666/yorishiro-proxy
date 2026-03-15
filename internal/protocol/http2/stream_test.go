package http2

import (
	"sync"
	"testing"
)

func TestStreamState_String(t *testing.T) {
	tests := []struct {
		state StreamState
		want  string
	}{
		{StateIdle, "idle"},
		{StateReservedLocal, "reserved (local)"},
		{StateReservedRemote, "reserved (remote)"},
		{StateOpen, "open"},
		{StateHalfClosedLocal, "half-closed (local)"},
		{StateHalfClosedRemote, "half-closed (remote)"},
		{StateClosed, "closed"},
		{StreamState(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.state.String(); got != tt.want {
				t.Errorf("StreamState.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestStreamEvent_String(t *testing.T) {
	tests := []struct {
		event StreamEvent
		want  string
	}{
		{EventSendHeaders, "send_headers"},
		{EventRecvHeaders, "recv_headers"},
		{EventSendEndStream, "send_end_stream"},
		{EventRecvEndStream, "recv_end_stream"},
		{EventSendRST, "send_rst"},
		{EventRecvRST, "recv_rst"},
		{EventSendPushPromise, "send_push_promise"},
		{EventRecvPushPromise, "recv_push_promise"},
		{StreamEvent(99), "unknown(99)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.event.String(); got != tt.want {
				t.Errorf("StreamEvent.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNextState_ValidTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  StreamState
		event StreamEvent
		want  StreamState
	}{
		// idle transitions
		{"idle->open (send headers)", StateIdle, EventSendHeaders, StateOpen},
		{"idle->open (recv headers)", StateIdle, EventRecvHeaders, StateOpen},
		{"idle->reserved_local (send push promise)", StateIdle, EventSendPushPromise, StateReservedLocal},
		{"idle->reserved_remote (recv push promise)", StateIdle, EventRecvPushPromise, StateReservedRemote},

		// reserved (local) transitions
		{"reserved_local->half_closed_remote (send headers)", StateReservedLocal, EventSendHeaders, StateHalfClosedRemote},
		{"reserved_local->closed (send rst)", StateReservedLocal, EventSendRST, StateClosed},
		{"reserved_local->closed (recv rst)", StateReservedLocal, EventRecvRST, StateClosed},

		// reserved (remote) transitions
		{"reserved_remote->half_closed_local (recv headers)", StateReservedRemote, EventRecvHeaders, StateHalfClosedLocal},
		{"reserved_remote->closed (send rst)", StateReservedRemote, EventSendRST, StateClosed},
		{"reserved_remote->closed (recv rst)", StateReservedRemote, EventRecvRST, StateClosed},

		// open transitions
		{"open->half_closed_local (send end stream)", StateOpen, EventSendEndStream, StateHalfClosedLocal},
		{"open->half_closed_remote (recv end stream)", StateOpen, EventRecvEndStream, StateHalfClosedRemote},
		{"open->closed (send rst)", StateOpen, EventSendRST, StateClosed},
		{"open->closed (recv rst)", StateOpen, EventRecvRST, StateClosed},

		// half-closed (local) transitions
		{"half_closed_local->closed (recv end stream)", StateHalfClosedLocal, EventRecvEndStream, StateClosed},
		{"half_closed_local->closed (send rst)", StateHalfClosedLocal, EventSendRST, StateClosed},
		{"half_closed_local->closed (recv rst)", StateHalfClosedLocal, EventRecvRST, StateClosed},

		// half-closed (remote) transitions
		{"half_closed_remote->closed (send end stream)", StateHalfClosedRemote, EventSendEndStream, StateClosed},
		{"half_closed_remote->closed (send rst)", StateHalfClosedRemote, EventSendRST, StateClosed},
		{"half_closed_remote->closed (recv rst)", StateHalfClosedRemote, EventRecvRST, StateClosed},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := nextState(tt.from, tt.event)
			if err != nil {
				t.Fatalf("nextState(%s, %s) returned unexpected error: %v", tt.from, tt.event, err)
			}
			if got != tt.want {
				t.Errorf("nextState(%s, %s) = %s, want %s", tt.from, tt.event, got, tt.want)
			}
		})
	}
}

func TestNextState_InvalidTransitions(t *testing.T) {
	tests := []struct {
		name  string
		from  StreamState
		event StreamEvent
	}{
		{"idle + send end stream", StateIdle, EventSendEndStream},
		{"idle + recv end stream", StateIdle, EventRecvEndStream},
		{"idle + send rst", StateIdle, EventSendRST},
		{"idle + recv rst", StateIdle, EventRecvRST},
		{"reserved_local + recv headers", StateReservedLocal, EventRecvHeaders},
		{"reserved_local + send end stream", StateReservedLocal, EventSendEndStream},
		{"reserved_remote + send headers", StateReservedRemote, EventSendHeaders},
		{"reserved_remote + send end stream", StateReservedRemote, EventSendEndStream},
		{"half_closed_local + send end stream", StateHalfClosedLocal, EventSendEndStream},
		{"half_closed_local + send headers", StateHalfClosedLocal, EventSendHeaders},
		{"half_closed_remote + recv end stream", StateHalfClosedRemote, EventRecvEndStream},
		{"half_closed_remote + recv headers", StateHalfClosedRemote, EventRecvHeaders},
		{"closed + send headers", StateClosed, EventSendHeaders},
		{"closed + recv headers", StateClosed, EventRecvHeaders},
		{"closed + send end stream", StateClosed, EventSendEndStream},
		{"closed + recv end stream", StateClosed, EventRecvEndStream},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := nextState(tt.from, tt.event)
			if err == nil {
				t.Errorf("nextState(%s, %s) expected error, got nil", tt.from, tt.event)
			}
		})
	}
}

func TestStreamMap_GetOrCreate(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	s := sm.GetOrCreate(1)
	if s.ID != 1 {
		t.Errorf("stream ID = %d, want 1", s.ID)
	}
	if s.State != StateIdle {
		t.Errorf("stream state = %s, want idle", s.State)
	}
	if s.SendWindow != 65535 {
		t.Errorf("send window = %d, want 65535", s.SendWindow)
	}
	if s.RecvWindow != 65535 {
		t.Errorf("recv window = %d, want 65535", s.RecvWindow)
	}

	// Getting the same stream should return the same instance.
	s2 := sm.GetOrCreate(1)
	if s2 != s {
		t.Error("GetOrCreate returned different instance for same ID")
	}
}

func TestStreamMap_Transition(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	// idle -> open
	if err := sm.Transition(1, EventSendHeaders); err != nil {
		t.Fatalf("Transition(1, SendHeaders) error: %v", err)
	}
	s := sm.Get(1)
	if s.State != StateOpen {
		t.Errorf("state = %s, want open", s.State)
	}

	// open -> half-closed (local)
	if err := sm.Transition(1, EventSendEndStream); err != nil {
		t.Fatalf("Transition(1, SendEndStream) error: %v", err)
	}
	if s.State != StateHalfClosedLocal {
		t.Errorf("state = %s, want half-closed (local)", s.State)
	}

	// half-closed (local) -> closed
	if err := sm.Transition(1, EventRecvEndStream); err != nil {
		t.Fatalf("Transition(1, RecvEndStream) error: %v", err)
	}
	if s.State != StateClosed {
		t.Errorf("state = %s, want closed", s.State)
	}
}

func TestStreamMap_Transition_Invalid(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	// idle -> (send end stream) should fail
	err := sm.Transition(1, EventSendEndStream)
	if err == nil {
		t.Fatal("expected error for invalid transition, got nil")
	}
	if _, ok := err.(*StreamError); !ok {
		t.Errorf("expected *StreamError, got %T", err)
	}
}

func TestStreamMap_FlowControl(t *testing.T) {
	sm := NewStreamMap(65535, 65535)
	sm.GetOrCreate(1)

	// Consume send window
	if err := sm.ConsumeSendWindow(1, 1000); err != nil {
		t.Fatalf("ConsumeSendWindow error: %v", err)
	}
	s := sm.Get(1)
	if s.SendWindow != 64535 {
		t.Errorf("send window = %d, want 64535", s.SendWindow)
	}

	// Increment send window
	if err := sm.IncrementSendWindow(1, 500); err != nil {
		t.Fatalf("IncrementSendWindow error: %v", err)
	}
	if s.SendWindow != 65035 {
		t.Errorf("send window = %d, want 65035", s.SendWindow)
	}

	// Consume recv window
	if err := sm.ConsumeRecvWindow(1, 2000); err != nil {
		t.Fatalf("ConsumeRecvWindow error: %v", err)
	}
	if s.RecvWindow != 63535 {
		t.Errorf("recv window = %d, want 63535", s.RecvWindow)
	}

	// Increment recv window
	if err := sm.IncrementRecvWindow(1, 1000); err != nil {
		t.Fatalf("IncrementRecvWindow error: %v", err)
	}
	if s.RecvWindow != 64535 {
		t.Errorf("recv window = %d, want 64535", s.RecvWindow)
	}
}

func TestStreamMap_FlowControl_Exhausted(t *testing.T) {
	sm := NewStreamMap(100, 100)
	sm.GetOrCreate(1)

	err := sm.ConsumeSendWindow(1, 101)
	if err == nil {
		t.Fatal("expected error when exceeding send window")
	}
	se, ok := err.(*StreamError)
	if !ok {
		t.Fatalf("expected *StreamError, got %T", err)
	}
	if se.Code != ErrCodeFlowControl {
		t.Errorf("error code = %d, want %d (FLOW_CONTROL_ERROR)", se.Code, ErrCodeFlowControl)
	}

	err = sm.ConsumeRecvWindow(1, 101)
	if err == nil {
		t.Fatal("expected error when exceeding recv window")
	}
}

func TestStreamMap_FlowControl_Overflow(t *testing.T) {
	sm := NewStreamMap(maxWindowSize-10, maxWindowSize-10)
	sm.GetOrCreate(1)

	// This should overflow
	err := sm.IncrementSendWindow(1, 20)
	if err == nil {
		t.Fatal("expected error on window overflow")
	}
	se, ok := err.(*StreamError)
	if !ok {
		t.Fatalf("expected *StreamError, got %T", err)
	}
	if se.Code != ErrCodeFlowControl {
		t.Errorf("error code = %d, want %d", se.Code, ErrCodeFlowControl)
	}

	err = sm.IncrementRecvWindow(1, 20)
	if err == nil {
		t.Fatal("expected error on recv window overflow")
	}
}

func TestStreamMap_FlowControl_NonExistentStream(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	if err := sm.ConsumeSendWindow(99, 10); err == nil {
		t.Error("expected error for non-existent stream")
	}
	if err := sm.ConsumeRecvWindow(99, 10); err == nil {
		t.Error("expected error for non-existent stream")
	}
	if err := sm.IncrementSendWindow(99, 10); err == nil {
		t.Error("expected error for non-existent stream")
	}
	if err := sm.IncrementRecvWindow(99, 10); err == nil {
		t.Error("expected error for non-existent stream")
	}
}

func TestStreamMap_UpdateInitialSendWindow(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	// Create a few streams in different states
	if err := sm.Transition(1, EventSendHeaders); err != nil {
		t.Fatal(err)
	}
	if err := sm.Transition(3, EventRecvHeaders); err != nil {
		t.Fatal(err)
	}
	// Stream 3: open -> half-closed (local)
	if err := sm.Transition(3, EventSendEndStream); err != nil {
		t.Fatal(err)
	}

	// Stream 5 stays idle
	sm.GetOrCreate(5)

	// Update initial window size (increase by 1000)
	sm.UpdateInitialSendWindow(66535)

	s1 := sm.Get(1)
	if s1.SendWindow != 66535 {
		t.Errorf("stream 1 send window = %d, want 66535", s1.SendWindow)
	}

	s3 := sm.Get(3)
	// Stream 3 is half-closed (local), should still be adjusted.
	if s3.SendWindow != 66535 {
		t.Errorf("stream 3 send window = %d, want 66535", s3.SendWindow)
	}

	s5 := sm.Get(5)
	// Stream 5 is idle, should NOT be adjusted.
	if s5.SendWindow != 65535 {
		t.Errorf("stream 5 send window = %d, want 65535 (unchanged)", s5.SendWindow)
	}
}

func TestStreamMap_Count(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	if err := sm.Transition(1, EventSendHeaders); err != nil {
		t.Fatal(err)
	}
	if err := sm.Transition(3, EventRecvHeaders); err != nil {
		t.Fatal(err)
	}
	if err := sm.Transition(5, EventSendHeaders); err != nil {
		t.Fatal(err)
	}
	if err := sm.Transition(5, EventSendRST); err != nil {
		t.Fatal(err)
	}

	if got := sm.Count(StateOpen); got != 2 {
		t.Errorf("Count(open) = %d, want 2", got)
	}
	if got := sm.Count(StateClosed); got != 1 {
		t.Errorf("Count(closed) = %d, want 1", got)
	}
	if got := sm.ActiveCount(); got != 2 {
		t.Errorf("ActiveCount() = %d, want 2", got)
	}
}

func TestStreamMap_LastPeerStreamID(t *testing.T) {
	sm := NewStreamMap(65535, 65535)

	if got := sm.LastPeerStreamID(); got != 0 {
		t.Errorf("initial LastPeerStreamID = %d, want 0", got)
	}

	sm.SetLastPeerStreamID(3)
	if got := sm.LastPeerStreamID(); got != 3 {
		t.Errorf("LastPeerStreamID = %d, want 3", got)
	}

	// Setting a lower value should not decrease.
	sm.SetLastPeerStreamID(1)
	if got := sm.LastPeerStreamID(); got != 3 {
		t.Errorf("LastPeerStreamID = %d, want 3 (should not decrease)", got)
	}

	sm.SetLastPeerStreamID(7)
	if got := sm.LastPeerStreamID(); got != 7 {
		t.Errorf("LastPeerStreamID = %d, want 7", got)
	}
}

func TestStreamMap_ConcurrentAccess(t *testing.T) {
	sm := NewStreamMap(65535, 65535)
	var wg sync.WaitGroup

	// Concurrent transitions on different streams
	for i := uint32(1); i <= 100; i += 2 {
		wg.Add(1)
		go func(id uint32) {
			defer wg.Done()
			_ = sm.Transition(id, EventSendHeaders)
			_ = sm.Transition(id, EventSendEndStream)
			_ = sm.Transition(id, EventRecvEndStream)
		}(i)
	}
	wg.Wait()

	if got := sm.Count(StateClosed); got != 50 {
		t.Errorf("Count(closed) = %d, want 50", got)
	}
}

func TestStreamMap_FullLifecycle(t *testing.T) {
	tests := []struct {
		name   string
		events []StreamEvent
		states []StreamState
	}{
		{
			name:   "normal request-response",
			events: []StreamEvent{EventSendHeaders, EventSendEndStream, EventRecvEndStream},
			states: []StreamState{StateOpen, StateHalfClosedLocal, StateClosed},
		},
		{
			name:   "server push",
			events: []StreamEvent{EventRecvPushPromise, EventRecvHeaders, EventSendRST},
			states: []StreamState{StateReservedRemote, StateHalfClosedLocal, StateClosed},
		},
		{
			name:   "rst during open",
			events: []StreamEvent{EventSendHeaders, EventRecvRST},
			states: []StreamState{StateOpen, StateClosed},
		},
		{
			name:   "recv headers then send end stream then recv end stream",
			events: []StreamEvent{EventRecvHeaders, EventRecvEndStream, EventSendEndStream},
			states: []StreamState{StateOpen, StateHalfClosedRemote, StateClosed},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sm := NewStreamMap(65535, 65535)
			id := uint32(1)
			for i, event := range tt.events {
				if err := sm.Transition(id, event); err != nil {
					t.Fatalf("step %d: Transition(%s) error: %v", i, event, err)
				}
				s := sm.Get(id)
				if s.State != tt.states[i] {
					t.Errorf("step %d: state = %s, want %s", i, s.State, tt.states[i])
				}
			}
		})
	}
}
