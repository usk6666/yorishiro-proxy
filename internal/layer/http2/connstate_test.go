package http2

import (
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

func TestDefaultSettings(t *testing.T) {
	s := DefaultSettings()
	if s.HeaderTableSize != 4096 {
		t.Errorf("HeaderTableSize = %d, want 4096", s.HeaderTableSize)
	}
	if s.EnablePush != 1 {
		t.Errorf("EnablePush = %d, want 1", s.EnablePush)
	}
	if s.MaxConcurrentStreams != 100 {
		t.Errorf("MaxConcurrentStreams = %d, want 100", s.MaxConcurrentStreams)
	}
	if s.InitialWindowSize != 65535 {
		t.Errorf("InitialWindowSize = %d, want 65535", s.InitialWindowSize)
	}
	if s.MaxFrameSize != 16384 {
		t.Errorf("MaxFrameSize = %d, want 16384", s.MaxFrameSize)
	}
	if s.MaxHeaderListSize != 0 {
		t.Errorf("MaxHeaderListSize = %d, want 0", s.MaxHeaderListSize)
	}
}

func TestSettings_Apply(t *testing.T) {
	tests := []struct {
		name    string
		params  []frame.Setting
		check   func(t *testing.T, s Settings)
		wantErr bool
	}{
		{
			name: "valid header table size",
			params: []frame.Setting{
				{ID: frame.SettingHeaderTableSize, Value: 8192},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.HeaderTableSize != 8192 {
					t.Errorf("HeaderTableSize = %d, want 8192", s.HeaderTableSize)
				}
			},
		},
		{
			name: "enable push 0",
			params: []frame.Setting{
				{ID: frame.SettingEnablePush, Value: 0},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.EnablePush != 0 {
					t.Errorf("EnablePush = %d, want 0", s.EnablePush)
				}
			},
		},
		{
			name: "enable push invalid",
			params: []frame.Setting{
				{ID: frame.SettingEnablePush, Value: 2},
			},
			wantErr: true,
		},
		{
			name: "max concurrent streams",
			params: []frame.Setting{
				{ID: frame.SettingMaxConcurrentStreams, Value: 256},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.MaxConcurrentStreams != 256 {
					t.Errorf("MaxConcurrentStreams = %d, want 256", s.MaxConcurrentStreams)
				}
			},
		},
		{
			name: "initial window size valid",
			params: []frame.Setting{
				{ID: frame.SettingInitialWindowSize, Value: 1 << 20},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.InitialWindowSize != 1<<20 {
					t.Errorf("InitialWindowSize = %d, want %d", s.InitialWindowSize, 1<<20)
				}
			},
		},
		{
			name: "initial window size too large",
			params: []frame.Setting{
				{ID: frame.SettingInitialWindowSize, Value: 1 << 31},
			},
			wantErr: true,
		},
		{
			name: "max frame size valid",
			params: []frame.Setting{
				{ID: frame.SettingMaxFrameSize, Value: 32768},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.MaxFrameSize != 32768 {
					t.Errorf("MaxFrameSize = %d, want 32768", s.MaxFrameSize)
				}
			},
		},
		{
			name: "max frame size too small",
			params: []frame.Setting{
				{ID: frame.SettingMaxFrameSize, Value: 100},
			},
			wantErr: true,
		},
		{
			name: "max frame size too large",
			params: []frame.Setting{
				{ID: frame.SettingMaxFrameSize, Value: frame.MaxAllowedFrameSize + 1},
			},
			wantErr: true,
		},
		{
			name: "max header list size",
			params: []frame.Setting{
				{ID: frame.SettingMaxHeaderListSize, Value: 65536},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.MaxHeaderListSize != 65536 {
					t.Errorf("MaxHeaderListSize = %d, want 65536", s.MaxHeaderListSize)
				}
			},
		},
		{
			name: "unknown setting ignored",
			params: []frame.Setting{
				{ID: frame.SettingID(0xFF), Value: 42},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				// Should remain at defaults
				if s.HeaderTableSize != 4096 {
					t.Errorf("HeaderTableSize = %d, want 4096 (unchanged)", s.HeaderTableSize)
				}
			},
		},
		{
			name: "multiple settings",
			params: []frame.Setting{
				{ID: frame.SettingHeaderTableSize, Value: 0},
				{ID: frame.SettingMaxConcurrentStreams, Value: 50},
				{ID: frame.SettingInitialWindowSize, Value: 32768},
			},
			check: func(t *testing.T, s Settings) {
				t.Helper()
				if s.HeaderTableSize != 0 {
					t.Errorf("HeaderTableSize = %d, want 0", s.HeaderTableSize)
				}
				if s.MaxConcurrentStreams != 50 {
					t.Errorf("MaxConcurrentStreams = %d, want 50", s.MaxConcurrentStreams)
				}
				if s.InitialWindowSize != 32768 {
					t.Errorf("InitialWindowSize = %d, want 32768", s.InitialWindowSize)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := DefaultSettings()
			err := s.Apply(tt.params)
			if (err != nil) != tt.wantErr {
				t.Fatalf("Apply() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err == nil && tt.check != nil {
				tt.check(t, s)
			}
		})
	}
}

func TestSettings_Apply_ErrorTypes(t *testing.T) {
	s := DefaultSettings()
	err := s.Apply([]frame.Setting{{ID: frame.SettingEnablePush, Value: 2}})
	if err == nil {
		t.Fatal("expected error")
	}
	if _, ok := err.(*ConnError); !ok {
		t.Errorf("expected *ConnError, got %T", err)
	}
}

func TestNewConn(t *testing.T) {
	c := NewConn()

	local := c.LocalSettings()
	if local.InitialWindowSize != 65535 {
		t.Errorf("local InitialWindowSize = %d, want 65535", local.InitialWindowSize)
	}

	peer := c.PeerSettings()
	if peer.InitialWindowSize != 65535 {
		t.Errorf("peer InitialWindowSize = %d, want 65535", peer.InitialWindowSize)
	}

	if c.SendWindow() != 65535 {
		t.Errorf("SendWindow = %d, want 65535", c.SendWindow())
	}
	if c.RecvWindow() != 65535 {
		t.Errorf("RecvWindow = %d, want 65535", c.RecvWindow())
	}
	if c.IsClosed() {
		t.Error("new conn should not be closed")
	}
	if c.LocalSettingsAcked() {
		t.Error("local settings should not be acked initially")
	}
}

func TestConn_ConnectionFlowControl(t *testing.T) {
	c := NewConn()

	// Consume send window
	if err := c.ConsumeSendWindow(1000); err != nil {
		t.Fatalf("ConsumeSendWindow error: %v", err)
	}
	if got := c.SendWindow(); got != 64535 {
		t.Errorf("SendWindow = %d, want 64535", got)
	}

	// Increment send window
	if err := c.IncrementSendWindow(500); err != nil {
		t.Fatalf("IncrementSendWindow error: %v", err)
	}
	if got := c.SendWindow(); got != 65035 {
		t.Errorf("SendWindow = %d, want 65035", got)
	}

	// Consume recv window
	if err := c.ConsumeRecvWindow(2000); err != nil {
		t.Fatalf("ConsumeRecvWindow error: %v", err)
	}
	if got := c.RecvWindow(); got != 63535 {
		t.Errorf("RecvWindow = %d, want 63535", got)
	}

	// Increment recv window
	if err := c.IncrementRecvWindow(1000); err != nil {
		t.Fatalf("IncrementRecvWindow error: %v", err)
	}
	if got := c.RecvWindow(); got != 64535 {
		t.Errorf("RecvWindow = %d, want 64535", got)
	}
}

func TestConn_ConnectionFlowControl_NegativeAndZero(t *testing.T) {
	c := NewConn()

	// Zero value should be rejected.
	if err := c.ConsumeSendWindow(0); err == nil {
		t.Error("expected error for ConsumeSendWindow with n=0")
	}
	if err := c.ConsumeRecvWindow(0); err == nil {
		t.Error("expected error for ConsumeRecvWindow with n=0")
	}

	// Negative value should be rejected.
	if err := c.ConsumeSendWindow(-1); err == nil {
		t.Error("expected error for ConsumeSendWindow with n=-1")
	}
	if err := c.ConsumeRecvWindow(-1); err == nil {
		t.Error("expected error for ConsumeRecvWindow with n=-1")
	}

	// Verify windows are unchanged.
	if got := c.SendWindow(); got != 65535 {
		t.Errorf("SendWindow = %d, want 65535 (unchanged)", got)
	}
	if got := c.RecvWindow(); got != 65535 {
		t.Errorf("RecvWindow = %d, want 65535 (unchanged)", got)
	}
}

func TestConn_ConnectionFlowControl_Exhausted(t *testing.T) {
	c := NewConn()

	err := c.ConsumeSendWindow(65536)
	if err == nil {
		t.Fatal("expected error when exceeding send window")
	}
	ce, ok := err.(*ConnError)
	if !ok {
		t.Fatalf("expected *ConnError, got %T", err)
	}
	if ce.Code != ErrCodeFlowControl {
		t.Errorf("error code = %d, want %d", ce.Code, ErrCodeFlowControl)
	}

	err = c.ConsumeRecvWindow(65536)
	if err == nil {
		t.Fatal("expected error when exceeding recv window")
	}
}

func TestConn_ConnectionFlowControl_Overflow(t *testing.T) {
	c := NewConn()

	// Try to overflow the send window
	err := c.IncrementSendWindow(maxWindowSize)
	if err == nil {
		t.Fatal("expected error on overflow")
	}
	ce, ok := err.(*ConnError)
	if !ok {
		t.Fatalf("expected *ConnError, got %T", err)
	}
	if ce.Code != ErrCodeFlowControl {
		t.Errorf("error code = %d, want %d", ce.Code, ErrCodeFlowControl)
	}

	err = c.IncrementRecvWindow(maxWindowSize)
	if err == nil {
		t.Fatal("expected error on recv overflow")
	}
}

func TestConn_PeerSettingsReceived(t *testing.T) {
	c := NewConn()
	if c.PeerSettingsReceived() {
		t.Fatalf("PeerSettingsReceived = true before any peer SETTINGS, want false")
	}
	// Even an empty SETTINGS payload counts as the peer having spoken.
	if err := c.ApplyPeerSettings(nil); err != nil {
		t.Fatalf("ApplyPeerSettings(nil): %v", err)
	}
	if !c.PeerSettingsReceived() {
		t.Fatalf("PeerSettingsReceived = false after ApplyPeerSettings, want true")
	}
}

func TestConn_ApplyPeerSettings_WindowAdjust(t *testing.T) {
	c := NewConn()

	// Create a stream
	if err := c.Streams().Transition(1, EventSendHeaders); err != nil {
		t.Fatal(err)
	}

	// Verify initial send window
	s := c.Streams().Get(1)
	if s.SendWindow != 65535 {
		t.Fatalf("initial send window = %d, want 65535", s.SendWindow)
	}

	// Apply peer settings with larger initial window size
	err := c.ApplyPeerSettings([]frame.Setting{
		{ID: frame.SettingInitialWindowSize, Value: 131070},
	})
	if err != nil {
		t.Fatalf("ApplyPeerSettings error: %v", err)
	}

	// Stream send window should have been adjusted
	if s.SendWindow != 131070 {
		t.Errorf("adjusted send window = %d, want 131070", s.SendWindow)
	}

	// Peer settings should be updated
	ps := c.PeerSettings()
	if ps.InitialWindowSize != 131070 {
		t.Errorf("peer InitialWindowSize = %d, want 131070", ps.InitialWindowSize)
	}
}

func TestConn_HandleSettings(t *testing.T) {
	c := NewConn()

	// Non-ACK SETTINGS frame
	settingsFrame := makeSettingsFrame([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 200},
	})
	params, err := c.HandleSettings(settingsFrame)
	if err != nil {
		t.Fatalf("HandleSettings error: %v", err)
	}
	if len(params) != 1 {
		t.Fatalf("got %d params, want 1", len(params))
	}
	ps := c.PeerSettings()
	if ps.MaxConcurrentStreams != 200 {
		t.Errorf("MaxConcurrentStreams = %d, want 200", ps.MaxConcurrentStreams)
	}

	// ACK SETTINGS frame
	ackFrame := &frame.Frame{
		Header: frame.Header{
			Type:  frame.TypeSettings,
			Flags: frame.FlagAck,
		},
	}
	params, err = c.HandleSettings(ackFrame)
	if err != nil {
		t.Fatalf("HandleSettings ACK error: %v", err)
	}
	if params != nil {
		t.Errorf("ACK params = %v, want nil", params)
	}
	if !c.LocalSettingsAcked() {
		t.Error("local settings should be acked after ACK")
	}
}

func TestConn_HandleSettings_Errors(t *testing.T) {
	tests := []struct {
		name  string
		frame *frame.Frame
	}{
		{
			name: "non-zero stream ID",
			frame: &frame.Frame{
				Header: frame.Header{
					Type:     frame.TypeSettings,
					StreamID: 1,
				},
			},
		},
		{
			name: "ACK with non-empty payload",
			frame: &frame.Frame{
				Header: frame.Header{
					Type:  frame.TypeSettings,
					Flags: frame.FlagAck,
				},
				Payload: []byte{0, 1, 2, 3, 4, 5},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConn()
			_, err := c.HandleSettings(tt.frame)
			if err == nil {
				t.Fatal("expected error")
			}
			if _, ok := err.(*ConnError); !ok {
				t.Errorf("expected *ConnError, got %T", err)
			}
		})
	}
}

func TestConn_HandlePing(t *testing.T) {
	c := NewConn()

	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	pingFrame := &frame.Frame{
		Header: frame.Header{
			Length: 8,
			Type:   frame.TypePing,
		},
		Payload: pingData[:],
	}

	needsAck, data, err := c.HandlePing(pingFrame)
	if err != nil {
		t.Fatalf("HandlePing error: %v", err)
	}
	if !needsAck {
		t.Error("expected needsAck=true for non-ACK PING")
	}
	if data != pingData {
		t.Errorf("data = %v, want %v", data, pingData)
	}
}

func TestConn_HandlePing_Ack(t *testing.T) {
	c := NewConn()

	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	pingFrame := &frame.Frame{
		Header: frame.Header{
			Length: 8,
			Type:   frame.TypePing,
			Flags:  frame.FlagAck,
		},
		Payload: pingData[:],
	}

	needsAck, _, err := c.HandlePing(pingFrame)
	if err != nil {
		t.Fatalf("HandlePing ACK error: %v", err)
	}
	if needsAck {
		t.Error("expected needsAck=false for ACK PING")
	}
}

func TestConn_HandlePing_NonZeroStreamID(t *testing.T) {
	c := NewConn()

	pingFrame := &frame.Frame{
		Header: frame.Header{
			Length:   8,
			Type:     frame.TypePing,
			StreamID: 1,
		},
		Payload: make([]byte, 8),
	}

	_, _, err := c.HandlePing(pingFrame)
	if err == nil {
		t.Fatal("expected error for PING with non-zero stream ID")
	}
}

func TestConn_HandleGoAway(t *testing.T) {
	c := NewConn()

	goawayFrame := makeGoAwayFrame(7, ErrCodeNo, []byte("graceful"))

	lastStreamID, errCode, debugData, err := c.HandleGoAway(goawayFrame)
	if err != nil {
		t.Fatalf("HandleGoAway error: %v", err)
	}
	if lastStreamID != 7 {
		t.Errorf("lastStreamID = %d, want 7", lastStreamID)
	}
	if errCode != ErrCodeNo {
		t.Errorf("errCode = %d, want %d", errCode, ErrCodeNo)
	}
	if string(debugData) != "graceful" {
		t.Errorf("debugData = %q, want %q", debugData, "graceful")
	}

	received, gotLast, gotCode := c.GoAwayReceived()
	if !received {
		t.Error("GoAwayReceived should be true")
	}
	if gotLast != 7 {
		t.Errorf("GoAwayReceived lastStreamID = %d, want 7", gotLast)
	}
	if gotCode != ErrCodeNo {
		t.Errorf("GoAwayReceived errCode = %d, want 0", gotCode)
	}
}

func TestConn_HandleGoAway_NonZeroStreamID(t *testing.T) {
	c := NewConn()

	goawayFrame := makeGoAwayFrame(0, ErrCodeNo, nil)
	goawayFrame.Header.StreamID = 1

	_, _, _, err := c.HandleGoAway(goawayFrame)
	if err == nil {
		t.Fatal("expected error for GOAWAY with non-zero stream ID")
	}
}

func TestConn_GoAwaySent(t *testing.T) {
	c := NewConn()

	sent, _ := c.GoAwaySent()
	if sent {
		t.Error("GoAwaySent should be false initially")
	}

	c.MarkGoAwaySent(5)
	sent, lastID := c.GoAwaySent()
	if !sent {
		t.Error("GoAwaySent should be true after MarkGoAwaySent")
	}
	if lastID != 5 {
		t.Errorf("GoAwaySent lastStreamID = %d, want 5", lastID)
	}
}

func TestConn_HandleWindowUpdate_Connection(t *testing.T) {
	c := NewConn()

	wuFrame := makeWindowUpdateFrame(0, 1000)
	if err := c.HandleWindowUpdate(wuFrame); err != nil {
		t.Fatalf("HandleWindowUpdate error: %v", err)
	}

	if got := c.SendWindow(); got != 66535 {
		t.Errorf("SendWindow = %d, want 66535", got)
	}
}

func TestConn_HandleWindowUpdate_Stream(t *testing.T) {
	c := NewConn()

	// Create a stream first
	c.Streams().GetOrCreate(1)

	wuFrame := makeWindowUpdateFrame(1, 2000)
	if err := c.HandleWindowUpdate(wuFrame); err != nil {
		t.Fatalf("HandleWindowUpdate error: %v", err)
	}

	s := c.Streams().Get(1)
	if s.SendWindow != 67535 {
		t.Errorf("stream SendWindow = %d, want 67535", s.SendWindow)
	}
}

func TestConn_HandleRSTStream(t *testing.T) {
	c := NewConn()

	// Open a stream first
	if err := c.Streams().Transition(1, EventSendHeaders); err != nil {
		t.Fatal(err)
	}

	rstFrame := makeRSTStreamFrame(1, ErrCodeCancel)
	errCode, err := c.HandleRSTStream(rstFrame)
	if err != nil {
		t.Fatalf("HandleRSTStream error: %v", err)
	}
	if errCode != ErrCodeCancel {
		t.Errorf("errCode = %d, want %d", errCode, ErrCodeCancel)
	}

	s := c.Streams().Get(1)
	if s.State != StateClosed {
		t.Errorf("stream state = %s, want closed", s.State)
	}
}

func TestConn_HandleRSTStream_ZeroStreamID(t *testing.T) {
	c := NewConn()

	rstFrame := makeRSTStreamFrame(0, ErrCodeCancel)
	_, err := c.HandleRSTStream(rstFrame)
	if err == nil {
		t.Fatal("expected error for RST_STREAM with stream ID 0")
	}
	if _, ok := err.(*ConnError); !ok {
		t.Errorf("expected *ConnError, got %T", err)
	}
}

func TestConn_Close(t *testing.T) {
	c := NewConn()

	if c.IsClosed() {
		t.Error("new conn should not be closed")
	}

	c.Close()
	if !c.IsClosed() {
		t.Error("conn should be closed after Close()")
	}
}

func TestConn_SetLocalSettings(t *testing.T) {
	c := NewConn()

	newSettings := DefaultSettings()
	newSettings.InitialWindowSize = 32768
	newSettings.MaxFrameSize = 32768
	if err := c.SetLocalSettings(newSettings); err != nil {
		t.Fatalf("SetLocalSettings error: %v", err)
	}

	got := c.LocalSettings()
	if got.InitialWindowSize != 32768 {
		t.Errorf("InitialWindowSize = %d, want 32768", got.InitialWindowSize)
	}
	if got.MaxFrameSize != 32768 {
		t.Errorf("MaxFrameSize = %d, want 32768", got.MaxFrameSize)
	}
}

func TestConn_SetLocalSettings_Validation(t *testing.T) {
	tests := []struct {
		name    string
		modify  func(s *Settings)
		wantErr bool
	}{
		{
			name: "InitialWindowSize exceeds max",
			modify: func(s *Settings) {
				s.InitialWindowSize = maxWindowSize + 1
			},
			wantErr: true,
		},
		{
			name: "MaxFrameSize too small",
			modify: func(s *Settings) {
				s.MaxFrameSize = frame.DefaultMaxFrameSize - 1
			},
			wantErr: true,
		},
		{
			name: "MaxFrameSize too large",
			modify: func(s *Settings) {
				s.MaxFrameSize = frame.MaxAllowedFrameSize + 1
			},
			wantErr: true,
		},
		{
			name:    "valid settings",
			modify:  func(s *Settings) {},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := NewConn()
			settings := DefaultSettings()
			tt.modify(&settings)
			err := c.SetLocalSettings(settings)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetLocalSettings() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr {
				if _, ok := err.(*ConnError); !ok {
					t.Errorf("expected *ConnError, got %T", err)
				}
			}
		})
	}
}

func TestConn_HandleRSTStream_IdleStream(t *testing.T) {
	c := NewConn()

	// RST_STREAM on an idle (never-seen) stream should be a connection error.
	rstFrame := makeRSTStreamFrame(99, ErrCodeCancel)
	_, err := c.HandleRSTStream(rstFrame)
	if err == nil {
		t.Fatal("expected error for RST_STREAM on idle stream")
	}
	ce, ok := err.(*ConnError)
	if !ok {
		t.Fatalf("expected *ConnError, got %T", err)
	}
	if ce.Code != ErrCodeProtocol {
		t.Errorf("error code = %d, want %d (PROTOCOL_ERROR)", ce.Code, ErrCodeProtocol)
	}
}

func TestConn_ConcurrentAccess(t *testing.T) {
	c := NewConn()
	var wg sync.WaitGroup

	// Concurrent flow control operations
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = c.ConsumeSendWindow(1)
			_ = c.IncrementSendWindow(1)
			_ = c.ConsumeRecvWindow(1)
			_ = c.IncrementRecvWindow(1)
			_ = c.SendWindow()
			_ = c.RecvWindow()
			_ = c.IsClosed()
			_ = c.LocalSettingsAcked()
			_ = c.LocalSettings()
			_ = c.PeerSettings()
		}()
	}
	wg.Wait()
}

// -- test helpers --

func makeSettingsFrame(settings []frame.Setting) *frame.Frame {
	payload := make([]byte, len(settings)*6)
	for i, s := range settings {
		off := i * 6
		payload[off] = byte(s.ID >> 8)
		payload[off+1] = byte(s.ID)
		payload[off+2] = byte(s.Value >> 24)
		payload[off+3] = byte(s.Value >> 16)
		payload[off+4] = byte(s.Value >> 8)
		payload[off+5] = byte(s.Value)
	}
	return &frame.Frame{
		Header: frame.Header{
			Length: uint32(len(payload)),
			Type:   frame.TypeSettings,
		},
		Payload: payload,
	}
}

func makeGoAwayFrame(lastStreamID, errCode uint32, debugData []byte) *frame.Frame {
	payload := make([]byte, 8+len(debugData))
	payload[0] = byte(lastStreamID >> 24)
	payload[1] = byte(lastStreamID >> 16)
	payload[2] = byte(lastStreamID >> 8)
	payload[3] = byte(lastStreamID)
	payload[4] = byte(errCode >> 24)
	payload[5] = byte(errCode >> 16)
	payload[6] = byte(errCode >> 8)
	payload[7] = byte(errCode)
	copy(payload[8:], debugData)
	return &frame.Frame{
		Header: frame.Header{
			Length: uint32(len(payload)),
			Type:   frame.TypeGoAway,
		},
		Payload: payload,
	}
}

func makeWindowUpdateFrame(streamID, increment uint32) *frame.Frame {
	payload := make([]byte, 4)
	payload[0] = byte(increment >> 24)
	payload[1] = byte(increment >> 16)
	payload[2] = byte(increment >> 8)
	payload[3] = byte(increment)
	return &frame.Frame{
		Header: frame.Header{
			Length:   4,
			Type:     frame.TypeWindowUpdate,
			StreamID: streamID,
		},
		Payload: payload,
	}
}

func makeRSTStreamFrame(streamID, errCode uint32) *frame.Frame {
	payload := make([]byte, 4)
	payload[0] = byte(errCode >> 24)
	payload[1] = byte(errCode >> 16)
	payload[2] = byte(errCode >> 8)
	payload[3] = byte(errCode)
	return &frame.Frame{
		Header: frame.Header{
			Length:   4,
			Type:     frame.TypeRSTStream,
			StreamID: streamID,
		},
		Payload: payload,
	}
}
