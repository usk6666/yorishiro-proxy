package http2

import (
	"fmt"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// Default HTTP/2 settings values per RFC 9113 Section 6.5.2.
const (
	defaultHeaderTableSize      = 4096
	defaultEnablePush           = 1
	defaultMaxConcurrentStreams = 100 // RFC says unlimited, but we use a reasonable default.
	defaultInitialWindowSize    = 65535
	defaultMaxFrameSize         = frame.DefaultMaxFrameSize
	defaultMaxHeaderListSize    = 0 // 0 means unlimited.
	defaultConnectionWindowSize = 65535

	// maxWindowSize is the maximum flow control window size per RFC 9113 Section 6.9.
	maxWindowSize = (1 << 31) - 1 // 2^31-1

	// maxInitialWindowSize is the maximum value for SETTINGS_INITIAL_WINDOW_SIZE.
	maxInitialWindowSize = maxWindowSize
)

// Settings holds the HTTP/2 settings for one side of a connection.
type Settings struct {
	// HeaderTableSize is the maximum size of the HPACK dynamic table.
	HeaderTableSize uint32
	// EnablePush controls whether server push is permitted.
	EnablePush uint32
	// MaxConcurrentStreams limits the number of concurrent streams.
	MaxConcurrentStreams uint32
	// InitialWindowSize is the initial flow control window size for new streams.
	InitialWindowSize uint32
	// MaxFrameSize is the maximum frame payload size.
	MaxFrameSize uint32
	// MaxHeaderListSize is the maximum size of header list the sender will accept.
	MaxHeaderListSize uint32
}

// DefaultSettings returns Settings populated with default values
// per RFC 9113 Section 6.5.2.
func DefaultSettings() Settings {
	return Settings{
		HeaderTableSize:      defaultHeaderTableSize,
		EnablePush:           defaultEnablePush,
		MaxConcurrentStreams: defaultMaxConcurrentStreams,
		InitialWindowSize:    defaultInitialWindowSize,
		MaxFrameSize:         defaultMaxFrameSize,
		MaxHeaderListSize:    defaultMaxHeaderListSize,
	}
}

// Apply applies a list of SETTINGS parameters to the settings.
// Returns an error if any setting value is invalid per RFC 9113 Section 6.5.2.
func (s *Settings) Apply(params []frame.Setting) error {
	for _, p := range params {
		if err := s.applySingle(p); err != nil {
			return err
		}
	}
	return nil
}

// applySingle applies a single setting parameter.
func (s *Settings) applySingle(p frame.Setting) error {
	switch p.ID {
	case frame.SettingHeaderTableSize:
		s.HeaderTableSize = p.Value
	case frame.SettingEnablePush:
		if p.Value > 1 {
			return &ConnError{
				Code:   ErrCodeProtocol,
				Reason: fmt.Sprintf("ENABLE_PUSH must be 0 or 1, got %d", p.Value),
			}
		}
		s.EnablePush = p.Value
	case frame.SettingMaxConcurrentStreams:
		s.MaxConcurrentStreams = p.Value
	case frame.SettingInitialWindowSize:
		if p.Value > maxInitialWindowSize {
			return &ConnError{
				Code:   ErrCodeFlowControl,
				Reason: fmt.Sprintf("INITIAL_WINDOW_SIZE %d exceeds maximum %d", p.Value, maxInitialWindowSize),
			}
		}
		s.InitialWindowSize = p.Value
	case frame.SettingMaxFrameSize:
		if p.Value < frame.DefaultMaxFrameSize || p.Value > frame.MaxAllowedFrameSize {
			return &ConnError{
				Code:   ErrCodeProtocol,
				Reason: fmt.Sprintf("MAX_FRAME_SIZE %d out of range [%d, %d]", p.Value, frame.DefaultMaxFrameSize, frame.MaxAllowedFrameSize),
			}
		}
		s.MaxFrameSize = p.Value
	case frame.SettingMaxHeaderListSize:
		s.MaxHeaderListSize = p.Value
	default:
		// Per RFC 9113 Section 6.5.2: unknown settings MUST be ignored.
	}
	return nil
}

// Conn manages the state of an HTTP/2 connection.
// It tracks settings negotiation, flow control windows, and stream state
// for both the local and peer sides of the connection.
//
// Conn is safe for concurrent use.
type Conn struct {
	mu sync.Mutex

	// localSettings holds the settings that apply to this endpoint.
	localSettings Settings
	// peerSettings holds the settings that apply to the peer.
	peerSettings Settings

	// peerSettingsReceived indicates whether at least one SETTINGS frame from
	// the peer has been applied. Until true, peerSettings still holds the
	// RFC 9113 §6.5.2 defaults seeded by NewConn, and callers (notably the
	// connection pool) should treat fields like MaxConcurrentStreams as
	// unadvertised rather than as advertised values.
	peerSettingsReceived bool

	// localSettingsAcked indicates whether our initial SETTINGS has been acknowledged.
	localSettingsAcked bool

	// sendWindow is the connection-level flow control window for sending.
	sendWindow int32
	// recvWindow is the connection-level flow control window for receiving.
	recvWindow int32

	// streams manages per-stream state.
	streams *StreamMap

	// goawayReceived indicates whether a GOAWAY frame has been received.
	goawayReceived bool
	// goawayLastStreamID is the last stream ID from the received GOAWAY.
	goawayLastStreamID uint32
	// goawayCode is the error code from the received GOAWAY.
	goawayCode uint32

	// goawaySent indicates whether a GOAWAY frame has been sent.
	goawaySent bool
	// goawaySentLastStreamID is the last stream ID in the sent GOAWAY.
	goawaySentLastStreamID uint32

	// closed indicates whether the connection has been closed.
	closed bool
}

// NewConn creates a new Conn with default settings and initial window sizes.
func NewConn() *Conn {
	local := DefaultSettings()
	peer := DefaultSettings()
	return &Conn{
		localSettings: local,
		peerSettings:  peer,
		sendWindow:    defaultConnectionWindowSize,
		recvWindow:    defaultConnectionWindowSize,
		streams:       NewStreamMap(int32(peer.InitialWindowSize), int32(local.InitialWindowSize)),
	}
}

// LocalSettings returns a copy of the local settings.
func (c *Conn) LocalSettings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localSettings
}

// PeerSettings returns a copy of the peer settings.
func (c *Conn) PeerSettings() Settings {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerSettings
}

// PeerSettingsReceived reports whether the peer has sent at least one
// SETTINGS frame. Before the first peer SETTINGS arrives, PeerSettings
// still returns RFC 9113 §6.5.2 defaults (e.g. MaxConcurrentStreams=100),
// so callers that need to distinguish "peer advertised value X" from
// "peer has not advertised yet" must consult this flag.
func (c *Conn) PeerSettingsReceived() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.peerSettingsReceived
}

// SetLocalSettings updates the local settings. This should be called
// before sending the SETTINGS frame. The settings take effect locally
// immediately for new streams.
// Returns an error if InitialWindowSize exceeds the maximum (2^31-1)
// or MaxFrameSize is outside the RFC 9113 allowed range.
func (c *Conn) SetLocalSettings(settings Settings) error {
	if settings.InitialWindowSize > maxWindowSize {
		return &ConnError{
			Code:   ErrCodeFlowControl,
			Reason: fmt.Sprintf("initial window size %d exceeds maximum %d", settings.InitialWindowSize, maxWindowSize),
		}
	}
	if settings.MaxFrameSize < frame.DefaultMaxFrameSize || settings.MaxFrameSize > frame.MaxAllowedFrameSize {
		return &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("max frame size %d out of range [%d, %d]", settings.MaxFrameSize, frame.DefaultMaxFrameSize, frame.MaxAllowedFrameSize),
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localSettings = settings
	c.streams.SetInitialRecvWindow(int32(settings.InitialWindowSize))
	return nil
}

// ApplyPeerSettings applies settings received from the peer in a SETTINGS frame.
// This updates the peer settings and adjusts existing streams' send windows
// per RFC 9113 Section 6.9.2.
func (c *Conn) ApplyPeerSettings(params []frame.Setting) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	oldInitialWindowSize := c.peerSettings.InitialWindowSize
	if err := c.peerSettings.Apply(params); err != nil {
		return err
	}
	c.peerSettingsReceived = true

	// If INITIAL_WINDOW_SIZE changed, adjust all active streams' send windows.
	if c.peerSettings.InitialWindowSize != oldInitialWindowSize {
		if err := c.streams.UpdateInitialSendWindow(int32(c.peerSettings.InitialWindowSize)); err != nil {
			return err
		}
	}

	return nil
}

// AckLocalSettings marks the local settings as acknowledged by the peer.
func (c *Conn) AckLocalSettings() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.localSettingsAcked = true
}

// LocalSettingsAcked reports whether the local settings have been acknowledged.
func (c *Conn) LocalSettingsAcked() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.localSettingsAcked
}

// Streams returns the stream map for direct stream state operations.
// The returned StreamMap has its own synchronization independent of Conn.mu.
func (c *Conn) Streams() *StreamMap {
	return c.streams
}

// SendWindow returns the current connection-level send window.
func (c *Conn) SendWindow() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.sendWindow
}

// RecvWindow returns the current connection-level receive window.
func (c *Conn) RecvWindow() int32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.recvWindow
}

// ConsumeSendWindow decrements the connection-level send window by n bytes.
// Returns an error if n is not positive or the window would go below zero.
func (c *Conn) ConsumeSendWindow(n int32) error {
	if n <= 0 {
		return fmt.Errorf("consume send window: n must be positive, got %d", n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.sendWindow < n {
		return &ConnError{
			Code:   ErrCodeFlowControl,
			Reason: fmt.Sprintf("connection send window exhausted: window=%d, requested=%d", c.sendWindow, n),
		}
	}
	c.sendWindow -= n
	return nil
}

// ConsumeRecvWindow decrements the connection-level receive window by n bytes.
// Returns an error if n is not positive or the window would go below zero.
func (c *Conn) ConsumeRecvWindow(n int32) error {
	if n <= 0 {
		return fmt.Errorf("consume recv window: n must be positive, got %d", n)
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.recvWindow < n {
		return &ConnError{
			Code:   ErrCodeFlowControl,
			Reason: fmt.Sprintf("connection receive window exhausted: window=%d, received=%d", c.recvWindow, n),
		}
	}
	c.recvWindow -= n
	return nil
}

// IncrementSendWindow adds the given increment to the connection-level send window.
// Returns an error if the resulting window exceeds the maximum (2^31-1).
func (c *Conn) IncrementSendWindow(inc uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	newWindow := int64(c.sendWindow) + int64(inc)
	if newWindow > maxWindowSize {
		return &ConnError{
			Code:   ErrCodeFlowControl,
			Reason: fmt.Sprintf("connection send window overflow: current=%d, increment=%d, max=%d", c.sendWindow, inc, maxWindowSize),
		}
	}
	c.sendWindow = int32(newWindow)
	return nil
}

// IncrementRecvWindow adds the given increment to the connection-level receive window.
// Returns an error if the resulting window exceeds the maximum (2^31-1).
func (c *Conn) IncrementRecvWindow(inc uint32) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	newWindow := int64(c.recvWindow) + int64(inc)
	if newWindow > maxWindowSize {
		return &ConnError{
			Code:   ErrCodeFlowControl,
			Reason: fmt.Sprintf("connection receive window overflow: current=%d, increment=%d, max=%d", c.recvWindow, inc, maxWindowSize),
		}
	}
	c.recvWindow = int32(newWindow)
	return nil
}

// HandlePing processes a received PING frame. If it is not an ACK, the caller
// should send a PING ACK with the same opaque data.
// Returns (needsAck, pingData, error).
func (c *Conn) HandlePing(f *frame.Frame) (bool, [8]byte, error) {
	data, err := f.PingData()
	if err != nil {
		return false, [8]byte{}, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("invalid PING frame: %v", err),
		}
	}
	if f.Header.StreamID != 0 {
		return false, [8]byte{}, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "PING frame must have stream ID 0",
		}
	}
	if f.Header.Flags.Has(frame.FlagAck) {
		// PING ACK received — no action needed.
		return false, data, nil
	}
	return true, data, nil
}

// HandleGoAway processes a received GOAWAY frame.
// After receiving GOAWAY, no new streams should be initiated.
func (c *Conn) HandleGoAway(f *frame.Frame) (lastStreamID, errCode uint32, debugData []byte, err error) {
	if f.Header.StreamID != 0 {
		return 0, 0, nil, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "GOAWAY frame must have stream ID 0",
		}
	}
	lastStreamID, errCode, debugData, err = f.GoAwayInfo()
	if err != nil {
		return 0, 0, nil, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("invalid GOAWAY frame: %v", err),
		}
	}

	c.mu.Lock()
	c.goawayReceived = true
	c.goawayLastStreamID = lastStreamID
	c.goawayCode = errCode
	c.mu.Unlock()

	return lastStreamID, errCode, debugData, nil
}

// GoAwayReceived reports whether a GOAWAY frame has been received
// and returns the last stream ID and error code.
func (c *Conn) GoAwayReceived() (received bool, lastStreamID, errCode uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.goawayReceived, c.goawayLastStreamID, c.goawayCode
}

// MarkGoAwaySent records that a GOAWAY frame has been sent with the given
// last stream ID.
func (c *Conn) MarkGoAwaySent(lastStreamID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.goawaySent = true
	c.goawaySentLastStreamID = lastStreamID
}

// GoAwaySent reports whether a GOAWAY frame has been sent
// and returns the last stream ID.
func (c *Conn) GoAwaySent() (sent bool, lastStreamID uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.goawaySent, c.goawaySentLastStreamID
}

// HandleWindowUpdate processes a received WINDOW_UPDATE frame.
// For stream ID 0, it updates the connection-level send window.
// For other stream IDs, it updates the stream-level send window.
func (c *Conn) HandleWindowUpdate(f *frame.Frame) error {
	inc, err := f.WindowUpdateIncrement()
	if err != nil {
		if f.Header.StreamID == 0 {
			return &ConnError{
				Code:   ErrCodeProtocol,
				Reason: fmt.Sprintf("invalid WINDOW_UPDATE: %v", err),
			}
		}
		return &StreamError{
			StreamID: f.Header.StreamID,
			Code:     ErrCodeProtocol,
			Reason:   fmt.Sprintf("invalid WINDOW_UPDATE: %v", err),
		}
	}

	if f.Header.StreamID == 0 {
		return c.IncrementSendWindow(inc)
	}
	return c.streams.IncrementSendWindow(f.Header.StreamID, inc)
}

// HandleRSTStream processes a received RST_STREAM frame.
// It transitions the stream to the closed state.
func (c *Conn) HandleRSTStream(f *frame.Frame) (uint32, error) {
	if f.Header.StreamID == 0 {
		return 0, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "RST_STREAM must not have stream ID 0",
		}
	}
	errCode, err := f.RSTStreamErrorCode()
	if err != nil {
		return 0, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("invalid RST_STREAM: %v", err),
		}
	}

	// RST_STREAM on an idle (unknown) stream is a connection error per RFC 9113 Section 6.4.
	stream := c.streams.Get(f.Header.StreamID)
	if stream == nil {
		return 0, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("RST_STREAM on idle stream %d", f.Header.StreamID),
		}
	}

	if transErr := c.streams.Transition(f.Header.StreamID, EventRecvRST); transErr != nil {
		// Per RFC 9113, RST_STREAM on a closed stream should be ignored
		// to handle race conditions.
		if stream.State == StateClosed {
			return errCode, nil
		}
		return 0, transErr
	}

	return errCode, nil
}

// HandleSettings processes a received SETTINGS frame (non-ACK).
// It applies the settings from the frame and returns the parameters
// that were applied (for the caller to send an ACK).
func (c *Conn) HandleSettings(f *frame.Frame) ([]frame.Setting, error) {
	if f.Header.StreamID != 0 {
		return nil, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: "SETTINGS frame must have stream ID 0",
		}
	}
	if f.Header.Flags.Has(frame.FlagAck) {
		// This is a SETTINGS ACK. Mark local settings as acknowledged.
		if len(f.Payload) != 0 {
			return nil, &ConnError{
				Code:   ErrCodeFrameSize,
				Reason: "SETTINGS ACK must have empty payload",
			}
		}
		c.AckLocalSettings()
		return nil, nil
	}
	params, err := f.SettingsParams()
	if err != nil {
		return nil, &ConnError{
			Code:   ErrCodeProtocol,
			Reason: fmt.Sprintf("invalid SETTINGS frame: %v", err),
		}
	}
	if err := c.ApplyPeerSettings(params); err != nil {
		return nil, err
	}
	return params, nil
}

// Close marks the connection as closed.
func (c *Conn) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
}

// IsClosed reports whether the connection has been marked as closed.
func (c *Conn) IsClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}
