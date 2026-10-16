package http2

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// withAfterLoopsStartHook installs the USK-1138 test seam: fn runs inside
// New() right after writerLoop / readerLoop have been started.
func withAfterLoopsStartHook(fn func()) Option {
	return func(o *options) { o.afterLoopsStart = fn }
}

// observedFrame is the subset of a frame the startup-order assertions need,
// copied out of the reader so buffer reuse cannot alias it.
type observedFrame struct {
	typ       frame.Type
	flags     frame.Flags
	streamID  uint32
	increment uint32 // WINDOW_UPDATE only
}

func (f observedFrame) isSettingsAck() bool {
	return f.typ == frame.TypeSettings && f.flags.Has(frame.FlagAck)
}

// peerSettingsBytes serializes a non-ACK SETTINGS frame as a real h2 peer
// would send it right after (or coalesced with) its connection preface.
func peerSettingsBytes(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := frame.NewWriter(&buf).WriteSettings([]frame.Setting{
		{ID: frame.SettingMaxConcurrentStreams, Value: 100},
		{ID: frame.SettingInitialWindowSize, Value: 65535},
	}); err != nil {
		t.Fatalf("serialize peer SETTINGS: %v", err)
	}
	return buf.Bytes()
}

// TestNew_FirstFrameIsOwnSettings_WhenPeerSettingsArriveEarly pins the
// RFC 9113 §3.4 connection-preface ordering: the first frame a Layer puts
// on the wire must be its own non-ACK SETTINGS, even when the peer's
// SETTINGS is already readable the instant the preface completes and the
// reader goroutine gets to it first. nghttp2 (curl) rejects a leading
// SETTINGS ACK with GOAWAY(PROTOCOL_ERROR, "SETTINGS expected").
//
// The afterLoopsStart hook holds New() until the peer has observed the first
// frame. With the pre-fix order (enqueue after `go readerLoop`) only the
// reader can produce that frame, so it is always the ACK; with the fix the
// SETTINGS and connection WINDOW_UPDATE are already queued.
func TestNew_FirstFrameIsOwnSettings_WhenPeerSettingsArriveEarly(t *testing.T) {
	tests := []struct {
		name          string
		role          Role
		opts          []Option
		wantIncrement uint32
	}{
		{
			name:          "server role, client preface coalesced with SETTINGS",
			role:          ServerRole,
			wantIncrement: connWindowIncrement(H2FingerprintDefault),
		},
		{
			name:          "client role, upstream SETTINGS sent immediately",
			role:          ClientRole,
			wantIncrement: connWindowIncrement(H2FingerprintDefault),
		},
		{
			name:          "client role with firefox fingerprint",
			role:          ClientRole,
			opts:          []Option{WithH2Fingerprint("firefox")},
			wantIncrement: connWindowIncrement(H2FingerprintFirefox),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			layerConn, peerConn := net.Pipe()
			_ = peerConn.SetDeadline(time.Now().Add(10 * time.Second))

			var wg sync.WaitGroup
			firstFrameSeen := make(chan struct{})
			type readResult struct {
				frames []observedFrame
				err    error
			}
			readDone := make(chan readResult, 1)

			// Peer reader: the only goroutine reading peerConn. Records frames
			// until our SETTINGS ACK shows up, proving the reader-first window
			// was actually exercised.
			wg.Add(1)
			go func() {
				defer wg.Done()
				var res readResult
				defer func() { readDone <- res }()
				if tt.role == ClientRole {
					magic := make([]byte, len(ClientPreface))
					if _, err := io.ReadFull(peerConn, magic); err != nil {
						res.err = err
						close(firstFrameSeen)
						return
					}
					if string(magic) != ClientPreface {
						res.err = io.ErrUnexpectedEOF
						close(firstFrameSeen)
						return
					}
				}
				rd := frame.NewReader(peerConn)
				for {
					f, err := rd.ReadFrame()
					if err != nil {
						res.err = err
						if len(res.frames) == 0 {
							close(firstFrameSeen)
						}
						return
					}
					of := observedFrame{
						typ:      f.Header.Type,
						flags:    f.Header.Flags,
						streamID: f.Header.StreamID,
					}
					if f.Header.Type == frame.TypeWindowUpdate {
						of.increment, _ = f.WindowUpdateIncrement()
					}
					res.frames = append(res.frames, of)
					if len(res.frames) == 1 {
						close(firstFrameSeen)
					}
					if of.isSettingsAck() {
						return
					}
				}
			}()

			// Peer writer: separate goroutine because net.Pipe writes block
			// until the Layer side reads them.
			out := peerSettingsBytes(t)
			wg.Add(1)
			go func() {
				defer wg.Done()
				if tt.role == ServerRole {
					out = append([]byte(ClientPreface), out...)
				}
				_, _ = peerConn.Write(out)
			}()

			hook := withAfterLoopsStartHook(func() {
				select {
				case <-firstFrameSeen:
				case <-time.After(5 * time.Second):
				}
			})
			opts := append(append([]Option{}, tt.opts...), hook)

			type newResult struct {
				l   *Layer
				err error
			}
			newDone := make(chan newResult, 1)
			go func() {
				l, err := New(layerConn, "usk-1138", tt.role, opts...)
				newDone <- newResult{l: l, err: err}
			}()

			var nr newResult
			select {
			case nr = <-newDone:
			case <-time.After(10 * time.Second):
				t.Fatal("New() did not return")
			}
			if nr.err != nil {
				t.Fatalf("New(): %v", nr.err)
			}
			t.Cleanup(func() {
				_ = peerConn.Close()
				_ = nr.l.Close()
				wg.Wait()
			})

			var rr readResult
			select {
			case rr = <-readDone:
			case <-time.After(10 * time.Second):
				t.Fatal("peer reader did not finish")
			}
			if rr.err != nil {
				t.Fatalf("peer read: %v (frames so far: %+v)", rr.err, rr.frames)
			}

			frames := rr.frames
			if len(frames) == 0 {
				t.Fatal("no frames observed")
			}
			if first := frames[0]; first.typ != frame.TypeSettings || first.flags.Has(frame.FlagAck) {
				t.Fatalf("first frame = type %v flags %#x (ack=%v), want non-ACK SETTINGS (RFC 9113 §3.4); frames=%+v",
					first.typ, first.flags, first.isSettingsAck(), frames)
			}
			if len(frames) < 2 {
				t.Fatalf("got %d frames, want SETTINGS then WINDOW_UPDATE; frames=%+v", len(frames), frames)
			}
			wu := frames[1]
			if wu.typ != frame.TypeWindowUpdate || wu.streamID != 0 {
				t.Fatalf("second frame = type %v stream %d, want connection WINDOW_UPDATE; frames=%+v",
					wu.typ, wu.streamID, frames)
			}
			if wu.increment != tt.wantIncrement {
				t.Errorf("connection WINDOW_UPDATE increment = %d, want %d", wu.increment, tt.wantIncrement)
			}
			if !frames[len(frames)-1].isSettingsAck() {
				t.Errorf("SETTINGS ACK for peer SETTINGS never observed; frames=%+v", frames)
			}
		})
	}
}
