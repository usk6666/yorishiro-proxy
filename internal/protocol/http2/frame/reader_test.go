package frame

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestNewReader(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))
	if r.MaxFrameSize() != DefaultMaxFrameSize {
		t.Errorf("MaxFrameSize() = %d, want %d", r.MaxFrameSize(), DefaultMaxFrameSize)
	}
}

func TestReader_SetMaxFrameSize(t *testing.T) {
	r := NewReader(bytes.NewReader(nil))

	tests := []struct {
		name    string
		size    uint32
		wantErr bool
	}{
		{"default", DefaultMaxFrameSize, false},
		{"max allowed", MaxAllowedFrameSize, false},
		{"custom", 32768, false},
		{"too small", DefaultMaxFrameSize - 1, true},
		{"too large", MaxAllowedFrameSize + 1, true},
		{"zero", 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := r.SetMaxFrameSize(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetMaxFrameSize(%d) error = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
			if !tt.wantErr && r.MaxFrameSize() != tt.size {
				t.Errorf("MaxFrameSize() = %d, want %d", r.MaxFrameSize(), tt.size)
			}
		})
	}
}

func TestReader_ReadFrame(t *testing.T) {
	t.Run("valid DATA frame", func(t *testing.T) {
		payload := []byte("hello")
		raw := buildRawFrame(TypeData, FlagEndStream, 1, payload)

		r := NewReader(bytes.NewReader(raw))
		f, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() error: %v", err)
		}
		if f.Header.Type != TypeData {
			t.Errorf("Type = %s, want DATA", f.Header.Type)
		}
		if f.Header.Flags != FlagEndStream {
			t.Errorf("Flags = %02x, want %02x", f.Header.Flags, FlagEndStream)
		}
		if f.Header.StreamID != 1 {
			t.Errorf("StreamID = %d, want 1", f.Header.StreamID)
		}
		if !bytes.Equal(f.Payload, payload) {
			t.Errorf("Payload = %q, want %q", f.Payload, payload)
		}
		if !bytes.Equal(f.RawBytes, raw) {
			t.Errorf("RawBytes mismatch")
		}
	})

	t.Run("empty payload SETTINGS ACK", func(t *testing.T) {
		raw := buildRawFrame(TypeSettings, FlagAck, 0, nil)

		r := NewReader(bytes.NewReader(raw))
		f, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() error: %v", err)
		}
		if f.Header.Type != TypeSettings {
			t.Errorf("Type = %s, want SETTINGS", f.Header.Type)
		}
		if !f.Header.Flags.Has(FlagAck) {
			t.Error("ACK flag not set")
		}
		if len(f.Payload) != 0 {
			t.Errorf("Payload length = %d, want 0", len(f.Payload))
		}
	})

	t.Run("multiple frames", func(t *testing.T) {
		var buf bytes.Buffer
		buf.Write(buildRawFrame(TypeSettings, 0, 0, make([]byte, 6)))
		buf.Write(buildRawFrame(TypeData, FlagEndStream, 1, []byte("data")))

		r := NewReader(&buf)

		f1, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() 1 error: %v", err)
		}
		if f1.Header.Type != TypeSettings {
			t.Errorf("Frame 1 Type = %s, want SETTINGS", f1.Header.Type)
		}

		f2, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() 2 error: %v", err)
		}
		if f2.Header.Type != TypeData {
			t.Errorf("Frame 2 Type = %s, want DATA", f2.Header.Type)
		}
	})

	t.Run("EOF returns io.EOF", func(t *testing.T) {
		r := NewReader(bytes.NewReader(nil))
		_, err := r.ReadFrame()
		if !errors.Is(err, io.EOF) {
			t.Errorf("ReadFrame() error = %v, want io.EOF", err)
		}
	})

	t.Run("partial header returns ErrUnexpectedEOF", func(t *testing.T) {
		r := NewReader(bytes.NewReader([]byte{0x00, 0x00, 0x05}))
		_, err := r.ReadFrame()
		if !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Errorf("ReadFrame() error = %v, want io.ErrUnexpectedEOF", err)
		}
	})

	t.Run("partial payload returns error", func(t *testing.T) {
		hdr := Header{Length: 10, Type: TypeData, StreamID: 1}
		buf := hdr.AppendTo(nil)
		buf = append(buf, []byte("short")...) // only 5 of 10 bytes

		r := NewReader(bytes.NewReader(buf))
		_, err := r.ReadFrame()
		if err == nil {
			t.Error("ReadFrame() should return error for truncated payload")
		}
	})

	t.Run("payload exceeds max frame size", func(t *testing.T) {
		// Build a frame with payload larger than default max.
		oversized := make([]byte, DefaultMaxFrameSize+1)
		raw := buildRawFrame(TypeData, 0, 1, oversized)

		r := NewReader(bytes.NewReader(raw))
		_, err := r.ReadFrame()
		if err == nil {
			t.Error("ReadFrame() should return error for oversized payload")
		}
	})

	t.Run("payload within custom max frame size", func(t *testing.T) {
		payload := make([]byte, DefaultMaxFrameSize+100)
		raw := buildRawFrame(TypeData, 0, 1, payload)

		r := NewReader(bytes.NewReader(raw))
		if err := r.SetMaxFrameSize(DefaultMaxFrameSize + 200); err != nil {
			t.Fatalf("SetMaxFrameSize() error: %v", err)
		}
		f, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() error: %v", err)
		}
		if f.Header.Length != uint32(len(payload)) {
			t.Errorf("Length = %d, want %d", f.Header.Length, len(payload))
		}
	})

	t.Run("all frame types round-trip", func(t *testing.T) {
		frameTypes := []Type{
			TypeData, TypeHeaders, TypePriority, TypeRSTStream,
			TypeSettings, TypePushPromise, TypePing, TypeGoAway,
			TypeWindowUpdate, TypeContinuation,
		}
		for _, ft := range frameTypes {
			payload := []byte{0x01, 0x02, 0x03}
			raw := buildRawFrame(ft, 0, 1, payload)

			r := NewReader(bytes.NewReader(raw))
			f, err := r.ReadFrame()
			if err != nil {
				t.Errorf("ReadFrame(%s) error: %v", ft, err)
				continue
			}
			if f.Header.Type != ft {
				t.Errorf("ReadFrame(%s) Type = %s", ft, f.Header.Type)
			}
		}
	})
}

// buildRawFrame constructs a raw HTTP/2 frame for testing.
func buildRawFrame(typ Type, flags Flags, streamID uint32, payload []byte) []byte {
	hdr := Header{
		Length:   uint32(len(payload)),
		Type:     typ,
		Flags:    flags,
		StreamID: streamID,
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)
	return buf
}

func TestReader_ReadFrame_PING(t *testing.T) {
	pingData := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	raw := buildRawFrame(TypePing, FlagAck, 0, pingData[:])

	r := NewReader(bytes.NewReader(raw))
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}

	got, err := f.PingData()
	if err != nil {
		t.Fatalf("PingData() error: %v", err)
	}
	if got != pingData {
		t.Errorf("PingData() = %v, want %v", got, pingData)
	}
	if !f.Header.Flags.Has(FlagAck) {
		t.Error("ACK flag not set")
	}
}

func TestReader_ReadFrame_WindowUpdate(t *testing.T) {
	var payload [4]byte
	binary.BigEndian.PutUint32(payload[:], 65535)
	raw := buildRawFrame(TypeWindowUpdate, 0, 0, payload[:])

	r := NewReader(bytes.NewReader(raw))
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}

	inc, err := f.WindowUpdateIncrement()
	if err != nil {
		t.Fatalf("WindowUpdateIncrement() error: %v", err)
	}
	if inc != 65535 {
		t.Errorf("WindowUpdateIncrement() = %d, want 65535", inc)
	}
}
