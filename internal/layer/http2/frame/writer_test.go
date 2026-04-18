package frame

import (
	"bytes"
	"encoding/binary"
	"io"
	"testing"
)

func TestNewWriter(t *testing.T) {
	w := NewWriter(&bytes.Buffer{})
	if w.MaxFrameSize() != DefaultMaxFrameSize {
		t.Errorf("MaxFrameSize() = %d, want %d", w.MaxFrameSize(), DefaultMaxFrameSize)
	}
}

func TestWriter_SetMaxFrameSize(t *testing.T) {
	w := NewWriter(&bytes.Buffer{})

	tests := []struct {
		name    string
		size    uint32
		wantErr bool
	}{
		{"default", DefaultMaxFrameSize, false},
		{"max allowed", MaxAllowedFrameSize, false},
		{"too small", DefaultMaxFrameSize - 1, true},
		{"too large", MaxAllowedFrameSize + 1, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := w.SetMaxFrameSize(tt.size)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetMaxFrameSize(%d) error = %v, wantErr %v", tt.size, err, tt.wantErr)
			}
		})
	}
}

func TestWriter_WriteFrame_ExceedsMaxSize(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	payload := make([]byte, DefaultMaxFrameSize+1)
	err := w.WriteFrame(&Frame{
		Header:  Header{Length: uint32(len(payload)), Type: TypeData, StreamID: 1},
		Payload: payload,
	})
	if err == nil {
		t.Error("WriteFrame() should return error for oversized payload")
	}
}

func TestWriter_WriteFrame_UsesRawBytes(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	raw := buildRawFrame(TypeData, FlagEndStream, 1, []byte("hello"))
	err := w.WriteFrame(&Frame{
		Header:   Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		Payload:  []byte("hello"),
		RawBytes: raw,
	})
	if err != nil {
		t.Fatalf("WriteFrame() error: %v", err)
	}
	if !bytes.Equal(buf.Bytes(), raw) {
		t.Error("WriteFrame() did not use RawBytes")
	}
}

func TestWriter_WriteFrame_RawBytesHeaderMismatch(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	payload := []byte("hello")
	// Build RawBytes with a mismatched length field (claims 10 bytes but payload is 5).
	badHdr := Header{Length: 10, Type: TypeData, StreamID: 1}
	rawBytes := badHdr.AppendTo(nil)
	rawBytes = append(rawBytes, payload...) // len = HeaderSize + 5, but header says 10

	err := w.WriteFrame(&Frame{
		Header:   Header{Length: uint32(len(payload)), Type: TypeData, StreamID: 1},
		Payload:  payload,
		RawBytes: rawBytes,
	})
	if err != nil {
		t.Fatalf("WriteFrame() error: %v", err)
	}

	// Should have fallen through to serialization, so verify the written frame is valid.
	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Length != uint32(len(payload)) {
		t.Errorf("Length = %d, want %d", f.Header.Length, len(payload))
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload = %q, want %q", f.Payload, payload)
	}
}

func TestWriter_WriteFrame_SerializesWithoutRawBytes(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	payload := []byte("world")
	err := w.WriteFrame(&Frame{
		Header:  Header{Length: uint32(len(payload)), Type: TypeData, Flags: 0, StreamID: 3},
		Payload: payload,
	})
	if err != nil {
		t.Fatalf("WriteFrame() error: %v", err)
	}

	// Parse back.
	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeData {
		t.Errorf("Type = %s, want DATA", f.Header.Type)
	}
	if f.Header.StreamID != 3 {
		t.Errorf("StreamID = %d, want 3", f.Header.StreamID)
	}
	if !bytes.Equal(f.Payload, payload) {
		t.Errorf("Payload = %q, want %q", f.Payload, payload)
	}
}

func TestWriter_WriteData(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteData(1, true, []byte("body")); err != nil {
		t.Fatalf("WriteData() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeData {
		t.Errorf("Type = %s, want DATA", f.Header.Type)
	}
	if !f.Header.Flags.Has(FlagEndStream) {
		t.Error("END_STREAM flag not set")
	}
	if f.Header.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", f.Header.StreamID)
	}
	data, err := f.DataPayload()
	if err != nil {
		t.Fatalf("DataPayload() error: %v", err)
	}
	if !bytes.Equal(data, []byte("body")) {
		t.Errorf("DataPayload() = %q, want %q", data, "body")
	}
}

func TestWriter_WriteHeaders(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	fragment := []byte{0x82, 0x86, 0x84}
	if err := w.WriteHeaders(1, true, true, fragment); err != nil {
		t.Fatalf("WriteHeaders() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeHeaders {
		t.Errorf("Type = %s, want HEADERS", f.Header.Type)
	}
	if !f.Header.Flags.Has(FlagEndStream) {
		t.Error("END_STREAM flag not set")
	}
	if !f.Header.Flags.Has(FlagEndHeaders) {
		t.Error("END_HEADERS flag not set")
	}
	got, err := f.HeaderBlockFragment()
	if err != nil {
		t.Fatalf("HeaderBlockFragment() error: %v", err)
	}
	if !bytes.Equal(got, fragment) {
		t.Errorf("fragment = %x, want %x", got, fragment)
	}
}

func TestWriter_WriteContinuation(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	fragment := []byte{0x01, 0x02}
	if err := w.WriteContinuation(1, true, fragment); err != nil {
		t.Fatalf("WriteContinuation() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeContinuation {
		t.Errorf("Type = %s, want CONTINUATION", f.Header.Type)
	}
	if !f.Header.Flags.Has(FlagEndHeaders) {
		t.Error("END_HEADERS flag not set")
	}
}

func TestWriter_WriteSettings(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	settings := []Setting{
		{ID: SettingMaxFrameSize, Value: 32768},
		{ID: SettingInitialWindowSize, Value: 65535},
	}
	if err := w.WriteSettings(settings); err != nil {
		t.Fatalf("WriteSettings() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	got, err := f.SettingsParams()
	if err != nil {
		t.Fatalf("SettingsParams() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("SettingsParams() returned %d settings, want 2", len(got))
	}
	for i, s := range got {
		if s != settings[i] {
			t.Errorf("setting[%d] = %+v, want %+v", i, s, settings[i])
		}
	}
}

func TestWriter_WriteSettingsAck(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteSettingsAck(); err != nil {
		t.Fatalf("WriteSettingsAck() error: %v", err)
	}

	r := NewReader(&buf)
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
}

func TestWriter_WritePing(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	if err := w.WritePing(true, data); err != nil {
		t.Fatalf("WritePing() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	got, err := f.PingData()
	if err != nil {
		t.Fatalf("PingData() error: %v", err)
	}
	if got != data {
		t.Errorf("PingData() = %v, want %v", got, data)
	}
	if !f.Header.Flags.Has(FlagAck) {
		t.Error("ACK flag not set")
	}
}

func TestWriter_WriteGoAway(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	debugData := []byte("connection error")
	if err := w.WriteGoAway(5, 1, debugData); err != nil {
		t.Fatalf("WriteGoAway() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	lastStreamID, errCode, gotDebug, err := f.GoAwayInfo()
	if err != nil {
		t.Fatalf("GoAwayInfo() error: %v", err)
	}
	if lastStreamID != 5 {
		t.Errorf("lastStreamID = %d, want 5", lastStreamID)
	}
	if errCode != 1 {
		t.Errorf("errCode = %d, want 1", errCode)
	}
	if !bytes.Equal(gotDebug, debugData) {
		t.Errorf("debugData = %q, want %q", gotDebug, debugData)
	}
}

func TestWriter_WriteGoAway_NoDebugData(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteGoAway(0, 0, nil); err != nil {
		t.Fatalf("WriteGoAway() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	lastStreamID, errCode, gotDebug, err := f.GoAwayInfo()
	if err != nil {
		t.Fatalf("GoAwayInfo() error: %v", err)
	}
	if lastStreamID != 0 || errCode != 0 {
		t.Errorf("lastStreamID = %d, errCode = %d", lastStreamID, errCode)
	}
	if gotDebug != nil {
		t.Errorf("debugData = %v, want nil", gotDebug)
	}
}

func TestWriter_WriteWindowUpdate(t *testing.T) {
	tests := []struct {
		name      string
		streamID  uint32
		increment uint32
		wantErr   bool
	}{
		{"valid", 0, 65535, false},
		{"stream scoped", 1, 1, false},
		{"max increment", 0, 0x7FFFFFFF, false},
		{"zero increment", 0, 0, true},
		{"overflow", 0, 0x80000000, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)

			err := w.WriteWindowUpdate(tt.streamID, tt.increment)
			if (err != nil) != tt.wantErr {
				t.Errorf("WriteWindowUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}

			r := NewReader(&buf)
			f, err := r.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame() error: %v", err)
			}
			inc, err := f.WindowUpdateIncrement()
			if err != nil {
				t.Fatalf("WindowUpdateIncrement() error: %v", err)
			}
			if inc != tt.increment {
				t.Errorf("increment = %d, want %d", inc, tt.increment)
			}
			if f.Header.StreamID != tt.streamID {
				t.Errorf("StreamID = %d, want %d", f.Header.StreamID, tt.streamID)
			}
		})
	}
}

func TestWriter_WriteRSTStream(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteRSTStream(3, 8); err != nil {
		t.Fatalf("WriteRSTStream() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeRSTStream {
		t.Errorf("Type = %s, want RST_STREAM", f.Header.Type)
	}
	if f.Header.StreamID != 3 {
		t.Errorf("StreamID = %d, want 3", f.Header.StreamID)
	}
	errCode, err := f.RSTStreamErrorCode()
	if err != nil {
		t.Fatalf("RSTStreamErrorCode() error: %v", err)
	}
	if errCode != 8 {
		t.Errorf("errCode = %d, want 8", errCode)
	}
}

func TestWriter_WritePriority(t *testing.T) {
	tests := []struct {
		name      string
		streamID  uint32
		exclusive bool
		streamDep uint32
		weight    uint8
	}{
		{"non-exclusive", 1, false, 0, 15},
		{"exclusive", 3, true, 1, 255},
		{"zero weight", 5, false, 0, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)

			if err := w.WritePriority(tt.streamID, tt.exclusive, tt.streamDep, tt.weight); err != nil {
				t.Fatalf("WritePriority() error: %v", err)
			}

			r := NewReader(&buf)
			f, err := r.ReadFrame()
			if err != nil {
				t.Fatalf("ReadFrame() error: %v", err)
			}
			exclusive, streamDep, weight, err := f.PriorityFields()
			if err != nil {
				t.Fatalf("PriorityFields() error: %v", err)
			}
			if exclusive != tt.exclusive {
				t.Errorf("exclusive = %v, want %v", exclusive, tt.exclusive)
			}
			if streamDep != tt.streamDep {
				t.Errorf("streamDep = %d, want %d", streamDep, tt.streamDep)
			}
			if weight != tt.weight {
				t.Errorf("weight = %d, want %d", weight, tt.weight)
			}
		})
	}
}

func TestWriter_WritePushPromise(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	fragment := []byte{0x82, 0x86}
	if err := w.WritePushPromise(1, 2, true, fragment); err != nil {
		t.Fatalf("WritePushPromise() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypePushPromise {
		t.Errorf("Type = %s, want PUSH_PROMISE", f.Header.Type)
	}
	if f.Header.StreamID != 1 {
		t.Errorf("StreamID = %d, want 1", f.Header.StreamID)
	}
	if !f.Header.Flags.Has(FlagEndHeaders) {
		t.Error("END_HEADERS flag not set")
	}

	promisedID, gotFragment, err := f.PushPromiseFields()
	if err != nil {
		t.Fatalf("PushPromiseFields() error: %v", err)
	}
	if promisedID != 2 {
		t.Errorf("promisedStreamID = %d, want 2", promisedID)
	}
	if !bytes.Equal(gotFragment, fragment) {
		t.Errorf("fragment = %x, want %x", gotFragment, fragment)
	}
}

func TestRoundTrip_AllFrameTypes(t *testing.T) {
	// This test verifies that all frame types can be written and read back
	// correctly through the Writer/Reader pair.
	var buf bytes.Buffer
	w := NewWriter(&buf)

	// Write various frame types.
	if err := w.WriteData(1, false, []byte("data")); err != nil {
		t.Fatalf("WriteData: %v", err)
	}
	if err := w.WriteHeaders(1, false, true, []byte{0x82}); err != nil {
		t.Fatalf("WriteHeaders: %v", err)
	}
	if err := w.WritePriority(3, true, 1, 128); err != nil {
		t.Fatalf("WritePriority: %v", err)
	}
	if err := w.WriteRSTStream(3, 2); err != nil {
		t.Fatalf("WriteRSTStream: %v", err)
	}
	if err := w.WriteSettings([]Setting{{ID: SettingMaxFrameSize, Value: 32768}}); err != nil {
		t.Fatalf("WriteSettings: %v", err)
	}
	if err := w.WriteSettingsAck(); err != nil {
		t.Fatalf("WriteSettingsAck: %v", err)
	}
	if err := w.WritePushPromise(1, 2, true, []byte{0x82}); err != nil {
		t.Fatalf("WritePushPromise: %v", err)
	}
	if err := w.WritePing(false, [8]byte{1, 2, 3, 4, 5, 6, 7, 8}); err != nil {
		t.Fatalf("WritePing: %v", err)
	}
	if err := w.WriteGoAway(1, 0, []byte("bye")); err != nil {
		t.Fatalf("WriteGoAway: %v", err)
	}
	if err := w.WriteWindowUpdate(0, 1000); err != nil {
		t.Fatalf("WriteWindowUpdate: %v", err)
	}
	if err := w.WriteContinuation(1, true, []byte{0x83}); err != nil {
		t.Fatalf("WriteContinuation: %v", err)
	}

	// Read all frames back.
	expectedTypes := []Type{
		TypeData, TypeHeaders, TypePriority, TypeRSTStream,
		TypeSettings, TypeSettings, TypePushPromise, TypePing,
		TypeGoAway, TypeWindowUpdate, TypeContinuation,
	}

	r := NewReader(&buf)
	for i, want := range expectedTypes {
		f, err := r.ReadFrame()
		if err != nil {
			t.Fatalf("ReadFrame() %d error: %v", i, err)
		}
		if f.Header.Type != want {
			t.Errorf("frame %d: Type = %s, want %s", i, f.Header.Type, want)
		}
		// Verify RawBytes length is consistent.
		if len(f.RawBytes) != HeaderSize+int(f.Header.Length) {
			t.Errorf("frame %d: RawBytes length = %d, want %d",
				i, len(f.RawBytes), HeaderSize+int(f.Header.Length))
		}
	}
}

func TestWriter_WriteSettings_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteSettings(nil); err != nil {
		t.Fatalf("WriteSettings(nil) error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Type != TypeSettings {
		t.Errorf("Type = %s, want SETTINGS", f.Header.Type)
	}
	if f.Header.Flags.Has(FlagAck) {
		t.Error("ACK flag should not be set for non-ACK SETTINGS")
	}
	if len(f.Payload) != 0 {
		t.Errorf("Payload length = %d, want 0", len(f.Payload))
	}
}

func TestWriter_WriteData_EmptyPayload(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteData(1, true, nil); err != nil {
		t.Fatalf("WriteData(nil) error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Length != 0 {
		t.Errorf("Length = %d, want 0", f.Header.Length)
	}
	if !f.Header.Flags.Has(FlagEndStream) {
		t.Error("END_STREAM flag not set")
	}
}

func TestWriter_WriteHeaders_NoEndStream(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WriteHeaders(1, false, false, []byte{0x82}); err != nil {
		t.Fatalf("WriteHeaders() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Flags.Has(FlagEndStream) {
		t.Error("END_STREAM flag should not be set")
	}
	if f.Header.Flags.Has(FlagEndHeaders) {
		t.Error("END_HEADERS flag should not be set")
	}
}

// errWriter is a writer that always returns an error.
type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestWriter_WriteFrame_WriteError(t *testing.T) {
	w := NewWriter(errWriter{})
	err := w.WriteData(1, false, []byte("hello"))
	if err == nil {
		t.Error("WriteFrame() should return error on write failure")
	}
}

func TestWriter_WriteFrame_WriteError_RawBytes(t *testing.T) {
	w := NewWriter(errWriter{})
	raw := buildRawFrame(TypeData, 0, 1, []byte("hello"))
	err := w.WriteFrame(&Frame{
		Header:   Header{Length: 5, Type: TypeData, StreamID: 1},
		Payload:  []byte("hello"),
		RawBytes: raw,
	})
	if err == nil {
		t.Error("WriteFrame() should return error on write failure with RawBytes")
	}
}

func TestWriter_WritePing_NoAck(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	data := [8]byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88}
	if err := w.WritePing(false, data); err != nil {
		t.Fatalf("WritePing() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Flags.Has(FlagAck) {
		t.Error("ACK flag should not be set")
	}
}

func TestWriter_WriteRawBytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantLen int
	}{
		{
			name:    "nil data is no-op",
			data:    nil,
			wantLen: 0,
		},
		{
			name:    "empty data is no-op",
			data:    []byte{},
			wantLen: 0,
		},
		{
			name:    "writes raw bytes verbatim",
			data:    []byte{0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 'h', 'e', 'l', 'l', 'o'},
			wantLen: 14,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			w := NewWriter(&buf)

			err := w.WriteRawBytes(tt.data)
			if err != nil {
				t.Fatalf("WriteRawBytes() error: %v", err)
			}
			if buf.Len() != tt.wantLen {
				t.Errorf("written bytes = %d, want %d", buf.Len(), tt.wantLen)
			}
			if tt.wantLen > 0 && !bytes.Equal(buf.Bytes(), tt.data) {
				t.Errorf("written data mismatch")
			}
		})
	}
}

func TestWriter_WriteRawBytes_Error(t *testing.T) {
	w := NewWriter(errWriter{})
	err := w.WriteRawBytes([]byte("hello"))
	if err == nil {
		t.Error("WriteRawBytes() should return error on write failure")
	}
}

func TestWriter_WritePushPromise_NoEndHeaders(t *testing.T) {
	var buf bytes.Buffer
	w := NewWriter(&buf)

	if err := w.WritePushPromise(1, 4, false, []byte{0x01}); err != nil {
		t.Fatalf("WritePushPromise() error: %v", err)
	}

	r := NewReader(&buf)
	f, err := r.ReadFrame()
	if err != nil {
		t.Fatalf("ReadFrame() error: %v", err)
	}
	if f.Header.Flags.Has(FlagEndHeaders) {
		t.Error("END_HEADERS flag should not be set")
	}

	// Verify the promised stream ID.
	promisedID := binary.BigEndian.Uint32(f.Payload[0:4]) & 0x7FFFFFFF
	if promisedID != 4 {
		t.Errorf("promisedStreamID = %d, want 4", promisedID)
	}
}
