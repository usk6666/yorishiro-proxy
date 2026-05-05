package frame

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestType_String(t *testing.T) {
	tests := []struct {
		typ  Type
		want string
	}{
		{TypeData, "DATA"},
		{TypeHeaders, "HEADERS"},
		{TypePriority, "PRIORITY"},
		{TypeRSTStream, "RST_STREAM"},
		{TypeSettings, "SETTINGS"},
		{TypePushPromise, "PUSH_PROMISE"},
		{TypePing, "PING"},
		{TypeGoAway, "GOAWAY"},
		{TypeWindowUpdate, "WINDOW_UPDATE"},
		{TypeContinuation, "CONTINUATION"},
		{Type(0xFF), "UNKNOWN(0xff)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.typ.String(); got != tt.want {
				t.Errorf("Type(%d).String() = %q, want %q", tt.typ, got, tt.want)
			}
		})
	}
}

func TestSettingID_String(t *testing.T) {
	tests := []struct {
		id   SettingID
		want string
	}{
		{SettingHeaderTableSize, "HEADER_TABLE_SIZE"},
		{SettingEnablePush, "ENABLE_PUSH"},
		{SettingMaxConcurrentStreams, "MAX_CONCURRENT_STREAMS"},
		{SettingInitialWindowSize, "INITIAL_WINDOW_SIZE"},
		{SettingMaxFrameSize, "MAX_FRAME_SIZE"},
		{SettingMaxHeaderListSize, "MAX_HEADER_LIST_SIZE"},
		{SettingID(0xFFFF), "UNKNOWN(0xffff)"},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := tt.id.String(); got != tt.want {
				t.Errorf("SettingID(%d).String() = %q, want %q", tt.id, got, tt.want)
			}
		})
	}
}

func TestFlags_Has(t *testing.T) {
	tests := []struct {
		name string
		f    Flags
		v    Flags
		want bool
	}{
		{"end_stream set", FlagEndStream, FlagEndStream, true},
		{"end_stream not set", 0, FlagEndStream, false},
		{"multiple flags", FlagEndStream | FlagEndHeaders, FlagEndStream, true},
		{"multiple check", FlagEndStream | FlagEndHeaders, FlagEndStream | FlagEndHeaders, true},
		{"partial match", FlagEndStream, FlagEndStream | FlagEndHeaders, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.f.Has(tt.v); got != tt.want {
				t.Errorf("Flags(%02x).Has(%02x) = %v, want %v", tt.f, tt.v, got, tt.want)
			}
		})
	}
}

func TestParseHeader(t *testing.T) {
	tests := []struct {
		name    string
		buf     []byte
		want    Header
		wantErr bool
	}{
		{
			name: "valid DATA frame header",
			buf:  []byte{0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01},
			want: Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		},
		{
			name: "valid SETTINGS frame header",
			buf:  []byte{0x00, 0x00, 0x0C, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00},
			want: Header{Length: 12, Type: TypeSettings, Flags: 0, StreamID: 0},
		},
		{
			name: "max payload length",
			buf:  []byte{0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01},
			want: Header{Length: MaxAllowedFrameSize, Type: TypeData, Flags: 0, StreamID: 1},
		},
		{
			name: "reserved bit in stream ID masked",
			buf:  []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x01},
			want: Header{Length: 0, Type: TypeData, Flags: 0, StreamID: 1},
		},
		{
			name:    "buffer too short",
			buf:     []byte{0x00, 0x00, 0x05},
			wantErr: true,
		},
		{
			name:    "empty buffer",
			buf:     nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseHeader(tt.buf)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseHeader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ParseHeader() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestHeader_AppendTo(t *testing.T) {
	tests := []struct {
		name string
		hdr  Header
	}{
		{
			name: "DATA frame",
			hdr:  Header{Length: 5, Type: TypeData, Flags: FlagEndStream, StreamID: 1},
		},
		{
			name: "SETTINGS frame stream 0",
			hdr:  Header{Length: 12, Type: TypeSettings, Flags: 0, StreamID: 0},
		},
		{
			name: "max length",
			hdr:  Header{Length: MaxAllowedFrameSize, Type: TypeHeaders, Flags: FlagEndHeaders | FlagEndStream, StreamID: 0x7FFFFFFF},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf := tt.hdr.AppendTo(nil)
			if len(buf) != HeaderSize {
				t.Fatalf("AppendTo() returned %d bytes, want %d", len(buf), HeaderSize)
			}
			// Round-trip: parse back and compare.
			got, err := ParseHeader(buf)
			if err != nil {
				t.Fatalf("ParseHeader(AppendTo()) error: %v", err)
			}
			if got != tt.hdr {
				t.Errorf("round-trip: got %+v, want %+v", got, tt.hdr)
			}
		})
	}
}

func TestFrame_DataPayload(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		want    []byte
		wantErr bool
	}{
		{
			name: "no padding",
			frame: Frame{
				Header:  Header{Type: TypeData, Flags: 0},
				Payload: []byte("hello"),
			},
			want: []byte("hello"),
		},
		{
			name: "with padding",
			frame: Frame{
				Header:  Header{Type: TypeData, Flags: FlagPadded},
				Payload: append([]byte{0x03}, append([]byte("hello"), 0x00, 0x00, 0x00)...),
			},
			want: []byte("hello"),
		},
		{
			name: "wrong type",
			frame: Frame{
				Header:  Header{Type: TypeHeaders},
				Payload: []byte("data"),
			},
			wantErr: true,
		},
		{
			name: "padded empty payload",
			frame: Frame{
				Header:  Header{Type: TypeData, Flags: FlagPadded},
				Payload: []byte{},
			},
			wantErr: true,
		},
		{
			name: "pad length exceeds payload",
			frame: Frame{
				Header:  Header{Type: TypeData, Flags: FlagPadded},
				Payload: []byte{0x05, 0x01},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.DataPayload()
			if (err != nil) != tt.wantErr {
				t.Errorf("DataPayload() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("DataPayload() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFrame_HeaderBlockFragment(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		want    []byte
		wantErr bool
	}{
		{
			name: "no padding no priority",
			frame: Frame{
				Header:  Header{Type: TypeHeaders, Flags: FlagEndHeaders},
				Payload: []byte{0x82, 0x86},
			},
			want: []byte{0x82, 0x86},
		},
		{
			name: "with priority",
			frame: Frame{
				Header:  Header{Type: TypeHeaders, Flags: FlagEndHeaders | FlagPriority},
				Payload: append(make([]byte, 5), 0x82, 0x86),
			},
			want: []byte{0x82, 0x86},
		},
		{
			name: "with padding",
			frame: Frame{
				Header:  Header{Type: TypeHeaders, Flags: FlagEndHeaders | FlagPadded},
				Payload: append([]byte{0x02}, append([]byte{0x82, 0x86}, 0x00, 0x00)...),
			},
			want: []byte{0x82, 0x86},
		},
		{
			name: "priority but payload too short",
			frame: Frame{
				Header:  Header{Type: TypeHeaders, Flags: FlagPriority},
				Payload: []byte{0x01, 0x02},
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.HeaderBlockFragment()
			if (err != nil) != tt.wantErr {
				t.Errorf("HeaderBlockFragment() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !bytes.Equal(got, tt.want) {
				t.Errorf("HeaderBlockFragment() = %x, want %x", got, tt.want)
			}
		})
	}
}

func TestFrame_ContinuationFragment(t *testing.T) {
	f := &Frame{
		Header:  Header{Type: TypeContinuation},
		Payload: []byte{0x01, 0x02, 0x03},
	}
	got, err := f.ContinuationFragment()
	if err != nil {
		t.Fatalf("ContinuationFragment() error: %v", err)
	}
	if !bytes.Equal(got, []byte{0x01, 0x02, 0x03}) {
		t.Errorf("ContinuationFragment() = %x, want 010203", got)
	}

	// Wrong type.
	f2 := &Frame{Header: Header{Type: TypeData}}
	_, err = f2.ContinuationFragment()
	if err == nil {
		t.Error("ContinuationFragment() on DATA frame should return error")
	}
}

func TestFrame_SettingsParams(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		want    []Setting
		wantErr bool
	}{
		{
			name: "two settings",
			frame: Frame{
				Header: Header{Type: TypeSettings},
				Payload: func() []byte {
					buf := make([]byte, 12)
					binary.BigEndian.PutUint16(buf[0:2], uint16(SettingMaxFrameSize))
					binary.BigEndian.PutUint32(buf[2:6], 32768)
					binary.BigEndian.PutUint16(buf[6:8], uint16(SettingInitialWindowSize))
					binary.BigEndian.PutUint32(buf[8:12], 65535)
					return buf
				}(),
			},
			want: []Setting{
				{ID: SettingMaxFrameSize, Value: 32768},
				{ID: SettingInitialWindowSize, Value: 65535},
			},
		},
		{
			name: "ACK with empty payload",
			frame: Frame{
				Header:  Header{Type: TypeSettings, Flags: FlagAck},
				Payload: nil,
			},
			want: nil,
		},
		{
			name: "ACK with non-empty payload",
			frame: Frame{
				Header:  Header{Type: TypeSettings, Flags: FlagAck},
				Payload: make([]byte, 6),
			},
			wantErr: true,
		},
		{
			name: "payload not multiple of 6",
			frame: Frame{
				Header:  Header{Type: TypeSettings},
				Payload: make([]byte, 7),
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.SettingsParams()
			if (err != nil) != tt.wantErr {
				t.Errorf("SettingsParams() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Fatalf("SettingsParams() returned %d settings, want %d", len(got), len(tt.want))
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("SettingsParams()[%d] = %+v, want %+v", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestFrame_PingData(t *testing.T) {
	data := [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
	f := &Frame{
		Header:  Header{Type: TypePing},
		Payload: data[:],
	}
	got, err := f.PingData()
	if err != nil {
		t.Fatalf("PingData() error: %v", err)
	}
	if got != data {
		t.Errorf("PingData() = %v, want %v", got, data)
	}

	// Wrong payload length.
	f2 := &Frame{Header: Header{Type: TypePing}, Payload: []byte{1, 2}}
	_, err = f2.PingData()
	if err == nil {
		t.Error("PingData() with 2-byte payload should return error")
	}

	// Wrong type.
	f3 := &Frame{Header: Header{Type: TypeData}, Payload: data[:]}
	_, err = f3.PingData()
	if err == nil {
		t.Error("PingData() on DATA frame should return error")
	}
}

func TestFrame_GoAwayInfo(t *testing.T) {
	tests := []struct {
		name             string
		frame            Frame
		wantLastStreamID uint32
		wantErrCode      uint32
		wantDebugData    []byte
		wantErr          bool
	}{
		{
			name: "with debug data",
			frame: Frame{
				Header: Header{Type: TypeGoAway},
				Payload: func() []byte {
					buf := make([]byte, 12)
					binary.BigEndian.PutUint32(buf[0:4], 3)
					binary.BigEndian.PutUint32(buf[4:8], 0)
					copy(buf[8:], "test")
					return buf
				}(),
			},
			wantLastStreamID: 3,
			wantErrCode:      0,
			wantDebugData:    []byte("test"),
		},
		{
			name: "without debug data",
			frame: Frame{
				Header: Header{Type: TypeGoAway},
				Payload: func() []byte {
					buf := make([]byte, 8)
					binary.BigEndian.PutUint32(buf[0:4], 1)
					binary.BigEndian.PutUint32(buf[4:8], 2)
					return buf
				}(),
			},
			wantLastStreamID: 1,
			wantErrCode:      2,
			wantDebugData:    nil,
		},
		{
			name: "payload too short",
			frame: Frame{
				Header:  Header{Type: TypeGoAway},
				Payload: make([]byte, 4),
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lastStreamID, errCode, debugData, err := tt.frame.GoAwayInfo()
			if (err != nil) != tt.wantErr {
				t.Errorf("GoAwayInfo() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if lastStreamID != tt.wantLastStreamID {
					t.Errorf("lastStreamID = %d, want %d", lastStreamID, tt.wantLastStreamID)
				}
				if errCode != tt.wantErrCode {
					t.Errorf("errCode = %d, want %d", errCode, tt.wantErrCode)
				}
				if !bytes.Equal(debugData, tt.wantDebugData) {
					t.Errorf("debugData = %q, want %q", debugData, tt.wantDebugData)
				}
			}
		})
	}
}

func TestFrame_WindowUpdateIncrement(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		want    uint32
		wantErr bool
	}{
		{
			name: "valid increment",
			frame: Frame{
				Header: Header{Type: TypeWindowUpdate},
				Payload: func() []byte {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], 1000)
					return buf[:]
				}(),
			},
			want: 1000,
		},
		{
			name: "zero increment",
			frame: Frame{
				Header: Header{Type: TypeWindowUpdate},
				Payload: func() []byte {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], 0)
					return buf[:]
				}(),
			},
			wantErr: true,
		},
		{
			name: "wrong payload length",
			frame: Frame{
				Header:  Header{Type: TypeWindowUpdate},
				Payload: []byte{0x01, 0x02},
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
		{
			name: "reserved bit masked",
			frame: Frame{
				Header: Header{Type: TypeWindowUpdate},
				Payload: func() []byte {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], 0x80000001)
					return buf[:]
				}(),
			},
			want: 1,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.WindowUpdateIncrement()
			if (err != nil) != tt.wantErr {
				t.Errorf("WindowUpdateIncrement() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("WindowUpdateIncrement() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFrame_RSTStreamErrorCode(t *testing.T) {
	tests := []struct {
		name    string
		frame   Frame
		want    uint32
		wantErr bool
	}{
		{
			name: "cancel",
			frame: Frame{
				Header: Header{Type: TypeRSTStream},
				Payload: func() []byte {
					var buf [4]byte
					binary.BigEndian.PutUint32(buf[:], 8) // CANCEL
					return buf[:]
				}(),
			},
			want: 8,
		},
		{
			name: "wrong payload length",
			frame: Frame{
				Header:  Header{Type: TypeRSTStream},
				Payload: []byte{0x01},
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := tt.frame.RSTStreamErrorCode()
			if (err != nil) != tt.wantErr {
				t.Errorf("RSTStreamErrorCode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("RSTStreamErrorCode() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestFrame_PushPromiseFields(t *testing.T) {
	tests := []struct {
		name           string
		frame          Frame
		wantPromisedID uint32
		wantFragment   []byte
		wantErr        bool
	}{
		{
			name: "valid push promise",
			frame: Frame{
				Header: Header{Type: TypePushPromise},
				Payload: func() []byte {
					buf := make([]byte, 6)
					binary.BigEndian.PutUint32(buf[0:4], 2)
					buf[4] = 0x82
					buf[5] = 0x86
					return buf
				}(),
			},
			wantPromisedID: 2,
			wantFragment:   []byte{0x82, 0x86},
		},
		{
			name: "with padding",
			frame: Frame{
				Header: Header{Type: TypePushPromise, Flags: FlagPadded},
				Payload: func() []byte {
					buf := make([]byte, 9)
					buf[0] = 2 // pad length
					binary.BigEndian.PutUint32(buf[1:5], 4)
					buf[5] = 0x82
					buf[6] = 0x86
					// 2 bytes padding
					return buf
				}(),
			},
			wantPromisedID: 4,
			wantFragment:   []byte{0x82, 0x86},
		},
		{
			name: "payload too short",
			frame: Frame{
				Header:  Header{Type: TypePushPromise},
				Payload: []byte{0x01, 0x02},
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			promisedID, fragment, err := tt.frame.PushPromiseFields()
			if (err != nil) != tt.wantErr {
				t.Errorf("PushPromiseFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if promisedID != tt.wantPromisedID {
					t.Errorf("promisedStreamID = %d, want %d", promisedID, tt.wantPromisedID)
				}
				if !bytes.Equal(fragment, tt.wantFragment) {
					t.Errorf("fragment = %x, want %x", fragment, tt.wantFragment)
				}
			}
		})
	}
}

func TestFrame_PriorityFields(t *testing.T) {
	tests := []struct {
		name          string
		frame         Frame
		wantExclusive bool
		wantStreamDep uint32
		wantWeight    uint8
		wantErr       bool
	}{
		{
			name: "non-exclusive",
			frame: Frame{
				Header: Header{Type: TypePriority},
				Payload: func() []byte {
					var buf [5]byte
					binary.BigEndian.PutUint32(buf[0:4], 3)
					buf[4] = 15
					return buf[:]
				}(),
			},
			wantExclusive: false,
			wantStreamDep: 3,
			wantWeight:    15,
		},
		{
			name: "exclusive",
			frame: Frame{
				Header: Header{Type: TypePriority},
				Payload: func() []byte {
					var buf [5]byte
					binary.BigEndian.PutUint32(buf[0:4], 0x80000005) // exclusive + dep 5
					buf[4] = 255
					return buf[:]
				}(),
			},
			wantExclusive: true,
			wantStreamDep: 5,
			wantWeight:    255,
		},
		{
			name: "wrong payload length",
			frame: Frame{
				Header:  Header{Type: TypePriority},
				Payload: []byte{0x01, 0x02, 0x03},
			},
			wantErr: true,
		},
		{
			name: "wrong type",
			frame: Frame{
				Header: Header{Type: TypeData},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exclusive, streamDep, weight, err := tt.frame.PriorityFields()
			if (err != nil) != tt.wantErr {
				t.Errorf("PriorityFields() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if exclusive != tt.wantExclusive {
					t.Errorf("exclusive = %v, want %v", exclusive, tt.wantExclusive)
				}
				if streamDep != tt.wantStreamDep {
					t.Errorf("streamDep = %d, want %d", streamDep, tt.wantStreamDep)
				}
				if weight != tt.wantWeight {
					t.Errorf("weight = %d, want %d", weight, tt.wantWeight)
				}
			}
		})
	}
}
