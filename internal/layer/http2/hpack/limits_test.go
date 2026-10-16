package hpack

import (
	"errors"
	"strings"
	"testing"
)

// USK-1137 (defect C): the default decoder limits must reach browser parity.
// Chromium accepts header lists up to 256 KiB and Firefox up to 384 KiB, and
// real pages send single values (Google Ad Manager :path) of 21–26 KiB. The
// decoder now defaults both the per-string and the per-list cap to 1 MiB,
// matching Go net/http's DefaultMaxHeaderBytes and x/net http2's
// maxHeaderStringLen() == maxHeaderListSize().

const (
	kib = 1024
	mib = 1024 * 1024
)

// literalNoIndexNewName encodes a "Literal Header Field without Indexing —
// New Name" representation (RFC 7541 §6.2.2) with raw (non-Huffman) strings,
// the shape the Issue's reproducer reaches the proxy in.
func literalNoIndexNewName(dst []byte, name, value string) []byte {
	dst = append(dst, 0x00)
	dst = encodeInteger(dst, 0x00, 7, uint64(len(name)))
	dst = append(dst, name...)
	dst = encodeInteger(dst, 0x00, 7, uint64(len(value)))
	dst = append(dst, value...)
	return dst
}

// literalNoIndexPath encodes ":path" as "Literal Header Field without
// Indexing — Indexed Name" (static index 4) with a raw value.
func literalNoIndexPath(dst []byte, value string) []byte {
	dst = encodeInteger(dst, 0x00, 4, 4)
	dst = encodeInteger(dst, 0x00, 7, uint64(len(value)))
	dst = append(dst, value...)
	return dst
}

// TestDecoder_DefaultLimits_AcceptBrowserSizedHeaders covers Test Plan #6:
// the default decoder accepts a 21 KiB literal :path (Issue repro C) and a
// single value just under the 1 MiB cap, returning the exact bytes.
func TestDecoder_DefaultLimits_AcceptBrowserSizedHeaders(t *testing.T) {
	path21K := "/?q=" + strings.Repeat("x", 21000)
	tests := []struct {
		name  string
		block []byte
		want  []HeaderField
	}{
		{
			name:  "21 KiB :path (Google Ad Manager repro)",
			block: literalNoIndexPath(nil, path21K),
			want:  []HeaderField{{Name: ":path", Value: path21K}},
		},
		{
			name:  "26 KiB value",
			block: literalNoIndexNewName(nil, "x-big", strings.Repeat("y", 26*kib)),
			want:  []HeaderField{{Name: "x-big", Value: strings.Repeat("y", 26*kib)}},
		},
		{
			// 1 MiB - 64 + len("x-big") + 32 stays below the 1 MiB list cap.
			name:  "value just under 1 MiB",
			block: literalNoIndexNewName(nil, "x-big", strings.Repeat("z", mib-64)),
			want:  []HeaderField{{Name: "x-big", Value: strings.Repeat("z", mib-64)}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewDecoder(4096).Decode(tt.block)
			if err != nil {
				t.Fatalf("Decode() error = %v, want nil", err)
			}
			if len(got) != len(tt.want) {
				t.Fatalf("Decode() returned %d fields, want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i].Name != tt.want[i].Name || got[i].Value != tt.want[i].Value {
					t.Errorf("field %d = %q (%d bytes), want %q (%d bytes)",
						i, got[i].Name, len(got[i].Value), tt.want[i].Name, len(tt.want[i].Value))
				}
			}
		})
	}
}

// TestDecoder_DefaultLimits_RejectOverCap covers Test Plan #7: the default
// decoder still enforces both caps at parse time. A string one byte over
// the 1 MiB cap fails with ErrStringTooLong (checked against the wire length
// before allocating), and a list whose fields are individually fine but sum
// past 1 MiB fails with ErrHeaderListTooLarge.
func TestDecoder_DefaultLimits_RejectOverCap(t *testing.T) {
	half := strings.Repeat("a", 600*kib)
	tests := []struct {
		name    string
		block   []byte
		wantErr error
	}{
		{
			name:    "string of 1 MiB + 1",
			block:   literalNoIndexNewName(nil, "x-big", strings.Repeat("b", mib+1)),
			wantErr: ErrStringTooLong,
		},
		{
			// Only the length prefix is present: the cap must trip before
			// the decoder looks for (or allocates) the value bytes.
			name:    "string length prefix of 1 MiB + 1 without data",
			block:   encodeInteger([]byte{0x00, 0x01, 'x'}, 0x00, 7, mib+1),
			wantErr: ErrStringTooLong,
		},
		{
			name:    "two 600 KiB fields (list > 1 MiB)",
			block:   literalNoIndexNewName(literalNoIndexNewName(nil, "x-a", half), "x-b", half),
			wantErr: ErrHeaderListTooLarge,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewDecoder(4096).Decode(tt.block)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Decode() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}
