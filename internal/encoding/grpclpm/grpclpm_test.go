package grpclpm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"testing"
)

func TestWalkCompleteFrames(t *testing.T) {
	f1 := []byte{0x00, 0, 0, 0, 2, 'h', 'i'}
	f2 := []byte{0x01, 0, 0, 0, 1, 'z'}
	tests := []struct {
		name string
		data []byte
		want int
	}{
		{"empty", nil, 0},
		{"two frames", append(append([]byte{}, f1...), f2...), 2},
		{"stray byte after frame", append(append([]byte{}, f1...), 0x00), 1},
		{"declared length too long", []byte{0x00, 0, 0, 3, 0xe8, 'a'}, 0},
		{"short header", []byte{0x00, 0, 0}, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := WalkCompleteFrames(tt.data); len(got) != tt.want {
				t.Fatalf("frames = %d, want %d", len(got), tt.want)
			}
		})
	}
	got := WalkCompleteFrames(append(append([]byte{}, f1...), f2...))
	if !bytes.Equal(got[0].Payload, []byte("hi")) || got[0].Compressed() || !got[1].Compressed() {
		t.Errorf("unexpected frames: %+v", got)
	}
}

func TestDecompress(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("hello world"))
	_ = zw.Close()

	if out, err := Decompress(buf.Bytes(), "GZIP", 64); err != nil || string(out) != "hello world" {
		t.Errorf("gzip: out=%q err=%v", out, err)
	}
	if out, err := Decompress([]byte("raw"), "identity", 1); err != nil || string(out) != "raw" {
		t.Errorf("identity: out=%q err=%v", out, err)
	}
	if _, err := Decompress(buf.Bytes(), "gzip", 4); !errors.Is(err, ErrSizeExceeded) {
		t.Errorf("over cap: err=%v, want ErrSizeExceeded", err)
	}
	if _, err := Decompress([]byte("x"), "br", 64); !errors.Is(err, ErrUnsupportedEncoding) {
		t.Errorf("br: err=%v, want ErrUnsupportedEncoding", err)
	}
	if _, err := Decompress([]byte("not gzip"), "gzip", 64); err == nil {
		t.Error("corrupt gzip: want error")
	}
}
