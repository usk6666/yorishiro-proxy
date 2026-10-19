// Package grpclpm holds gRPC Length-Prefixed Message (LPM) helpers shared by
// the gRPC-Web Layer (internal/layer/grpcweb) and the gRPC rules engine
// (internal/rules/grpc). It is a stdlib-only leaf so the rules engine can use
// the Layer's exact decompression semantics without importing a Layer
// package (USK-1203).
package grpclpm

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrUnsupportedEncoding is returned by Decompress for a grpc-encoding value
// it cannot inflate.
var ErrUnsupportedEncoding = errors.New("unsupported grpc-encoding")

// ErrSizeExceeded is returned by Decompress when the inflated payload is
// larger than the supplied cap.
var ErrSizeExceeded = errors.New("decompressed size exceeds cap")

// Decompress inflates one LPM payload whose compressed flag is set, per the
// negotiated grpc-encoding. "" and "identity" return payload unchanged (a
// compressed flag with identity encoding is an RFC violation the Layer
// tolerates). "gzip" is inflated with the output bounded to maxSize bytes
// (gzip-bomb defence, CWE-409). Any other encoding returns
// ErrUnsupportedEncoding.
//
// This is the algorithm set and bound the gRPC-Web Layer applies to every
// data frame it emits (grpcweb.maybeDecompress delegates here).
func Decompress(payload []byte, encoding string, maxSize uint32) ([]byte, error) {
	switch strings.ToLower(strings.TrimSpace(encoding)) {
	case "", "identity":
		return payload, nil
	case "gzip":
		zr, err := gzip.NewReader(bytes.NewReader(payload))
		if err != nil {
			return nil, fmt.Errorf("gzip new reader: %w", err)
		}
		defer zr.Close()
		limit := int64(maxSize)
		// Read at most limit+1 bytes so overflow is detectable.
		out, err := io.ReadAll(io.LimitReader(zr, limit+1))
		if err != nil {
			return nil, fmt.Errorf("gzip read: %w", err)
		}
		if int64(len(out)) > limit {
			return nil, fmt.Errorf("gzip %w %d", ErrSizeExceeded, limit)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedEncoding, encoding)
	}
}

// Frame is one complete LPM frame found by WalkCompleteFrames.
type Frame struct {
	// Flags is the frame's flags byte verbatim (bit 0x01 = compressed,
	// bit 0x80 = gRPC-Web trailer); other bits are not validated.
	Flags byte
	// Payload aliases the input slice.
	Payload []byte
}

// Compressed reports whether the frame's compressed flag is set.
func (f Frame) Compressed() bool { return f.Flags&0x01 != 0 }

// WalkCompleteFrames returns every complete LPM frame at the start of data,
// stopping silently at the first incomplete 5-byte header or at a declared
// length larger than the remaining bytes. Unlike the Layer's strict parser
// it never fails: it exists so a deny-only scanner can see the frames of a
// body the strict parser rejected.
func WalkCompleteFrames(data []byte) []Frame {
	var frames []Frame
	for len(data) >= 5 {
		n := binary.BigEndian.Uint32(data[1:5])
		if uint64(n) > uint64(len(data)-5) {
			break
		}
		frames = append(frames, Frame{Flags: data[0], Payload: data[5 : 5+int(n)]})
		data = data[5+int(n):]
	}
	return frames
}
