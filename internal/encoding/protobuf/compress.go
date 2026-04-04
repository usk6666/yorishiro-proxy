package protobuf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"errors"
	"fmt"
	"io"

	"github.com/klauspost/compress/s2"
	"github.com/klauspost/compress/zstd"
)

// maxDecompressedSize is the maximum allowed size of decompressed data (254 MB).
// This matches config.MaxGRPCMessageSize (internal/config/limits.go) and prevents
// decompression bomb attacks (CWE-409) where a small compressed payload expands
// to consume excessive memory.
// Any change to config.MaxGRPCMessageSize should be reflected here.
//
// This is a var (not const) so that tests can temporarily override it with a
// smaller value to avoid allocating 254 MB+ of memory in every test run.
var maxDecompressedSize = 254 << 20 // 254 MB

// ErrDecompressedSizeExceeded is returned when decompressed data exceeds maxDecompressedSize.
var ErrDecompressedSizeExceeded = errors.New("protobuf: decompressed size exceeds limit")

// ErrUnknownCompression is returned when the grpc-encoding value is not recognized.
var ErrUnknownCompression = fmt.Errorf("protobuf: unknown compression algorithm")

// Decompress decompresses data using the specified gRPC encoding algorithm.
// Supported algorithms: "identity" (or ""), "gzip", "deflate", "snappy", "zstd".
// Returns ErrUnknownCompression for unrecognized algorithms.
func Decompress(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "", "identity":
		return data, nil
	case "gzip":
		return decompressGzip(data)
	case "deflate":
		return decompressDeflate(data)
	case "snappy":
		return decompressSnappy(data)
	case "zstd":
		return decompressZstd(data)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownCompression, encoding)
	}
}

// Compress compresses data using the specified gRPC encoding algorithm.
// Supported algorithms: "identity" (or ""), "gzip", "deflate", "snappy", "zstd".
// Returns ErrUnknownCompression for unrecognized algorithms.
func Compress(data []byte, encoding string) ([]byte, error) {
	switch encoding {
	case "", "identity":
		return data, nil
	case "gzip":
		return compressGzip(data)
	case "deflate":
		return compressDeflate(data)
	case "snappy":
		return compressSnappy(data)
	case "zstd":
		return compressZstd(data)
	default:
		return nil, fmt.Errorf("%w: %q", ErrUnknownCompression, encoding)
	}
}

func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip decompress: %w", err)
	}
	defer r.Close()
	limited := &io.LimitedReader{R: r, N: int64(maxDecompressedSize) + 1}
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress read: %w", err)
	}
	if len(out) > maxDecompressedSize {
		return nil, fmt.Errorf("%w (%d bytes)", ErrDecompressedSizeExceeded, maxDecompressedSize)
	}
	return out, nil
}

func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("gzip compress write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("gzip compress close: %w", err)
	}
	return buf.Bytes(), nil
}

func decompressDeflate(data []byte) ([]byte, error) {
	r := flate.NewReader(bytes.NewReader(data))
	defer r.Close()
	limited := &io.LimitedReader{R: r, N: int64(maxDecompressedSize) + 1}
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("deflate decompress: %w", err)
	}
	if len(out) > maxDecompressedSize {
		return nil, fmt.Errorf("%w (%d bytes)", ErrDecompressedSizeExceeded, maxDecompressedSize)
	}
	return out, nil
}

func compressDeflate(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		return nil, fmt.Errorf("deflate compress init: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("deflate compress write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("deflate compress close: %w", err)
	}
	return buf.Bytes(), nil
}

func decompressSnappy(data []byte) ([]byte, error) {
	decodedLen, err := s2.DecodedLen(data)
	if err != nil {
		return nil, fmt.Errorf("snappy decompress: %w", err)
	}
	if decodedLen > maxDecompressedSize {
		return nil, fmt.Errorf("%w (%d bytes)", ErrDecompressedSizeExceeded, maxDecompressedSize)
	}
	out, err := s2.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("snappy decompress: %w", err)
	}
	return out, nil
}

func compressSnappy(data []byte) ([]byte, error) {
	return s2.EncodeSnappy(nil, data), nil
}

func decompressZstd(data []byte) ([]byte, error) {
	r, err := zstd.NewReader(bytes.NewReader(data), zstd.WithDecoderMaxMemory(uint64(maxDecompressedSize)))
	if err != nil {
		return nil, fmt.Errorf("zstd decompress init: %w", err)
	}
	defer r.Close()
	limited := &io.LimitedReader{R: r, N: int64(maxDecompressedSize) + 1}
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress read: %w", err)
	}
	if len(out) > maxDecompressedSize {
		return nil, fmt.Errorf("%w (%d bytes)", ErrDecompressedSizeExceeded, maxDecompressedSize)
	}
	return out, nil
}

func compressZstd(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		return nil, fmt.Errorf("zstd compress init: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return nil, fmt.Errorf("zstd compress write: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("zstd compress close: %w", err)
	}
	return buf.Bytes(), nil
}
