package protobuf

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"fmt"
	"io"

	"github.com/golang/snappy"
	"github.com/klauspost/compress/zstd"
)

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
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("gzip decompress read: %w", err)
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
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("deflate decompress: %w", err)
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
	out, err := snappy.Decode(nil, data)
	if err != nil {
		return nil, fmt.Errorf("snappy decompress: %w", err)
	}
	return out, nil
}

func compressSnappy(data []byte) ([]byte, error) {
	return snappy.Encode(nil, data), nil
}

func decompressZstd(data []byte) ([]byte, error) {
	r, err := zstd.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("zstd decompress init: %w", err)
	}
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("zstd decompress read: %w", err)
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
