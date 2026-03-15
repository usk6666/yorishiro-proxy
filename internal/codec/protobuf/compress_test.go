package protobuf

import (
	"errors"
	"testing"
)

// TestCompress_RoundTrip tests compress/decompress round-trip for all algorithms.
func TestCompress_RoundTrip(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog. " +
		"This is a test payload for compression round-trip testing.")

	algorithms := []string{"identity", "", "gzip", "deflate", "snappy", "zstd"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			compressed, err := Compress(data, alg)
			if err != nil {
				t.Fatalf("Compress(%q): %v", alg, err)
			}
			decompressed, err := Decompress(compressed, alg)
			if err != nil {
				t.Fatalf("Decompress(%q): %v", alg, err)
			}
			assertBytesEqual(t, data, decompressed)
		})
	}
}

// TestCompress_Identity tests that identity compression is a passthrough.
func TestCompress_Identity(t *testing.T) {
	data := []byte("hello world")

	compressed, err := Compress(data, "identity")
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	assertBytesEqual(t, data, compressed)

	decompressed, err := Decompress(data, "identity")
	if err != nil {
		t.Fatalf("Decompress: %v", err)
	}
	assertBytesEqual(t, data, decompressed)
}

// TestCompress_EmptyData tests compressing/decompressing empty data.
func TestCompress_EmptyData(t *testing.T) {
	algorithms := []string{"gzip", "deflate", "snappy", "zstd"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			compressed, err := Compress([]byte{}, alg)
			if err != nil {
				t.Fatalf("Compress(%q) empty: %v", alg, err)
			}
			decompressed, err := Decompress(compressed, alg)
			if err != nil {
				t.Fatalf("Decompress(%q) empty: %v", alg, err)
			}
			if len(decompressed) != 0 {
				t.Errorf("expected empty decompressed data, got %d bytes", len(decompressed))
			}
		})
	}
}

// TestCompress_Unknown tests that unknown algorithms return ErrUnknownCompression.
func TestCompress_Unknown(t *testing.T) {
	_, err := Compress([]byte("data"), "lz4")
	if !errors.Is(err, ErrUnknownCompression) {
		t.Errorf("Compress: expected ErrUnknownCompression, got %v", err)
	}

	_, err = Decompress([]byte("data"), "brotli")
	if !errors.Is(err, ErrUnknownCompression) {
		t.Errorf("Decompress: expected ErrUnknownCompression, got %v", err)
	}
}

// TestDecompress_InvalidData tests decompressing invalid compressed data.
func TestDecompress_InvalidData(t *testing.T) {
	algorithms := []string{"gzip", "deflate", "snappy", "zstd"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			_, err := Decompress([]byte("this is not valid compressed data"), alg)
			if err == nil {
				t.Errorf("Decompress(%q) with invalid data: expected error", alg)
			}
		})
	}
}

// TestCompress_LargePayload tests compression with a large payload.
func TestCompress_LargePayload(t *testing.T) {
	// Create a 100KB payload
	data := make([]byte, 100*1024)
	for i := range data {
		data[i] = byte(i % 256)
	}

	algorithms := []string{"gzip", "deflate", "snappy", "zstd"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			compressed, err := Compress(data, alg)
			if err != nil {
				t.Fatalf("Compress(%q): %v", alg, err)
			}
			decompressed, err := Decompress(compressed, alg)
			if err != nil {
				t.Fatalf("Decompress(%q): %v", alg, err)
			}
			assertBytesEqual(t, data, decompressed)
		})
	}
}

// TestDecompress_BombProtection tests that decompression is limited to maxDecompressedSize.
func TestDecompress_BombProtection(t *testing.T) {
	// Create data slightly over the limit
	oversize := make([]byte, maxDecompressedSize+1)
	for i := range oversize {
		oversize[i] = 'A'
	}

	// Test gzip
	t.Run("gzip", func(t *testing.T) {
		compressed, err := Compress(oversize, "gzip")
		if err != nil {
			t.Fatalf("Compress: %v", err)
		}
		_, err = Decompress(compressed, "gzip")
		if err == nil {
			t.Error("expected error for oversized decompressed data")
		}
	})

	// Test deflate
	t.Run("deflate", func(t *testing.T) {
		compressed, err := Compress(oversize, "deflate")
		if err != nil {
			t.Fatalf("Compress: %v", err)
		}
		_, err = Decompress(compressed, "deflate")
		if err == nil {
			t.Error("expected error for oversized decompressed data")
		}
	})

	// Test snappy
	t.Run("snappy", func(t *testing.T) {
		compressed, err := Compress(oversize, "snappy")
		if err != nil {
			t.Fatalf("Compress: %v", err)
		}
		_, err = Decompress(compressed, "snappy")
		if err == nil {
			t.Error("expected error for oversized decompressed data")
		}
	})

	// Test zstd
	t.Run("zstd", func(t *testing.T) {
		compressed, err := Compress(oversize, "zstd")
		if err != nil {
			t.Fatalf("Compress: %v", err)
		}
		_, err = Decompress(compressed, "zstd")
		if err == nil {
			t.Error("expected error for oversized decompressed data")
		}
	})
}

// TestDecompress_AtLimit tests that data exactly at the limit succeeds.
func TestDecompress_AtLimit(t *testing.T) {
	atLimit := make([]byte, maxDecompressedSize)
	for i := range atLimit {
		atLimit[i] = 'B'
	}

	algorithms := []string{"gzip", "deflate", "snappy", "zstd"}
	for _, alg := range algorithms {
		t.Run(alg, func(t *testing.T) {
			compressed, err := Compress(atLimit, alg)
			if err != nil {
				t.Fatalf("Compress: %v", err)
			}
			decompressed, err := Decompress(compressed, alg)
			if err != nil {
				t.Fatalf("Decompress: %v", err)
			}
			if len(decompressed) != maxDecompressedSize {
				t.Errorf("expected %d bytes, got %d", maxDecompressedSize, len(decompressed))
			}
		})
	}
}

// TestCompress_GzipActuallyCompresses verifies gzip produces smaller output for repetitive data.
func TestCompress_GzipActuallyCompresses(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 'a'
	}
	compressed, err := Compress(data, "gzip")
	if err != nil {
		t.Fatalf("Compress: %v", err)
	}
	if len(compressed) >= len(data) {
		t.Errorf("expected compressed size (%d) < original (%d)", len(compressed), len(data))
	}
}
