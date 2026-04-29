package pluginv2

import (
	"strings"
	"testing"
)

// Regression for the padding-oracle hardening of pkcs7Unpad. All padding
// failures must surface a single generic "invalid padding" message; the
// distinction between "padding value out of range" and "padding bytes
// mismatch" must NOT be observable via error text.
func TestPKCS7Unpad_PaddingFailuresReturnUnifiedError(t *testing.T) {
	const blockSize = 16
	cases := []struct {
		name string
		data []byte
	}{
		{
			name: "padding_value_zero",
			// last byte is 0 — out of valid range [1, blockSize]
			data: append(make([]byte, blockSize-1), 0x00),
		},
		{
			name: "padding_value_above_blocksize",
			// last byte is blockSize+1 — out of range
			data: append(make([]byte, blockSize-1), byte(blockSize+1)),
		},
		{
			name: "padding_bytes_mismatch",
			// last byte says padding=4, but the preceding 3 bytes are 0x00
			// instead of 0x04 — bytes mismatch the declared padding length
			data: append(append(make([]byte, blockSize-4), 0x00, 0x00, 0x00), 0x04),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := pkcs7Unpad(tc.data, blockSize)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if got := err.Error(); got != "pkcs7 unpad: invalid padding" {
				t.Errorf("error message = %q, want %q (oracle leak)", got, "pkcs7 unpad: invalid padding")
			}
		})
	}
}

func TestPKCS7Unpad_StructuralErrorsKeepDistinctMessages(t *testing.T) {
	// Length-shape errors leak only ciphertext shape (already observable to
	// any attacker), so distinct messages are fine and aid debugging.
	const blockSize = 16
	if _, err := pkcs7Unpad(nil, blockSize); err == nil || !strings.Contains(err.Error(), "empty data") {
		t.Errorf("empty input: got %v", err)
	}
	if _, err := pkcs7Unpad(make([]byte, blockSize+1), blockSize); err == nil || !strings.Contains(err.Error(), "multiple of block size") {
		t.Errorf("non-multiple input: got %v", err)
	}
}

func TestPKCS7Unpad_HappyPath(t *testing.T) {
	const blockSize = 16
	// 12 bytes of plaintext + 4 bytes of 0x04 padding
	plaintext := []byte("abcdefghijkl")
	padded := append(plaintext, 0x04, 0x04, 0x04, 0x04)

	out, err := pkcs7Unpad(padded, blockSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(out) != "abcdefghijkl" {
		t.Errorf("got %q, want %q", out, "abcdefghijkl")
	}
}

func TestPKCS7Unpad_FullBlockOfPadding(t *testing.T) {
	const blockSize = 16
	// Exactly one full block of padding (data was a multiple of blockSize)
	padded := make([]byte, blockSize)
	for i := range padded {
		padded[i] = byte(blockSize)
	}
	out, err := pkcs7Unpad(padded, blockSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(out) != 0 {
		t.Errorf("got %v, want empty", out)
	}
}
