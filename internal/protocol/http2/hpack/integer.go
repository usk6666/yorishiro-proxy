package hpack

import (
	"errors"
	"fmt"
)

// ErrIntegerOverflow is returned when an encoded integer exceeds the maximum
// allowed value (to prevent denial-of-service via huge allocations).
var ErrIntegerOverflow = errors.New("hpack: integer overflow")

// maxInteger is the maximum integer value we accept during decoding.
// This prevents denial-of-service attacks where crafted integers are
// used as string lengths or table sizes, causing excessive resource
// consumption.
const maxInteger = 1<<32 - 1

// encodeInteger encodes an integer I using the prefix-coded representation
// described in RFC 7541 Section 5.1. The n least significant bits of the
// first byte are used for the prefix; the remaining high bits of the first
// byte are preserved from the prefixByte argument.
func encodeInteger(dst []byte, prefixByte byte, n uint8, value uint64) []byte {
	maxPrefix := uint64((1 << n) - 1)
	if value < maxPrefix {
		dst = append(dst, prefixByte|byte(value))
		return dst
	}
	dst = append(dst, prefixByte|byte(maxPrefix))
	value -= maxPrefix
	for value >= 128 {
		dst = append(dst, byte(value%128+128))
		value /= 128
	}
	dst = append(dst, byte(value))
	return dst
}

// decodeInteger decodes a prefix-coded integer from src. n is the prefix size
// in bits (1-8). It returns the decoded value, the number of bytes consumed,
// and any error.
func decodeInteger(src []byte, n uint8) (uint64, int, error) {
	if len(src) == 0 {
		return 0, 0, fmt.Errorf("hpack: empty buffer for integer decode")
	}
	maxPrefix := uint64((1 << n) - 1)
	value := uint64(src[0]) & maxPrefix
	if value < maxPrefix {
		return value, 1, nil
	}
	var m uint64
	for i := 1; ; i++ {
		if i >= len(src) {
			return 0, 0, fmt.Errorf("hpack: truncated integer")
		}
		b := uint64(src[i])
		value += (b & 127) << m
		if value > maxInteger {
			return 0, 0, ErrIntegerOverflow
		}
		m += 7
		if b&128 == 0 {
			return value, i + 1, nil
		}
		if m > 63 {
			return 0, 0, ErrIntegerOverflow
		}
	}
}
