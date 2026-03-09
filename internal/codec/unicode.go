package codec

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// unicodeEscapeCodec implements \uXXXX Unicode escaping.
type unicodeEscapeCodec struct{}

func (c *unicodeEscapeCodec) Name() string { return "unicode_escape" }

func (c *unicodeEscapeCodec) Encode(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		if r <= 0xFFFF {
			fmt.Fprintf(&b, "\\u%04X", r)
		} else {
			// Use surrogate pair for supplementary characters.
			r -= 0x10000
			hi := rune(0xD800 + (r>>10)&0x3FF)
			lo := rune(0xDC00 + r&0x3FF)
			fmt.Fprintf(&b, "\\u%04X\\u%04X", hi, lo)
		}
	}
	return b.String(), nil
}

func (c *unicodeEscapeCodec) Decode(s string) (string, error) {
	var b strings.Builder
	remaining := s
	for len(remaining) > 0 {
		if strings.HasPrefix(remaining, "\\u") && len(remaining) >= 6 {
			hexStr := remaining[2:6]
			val, err := strconv.ParseUint(hexStr, 16, 32)
			if err != nil {
				b.WriteString(remaining[:2])
				remaining = remaining[2:]
				continue
			}
			r := rune(val)
			// Handle surrogate pairs.
			if r >= 0xD800 && r <= 0xDBFF && len(remaining) >= 12 && remaining[6:8] == "\\u" {
				lowHex := remaining[8:12]
				lowVal, err := strconv.ParseUint(lowHex, 16, 32)
				if err == nil {
					lowR := rune(lowVal)
					if lowR >= 0xDC00 && lowR <= 0xDFFF {
						combined := 0x10000 + (r-0xD800)*0x400 + (lowR - 0xDC00)
						b.WriteRune(combined)
						remaining = remaining[12:]
						continue
					}
				}
			}
			b.WriteRune(r)
			remaining = remaining[6:]
		} else {
			r, size := utf8.DecodeRuneInString(remaining)
			b.WriteRune(r)
			remaining = remaining[size:]
		}
	}
	return b.String(), nil
}
