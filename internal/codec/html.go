package codec

import (
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

// htmlEntityCodec encodes characters as numeric HTML entities (&#xNN;).
// This is useful for WAF bypass scenarios.
type htmlEntityCodec struct{}

func (c *htmlEntityCodec) Name() string { return "html_entity" }

func (c *htmlEntityCodec) Encode(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s) * 6)
	for _, r := range s {
		fmt.Fprintf(&b, "&#x%X;", r)
	}
	return b.String(), nil
}

func (c *htmlEntityCodec) Decode(s string) (string, error) {
	var b strings.Builder
	remaining := s
	for len(remaining) > 0 {
		if strings.HasPrefix(remaining, "&#x") || strings.HasPrefix(remaining, "&#X") {
			end := strings.Index(remaining[3:], ";")
			if end == -1 {
				b.WriteString(remaining)
				break
			}
			hexStr := remaining[3 : 3+end]
			var codepoint int
			_, err := fmt.Sscanf(hexStr, "%x", &codepoint)
			if err != nil || !utf8.ValidRune(rune(codepoint)) {
				b.WriteString(remaining[:3+end+1])
			} else {
				b.WriteRune(rune(codepoint))
			}
			remaining = remaining[3+end+1:]
		} else if strings.HasPrefix(remaining, "&#") {
			end := strings.Index(remaining[2:], ";")
			if end == -1 {
				b.WriteString(remaining)
				break
			}
			numStr := remaining[2 : 2+end]
			var codepoint int
			_, err := fmt.Sscanf(numStr, "%d", &codepoint)
			if err != nil || !utf8.ValidRune(rune(codepoint)) {
				b.WriteString(remaining[:2+end+1])
			} else {
				b.WriteRune(rune(codepoint))
			}
			remaining = remaining[2+end+1:]
		} else {
			r, size := utf8.DecodeRuneInString(remaining)
			b.WriteRune(r)
			remaining = remaining[size:]
		}
	}
	return b.String(), nil
}

// htmlEscapeCodec uses Go's html.EscapeString for named HTML entities (&amp; etc.).
type htmlEscapeCodec struct{}

func (c *htmlEscapeCodec) Name() string { return "html_escape" }

func (c *htmlEscapeCodec) Encode(s string) (string, error) {
	return html.EscapeString(s), nil
}

func (c *htmlEscapeCodec) Decode(s string) (string, error) {
	return html.UnescapeString(s), nil
}
