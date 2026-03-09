package codec

import (
	"fmt"
	"net/url"
	"strings"
)

// urlEncodeQueryCodec implements URL query encoding using url.QueryEscape.
type urlEncodeQueryCodec struct{}

func (c *urlEncodeQueryCodec) Name() string { return "url_encode_query" }

func (c *urlEncodeQueryCodec) Encode(s string) (string, error) {
	return url.QueryEscape(s), nil
}

func (c *urlEncodeQueryCodec) Decode(s string) (string, error) {
	decoded, err := url.QueryUnescape(s)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// urlEncodePathCodec implements URL path encoding using url.PathEscape.
type urlEncodePathCodec struct{}

func (c *urlEncodePathCodec) Name() string { return "url_encode_path" }

func (c *urlEncodePathCodec) Encode(s string) (string, error) {
	return url.PathEscape(s), nil
}

func (c *urlEncodePathCodec) Decode(s string) (string, error) {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// urlEncodeFullCodec encodes all non-alphanumeric characters to %XX.
type urlEncodeFullCodec struct{}

func (c *urlEncodeFullCodec) Name() string { return "url_encode_full" }

func (c *urlEncodeFullCodec) Encode(s string) (string, error) {
	var b strings.Builder
	b.Grow(len(s) * 3)
	for i := 0; i < len(s); i++ {
		ch := s[i]
		if isUnreservedByte(ch) {
			b.WriteByte(ch)
		} else {
			fmt.Fprintf(&b, "%%%02X", ch)
		}
	}
	return b.String(), nil
}

func (c *urlEncodeFullCodec) Decode(s string) (string, error) {
	decoded, err := url.PathUnescape(s)
	if err != nil {
		return "", err
	}
	return decoded, nil
}

// doubleURLEncodeCodec applies URL encoding twice.
type doubleURLEncodeCodec struct{}

func (c *doubleURLEncodeCodec) Name() string { return "double_url_encode" }

func (c *doubleURLEncodeCodec) Encode(s string) (string, error) {
	first := url.QueryEscape(s)
	return url.QueryEscape(first), nil
}

func (c *doubleURLEncodeCodec) Decode(s string) (string, error) {
	first, err := url.QueryUnescape(s)
	if err != nil {
		return "", err
	}
	second, err := url.QueryUnescape(first)
	if err != nil {
		return "", err
	}
	return second, nil
}

// isUnreservedByte returns true for unreserved URI characters (RFC 3986 §2.3):
// ALPHA / DIGIT / "-" / "." / "_" / "~"
func isUnreservedByte(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
		c == '-' || c == '.' || c == '_' || c == '~'
}
