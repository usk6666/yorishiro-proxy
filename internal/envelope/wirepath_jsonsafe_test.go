package envelope

import (
	"encoding/json"
	"net/url"
	"testing"
)

func TestEscapeInvalidUTF8(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"/plain", "/plain"},
		{"/caf\xc3\xa9", "/caf\xc3\xa9"},       // valid UTF-8 untouched
		{"/%ff%zz", "/%ff%zz"},                 // existing escapes untouched
		{"/ctl\x01x", "/ctl\x01x"},             // control bytes are valid UTF-8
		{"/\xff\xfe", "/%FF%FE"},               // invalid bytes escaped
		{"/a\x80b", "/a%80b"},                  // lone continuation byte
		{"/\xc3", "/%C3"},                      // truncated sequence
		{"/\xef\xbf\xbd", "/\xef\xbf\xbd"},     // a real U+FFFD stays
		{"/\xc3\xa9\xff\xc3\xa9", "/é%FFé"},    // mixed
		{"/\xed\xa0\x80", "/%ED%A0%80"},        // UTF-16 surrogate encoding is invalid
		{"/\xf4\x90\x80\x80", "/%F4%90%80%80"}, // above U+10FFFF
	}
	for _, tt := range tests {
		got := EscapeInvalidUTF8(tt.in)
		if got != tt.want {
			t.Errorf("EscapeInvalidUTF8(%q) = %q, want %q", tt.in, got, tt.want)
		}
		raw, err := json.Marshal(got)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		var back string
		if err := json.Unmarshal(raw, &back); err != nil || back != got {
			t.Errorf("EscapeInvalidUTF8(%q) = %q does not survive JSON (got %q, err %v)", tt.in, got, back, err)
		}
	}
}

func TestWireURLStringJSONSafe(t *testing.T) {
	if got := WireURLStringJSONSafe(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	u := URLFromWirePath("https", "example.com", "/a\x80b/%61", "q=\xff")
	if got, want := WireURLStringJSONSafe(u), "https://example.com/a%80b/%61?q=%FF"; got != want {
		t.Errorf("WireURLStringJSONSafe = %q, want %q", got, want)
	}
	// The byte-exact serialization is unchanged.
	if got, want := WireURLString(u), "https://example.com/a\x80b/%61?q=\xff"; got != want {
		t.Errorf("WireURLString = %q, want %q", got, want)
	}
}

func TestDecodedPathURLString(t *testing.T) {
	if got := DecodedPathURLString(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}
	u := URLFromWirePath("https", "example.com", "/%6dkfs.ext4/%zz", "a=%41")
	if got, want := DecodedPathURLString(u), "https://example.com/mkfs.ext4/%zz?a=%41"; got != want {
		t.Errorf("DecodedPathURLString = %q, want %q", got, want)
	}
	if WirePath(u) != "/%6dkfs.ext4/%zz" {
		t.Errorf("DecodedPathURLString mutated the URL: wire path now %q", WirePath(u))
	}
}

func TestSetWirePath(t *testing.T) {
	SetWirePath(nil, "/x") // must not panic

	u, err := url.Parse("https://example.com/api?q=1")
	if err != nil {
		t.Fatal(err)
	}
	SetWirePath(u, "/%2e%2e/etc")
	if got := WirePath(u); got != "/%2e%2e/etc" {
		t.Errorf("WirePath after SetWirePath = %q, want /%%2e%%2e/etc", got)
	}
	if u.Path != "/../etc" {
		t.Errorf("Path = %q, want decoded /../etc", u.Path)
	}
	if got, want := WireURLString(u), "https://example.com/%2e%2e/etc?q=1"; got != want {
		t.Errorf("WireURLString = %q, want %q", got, want)
	}

	// Assigning Path directly is the decoded-path contract documented on
	// WirePath: the '%' is re-escaped.
	u.Path = "/%2e"
	u.RawPath = ""
	if got := WirePath(u); got != "/%252e" {
		t.Errorf("WirePath after direct Path assignment = %q, want /%%252e", got)
	}
}

// TestWireURLString_KnownNonRoundTrip pins the cases documented on
// WireURLString (USK-1139 review S-4) so the godoc stays truthful.
func TestWireURLString_KnownNonRoundTrip(t *testing.T) {
	tests := []struct {
		name               string
		u                  *url.URL
		wantHost, wantPath string
	}{
		{"host + non-slash path", URLFromWirePath("https", "h", "a/b", ""), "h", "/a/b"},
		{"scheme, no host, non-slash path", URLFromWirePath("https", "", "a/b", ""), "a", "/b"},
		{"no scheme, no host, double-slash path", URLFromWirePath("", "", "//x/y", ""), "x", "/y"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			back := ParseWireURL(WireURLString(tt.u))
			if back.Host != tt.wantHost || WirePath(back) != tt.wantPath {
				t.Errorf("round trip of %q = host %q path %q, want host %q path %q",
					WireURLString(tt.u), back.Host, WirePath(back), tt.wantHost, tt.wantPath)
			}
		})
	}
}
