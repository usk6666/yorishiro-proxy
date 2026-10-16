package envelope

import (
	"net/url"
	"strings"
	"testing"
)

// wirePathPayloads are request paths exactly as they appear on the wire
// (HTTP/1.x request-target before '?', HTTP/2 :path before '?'). The first
// row is the GitHub-reported ad cookie-sync shape (USK-1139); the rest are
// pentest shapes that net/url's RawPath machinery cannot carry verbatim
// (validEncoded rejects { } | ^ " space and non-ASCII; unescape rejects %zz).
var wirePathPayloads = []struct {
	name string
	wire string
}{
	{"reported cookie-sync", "/check_uuid/https%3A%2F%2Fsync.example%2Fsetuid%3Fa%3D1"},
	{"encoded question mark", "/a%3Fb"},
	{"encoded slash", "/a%2Fb"},
	{"encoded unreserved", "/%61dmin"},
	{"encoded space", "/a%20b"},
	{"encoded percent", "/a%25b"},
	{"invalid escape", "/a%zz"},
	{"bare percent", "/a%"},
	{"template braces", "/{{7*7}}"},
	{"pipe and caret", "/a|b^c"},
	{"raw utf-8", "/caf\xc3\xa9"},
	{"literal hash", "/a#b"},
	{"double slash", "//foo/bar"},
	{"params", "/a;b=c"},
	{"control byte", "/ctl\x01x"},
	{"plain", "/plain/path"},
}

func TestLenientDecodePath(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"", ""},
		{"/plain", "/plain"},
		{"/%61dmin", "/admin"},
		{"/a%3Fb", "/a?b"},
		{"/a%2fb", "/a/b"},
		{"/a%20b", "/a b"},
		{"/a%25b", "/a%b"},
		{"/a%zz", "/a%zz"},
		{"/a%", "/a%"},
		{"/a%4", "/a%4"},
		{"/a%%41", "/a%A"},
		{"/a+b", "/a+b"},
		{"/caf\xc3\xa9", "/caf\xc3\xa9"},
		{"/x%2541", "/x%41"},
	}
	for _, tt := range tests {
		if got := LenientDecodePath(tt.in); got != tt.want {
			t.Errorf("LenientDecodePath(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

// TestWireURLString_IsWireExact pins that the stored string form of a
// Flow.URL built from a wire path carries the wire bytes verbatim — no
// re-escaping (the HTTP/2 %253A doubling) and no decoding.
func TestWireURLString_IsWireExact(t *testing.T) {
	for _, p := range wirePathPayloads {
		t.Run(p.name, func(t *testing.T) {
			u := URLFromWirePath("https", "example.com", p.wire, "q=x%3Ay")
			want := "https://example.com" + p.wire + "?q=x%3Ay"
			if got := WireURLString(u); got != want {
				t.Errorf("WireURLString = %q, want %q", got, want)
			}
			if got := WirePath(u); got != p.wire {
				t.Errorf("WirePath = %q, want %q", got, p.wire)
			}
			if got, want := u.Path, LenientDecodePath(p.wire); got != want {
				t.Errorf("u.Path = %q, want decoded %q", got, want)
			}
		})
	}
}

// TestParseWireURL_RoundTrip covers the flow-store round trip:
// WireURLString → (sqlite / JSONL) → ParseWireURL → WirePath.
func TestParseWireURL_RoundTrip(t *testing.T) {
	for _, p := range wirePathPayloads {
		for _, tc := range []struct {
			scheme, host, query string
		}{
			{"https", "example.com", "q=x%3Ay"},
			{"http", "127.0.0.1:8080", ""},
			{"", "example.com", "a=1"},
			{"", "", ""},
		} {
			name := p.name + "/" + tc.scheme + "/" + tc.host
			t.Run(name, func(t *testing.T) {
				if tc.scheme == "" && tc.host == "" && strings.HasPrefix(p.wire, "//") {
					// Same ambiguity url.String() has: "//foo/bar" with
					// neither scheme nor host reads back as host "foo".
					// Only a Host-less HTTP/1.x request can produce it.
					t.Skip("scheme-less, host-less '//' path is ambiguous in URL string form")
				}
				orig := URLFromWirePath(tc.scheme, tc.host, p.wire, tc.query)
				s := WireURLString(orig)
				got := ParseWireURL(s)
				if got == nil {
					t.Fatalf("ParseWireURL(%q) = nil", s)
				}
				if WirePath(got) != p.wire {
					t.Errorf("WirePath(ParseWireURL(%q)) = %q, want %q", s, WirePath(got), p.wire)
				}
				if got.Scheme != tc.scheme || got.Host != tc.host || got.RawQuery != tc.query {
					t.Errorf("ParseWireURL(%q) = scheme %q host %q query %q, want %q %q %q",
						s, got.Scheme, got.Host, got.RawQuery, tc.scheme, tc.host, tc.query)
				}
				if again := WireURLString(got); again != s {
					t.Errorf("re-serialized %q, want %q", again, s)
				}
			})
		}
	}
}

// TestWireURLString_BlankSchemeShape pins that a scheme-less URL keeps the
// url.String() "//host/path" shape so host LIKE filters keep matching
// legacy and new rows alike.
func TestWireURLString_BlankSchemeShape(t *testing.T) {
	u := URLFromWirePath("", "example.com", "/a%3Ab", "")
	if got, want := WireURLString(u), "//example.com/a%3Ab"; got != want {
		t.Errorf("WireURLString = %q, want %q", got, want)
	}
	u = URLFromWirePath("", "", "/a%3Ab", "x=1")
	if got, want := WireURLString(u), "/a%3Ab?x=1"; got != want {
		t.Errorf("WireURLString = %q, want %q", got, want)
	}
}

// TestWirePath_MutatedPath covers callers (fuzzer positions) that rewrite
// u.Path after URLFromWirePath: the stale RawPath must not win.
func TestWirePath_MutatedPath(t *testing.T) {
	u := URLFromWirePath("http", "h", "/a%2Fb", "")
	u.Path = "/x y"
	if got, want := WirePath(u), "/x%20y"; got != want {
		t.Errorf("WirePath after Path mutation = %q, want %q", got, want)
	}

	// A plain url.URL without RawPath falls back to EscapedPath.
	if got, want := WirePath(&url.URL{Path: "/a b"}), "/a%20b"; got != want {
		t.Errorf("WirePath(plain) = %q, want %q", got, want)
	}
	if got := WirePath(nil); got != "" {
		t.Errorf("WirePath(nil) = %q, want empty", got)
	}
}

// TestParseWireURL_NeverFails pins that strings net/url rejects (invalid
// escapes, control bytes, escaped hosts) still produce a URL instead of
// silently dropping Flow.URL on read.
func TestParseWireURL_NeverFails(t *testing.T) {
	for _, s := range []string{
		"http://h/a%zz",
		"http://h/a%",
		"http://h/ctl\x01x?k=v",
		"http://ho%20st/p",
		"http://h/a b?c d",
		"",
	} {
		if got := ParseWireURL(s); got == nil {
			t.Errorf("ParseWireURL(%q) = nil, want non-nil", s)
		}
	}
	got := ParseWireURL("http://ho%20st/p")
	if got != nil && got.Host != "ho st" {
		t.Errorf("ParseWireURL host = %q, want %q", got.Host, "ho st")
	}
}

// TestParseWireURL_LegacyRows pins that rows written by the pre-USK-1139
// url.String() projection still parse into the same scheme / host / query
// and yield the stored path bytes as the wire path.
func TestParseWireURL_LegacyRows(t *testing.T) {
	tests := []struct {
		in                           string
		scheme, host, wire, rawQuery string
	}{
		{"https://example.com/api?key=val", "https", "example.com", "/api", "key=val"},
		{"http://127.0.0.1:8080/a%253Ab", "http", "127.0.0.1:8080", "/a%253Ab", ""},
		{"//example.com/x", "", "example.com", "/x", ""},
		{"/only/path?x=1", "", "", "/only/path", "x=1"},
		{"http://[::1]:443/p", "http", "[::1]:443", "/p", ""},
		{"http://h", "http", "h", "", ""},
		{"http://h?x=1", "http", "h", "", "x=1"},
		{"./a:b", "", "", "a:b", ""},
	}
	for _, tt := range tests {
		got := ParseWireURL(tt.in)
		if got == nil {
			t.Errorf("ParseWireURL(%q) = nil", tt.in)
			continue
		}
		if got.Scheme != tt.scheme || got.Host != tt.host || WirePath(got) != tt.wire || got.RawQuery != tt.rawQuery {
			t.Errorf("ParseWireURL(%q) = (%q, %q, %q, %q), want (%q, %q, %q, %q)",
				tt.in, got.Scheme, got.Host, WirePath(got), got.RawQuery,
				tt.scheme, tt.host, tt.wire, tt.rawQuery)
		}
		if again := WireURLString(got); again != tt.in {
			t.Errorf("WireURLString(ParseWireURL(%q)) = %q", tt.in, again)
		}
	}
}
