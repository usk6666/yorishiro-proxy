package envelope

import (
	"net/url"
	"strings"
)

// This file is the single place where a wire-form request path meets
// net/url (USK-1139).
//
// HTTPMessage.Path / GRPCStartMessage.Path hold the request path exactly as
// observed on the wire. Flow.URL is a *url.URL, and net/url's own
// String() / Parse() / EscapedPath() cannot carry such a path verbatim:
// String() re-escapes Path (the HTTP/2 "%3A" → "%253A" doubling), Parse()
// decodes it (losing the original encoding) or rejects it outright ("%zz",
// control bytes), and EscapedPath() only honours RawPath when it is a
// "valid" encoding — which excludes { } | ^ " space, raw UTF-8 and other
// shapes a pentest payload carries.
//
// Every producer and consumer of Flow.URL (and of the canonical scope /
// safety URLs built from wire paths) therefore goes through these helpers:
//
//   - URLFromWirePath builds a URL whose RawPath is the wire path.
//   - WirePath reads the wire path back.
//   - WireURLString serializes with the wire path, in url.String()'s shape.
//   - ParseWireURL is the never-failing inverse of WireURLString.
//
// TestWireURLGuard_NoDirectNetURLOnWirePaths keeps direct net/url use from
// creeping back in.

// LenientDecodePath decodes every valid %XX escape in s and leaves any
// invalid '%' sequence ("%zz", a trailing "%") as literal bytes. '+' is not
// special (path semantics, not form encoding). Used both as URL.Path for a
// wire path and as the "decoded form" matchers compare against.
func LenientDecodePath(s string) string {
	if strings.IndexByte(s, '%') < 0 {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '%' && i+2 < len(s) {
			hi, ok1 := unhex(s[i+1])
			lo, ok2 := unhex(s[i+2])
			if ok1 && ok2 {
				b.WriteByte(hi<<4 | lo)
				i += 2
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

func unhex(c byte) (byte, bool) {
	switch {
	case '0' <= c && c <= '9':
		return c - '0', true
	case 'a' <= c && c <= 'f':
		return c - 'a' + 10, true
	case 'A' <= c && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// URLFromWirePath builds a *url.URL for a request whose path is wirePath
// exactly as observed on the wire (percent-encoding untouched, no query).
// Path holds LenientDecodePath(wirePath) for consumers that want a decoded
// view; RawPath always holds the wire bytes, so WirePath / WireURLString
// return them verbatim.
func URLFromWirePath(scheme, host, wirePath, rawQuery string) *url.URL {
	return &url.URL{
		Scheme:   scheme,
		Host:     host,
		Path:     LenientDecodePath(wirePath),
		RawPath:  wirePath,
		RawQuery: rawQuery,
	}
}

// WirePath returns the wire-form request path of u. When RawPath is set and
// still describes Path (a caller has not rewritten Path since the URL was
// built), RawPath is returned verbatim. Otherwise — a URL built by net/url,
// or one whose Path a caller mutated (fuzzer positions) — it falls back to
// u.EscapedPath(). Returns "" for nil.
func WirePath(u *url.URL) string {
	if u == nil {
		return ""
	}
	if u.RawPath != "" && LenientDecodePath(u.RawPath) == u.Path {
		return u.RawPath
	}
	return u.EscapedPath()
}

// WireURLString serializes u like url.URL.String() — including the
// "//host/path" shape for a blank scheme, so host LIKE filters match rows
// written before and after USK-1139 alike — except that the path is
// WirePath(u) verbatim. Host is escaped exactly as url.String() escapes it,
// so a host can never contain the '/' '?' '@' delimiters ParseWireURL
// splits on. Returns "" for nil.
func WireURLString(u *url.URL) string {
	if u == nil {
		return ""
	}
	var b strings.Builder
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteByte(':')
	}
	if u.Opaque != "" {
		b.WriteString(u.Opaque)
	} else {
		path := WirePath(u)
		writeWireAuthority(&b, u, path)
		if path != "" && path[0] != '/' && u.Host != "" {
			b.WriteByte('/')
		}
		if b.Len() == 0 {
			// RFC 3986 §4.2: a first segment containing ':' would read
			// back as a scheme; url.String() prefixes "./" — mirror it.
			if segment, _, _ := strings.Cut(path, "/"); strings.Contains(segment, ":") {
				b.WriteString("./")
			}
		}
		b.WriteString(path)
	}
	if u.ForceQuery || u.RawQuery != "" {
		b.WriteByte('?')
		b.WriteString(u.RawQuery)
	}
	if u.Fragment != "" {
		b.WriteByte('#')
		b.WriteString(u.EscapedFragment())
	}
	return b.String()
}

// writeWireAuthority writes the "//userinfo@host" part exactly as
// url.URL.String() would.
func writeWireAuthority(b *strings.Builder, u *url.URL, path string) {
	if u.Scheme == "" && u.Host == "" && u.User == nil {
		return
	}
	if u.OmitHost && u.Host == "" && u.User == nil {
		return
	}
	if u.Host != "" || path != "" || u.User != nil {
		b.WriteString("//")
	}
	if u.User != nil || u.Host != "" {
		// Delegate userinfo + host escaping to net/url so the authority
		// bytes match url.String() byte for byte.
		b.WriteString(strings.TrimPrefix((&url.URL{User: u.User, Host: u.Host}).String(), "//"))
	}
}

// ParseWireURL parses a string written by WireURLString (or by the
// pre-USK-1139 url.String() projection) back into a *url.URL whose
// WirePath is the stored path bytes. It never fails: unlike url.Parse it
// accepts invalid escapes and control bytes, so a stored Flow.URL is never
// silently dropped on read. '#' is not treated as a fragment delimiter
// because a wire path may legitimately contain it; recorded URLs never
// carry a fragment.
func ParseWireURL(s string) *url.URL {
	rest := s
	scheme := ""
	if i := schemeEnd(rest); i > 0 {
		// Lowercased like url.Parse (RFC 3986 §3.1: schemes are
		// case-insensitive); store readers rely on that canonical form.
		scheme = strings.ToLower(rest[:i])
		rest = rest[i+1:]
	}

	host := ""
	var user *url.Userinfo
	switch {
	case strings.HasPrefix(rest, "//"):
		rest = rest[2:]
		end := strings.IndexAny(rest, "/?")
		if end < 0 {
			end = len(rest)
		}
		authority := rest[:end]
		rest = rest[end:]
		if at := strings.LastIndexByte(authority, '@'); at >= 0 {
			user = parseWireUserinfo(authority[:at])
			authority = authority[at+1:]
		}
		host = LenientDecodePath(authority)
	case scheme == "" && strings.HasPrefix(rest, "./"):
		// Undo the RFC 3986 §4.2 "./" guard WireURLString adds for a
		// hostless path whose first segment contains ':'.
		if segment, _, _ := strings.Cut(rest[2:], "/"); strings.Contains(segment, ":") {
			rest = rest[2:]
		}
	}

	wirePath, rawQuery, forceQuery := rest, "", false
	if i := strings.IndexByte(rest, '?'); i >= 0 {
		wirePath, rawQuery = rest[:i], rest[i+1:]
		forceQuery = rawQuery == ""
	}
	u := URLFromWirePath(scheme, host, wirePath, rawQuery)
	u.User = user
	u.ForceQuery = forceQuery
	return u
}

// schemeEnd returns the index of the ':' ending a leading RFC 3986 scheme
// in s, or -1 when s does not start with one.
func schemeEnd(s string) int {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'a' <= c && c <= 'z' || 'A' <= c && c <= 'Z':
		case '0' <= c && c <= '9' || c == '+' || c == '-' || c == '.':
			if i == 0 {
				return -1
			}
		case c == ':':
			if i == 0 {
				return -1
			}
			return i
		default:
			return -1
		}
	}
	return -1
}

func parseWireUserinfo(s string) *url.Userinfo {
	if name, pass, ok := strings.Cut(s, ":"); ok {
		return url.UserPassword(LenientDecodePath(name), LenientDecodePath(pass))
	}
	return url.User(LenientDecodePath(s))
}
