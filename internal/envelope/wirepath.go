package envelope

import "net/url"

// LenientDecodePath decodes every valid %XX escape in s and leaves any
// invalid '%' sequence literal. Not yet implemented (USK-1139 red commit).
func LenientDecodePath(s string) string { return s }

// URLFromWirePath builds a *url.URL from a wire-form request path.
// Not yet implemented (USK-1139 red commit): mirrors the pre-fix projection.
func URLFromWirePath(scheme, host, wirePath, rawQuery string) *url.URL {
	return &url.URL{Scheme: scheme, Host: host, Path: wirePath, RawQuery: rawQuery}
}

// WirePath returns the wire-form request path of u.
// Not yet implemented (USK-1139 red commit): mirrors the pre-fix readers.
func WirePath(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.Path
}

// WireURLString serializes u with its wire-form path.
// Not yet implemented (USK-1139 red commit): mirrors the pre-fix writers.
func WireURLString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// ParseWireURL parses a string produced by WireURLString.
// Not yet implemented (USK-1139 red commit): mirrors the pre-fix readers.
func ParseWireURL(s string) *url.URL {
	u, err := url.Parse(s)
	if err != nil {
		return nil
	}
	return u
}
