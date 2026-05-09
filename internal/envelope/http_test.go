package envelope

import "testing"

// TestHTTPMessage_CloneMessage_PropagatesProtocol pins that the new
// Protocol field (USK-764, RFC 8441 extended CONNECT) is copied through
// CloneMessage. Variant snapshotting in the pipeline relies on
// CloneMessage to produce a logically-equal but independent payload, so
// any field we add to HTTPMessage MUST be reflected here or we'll have
// silent loss when the modified variant is recorded.
func TestHTTPMessage_CloneMessage_PropagatesProtocol(t *testing.T) {
	m := &HTTPMessage{
		Method:          "CONNECT",
		Scheme:          "https",
		Authority:       "echo.example.com",
		Path:            "/chat",
		ConnectProtocol: "websocket",
	}
	cloned, ok := m.CloneMessage().(*HTTPMessage)
	if !ok {
		t.Fatalf("CloneMessage returned %T, want *HTTPMessage", m.CloneMessage())
	}
	if cloned.ConnectProtocol != "websocket" {
		t.Errorf("clone Protocol = %q, want websocket", cloned.ConnectProtocol)
	}
	// Mutating the clone must not mutate the source — independence check.
	cloned.ConnectProtocol = "webtransport"
	if m.ConnectProtocol != "websocket" {
		t.Errorf("source Protocol = %q after clone mutation; CloneMessage produced shared state", m.ConnectProtocol)
	}
}

// TestHTTPMessage_DefaultProtocol verifies that a freshly-zero HTTPMessage
// (the common case for HTTP/1.x and non-CONNECT HTTP/2) has Protocol="".
// This is the contract downstream session-layer code uses to detect that
// a stream is NOT extended CONNECT.
func TestHTTPMessage_DefaultProtocol(t *testing.T) {
	m := &HTTPMessage{Method: "GET", Path: "/"}
	if m.ConnectProtocol != "" {
		t.Errorf("default Protocol = %q, want empty", m.ConnectProtocol)
	}
	cloned := m.CloneMessage().(*HTTPMessage)
	if cloned.ConnectProtocol != "" {
		t.Errorf("clone of default Protocol = %q, want empty", cloned.ConnectProtocol)
	}
}

// TestHTTPVersionFromProto pins the canonical lowercased mapping from
// HTTP/1.x parser proto strings (USK-788). HTTP/1.0 and HTTP/1.1 are the
// only values the parser emits today; unknown values fall through
// unchanged so a future "HTTP/0.9" curiosity surfaces verbatim instead
// of silently masking.
func TestHTTPVersionFromProto(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "HTTP/1.0", want: HTTPVersion10},
		{in: "HTTP/1.1", want: HTTPVersion11},
		{in: "", want: ""},
		{in: "HTTP/0.9", want: "HTTP/0.9"},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := HTTPVersionFromProto(tc.in); got != tc.want {
				t.Errorf("HTTPVersionFromProto(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHTTPVersionFromH2Scheme pins the h2/h2c discrimination from the
// HTTP/2 Layer's stamped scheme (USK-788). The h2c handler in
// internal/connector/h2c_handler.go is the sole producer of "http"; a
// future "https" + h2c-via-ALPN scenario is forward-compat (resolves to
// h2 here, which matches the IANA tokens used by ALPN over TLS).
func TestHTTPVersionFromH2Scheme(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "https", want: HTTPVersionH2},
		{in: "http", want: HTTPVersionH2C},
		{in: "", want: HTTPVersionH2}, // safe default — HTTP/2 frames are scheme-agnostic
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := HTTPVersionFromH2Scheme(tc.in); got != tc.want {
				t.Errorf("HTTPVersionFromH2Scheme(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestHTTPMessage_CloneMessage_PropagatesHTTPVersion pins that
// HTTPVersion is carried through CloneMessage. RecordStep relies on
// CloneMessage to produce variant snapshots; if HTTPVersion is dropped
// in the clone, the recorded "modified" variant would lose the wire
// version even though the original kept it.
func TestHTTPMessage_CloneMessage_PropagatesHTTPVersion(t *testing.T) {
	cases := []string{HTTPVersion10, HTTPVersion11, HTTPVersionH2, HTTPVersionH2C, ""}
	for _, version := range cases {
		t.Run(version, func(t *testing.T) {
			m := &HTTPMessage{Method: "GET", HTTPVersion: version}
			cloned, ok := m.CloneMessage().(*HTTPMessage)
			if !ok {
				t.Fatalf("CloneMessage returned %T, want *HTTPMessage", m.CloneMessage())
			}
			if cloned.HTTPVersion != version {
				t.Errorf("clone HTTPVersion = %q, want %q", cloned.HTTPVersion, version)
			}
			cloned.HTTPVersion = "mutated"
			if m.HTTPVersion != version {
				t.Errorf("source HTTPVersion = %q after clone mutation; CloneMessage produced shared state", m.HTTPVersion)
			}
		})
	}
}
