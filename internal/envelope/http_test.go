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
