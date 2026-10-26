package connector

import (
	"bytes"
	"testing"
)

// TestRateLimitRefusalResponse_MatchesGates pins the exported 429 to the
// bytes the CONNECT gate and the transparent plain-HTTP route answer, so
// every live rate-limit gate (tcp_forwards included) answers in one shape.
func TestRateLimitRefusalResponse_MatchesGates(t *testing.T) {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerSecond: 0.001})
	cfg := CONNECTHandlerConfig{RateLimiter: rl}
	if got := connectPolicyReject(cfg, "burst.test:443", false, discardLogger()); got != nil {
		t.Fatalf("first CONNECT denied: %q", got)
	}
	connectBytes := connectPolicyReject(cfg, "burst.test:443", false, discardLogger())
	if connectBytes == nil {
		t.Fatal("second CONNECT admitted under a burst-1 limit")
	}

	got := RateLimitRefusalResponse()
	if !bytes.Equal(got, connectBytes) {
		t.Errorf("RateLimitRefusalResponse() = %q, want the CONNECT gate's %q", got, connectBytes)
	}
	if !bytes.Equal(got, transparentRateLimitResponse) {
		t.Errorf("RateLimitRefusalResponse() = %q, want the transparent route's %q", got, transparentRateLimitResponse)
	}
	if !bytes.HasPrefix(got, []byte("HTTP/1.1 429 Too Many Requests\r\n")) {
		t.Errorf("RateLimitRefusalResponse() = %q, want an HTTP/1.1 429 status line", got)
	}

	// Each call is a fresh slice: a caller mutating its copy must not
	// change what the next gate writes.
	if len(got) > 0 {
		got[0] = 'X'
		if again := RateLimitRefusalResponse(); len(again) == 0 || again[0] != 'H' {
			t.Errorf("RateLimitRefusalResponse() shares its backing array across calls")
		}
	}
}
