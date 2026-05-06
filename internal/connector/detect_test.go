package connector

import (
	"sync"
	"testing"
)

func TestDetectKind(t *testing.T) {
	tests := []struct {
		name string
		peek []byte
		want ProtocolKind
	}{
		{"empty", []byte{}, ProtocolUnknown},
		{"nil", nil, ProtocolUnknown},

		// SOCKS5: single 0x05 byte.
		{"socks5 single byte", []byte{0x05}, ProtocolSOCKS5},
		{"socks5 with greeting", []byte{0x05, 0x02, 0x00, 0x02}, ProtocolSOCKS5},

		// CONNECT: requires exact prefix with trailing space.
		{"http connect", []byte("CONNECT example.com:443"), ProtocolHTTPConnect},
		{"http connect full", []byte("CONNECT example.com:443 HTTP/1.1\r\n"), ProtocolHTTPConnect},
		{"http connected (negative)", []byte("CONNECTED "), ProtocolTCP},

		// HTTP methods: known methods with trailing space.
		{"get", []byte("GET / HTTP/1.1"), ProtocolHTTP1},
		{"post", []byte("POST /api/x HT"), ProtocolHTTP1},
		{"put", []byte("PUT /foo HTTP/1"), ProtocolHTTP1},
		{"delete", []byte("DELETE /x HTTP/"), ProtocolHTTP1},
		{"head", []byte("HEAD /x HTTP/1.1"), ProtocolHTTP1},
		{"options", []byte("OPTIONS * HTTP/1.1"), ProtocolHTTP1},
		{"patch", []byte("PATCH /x HTTP/1."), ProtocolHTTP1},
		{"trace", []byte("TRACE /x HTTP/1.1"), ProtocolHTTP1},

		// Short HTTP method read that is still consistent — allowed by
		// stage 1 so the listener retries in stage 2.
		{"short get", []byte("GE"), ProtocolHTTP1},
		{"short post", []byte("POS"), ProtocolHTTP1},

		// Unknown method should fall through to TCP.
		{"unknown method", []byte("BREW / HTTP/1.1"), ProtocolTCP},

		// h2c connection preface.
		{"h2c preface", []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"), ProtocolHTTP2},
		{"h2c first 8", []byte("PRI * HT"), ProtocolHTTP2},
		{"h2c short 7", []byte("PRI * H"), ProtocolTCP}, // not enough bytes

		// Raw TCP fall-through.
		{"binary", []byte{0xFF, 0xFE, 0xFD, 0x00}, ProtocolTCP},
		{"single letter", []byte{'A'}, ProtocolTCP},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := DetectKind(tt.peek)
			if got != tt.want {
				t.Errorf("DetectKind(%q) = %v, want %v", tt.peek, got, tt.want)
			}
		})
	}
}

// TestProtocolKind_UserName covers the user-facing-name mapping used by
// the EnabledProtocols allow-list (USK-732). HTTPS is the load-bearing
// case: ProtocolHTTPConnect (the listener-level kind for "CONNECT host:port"
// requests) maps to "HTTPS" because that is the user-visible protocol of
// the resulting tunnel. Kinds without a user-facing equivalent return "".
func TestProtocolKind_UserName(t *testing.T) {
	tests := []struct {
		name string
		kind ProtocolKind
		want string
	}{
		{"socks5", ProtocolSOCKS5, "SOCKS5"},
		{"http_connect_maps_to_https", ProtocolHTTPConnect, "HTTPS"},
		{"http1", ProtocolHTTP1, "HTTP/1.x"},
		{"http2_h2c", ProtocolHTTP2, "HTTP/2"},
		{"tcp", ProtocolTCP, "TCP"},
		{"unknown_returns_empty", ProtocolUnknown, ""},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := tt.kind.UserName()
			if got != tt.want {
				t.Errorf("ProtocolKind(%v).UserName() = %q, want %q",
					tt.kind, got, tt.want)
			}
		})
	}
}

// TestKindMatchesEnabledNames covers the allow-list matching used by the
// FullListener detection path (USK-732). The matrix verifies:
//   - canonical name match (e.g. ProtocolHTTP1 vs "HTTP/1.x")
//   - cross-name miss (HTTP/2 detected but only HTTP/1.x enabled)
//   - HTTPS-tunnel inner-protocol precondition: when the operator enables
//     "HTTP/2" / "WebSocket" / "gRPC", ProtocolHTTPConnect is accepted at
//     the listener so the post-CONNECT ALPN can deliver the requested
//     inner protocol
//   - empty allow-list never matches (the caller is expected to short-
//     circuit before invoking this function, but defence-in-depth)
//   - ProtocolUnknown never matches (no canonical UserName)
func TestKindMatchesEnabledNames(t *testing.T) {
	tests := []struct {
		name  string
		kind  ProtocolKind
		names []string
		want  bool
	}{
		// Canonical match.
		{"http1_canonical", ProtocolHTTP1, []string{"HTTP/1.x"}, true},
		{"https_canonical", ProtocolHTTPConnect, []string{"HTTPS"}, true},
		{"http2_canonical", ProtocolHTTP2, []string{"HTTP/2"}, true},
		{"socks5_canonical", ProtocolSOCKS5, []string{"SOCKS5"}, true},
		{"tcp_canonical", ProtocolTCP, []string{"TCP"}, true},

		// Cross-name miss.
		{"http2_not_enabled_when_only_http1", ProtocolHTTP2, []string{"HTTP/1.x"}, false},
		{"http1_not_enabled_when_only_http2", ProtocolHTTP1, []string{"HTTP/2"}, false},
		{"socks5_not_enabled_when_only_http1", ProtocolSOCKS5, []string{"HTTP/1.x"}, false},
		{"tcp_not_enabled_when_only_https", ProtocolTCP, []string{"HTTPS"}, false},

		// Inner-protocol precondition: enabling HTTP/2 (which usually
		// rides on TLS) implies HTTPS at the listener layer.
		{"https_accepted_when_http2_enabled", ProtocolHTTPConnect, []string{"HTTP/2"}, true},
		{"https_accepted_when_websocket_enabled", ProtocolHTTPConnect, []string{"WebSocket"}, true},
		{"https_accepted_when_grpc_enabled", ProtocolHTTPConnect, []string{"gRPC"}, true},

		// Inner-protocol precondition does NOT leak to other kinds: only
		// ProtocolHTTPConnect (the listener-level CONNECT) is the
		// pre-requisite for tunneled protocols. Plain h2c is its own
		// kind.
		{"http2_h2c_not_enabled_by_websocket", ProtocolHTTP2, []string{"WebSocket"}, false},
		{"socks5_not_enabled_by_grpc", ProtocolSOCKS5, []string{"gRPC"}, false},

		// Names not on the proxy_start accept-list ("gRPC-Web", "SSE")
		// are inert — they neither match nor enable HTTPS as a
		// pre-requisite (USK-732 review F-3).
		{"https_not_enabled_by_grpcweb_dead_branch", ProtocolHTTPConnect, []string{"gRPC-Web"}, false},
		{"https_not_enabled_by_sse_dead_branch", ProtocolHTTPConnect, []string{"SSE"}, false},

		// Multiple names; first-match-wins iteration but order shouldn't
		// matter for equivalent positive matches.
		{"http1_in_multi_set", ProtocolHTTP1, []string{"HTTPS", "HTTP/1.x", "TCP"}, true},
		{"https_via_inner_proto_in_multi_set", ProtocolHTTPConnect, []string{"HTTP/1.x", "TCP", "gRPC"}, true},

		// Empty allow-list never matches (FullListener short-circuits
		// before reaching this function, but the helper itself must be
		// safe for direct use).
		{"empty_names_no_match", ProtocolHTTP1, nil, false},
		{"empty_slice_no_match", ProtocolHTTP1, []string{}, false},

		// ProtocolUnknown has no canonical UserName; never matches.
		{"unknown_never_matches", ProtocolUnknown, []string{"HTTP/1.x", "HTTPS"}, false},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			got := kindMatchesEnabledNames(tt.kind, tt.names)
			if got != tt.want {
				t.Errorf("kindMatchesEnabledNames(%v, %v) = %v, want %v",
					tt.kind, tt.names, got, tt.want)
			}
		})
	}
}

// TestFullListener_EnabledProtocols_RoundTrip verifies the
// SetEnabledProtocols / EnabledProtocols pair preserves contents,
// returns nil for the "no filter" zero state, makes a defensive copy
// (callers cannot mutate the stored slice via the input or output), and
// resets to the no-filter state when given nil or an empty slice.
// USK-732 wiring; F-2 review.
func TestFullListener_EnabledProtocols_RoundTrip(t *testing.T) {
	fl := NewFullListener(FullListenerConfig{Addr: "127.0.0.1:0"})

	if got := fl.EnabledProtocols(); got != nil {
		t.Fatalf("zero state EnabledProtocols() = %v, want nil", got)
	}

	in := []string{"HTTP/1.x", "HTTPS"}
	fl.SetEnabledProtocols(in)
	got := fl.EnabledProtocols()
	if len(got) != 2 || got[0] != "HTTP/1.x" || got[1] != "HTTPS" {
		t.Fatalf("after Set: EnabledProtocols() = %v, want [HTTP/1.x HTTPS]", got)
	}

	// Defensive-copy on input: mutating the caller's input must not
	// affect the listener's stored allow-list.
	in[0] = "MUTATED"
	got = fl.EnabledProtocols()
	if got[0] != "HTTP/1.x" {
		t.Errorf("input mutation leaked into stored allow-list: got %v", got)
	}

	// Defensive-copy on output: mutating the returned snapshot must not
	// affect the listener's stored allow-list.
	got[0] = "ALSO_MUTATED"
	got2 := fl.EnabledProtocols()
	if got2[0] != "HTTP/1.x" {
		t.Errorf("output mutation leaked into stored allow-list: got %v", got2)
	}

	// Reset paths.
	fl.SetEnabledProtocols(nil)
	if got := fl.EnabledProtocols(); got != nil {
		t.Errorf("after Set(nil): EnabledProtocols() = %v, want nil", got)
	}
	fl.SetEnabledProtocols([]string{"HTTP/2"})
	fl.SetEnabledProtocols([]string{})
	if got := fl.EnabledProtocols(); got != nil {
		t.Errorf("after Set(empty slice): EnabledProtocols() = %v, want nil", got)
	}
}

// TestFullListener_EnabledProtocols_ConcurrentAccess is a smoke test for
// the atomic.Pointer-based round-trip: many goroutines Set and Get
// concurrently. Run under -race; the test passes if there is no data
// race and EnabledProtocols always returns a self-consistent snapshot
// (i.e. one of the slices that was Set, never a torn intermediate).
func TestFullListener_EnabledProtocols_ConcurrentAccess(t *testing.T) {
	fl := NewFullListener(FullListenerConfig{Addr: "127.0.0.1:0"})
	const goroutines = 8
	const iterations = 200

	candidates := [][]string{
		{"HTTP/1.x"},
		{"HTTPS", "HTTP/2"},
		{"SOCKS5", "TCP"},
		nil,
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				if (i+seed)%2 == 0 {
					fl.SetEnabledProtocols(candidates[(i+seed)%len(candidates)])
					continue
				}
				snap := fl.EnabledProtocols()
				// Self-consistency check: a returned snapshot must
				// either be nil or equal one of the candidates we
				// ever Set.
				if snap == nil {
					continue
				}
				match := false
				for _, c := range candidates {
					if len(c) != len(snap) {
						continue
					}
					eq := true
					for j := range c {
						if c[j] != snap[j] {
							eq = false
							break
						}
					}
					if eq {
						match = true
						break
					}
				}
				if !match {
					t.Errorf("torn snapshot observed: %v not in candidate set", snap)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
