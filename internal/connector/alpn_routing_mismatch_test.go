package connector

import "testing"

// TestClientALPNMatchesUpstream verifies the matcher used to decide whether
// to re-dial upstream after a client/upstream ALPN mismatch. Empty client
// ALPN (no offer / no overlap) folds to the http/1.1 route, matching empty
// or http/1.1 upstream ALPN — both collapse to the http1 route in alpnRoute.
func TestClientALPNMatchesUpstream(t *testing.T) {
	tests := []struct {
		name         string
		clientALPN   string
		upstreamALPN string
		want         bool
	}{
		{"both h2", "h2", "h2", true},
		{"both http/1.1", "http/1.1", "http/1.1", true},
		{"client empty, upstream http/1.1", "", "http/1.1", true},
		{"client http/1.1, upstream empty", "http/1.1", "", true},
		{"client empty, upstream empty", "", "", true},
		{"client h2, upstream http/1.1", "h2", "http/1.1", false},
		{"client http/1.1, upstream h2", "http/1.1", "h2", false},
		{"client empty, upstream h2", "", "h2", false},
		{"client h2, upstream empty", "h2", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clientALPNMatchesUpstream(tt.clientALPN, tt.upstreamALPN)
			if got != tt.want {
				t.Errorf("clientALPNMatchesUpstream(%q, %q) = %v, want %v",
					tt.clientALPN, tt.upstreamALPN, got, tt.want)
			}
		})
	}
}

// TestCanonicalRedialALPNOffer verifies the redial offer encoding. An empty
// client ALPN (the curl --http1.1 against an h2-only-advertising proxy
// fallback case) must collapse to ["http/1.1"] so the upstream redial
// negotiates a route the proxy can serve.
func TestCanonicalRedialALPNOffer(t *testing.T) {
	tests := []struct {
		name       string
		clientALPN string
		want       []string
	}{
		{"empty → http/1.1", "", []string{"http/1.1"}},
		{"h2 → h2", "h2", []string{"h2"}},
		{"http/1.1 → http/1.1", "http/1.1", []string{"http/1.1"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalRedialALPNOffer(tt.clientALPN)
			if len(got) != len(tt.want) {
				t.Fatalf("len(offers) = %d, want %d (got %v)", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("offers[%d] = %q, want %q (got %v)", i, got[i], tt.want[i], got)
				}
			}
		})
	}
}
