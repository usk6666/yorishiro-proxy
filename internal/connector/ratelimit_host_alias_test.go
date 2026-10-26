package connector

import (
	"context"
	"errors"
	"testing"
	"time"
)

// USK-1263: the per-host RateLimiter keys its buckets on the
// canonicalScopeHost form of the host, so a client cannot get a fresh
// bucket for an already-limited host by respelling it (trailing dot,
// IPv4-mapped IPv6, IPv6 text forms, zone, brackets, legacy IPv4). The
// fold is used for the map key only; callers, logs and denial tags keep
// the host as written.

// rateLimitHostAliases maps a canonical host to spellings of it that the
// per-host RateLimiter must count on the same bucket. Legacy IPv4
// spellings are included: the limiter is deny-like, so folding them can
// only make the limit stricter.
var rateLimitHostAliases = map[string][]string{
	"localhost":   {"localhost.", "LOCALHOST.", "LocalHost", "[localhost]"},
	"example.com": {"Example.COM.", "example.com."},
	"127.0.0.1": {
		"::ffff:127.0.0.1", "[::ffff:127.0.0.1]", "0:0::ffff:7f00:1", "::FFFF:7F00:1",
		"::ffff:127.0.0.1%lo", "127.0.0.1.", "[127.0.0.1]",
		"0x7f.0.0.1", "2130706433", "127.1", "0177.0.0.1",
	},
	"::1": {"0:0::1", "[::1]", "::1%lo", "::1%eth0", "0:0:0:0:0:0:0:1", "[0:0::1]"},
}

// rateLimitDistinctHosts pairs a host with a spelling that names a
// different destination and must keep its own bucket (negative controls
// against an over-broad fold).
var rateLimitDistinctHosts = [][2]string{
	{"localhost", "localhost.."},        // two trailing dots: not a resolvable name
	{"127.0.0.1", "::127.0.0.1"},        // IPv4-compatible: routed as IPv6
	{"::1", "::2"},                      // different address
	{"example.com", "a.example.com"},    // subdomain
	{"127.0.0.1", "127.0.0.2"},          // different address
	{"example.com", "example.com.evil"}, // different name
}

// newOneTokenPerHostLimiter returns a limiter whose per-host bucket holds a
// single token that does not refill within a test.
func newOneTokenPerHostLimiter() *RateLimiter {
	rl := NewRateLimiter()
	rl.SetPolicyLimits(RateLimitConfig{MaxRequestsPerHostPerSecond: 0.001})
	return rl
}

func TestRateLimiter_PerHostAliasesShareBucket(t *testing.T) {
	for canonical, aliases := range rateLimitHostAliases {
		for _, alias := range aliases {
			t.Run(canonical+"/"+alias, func(t *testing.T) {
				// Check then Check.
				rl := newOneTokenPerHostLimiter()
				if d := rl.Check(canonical); d != nil {
					t.Fatalf("Check(%q) first call denied: %+v", canonical, d)
				}
				if d := rl.Check(alias); d == nil || d.LimitType != "per_host" {
					t.Errorf("Check(%q) after Check(%q) = %+v, want per_host denial", alias, canonical, d)
				}

				// Alias first, then canonical: the fold is symmetric.
				rl = newOneTokenPerHostLimiter()
				if d := rl.Check(alias); d != nil {
					t.Fatalf("Check(%q) first call denied: %+v", alias, d)
				}
				if d := rl.Check(canonical); d == nil {
					t.Errorf("Check(%q) after Check(%q) allowed, want per_host denial", canonical, alias)
				}

				// Check then Wait: Wait must see the drained bucket.
				rl = newOneTokenPerHostLimiter()
				_ = rl.Check(canonical)
				ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
				defer cancel()
				if err := rl.Wait(ctx, alias); err == nil {
					t.Errorf("Wait(%q) after Check(%q) returned nil, want a wait error", alias, canonical)
				}

				// Wait then Check.
				rl = newOneTokenPerHostLimiter()
				if err := rl.Wait(context.Background(), canonical); err != nil {
					t.Fatalf("Wait(%q): %v", canonical, err)
				}
				if d := rl.Check(alias); d == nil {
					t.Errorf("Check(%q) after Wait(%q) allowed, want per_host denial", alias, canonical)
				}
			})
		}
	}
}

func TestRateLimiter_PerHostDistinctHostsKeepOwnBucket(t *testing.T) {
	for _, pair := range rateLimitDistinctHosts {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			rl := newOneTokenPerHostLimiter()
			_ = rl.Check(pair[0])
			if d := rl.Check(pair[1]); d != nil {
				t.Errorf("Check(%q) after Check(%q) = %+v, want allowed (distinct host)", pair[1], pair[0], d)
			}
		})
	}
}

// TestSOCKS5Negotiator_RateLimitHostAliases: a SOCKS5 domain spelling of
// an already rate-limited host lands on the same per-host bucket.
func TestSOCKS5Negotiator_RateLimitHostAliases(t *testing.T) {
	tests := []struct{ drained, domain string }{
		{"localhost", "localhost."},
		{"localhost", "LOCALHOST."},
		{"::1", "0:0::1"},
		{"127.0.0.1", "::ffff:127.0.0.1"},
	}
	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			neg := NewSOCKS5Negotiator(newTestLogger())
			rl := newOneTokenPerHostLimiter()
			_ = rl.Check(tt.drained)
			neg.RateLimiter = rl

			rig := newSOCKS5TestRig(t, neg)
			defer rig.closeAll()
			rig.start()

			go func() {
				rig.writeClient(buildMethodGreeting(socks5MethodNoAuth))
				rig.writeClient(buildConnectDomain(tt.domain, 443))
			}()

			_ = rig.readClient(2)
			reply := rig.readClient(10)
			if reply[1] != socks5ReplyConnectionNotAllowed {
				t.Errorf("reply REP = 0x%02x, want 0x02", reply[1])
			}
			rig.waitDone(2 * time.Second)
			if !errors.Is(rig.retErr, ErrSOCKS5BlockedByRateLimit) {
				t.Errorf("err = %v, want ErrSOCKS5BlockedByRateLimit", rig.retErr)
			}
		})
	}
}
