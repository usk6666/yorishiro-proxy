package pipeline

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// recordingNameResolver answers name-binding lookups from a table and
// records every name it was asked for.
type recordingNameResolver struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	asked   []string
}

func (r *recordingNameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.asked = append(r.asked, host)
	return r.answers[host], nil
}

func (r *recordingNameResolver) lookedUp() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asked...)
}

// USK-1316: on a transparent connection admitted by a name, the DNS
// binding lookup runs only on names the scope already admitted. A name
// the scope refuses (here an absolute-form authority outside the allow
// list) must never be resolved: the lookup itself would leak
// attacker-chosen data to DNS.
func TestHTTPScopeStep_Transparent_RefusedNameNotLookedUp(t *testing.T) {
	const target = "192.0.2.10:80"
	dst := netip.MustParseAddrPort(target)
	r := &recordingNameResolver{answers: map[string][]netip.Addr{
		"allowed.example.com": {dst.Addr()},
	}}
	ctx := connector.ContextWithTransparentScope(context.Background(), &connector.TransparentScope{
		Dst:    dst,
		Binder: connector.NewNameBindingCache(r, connector.NameBindingConfig{}),
	})
	step := NewHTTPScopeStep(hostLegScope([]connector.TargetRule{{Hostname: "allowed.example.com"}}, nil))

	t.Run("refused absolute-form authority", func(t *testing.T) {
		env := realH1RequestEnvelopeWithContext(t, "http", envelope.EnvelopeContext{TargetHost: target},
			"GET http://leak.attacker.example/ HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
		res := step.Process(ctx, env)
		if res.Action != Respond || res.BlockedBy != BlockedByTargetScope {
			t.Fatalf("Action=%v BlockedBy=%q, want Respond / %q", res.Action, res.BlockedBy, BlockedByTargetScope)
		}
		for _, n := range r.lookedUp() {
			if n == "leak.attacker.example" {
				t.Fatalf("refused name was resolved (lookups %q)", r.lookedUp())
			}
		}
	})
	t.Run("allowed and bound name still admitted", func(t *testing.T) {
		env := realH1RequestEnvelopeWithContext(t, "http", envelope.EnvelopeContext{TargetHost: target},
			"GET / HTTP/1.1\r\nHost: allowed.example.com\r\n\r\n")
		if res := step.Process(ctx, env); res.Action != Continue {
			t.Fatalf("Action=%v, want Continue", res.Action)
		}
	})
}
