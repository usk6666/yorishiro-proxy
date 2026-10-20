package mcp

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
)

// USK-1304 / USK-1306 (review S-1): the WebSocket upgrade request's Host
// header is always plan.upgradeURL.Host (buildResendWSUpgradeHeaders), so
// resend_ws and fuzz_ws (base plan and every variant) must check it as a
// name leg against the dial address — the dial port joins a port-scoped
// deny, and every comma-separated part is deny-checked — exactly as
// resend_http does for its Host / authority.

type wsNameLegCase struct {
	name      string
	allows    []connector.TargetRule
	denies    []connector.TargetRule
	authority string
	dialAddr  string
	wantErr   bool
}

func wsNameLegCases() []wsNameLegCase {
	// Deny-only scopes: with an allow list the canonical upgrade-URL leg
	// (full CheckTarget) already demands the authority be allow-listed,
	// so only the deny side is new here.
	portDeny := []connector.TargetRule{{Hostname: "portd.example", Ports: []int{80}}}
	deny := []connector.TargetRule{{Hostname: "denied.example"}}
	return []wsNameLegCase{
		{name: "dial port matches a port-scoped deny", denies: portDeny, authority: "portd.example:8080", dialAddr: "203.0.113.5:80", wantErr: true},
		{name: "comma Host with a denied part", denies: deny, authority: "ok.example,denied.example", dialAddr: "203.0.113.5:80", wantErr: true},
		{name: "comma Host with a denied first part", denies: deny, authority: "denied.example,ok.example", dialAddr: "203.0.113.5:80", wantErr: true},
		{name: "guard: non-denied comma Host passes", denies: deny, authority: "a.example,b.example", dialAddr: "203.0.113.5:80"},
		{name: "guard: neither port matches", denies: portDeny, authority: "portd.example:8080", dialAddr: "203.0.113.5:8080"},
		{name: "guard: IP authority on an IP-literal allow passes", allows: []connector.TargetRule{{Hostname: "203.0.113.5"}}, denies: deny, authority: "203.0.113.5", dialAddr: "203.0.113.5:80"},
	}
}

func wsNameLegPlan(authority, dialAddr string) *resendWSPlan {
	return &resendWSPlan{
		upgradeURL: &url.URL{Scheme: "http", Host: authority, Path: "/chat"},
		dialAddr:   dialAddr,
	}
}

func TestCheckResendWSScope_HostNameLeg(t *testing.T) {
	for _, tc := range wsNameLegCases() {
		t.Run(tc.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{targetScope: newScopeWithRules(t, tc.allows, tc.denies, nil, nil)})
			err := s.checkResendWSScope(wsNameLegPlan(tc.authority, tc.dialAddr))
			if (err != nil) != tc.wantErr {
				t.Fatalf("checkResendWSScope(Host %q, dial %q) = %v, wantErr %v", tc.authority, tc.dialAddr, err, tc.wantErr)
			}
		})
	}
}

// The fuzz_ws base plan, through the real plan builder: the authority is
// recovered from the recorded upgrade flow and target_addr redirects the
// dial.
func TestBuildFuzzWSPlan_HostNameLeg(t *testing.T) {
	for _, tc := range wsNameLegCases() {
		t.Run(tc.name, func(t *testing.T) {
			store := newTestStore(t)
			flowID := saveWSUpgradeFlow(t, store, "ws://"+tc.authority+"/chat")
			s := mkServerFromLegacyDeps(legacyDeps{
				store:       store,
				targetScope: newScopeWithRules(t, tc.allows, tc.denies, nil, nil),
			})
			input := &fuzzWSInput{
				FlowID:     flowID,
				TargetAddr: tc.dialAddr,
				Opcode:     "text",
				Payload:    "hi",
				Positions:  []fuzzWSPosition{{Path: "payload", Payloads: []string{"a"}}},
			}
			_, err := s.buildFuzzWSPlan(context.Background(), input)
			if (err != nil) != tc.wantErr {
				t.Fatalf("buildFuzzWSPlan(Host %q, dial %q) = %v, wantErr %v", tc.authority, tc.dialAddr, err, tc.wantErr)
			}
			if err != nil && !strings.Contains(err.Error(), "target scope") {
				t.Errorf("error = %v, want a target scope block", err)
			}
		})
	}
}

// The fuzz_ws per-variant re-check: a blocked variant is recorded with
// row.Error before any dial (the pipeline is never reached).
func TestRunFuzzWSSingleVariant_HostNameLeg(t *testing.T) {
	for _, tc := range wsNameLegCases() {
		if !tc.wantErr {
			continue // a passing variant would dial; the guards run above
		}
		t.Run(tc.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{targetScope: newScopeWithRules(t, tc.allows, tc.denies, nil, nil)})
			plan := &fuzzWSPlan{base: wsNameLegPlan(tc.authority, tc.dialAddr)}
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("variant passed the scope check and reached the pipeline (Host %q, dial %q): %v", tc.authority, tc.dialAddr, r)
				}
			}()
			row, _, err := s.runFuzzWSSingleVariant(context.Background(), plan, nil, time.Second, 0, map[string]string{}, "")
			if err != nil {
				t.Fatalf("runFuzzWSSingleVariant: %v", err)
			}
			if !strings.Contains(row.Error, "target scope") {
				t.Fatalf("row.Error = %q, want a target scope block for Host %q, dial %q", row.Error, tc.authority, tc.dialAddr)
			}
		})
	}
}
