package mcp

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// USK-1061 regression suite.
//
// Every MCP resend / fuzz tool checks its dial target against TargetScope
// twice: once on the canonical URL it reconstructed, and once on the
// override address when target_addr / override_host redirects the dial. The
// override leg used to be handed an empty scheme whenever the dial was not
// TLS, and connector.matchTargetRule is AND logic — `len(rule.Schemes) > 0 &&
// !containsStringFold(rule.Schemes, scheme)` — so a blank scheme silently
// stopped matching every rule that carried a `schemes` condition.
//
// That breaks the engine in BOTH directions, which is why each helper gets a
// deny case and an allow case here:
//
//   - a deny rule that stops matching is a BYPASS: CheckTarget falls through
//     to the allow check, and with no allow rules configured the target is
//     ALLOWED (cloud metadata at 169.254.169.254 being the canonical target);
//   - an allow rule that stops matching is a FALSE BLOCK: a legitimate
//     plaintext resend is rejected with "not in policy allow list".
//
// Every deny case below redirects to a host that appears in no rule on the
// canonical leg, so a canonical-leg block cannot mask an override-leg
// failure — the assertion can only be satisfied by the override leg
// actually matching.

// scopeSchemeCase drives one real scope helper against one real
// *connector.TargetScope. run receives the assembled *Server so each case
// exercises the production code path rather than a reconstruction of it.
type scopeSchemeCase struct {
	name         string
	policyAllows []connector.TargetRule
	policyDenies []connector.TargetRule
	agentAllows  []connector.TargetRule
	agentDenies  []connector.TargetRule
	run          func(t *testing.T, s *Server) error
	wantErr      bool
	// wantErrContains is checked only when wantErr is true.
	wantErrContains string
}

// metadataDenyHTTP is the classic SSRF target, denied on the plaintext
// transport only. A rule written this way must block a plaintext dial.
func metadataDenyHTTP() []connector.TargetRule {
	return []connector.TargetRule{{Hostname: "169.254.169.254", Schemes: []string{"http"}}}
}

// plaintextAllowPair permits the canonical authority and a separate
// redirect target, both on the plaintext transport only. A legitimate
// plaintext resend to either must not be blocked.
func plaintextAllowPair() []connector.TargetRule {
	return []connector.TargetRule{
		{Hostname: "example.com", Schemes: []string{"http"}},
		{Hostname: "10.0.0.5", Schemes: []string{"http"}},
	}
}

func TestResendScopeScheme_NonTLSDialMatchesSchemeConditionedRules(t *testing.T) {
	cases := []scopeSchemeCase{
		// --- resend_raw -------------------------------------------------
		{
			name:        "raw/deny_plaintext_metadata_dial",
			agentDenies: metadataDenyHTTP(),
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendRawScope(&resendRawPlan{
					useTLS:   false,
					dialAddr: "169.254.169.254:80",
				})
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			name:         "raw/allow_plaintext_internal_dial",
			policyAllows: []connector.TargetRule{{Hostname: "internal.example", Schemes: []string{"http"}}},
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendRawScope(&resendRawPlan{
					useTLS:   false,
					dialAddr: "internal.example:8080",
				})
			},
		},
		{
			// TLS side of the same helper: unchanged behaviour, and a
			// guard that the http/https mapping did not get inverted.
			name:        "raw/deny_tls_dial_still_matches_https_rule",
			agentDenies: []connector.TargetRule{{Hostname: "169.254.169.254", Schemes: []string{"https"}}},
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendRawScope(&resendRawPlan{
					useTLS:   true,
					dialAddr: "169.254.169.254:443",
				})
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			// An https-only deny must NOT catch a plaintext dial. Pins the
			// "schemes narrows in both directions" semantic documented in
			// RFC-001 §3.8 — the fix must not collapse into "match all".
			name:        "raw/https_only_deny_does_not_catch_plaintext_dial",
			agentDenies: []connector.TargetRule{{Hostname: "169.254.169.254", Schemes: []string{"https"}}},
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendRawScope(&resendRawPlan{
					useTLS:   false,
					dialAddr: "169.254.169.254:80",
				})
			},
		},

		// --- resend_ws --------------------------------------------------
		{
			name:        "ws/deny_plaintext_metadata_redirect",
			agentDenies: metadataDenyHTTP(),
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendWSScope(&resendWSPlan{
					useTLS:     false,
					upgradeURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
					dialAddr:   "169.254.169.254:80",
				})
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			name:         "ws/allow_plaintext_redirect",
			policyAllows: plaintextAllowPair(),
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendWSScope(&resendWSPlan{
					useTLS:     false,
					upgradeURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/"},
					dialAddr:   "10.0.0.5:80",
				})
			},
		},

		// --- resend_grpc ------------------------------------------------
		{
			name:        "grpc/deny_plaintext_metadata_redirect",
			agentDenies: metadataDenyHTTP(),
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendGRPCScope(&resendGRPCPlan{
					scheme:       "http",
					useTLS:       false,
					canonicalURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/pkg.Svc/M"},
					dialAddr:     "169.254.169.254:80",
				})
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			name:         "grpc/allow_plaintext_redirect",
			policyAllows: plaintextAllowPair(),
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendGRPCScope(&resendGRPCPlan{
					scheme:       "http",
					useTLS:       false,
					canonicalURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/pkg.Svc/M"},
					dialAddr:     "10.0.0.5:80",
				})
			},
		},
		{
			// USK-1056 divergence case, and the pin for Resolved #9.
			//
			// applyResendGRPCDialGroundTruth may upgrade the dial to TLS
			// (useTLS=true) while plan.scheme deliberately stays at the
			// recorded ":scheme: http" — wire fidelity on the resent HEADERS
			// frame. The scope check must follow plan.scheme, the value the
			// canonical leg already matched on and the value test_target and
			// the recorded flow both show. Reading plan.useTLS here would be
			// "deriving scheme from useTLS", which USK-1056's acceptance
			// criteria forbid; this case fails again if anyone switches back.
			name:        "grpc/override_leg_follows_plan_scheme_not_useTLS",
			agentDenies: []connector.TargetRule{{Hostname: "10.0.0.5", Schemes: []string{"http"}}},
			run: func(_ *testing.T, s *Server) error {
				return s.checkResendGRPCScope(&resendGRPCPlan{
					scheme:       "http",
					useTLS:       true, // observed-transport upgrade
					canonicalURL: &url.URL{Scheme: "http", Host: "example.com", Path: "/pkg.Svc/M"},
					dialAddr:     "10.0.0.5:443",
				})
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},

		// --- resend_http ------------------------------------------------
		{
			name:        "http/deny_plaintext_metadata_override_host",
			agentDenies: metadataDenyHTTP(),
			run: func(_ *testing.T, s *Server) error {
				msg := &envelope.HTTPMessage{
					Method:    "GET",
					Scheme:    "http",
					Authority: "example.com",
					Path:      "/",
				}
				return s.checkResendHTTPScope(msg, "169.254.169.254:80", "169.254.169.254:80")
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			name:         "http/allow_plaintext_override_host",
			policyAllows: plaintextAllowPair(),
			run: func(_ *testing.T, s *Server) error {
				msg := &envelope.HTTPMessage{
					Method:    "GET",
					Scheme:    "http",
					Authority: "example.com",
					Path:      "/",
				}
				return s.checkResendHTTPScope(msg, "10.0.0.5:80", "10.0.0.5:80")
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{
				targetScope: newScopeWithRules(t, tc.policyAllows, tc.policyDenies, tc.agentAllows, tc.agentDenies),
			})
			err := tc.run(t, s)
			assertScopeVerdict(t, err, tc.wantErr, tc.wantErrContains)
		})
	}
}

// TestBuildFuzzRawPlan_NonTLSDialMatchesSchemeConditionedRules drives the
// real fuzz_raw plan builder rather than resend_raw's helper.
//
// fuzz_raw is the only one of the four fuzz tools that does not reuse its
// resend sibling's scope helper — it carried an inline copy of the body,
// free to drift from the original. Exercising it independently means the
// duplicate is pinned even while it is a duplicate; the fix routes both
// through checkRawDialScope, and this test is what would catch a future
// re-divergence.
//
// override_bytes supplies the base payload so the builder needs no flow
// store, and positions are left empty (the builder only multiplies them into
// totalVariants; shape validation lives in validateFuzzRawInput).
func TestBuildFuzzRawPlan_NonTLSDialMatchesSchemeConditionedRules(t *testing.T) {
	cases := []scopeSchemeCase{
		{
			name:        "deny_plaintext_metadata_dial",
			agentDenies: metadataDenyHTTP(),
			run: func(_ *testing.T, s *Server) error {
				_, err := s.buildFuzzRawPlan(context.Background(), &fuzzRawInput{
					TargetAddr:    "169.254.169.254:80",
					UseTLS:        false,
					OverrideBytes: "x",
				})
				return err
			},
			wantErr:         true,
			wantErrContains: "blocked by agent deny rule",
		},
		{
			name:         "allow_plaintext_internal_dial",
			policyAllows: []connector.TargetRule{{Hostname: "internal.example", Schemes: []string{"http"}}},
			run: func(_ *testing.T, s *Server) error {
				_, err := s.buildFuzzRawPlan(context.Background(), &fuzzRawInput{
					TargetAddr:    "internal.example:8080",
					UseTLS:        false,
					OverrideBytes: "x",
				})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := mkServerFromLegacyDeps(legacyDeps{
				targetScope: newScopeWithRules(t, tc.policyAllows, tc.policyDenies, tc.agentAllows, tc.agentDenies),
			})
			err := tc.run(t, s)
			assertScopeVerdict(t, err, tc.wantErr, tc.wantErrContains)
		})
	}
}

// TestValidateResendSchemeAllowlist_CoversFlowIDPath pins Part D2.
//
// resend_http and resend_ws both kept their scheme allowlist inside the
// from-scratch validator, which runs only when flow_id is empty. With a
// flow_id the agent-supplied scheme got a CR/LF guard and nothing else — yet
// it still won over the recovered value (mergeResendWSURL and
// buildResendHTTPEnvelopeWithMeta both fall back to the recorded scheme only
// when the user value is empty). Hoisting the allowlist into the
// unconditional validator applies the USK-1051 precedent that resend_grpc
// has had since validateResendGRPCStringFields.
//
// The negative-control rows are load-bearing: they prove the hoisted check
// is not over-broad, i.e. that it rejects the unsupported value rather than
// rejecting the flow_id path as a whole.
func TestValidateResendSchemeAllowlist_CoversFlowIDPath(t *testing.T) {
	wsCases := []struct {
		name    string
		input   resendWSInput
		wantErr bool
	}{
		{
			// Drives the exact CWE-319 shape: useTLS is derived as
			// scheme == "wss", so "https" dials PLAINTEXT while
			// resendWSUpgradeURL passes "https" through to the scope check.
			name:    "flow_id_path_rejects_https",
			input:   resendWSInput{FlowID: "f", Scheme: "https", Opcode: "text"},
			wantErr: true,
		},
		{
			name:    "flow_id_path_rejects_gopher",
			input:   resendWSInput{FlowID: "f", Scheme: "gopher", Opcode: "text"},
			wantErr: true,
		},
		{
			name:  "negative_control_flow_id_path_accepts_wss",
			input: resendWSInput{FlowID: "f", Scheme: "wss", Opcode: "text"},
		},
		{
			name:  "negative_control_flow_id_path_accepts_ws",
			input: resendWSInput{FlowID: "f", Scheme: "ws", Opcode: "text"},
		},
		{
			name:  "negative_control_flow_id_path_accepts_empty_scheme",
			input: resendWSInput{FlowID: "f", Opcode: "text"},
		},
		{
			name:  "negative_control_from_scratch_still_accepts_wss",
			input: resendWSInput{TargetAddr: "example.com:443", Path: "/ws", Scheme: "wss", Opcode: "text"},
		},
	}
	for _, tc := range wsCases {
		t.Run("ws/"+tc.name, func(t *testing.T) {
			in := tc.input
			err := validateResendWSInput(&in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateResendWSInput(%+v) = nil, want an error", tc.input)
				}
				if !strings.Contains(err.Error(), "only ws and wss are allowed") {
					t.Errorf("error = %v, want the ws/wss allowlist message", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateResendWSInput(%+v) = %v, want nil", tc.input, err)
			}
		})
	}

	httpCases := []struct {
		name    string
		input   resendHTTPInput
		wantErr bool
	}{
		{
			name:    "flow_id_path_rejects_gopher",
			input:   resendHTTPInput{FlowID: "f", Scheme: "gopher", Authority: "169.254.169.254:80"},
			wantErr: true,
		},
		{
			name:  "negative_control_flow_id_path_accepts_https",
			input: resendHTTPInput{FlowID: "f", Scheme: "https"},
		},
		{
			name:  "negative_control_flow_id_path_accepts_http",
			input: resendHTTPInput{FlowID: "f", Scheme: "http"},
		},
		{
			name:  "negative_control_flow_id_path_accepts_empty_scheme",
			input: resendHTTPInput{FlowID: "f"},
		},
		{
			name:  "negative_control_from_scratch_still_accepts_https",
			input: resendHTTPInput{Method: "GET", Scheme: "https", Authority: "example.com", Path: "/"},
		},
	}
	for _, tc := range httpCases {
		t.Run("http/"+tc.name, func(t *testing.T) {
			in := tc.input
			err := validateResendHTTPInput(&in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("validateResendHTTPInput(%+v) = nil, want an error", tc.input)
				}
				if !strings.Contains(err.Error(), "only http and https are allowed") {
					t.Errorf("error = %v, want the http/https allowlist message", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("validateResendHTTPInput(%+v) = %v, want nil", tc.input, err)
			}
		})
	}
}

// TestBuildResendWSPlan_SchemeHTTPS_DecouplesDialFromScopeCheck shows why the
// D2 allowlist hoist is the fix rather than a defensive tweak, by driving the
// real plan builder and the real scope helper against a real recorded flow.
//
// The validator is the only gate: buildResendWSPlan itself cannot recover
// from `scheme: "https"`, because the value feeds two consumers that then
// disagree —
//
//	plan.useTLS      = scheme == "wss"   -> false  (the dial is PLAINTEXT)
//	upgradeURL.Scheme: resendWSUpgradeURL maps only ws/wss, so "https"
//	                   falls through its switch unchanged -> "https"
//
// and because the recorded authority already carries :80, dialAddr equals
// upgradeURL.Host and the override leg is skipped entirely. The scope check
// therefore sees only "https" while the socket is cleartext, so an allow rule
// scoped to TLS approves a cleartext replay of the recorded Authorization
// header (CWE-319).
//
// The two sub-tests are deliberately different in kind. "validator_rejects"
// is the regression assertion (it fails before the fix). "plan_pair" is a
// contract pin that holds both before and after: it records the decoupling
// the validator exists to prevent, so that removing or relocating the
// allowlist cannot quietly re-open the hole without this test going red.
func TestBuildResendWSPlan_SchemeHTTPS_DecouplesDialFromScopeCheck(t *testing.T) {
	store := newTestStore(t)
	flowID := saveWSUpgradeFlow(t, store, "ws://example.com:80/chat")

	input := resendWSInput{FlowID: flowID, Scheme: "https", Opcode: "text", Payload: "hi"}

	t.Run("validator_rejects", func(t *testing.T) {
		in := input
		if err := validateResendWSInput(&in); err == nil {
			t.Fatal("validateResendWSInput({flow_id, scheme: \"https\"}) = nil, want an error")
		}
	})

	t.Run("plan_pair", func(t *testing.T) {
		s := mkServerFromLegacyDeps(legacyDeps{
			store: store,
			targetScope: newScopeWithRules(t,
				[]connector.TargetRule{{Hostname: "example.com", Schemes: []string{"https"}}},
				nil, nil, nil),
		})
		in := input
		plan, err := s.buildResendWSPlan(context.Background(), &in)
		if err != nil {
			t.Fatalf("buildResendWSPlan: %v", err)
		}
		if plan.useTLS {
			t.Errorf("plan.useTLS = true, want false — scheme %q is not \"wss\", so the dial is plaintext", input.Scheme)
		}
		if got := plan.upgradeURL.Scheme; got != "https" {
			t.Errorf("plan.upgradeURL.Scheme = %q, want %q — resendWSUpgradeURL maps only ws/wss", got, "https")
		}
		if plan.dialAddr != plan.upgradeURL.Host {
			t.Errorf("dialAddr = %q, upgradeURL.Host = %q — the override leg would run, which is not the shape this case pins",
				plan.dialAddr, plan.upgradeURL.Host)
		}
		// The consequence, through the real scope helper: an allow rule
		// scoped to TLS approves a plaintext dial.
		if err := s.checkResendWSScope(plan); err != nil {
			t.Errorf("checkResendWSScope = %v, want nil — this documents the hole the validator closes", err)
		}
	})
}

// TestValidateRawTargetAddr_RejectsEmptyPort pins the small hardening that
// rides along with USK-1061.
//
// net.SplitHostPort("h:") succeeds with an empty port, so the bare-split
// check both raw tools used accepted "169.254.169.254:" — which then reaches
// checkTargetScopeAddr and makes targetDefaultPort return 0, so any rule
// carrying a `ports` condition stops matching. Same silent-non-match shape as
// the blank scheme, one field over. Not exploitable (the dial fails
// afterwards), but the scope check should never see a port it cannot resolve.
func TestValidateRawTargetAddr_RejectsEmptyPort(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr string
	}{
		{addr: "169.254.169.254:", wantErr: "port cannot be empty"},
		{addr: ":80", wantErr: "host cannot be empty"},
		{addr: "example.com", wantErr: "must be host:port"},
		{addr: "example.com:80"},
		{addr: "[::1]:443"},
	}
	for _, tc := range cases {
		t.Run(tc.addr, func(t *testing.T) {
			err := validateRawTargetAddr(tc.addr)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("validateRawTargetAddr(%q) = %v, want nil", tc.addr, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("validateRawTargetAddr(%q) = nil, want %q", tc.addr, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}

	// Both raw tools must share the guard — this is the drift the shared
	// helper exists to prevent.
	rawIn := resendRawInput{FlowID: "f", TargetAddr: "169.254.169.254:"}
	if err := validateResendRawInput(&rawIn); err == nil {
		t.Error("validateResendRawInput with an empty port = nil, want an error")
	}
	fuzzIn := fuzzRawInput{TargetAddr: "169.254.169.254:", OverrideBytes: "x"}
	if err := validateFuzzRawTargetAndSNI(&fuzzIn); err == nil {
		t.Error("validateFuzzRawTargetAndSNI with an empty port = nil, want an error")
	}
}

// newScopeWithRules assembles a real *connector.TargetScope. Policy rules are
// installed first because SetAgentRules validates agent allows against the
// policy allow boundary.
func newScopeWithRules(t *testing.T, policyAllows, policyDenies, agentAllows, agentDenies []connector.TargetRule) *connector.TargetScope {
	t.Helper()
	ts := connector.NewTargetScope()
	ts.SetPolicyRules(policyAllows, policyDenies)
	if err := ts.SetAgentRules(agentAllows, agentDenies); err != nil {
		t.Fatalf("SetAgentRules: %v", err)
	}
	return ts
}

// assertScopeVerdict checks a scope helper's error against the expectation.
func assertScopeVerdict(t *testing.T, err error, wantErr bool, wantErrContains string) {
	t.Helper()
	if wantErr {
		if err == nil {
			t.Fatal("scope check = nil, want a block — a schemes-bearing rule stopped matching")
		}
		if wantErrContains != "" && !strings.Contains(err.Error(), wantErrContains) {
			t.Errorf("error = %v, want it to contain %q", err, wantErrContains)
		}
		return
	}
	if err != nil {
		t.Fatalf("scope check = %v, want nil — a schemes-bearing allow rule stopped matching", err)
	}
}

// saveWSUpgradeFlow persists a minimal recorded WebSocket stream: one Stream
// row plus one send-direction upgrade Flow whose URL is the recorded
// authority. Goes through the real SQLite store rather than a mock so
// Flow.URL survives the String() -> url.Parse round-trip production performs.
func saveWSUpgradeFlow(t *testing.T, store flow.Store, rawURL string) string {
	t.Helper()
	ctx := context.Background()

	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("url.Parse(%q): %v", rawURL, err)
	}

	streamID := uuid.NewString()
	st := &flow.Stream{
		ID:        streamID,
		ConnID:    uuid.NewString(),
		Protocol:  "ws",
		State:     "complete",
		Scheme:    u.Scheme,
		Timestamp: time.Now(),
	}
	if err := store.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}

	sendFlow := &flow.Flow{
		ID:        uuid.NewString(),
		StreamID:  streamID,
		Sequence:  0,
		Direction: "send",
		Timestamp: time.Now(),
		Method:    "GET",
		URL:       u,
		Headers: map[string][]string{
			"authorization": {"Bearer recorded-secret"},
		},
	}
	if err := store.SaveFlow(ctx, sendFlow); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}
	return streamID
}
