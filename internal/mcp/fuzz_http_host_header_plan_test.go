package mcp

import (
	"context"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// USK-1167 review F-1: under a domain allow, the fuzz_http plan-level
// scope check must not judge a base Host value that a headers[N] position
// replaces, nor one that carries a §var§ placeholder — every variant is
// judged after positions and §var§ expansion by checkFuzzHTTPVariantScope,
// before it is sent. Untargeted literal Host values are still judged at
// plan time.

func newFuzzHostPlanServer(t *testing.T) *Server {
	t.Helper()
	ts := connector.NewTargetScope()
	ts.SetPolicyRules([]connector.TargetRule{{Hostname: "app.example"}}, nil)
	return newServer(context.Background(), nil, newTestStore(t), nil, WithTargetScope(ts))
}

func fuzzHostPlanInput(headers []headerKV, positions ...fuzzHTTPPosition) *fuzzHTTPInput {
	return &fuzzHTTPInput{
		Method:    "GET",
		Scheme:    "http",
		Authority: "app.example:80",
		Path:      "/",
		Headers:   headers,
		Positions: positions,
	}
}

func TestBuildFuzzHTTPPlan_HostHeaderLegs(t *testing.T) {
	tests := []struct {
		name      string
		input     *fuzzHTTPInput
		wantError bool
	}{
		{
			name: "placeholder Host replaced by a headers[0].value position",
			input: fuzzHostPlanInput(
				[]headerKV{{Name: "Host", Value: "placeholder.invalid"}},
				fuzzHTTPPosition{Path: "headers[0].value", Payloads: []string{"app.example"}}),
		},
		{
			name: "Host renamed by a headers[0].name position",
			input: fuzzHostPlanInput(
				[]headerKV{{Name: "Host", Value: "placeholder.invalid"}},
				fuzzHTTPPosition{Path: "headers[0].name", Payloads: []string{"X-Other"}}),
		},
		{
			name: "§var§ Host value",
			input: fuzzHostPlanInput(
				[]headerKV{{Name: "Host", Value: "§vhost§"}},
				fuzzHTTPPosition{Path: "path", Payloads: []string{"/a"}}),
		},
		{
			name: "untargeted literal Host outside the allow is still refused",
			input: fuzzHostPlanInput(
				[]headerKV{{Name: "Host", Value: "other.example"}, {Name: "X-A", Value: "1"}},
				fuzzHTTPPosition{Path: "headers[1].value", Payloads: []string{"2"}}),
			wantError: true,
		},
		{
			name: "only the targeted Host is skipped; a second literal Host is judged",
			input: fuzzHostPlanInput(
				[]headerKV{{Name: "Host", Value: "placeholder.invalid"}, {Name: "host", Value: "other.example"}},
				fuzzHTTPPosition{Path: "headers[0].value", Payloads: []string{"app.example"}}),
			wantError: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newFuzzHostPlanServer(t)
			_, err := s.buildFuzzHTTPPlan(context.Background(), tt.input)
			if tt.wantError {
				if err == nil || !strings.Contains(err.Error(), "target scope") {
					t.Fatalf("buildFuzzHTTPPlan err = %v, want a target scope rejection", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("buildFuzzHTTPPlan err = %v, want nil (the per-variant check judges this Host)", err)
			}
		})
	}
}

// The plan-level skip must not let a variant through: the per-variant
// check still judges the substituted Host value before send.
func TestFuzzHTTPVariantScope_PlaceholderHostStillJudgedPerVariant(t *testing.T) {
	s := newFuzzHostPlanServer(t)
	plan, err := s.buildFuzzHTTPPlan(context.Background(), fuzzHostPlanInput(
		[]headerKV{{Name: "Host", Value: "placeholder.invalid"}},
		fuzzHTTPPosition{Path: "headers[0].value", Payloads: []string{"app.example", "other.example"}}))
	if err != nil {
		t.Fatalf("buildFuzzHTTPPlan: %v", err)
	}
	for _, tc := range []struct {
		payload   string
		wantBlock bool
	}{{"app.example", false}, {"other.example", true}} {
		variant := cloneFuzzHTTPEnvelope(plan.baseEnv).Message.(*envelope.HTTPMessage)
		if err := applyFuzzHTTPPosition(variant, "headers[0].value", tc.payload, plan.hostInjected, plan.userHeaderCount); err != nil {
			t.Fatalf("applyFuzzHTTPPosition: %v", err)
		}
		err := s.checkFuzzHTTPVariantScope(plan, variant)
		if blocked := err != nil; blocked != tc.wantBlock {
			t.Errorf("variant Host %q: err = %v, want blocked=%v", tc.payload, err, tc.wantBlock)
		}
	}
}
