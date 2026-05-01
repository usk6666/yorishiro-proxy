package mcp

import (
	"strings"
	"testing"
)

// TestValidateResendWSInput_RejectsCRLF asserts the schema-boundary
// validator rejects CR/LF in user-supplied URL components — defense in
// depth against CWE-93 request smuggling on the upstream upgrade leg.
// Recovered-from-flow_id headers are NOT covered here per the project
// MITM-fidelity principle (preserve wire reality on recorded inputs).
func TestValidateResendWSInput_RejectsCRLF(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		mut   func(*resendWSInput)
		field string
	}{
		{"path with LF", func(in *resendWSInput) { in.Path = "/echo\nX-Inj: y" }, "path"},
		{"path with CR", func(in *resendWSInput) { in.Path = "/echo\rX-Inj: y" }, "path"},
		{"raw_query with CRLF", func(in *resendWSInput) { in.RawQuery = "a=b\r\nX-Inj: y" }, "raw_query"},
		{"scheme with LF", func(in *resendWSInput) { in.Scheme = "ws\nfoo" }, "scheme"},
		{"target_addr with CR", func(in *resendWSInput) { in.TargetAddr = "host:80\rX-Inj: y" }, "target_addr"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := &resendWSInput{
				Opcode:     "text",
				TargetAddr: "127.0.0.1:8080",
				Path:       "/echo",
			}
			tc.mut(in)
			err := validateResendWSInput(in)
			if err == nil {
				t.Fatalf("expected error for %s with CR/LF, got nil", tc.field)
			}
			if !strings.Contains(err.Error(), tc.field) {
				t.Errorf("error %q does not mention field %q", err.Error(), tc.field)
			}
			if !strings.Contains(err.Error(), "CR/LF") {
				t.Errorf("error %q does not mention CR/LF", err.Error())
			}
		})
	}
}

// TestValidateResendWSInput_AcceptsCleanInput sanity-checks the
// validator passes a normal from-scratch frame definition.
func TestValidateResendWSInput_AcceptsCleanInput(t *testing.T) {
	t.Parallel()
	in := &resendWSInput{
		Opcode:     "text",
		TargetAddr: "127.0.0.1:8080",
		Scheme:     "ws",
		Path:       "/echo",
		RawQuery:   "v=2",
	}
	if err := validateResendWSInput(in); err != nil {
		t.Fatalf("validateResendWSInput(clean) = %v, want nil", err)
	}
}
