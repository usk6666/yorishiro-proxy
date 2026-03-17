package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/fuzzer"
)

func TestValidateFuzzParams_AttackType(t *testing.T) {
	t.Parallel()

	// base returns a valid fuzzParams with all required fields populated.
	base := func() fuzzParams {
		return fuzzParams{
			FlowID:     "flow-1",
			AttackType: "sequential",
			Positions: []fuzzer.Position{
				{ID: "pos-0", Location: "body_regex"},
			},
		}
	}

	tests := []struct {
		name       string
		attackType string
		wantErr    string
	}{
		{
			name:       "valid sequential",
			attackType: "sequential",
		},
		{
			name:       "valid parallel",
			attackType: "parallel",
		},
		{
			name:       "empty attack_type includes valid values",
			attackType: "",
			wantErr:    "attack_type is required for fuzz action: valid values are sequential, parallel",
		},
		{
			name:       "invalid attack_type includes valid values",
			attackType: "unknown",
			wantErr:    `invalid attack_type "unknown": valid values are sequential, parallel`,
		},
		{
			name:       "similar but wrong value",
			attackType: "Sequential",
			wantErr:    `invalid attack_type "Sequential": valid values are sequential, parallel`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p := base()
			p.AttackType = tt.attackType
			err := validateFuzzParams(p)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.wantErr)
			}
			if err.Error() != tt.wantErr {
				t.Errorf("error mismatch:\n  got:  %s\n  want: %s", err.Error(), tt.wantErr)
			}
		})
	}
}
