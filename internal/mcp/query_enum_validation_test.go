package mcp

import (
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- Unit tests for validateEnum ---

func TestValidateEnum(t *testing.T) {
	valid := []string{"alpha", "beta", "gamma"}

	tests := []struct {
		name    string
		value   string
		wantErr bool
		errMsg  string
	}{
		{"empty value is valid", "", false, ""},
		{"valid value alpha", "alpha", false, ""},
		{"valid value beta", "beta", false, ""},
		{"valid value gamma", "gamma", false, ""},
		{"invalid value", "delta", true, `invalid test_param "delta": valid values are alpha, beta, gamma`},
		{"case sensitive", "Alpha", true, `invalid test_param "Alpha": valid values are alpha, beta, gamma`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateEnum("test_param", tt.value, valid)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if err.Error() != tt.errMsg {
					t.Errorf("error = %q, want %q", err.Error(), tt.errMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- Unit tests for validateFlowFilters ---

func TestValidateFlowFilters(t *testing.T) {
	tests := []struct {
		name    string
		input   queryInput
		wantErr bool
		errSub  string // substring to check in error message
	}{
		{
			name:  "no filter is valid",
			input: queryInput{Resource: "flows"},
		},
		{
			name:  "empty filter is valid",
			input: queryInput{Resource: "flows", Filter: &queryFilter{}},
		},
		{
			name:  "valid protocol",
			input: queryInput{Resource: "flows", Filter: &queryFilter{Protocol: "HTTPS"}},
		},
		{
			name:    "invalid protocol",
			input:   queryInput{Resource: "flows", Filter: &queryFilter{Protocol: "FTP"}},
			wantErr: true,
			errSub:  `invalid protocol "FTP"`,
		},
		{
			name:  "valid scheme",
			input: queryInput{Resource: "flows", Filter: &queryFilter{Scheme: "https"}},
		},
		{
			name:    "invalid scheme",
			input:   queryInput{Resource: "flows", Filter: &queryFilter{Scheme: "ftp"}},
			wantErr: true,
			errSub:  `invalid scheme "ftp"`,
		},
		{
			name:  "valid state",
			input: queryInput{Resource: "flows", Filter: &queryFilter{State: "complete"}},
		},
		{
			name:    "invalid state",
			input:   queryInput{Resource: "flows", Filter: &queryFilter{State: "pending"}},
			wantErr: true,
			errSub:  `invalid state "pending"`,
		},
		{
			name:  "valid blocked_by",
			input: queryInput{Resource: "flows", Filter: &queryFilter{BlockedBy: "target_scope"}},
		},
		{
			name:  "valid blocked_by safety_filter",
			input: queryInput{Resource: "flows", Filter: &queryFilter{BlockedBy: "safety_filter"}},
		},
		{
			name:    "invalid blocked_by",
			input:   queryInput{Resource: "flows", Filter: &queryFilter{BlockedBy: "firewall"}},
			wantErr: true,
			errSub:  `invalid blocked_by "firewall"`,
		},
		{
			name:  "valid sort_by",
			input: queryInput{Resource: "flows", SortBy: "timestamp"},
		},
		{
			name:    "invalid sort_by",
			input:   queryInput{Resource: "flows", SortBy: "size"},
			wantErr: true,
			errSub:  `invalid sort_by "size"`,
		},
		{
			name: "all valid values together",
			input: queryInput{
				Resource: "flows",
				SortBy:   "duration_ms",
				Filter: &queryFilter{
					Protocol:  "HTTP/2",
					Scheme:    "https",
					State:     "active",
					BlockedBy: "rate_limit",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlowFilters(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSub)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- Unit tests for validateFuzzJobFilters ---

func TestValidateFuzzJobFilters(t *testing.T) {
	tests := []struct {
		name    string
		input   queryInput
		wantErr bool
		errSub  string
	}{
		{
			name:  "no filter is valid",
			input: queryInput{Resource: "fuzz_jobs"},
		},
		{
			name:  "valid status running",
			input: queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "running"}},
		},
		{
			name:  "valid status completed",
			input: queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "completed"}},
		},
		{
			name:  "valid status paused",
			input: queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "paused"}},
		},
		{
			name:  "valid status cancelled",
			input: queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "cancelled"}},
		},
		{
			name:  "valid status error",
			input: queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "error"}},
		},
		{
			name:    "invalid status",
			input:   queryInput{Resource: "fuzz_jobs", Filter: &queryFilter{Status: "done"}},
			wantErr: true,
			errSub:  `invalid status "done"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFuzzJobFilters(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSub)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- Unit tests for validateFuzzResultFilters ---

func TestValidateFuzzResultFilters(t *testing.T) {
	tests := []struct {
		name    string
		input   queryInput
		wantErr bool
		errSub  string
	}{
		{
			name:  "no sort_by is valid",
			input: queryInput{Resource: "fuzz_results"},
		},
		{
			name:  "valid sort_by index_num",
			input: queryInput{Resource: "fuzz_results", SortBy: "index_num"},
		},
		{
			name:  "valid sort_by status_code",
			input: queryInput{Resource: "fuzz_results", SortBy: "status_code"},
		},
		{
			name:  "valid sort_by duration_ms",
			input: queryInput{Resource: "fuzz_results", SortBy: "duration_ms"},
		},
		{
			name:  "valid sort_by response_length",
			input: queryInput{Resource: "fuzz_results", SortBy: "response_length"},
		},
		{
			name:    "invalid sort_by",
			input:   queryInput{Resource: "fuzz_results", SortBy: "payload"},
			wantErr: true,
			errSub:  `invalid sort_by "payload"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFuzzResultFilters(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if !strings.Contains(err.Error(), tt.errSub) {
					t.Errorf("error = %q, want substring %q", err.Error(), tt.errSub)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			}
		})
	}
}

// --- Integration tests via MCP tool ---

func TestQuery_Flows_InvalidProtocol(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Protocol: "FTP"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid protocol")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, "invalid protocol") {
		t.Errorf("error should mention invalid protocol, got: %s", text.Text)
	}
	if !strings.Contains(text.Text, "HTTPS") {
		t.Errorf("error should list valid values, got: %s", text.Text)
	}
}

func TestQuery_Flows_ValidFiltersStillWork(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	// Valid filter should not produce an error.
	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		SortBy:   "timestamp",
		Filter: &queryFilter{
			Protocol: "HTTPS",
			Scheme:   "https",
			State:    "complete",
		},
	})
	if result.IsError {
		t.Fatalf("expected success for valid filters, got error: %v", result.Content)
	}
}

