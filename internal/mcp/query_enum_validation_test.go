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
			input: queryInput{Resource: "flows", Filter: &queryFilter{Protocol: "http"}},
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
			name:  "valid origin proxy",
			input: queryInput{Resource: "flows", Filter: &queryFilter{Origin: "proxy"}},
		},
		{
			name:  "valid origin resend",
			input: queryInput{Resource: "flows", Filter: &queryFilter{Origin: "resend"}},
		},
		{
			name:  "valid origin fuzz",
			input: queryInput{Resource: "flows", Filter: &queryFilter{Origin: "fuzz"}},
		},
		{
			name:    "invalid origin",
			input:   queryInput{Resource: "flows", Filter: &queryFilter{Origin: "unknown"}},
			wantErr: true,
			errSub:  `invalid origin "unknown"`,
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
					Protocol:  "http",
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
	if !strings.Contains(text.Text, "http") {
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
			Protocol: "http",
			Scheme:   "https",
			State:    "complete",
		},
	})
	if result.IsError {
		t.Fatalf("expected success for valid filters, got error: %v", result.Content)
	}
}

// TestValidateSchemeFilter_USK864 pins the USK-864 hard-reject for
// "ws"/"wss" filter values. Per USK-848, Stream.Scheme records the
// wire-observed handshake transport (http/https/tcp) and never the
// application protocol. The query/manage filter surfaces advertised
// ws/wss as valid before USK-864, which silently returned 0 results
// for live WebSocket flows. Rejecting them at the enum boundary with a
// remediation hint pointing at protocol="ws" makes the spec match the
// USK-848 invariant.
func TestValidateSchemeFilter_USK864(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		wantErr     bool
		errContains []string
	}{
		{"empty is valid (filter unset)", "", false, nil},
		{"http is valid", "http", false, nil},
		{"https is valid", "https", false, nil},
		{"tcp is valid", "tcp", false, nil},
		{
			name:        "ws is rejected with remediation hint",
			value:       "ws",
			wantErr:     true,
			errContains: []string{`invalid scheme "ws"`, `protocol="ws"`},
		},
		{
			name:        "wss is rejected with remediation hint",
			value:       "wss",
			wantErr:     true,
			errContains: []string{`invalid scheme "wss"`, `protocol="ws"`, `scheme="https"`},
		},
		{
			name:        "unknown value falls through to standard enum error",
			value:       "ftp",
			wantErr:     true,
			errContains: []string{`invalid scheme "ftp"`, "valid values are"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSchemeFilter(tt.value)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				for _, sub := range tt.errContains {
					if !strings.Contains(err.Error(), sub) {
						t.Errorf("error = %q, want substring %q", err.Error(), sub)
					}
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

// TestValidFilterSchemes_USK864 pins that ws/wss are absent from the
// enum and only the wire-observed handshake transports remain.
func TestValidFilterSchemes_USK864(t *testing.T) {
	want := map[string]bool{"http": true, "https": true, "tcp": true}
	if len(validFilterSchemes) != len(want) {
		t.Errorf("validFilterSchemes = %v, want exactly %v", validFilterSchemes, want)
	}
	for _, v := range validFilterSchemes {
		if !want[v] {
			t.Errorf("validFilterSchemes contains unexpected value %q (USK-864: only http/https/tcp permitted)", v)
		}
	}
	for _, rejected := range []string{"ws", "wss"} {
		for _, v := range validFilterSchemes {
			if v == rejected {
				t.Errorf("validFilterSchemes must not contain %q (USK-864 hard-reject)", rejected)
			}
		}
	}
}

// TestQuery_Flows_SchemeWS_Rejected verifies the MCP-tool surface
// rejects scheme="ws" with the USK-864 remediation hint.
func TestQuery_Flows_SchemeWS_Rejected(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Scheme: "ws"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for scheme=ws (USK-864)")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, `invalid scheme "ws"`) {
		t.Errorf("error should mention invalid scheme \"ws\", got: %s", text.Text)
	}
	if !strings.Contains(text.Text, `protocol="ws"`) {
		t.Errorf("error should point at protocol=\"ws\" remediation, got: %s", text.Text)
	}
}

// TestQuery_Flows_SchemeWSS_Rejected verifies the MCP-tool surface
// rejects scheme="wss" with a remediation hint pointing at the combined
// filter for WS-over-TLS.
func TestQuery_Flows_SchemeWSS_Rejected(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Scheme: "wss"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for scheme=wss (USK-864)")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, `invalid scheme "wss"`) {
		t.Errorf("error should mention invalid scheme \"wss\", got: %s", text.Text)
	}
	if !strings.Contains(text.Text, `protocol="ws"`) {
		t.Errorf("error should point at protocol=\"ws\", got: %s", text.Text)
	}
	if !strings.Contains(text.Text, `scheme="https"`) {
		t.Errorf("error should mention scheme=\"https\" for WS-over-TLS, got: %s", text.Text)
	}
}

// TestQuery_Flows_InvalidOrigin verifies that an unknown origin value is
// rejected with a validation error mentioning the parameter name. The schema
// JSON also enforces the same enum, but the Go-side validateEnum produces the
// canonical user-facing error message regardless of transport.
func TestQuery_Flows_InvalidOrigin(t *testing.T) {
	store := newTestStore(t)
	cs := setupQueryTestSession(t, store)

	result := callQuery(t, cs, queryInput{
		Resource: "flows",
		Filter:   &queryFilter{Origin: "unknown"},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for invalid origin")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, "invalid origin") {
		t.Errorf("error should mention invalid origin, got: %s", text.Text)
	}
	if !strings.Contains(text.Text, "resend") {
		t.Errorf("error should list valid values including resend, got: %s", text.Text)
	}
}
