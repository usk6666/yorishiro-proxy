package mcp

import (
	"strings"
	"testing"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
)

// TestValidateManageDeleteFilter_SchemeWS_USK864 pins that the manage
// delete_flows filter rejects scheme="ws" with the same USK-864
// remediation hint the query tool surface produces. Per USK-848,
// Stream.Scheme records the wire-observed handshake transport only.
func TestValidateManageDeleteFilter_SchemeWS_USK864(t *testing.T) {
	tests := []struct {
		name        string
		scheme      string
		wantErr     bool
		errContains []string
	}{
		{"empty is valid (filter unset)", "", false, nil},
		{"http is valid", "http", false, nil},
		{"https is valid", "https", false, nil},
		{"tcp is valid", "tcp", false, nil},
		{
			name:        "ws is rejected with remediation hint",
			scheme:      "ws",
			wantErr:     true,
			errContains: []string{`invalid scheme "ws"`, `protocol="ws"`},
		},
		{
			name:        "wss is rejected with remediation hint",
			scheme:      "wss",
			wantErr:     true,
			errContains: []string{`invalid scheme "wss"`, `protocol="ws"`, `scheme="https"`},
		},
		{
			name:        "unknown value falls through to standard enum error",
			scheme:      "ftp",
			wantErr:     true,
			errContains: []string{`invalid scheme "ftp"`, "valid values are"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManageDeleteFilter(manageParams{Scheme: tt.scheme})
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

// TestValidateManageExportFilter_SchemeWS_USK864 mirrors the
// delete_flows test for the export_flows / params.filter shape so
// every manage scheme entry point rejects ws/wss in lockstep.
func TestValidateManageExportFilter_SchemeWS_USK864(t *testing.T) {
	tests := []struct {
		name        string
		scheme      string
		wantErr     bool
		errContains []string
	}{
		{"empty is valid (filter unset)", "", false, nil},
		{"http is valid", "http", false, nil},
		{"https is valid", "https", false, nil},
		{"tcp is valid", "tcp", false, nil},
		{
			name:        "ws is rejected with remediation hint",
			scheme:      "ws",
			wantErr:     true,
			errContains: []string{`invalid scheme "ws"`, `protocol="ws"`},
		},
		{
			name:        "wss is rejected with remediation hint",
			scheme:      "wss",
			wantErr:     true,
			errContains: []string{`invalid scheme "wss"`, `protocol="ws"`, `scheme="https"`},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateManageExportFilter(&exportFilter{Scheme: tt.scheme})
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

// TestManageDelete_SchemeWS_Rejected verifies the manage MCP tool surface
// rejects scheme="ws" on delete_flows with the USK-864 remediation hint.
func TestManageDelete_SchemeWS_Rejected(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"scheme":  "ws",
			"confirm": true,
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for scheme=ws on delete_flows (USK-864)")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, `invalid scheme "ws"`) {
		t.Errorf("error should mention invalid scheme \"ws\", got: %s", text.Text)
	}
	if !strings.Contains(text.Text, `protocol="ws"`) {
		t.Errorf("error should point at protocol=\"ws\" remediation, got: %s", text.Text)
	}
}

// TestManageDelete_SchemeWSS_Rejected verifies delete_flows rejects
// scheme="wss" with a hint pointing at the WS-over-TLS combined filter.
func TestManageDelete_SchemeWSS_Rejected(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	result := manageCallTool(t, cs, map[string]any{
		"action": "delete_flows",
		"params": map[string]any{
			"scheme":  "wss",
			"confirm": true,
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for scheme=wss on delete_flows (USK-864)")
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

// TestManageExport_SchemeWS_Rejected verifies the export_flows surface
// rejects params.filter.scheme="ws".
func TestManageExport_SchemeWS_Rejected(t *testing.T) {
	store := newTestStore(t)
	cs := setupTestSession(t, newTestCA(t), store)

	dir := t.TempDir()
	result := manageCallTool(t, cs, map[string]any{
		"action": "export_flows",
		"params": map[string]any{
			"output_path": dir + "/out.jsonl",
			"filter": map[string]any{
				"scheme": "ws",
			},
		},
	})
	if !result.IsError {
		t.Fatal("expected IsError=true for scheme=ws on export_flows (USK-864)")
	}
	text := result.Content[0].(*gomcp.TextContent)
	if !strings.Contains(text.Text, `invalid scheme "ws"`) {
		t.Errorf("error should mention invalid scheme \"ws\", got: %s", text.Text)
	}
	if !strings.Contains(text.Text, `protocol="ws"`) {
		t.Errorf("error should point at protocol=\"ws\" remediation, got: %s", text.Text)
	}
}
