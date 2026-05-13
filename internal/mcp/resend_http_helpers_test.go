package mcp

// resend_http_helpers_test.go — unit tests for the resend_http control-plane
// helpers. Today covers splitResendHTTPPathQuery (USK-859); future helpers
// in resend_http_helpers.go should land tests here rather than only inside
// the heavier e2e integration harness.

import (
	"strings"
	"testing"
)

// TestSplitResendHTTPPathQuery exercises every documented behaviour of the
// auto-split helper used by buildResendHTTPEnvelopeWithMeta (USK-859):
//   - no-op when path has no '?'
//   - split on the first '?' when raw_query is empty
//   - error when both raw_query is non-empty AND path contains '?'
//   - literal '%3F' is NOT a delimiter (already percent-encoded)
//   - empty inputs pass through
//   - only-'?' yields empty-prefix path + empty raw_query
//   - multiple '?' chars split on the FIRST one only
func TestSplitResendHTTPPathQuery(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		rawQuery     string
		wantPath     string
		wantRawQuery string
		wantErr      bool
		wantErrFrag  string // substring expected in the returned error
	}{
		{
			name:         "no question mark passes through",
			path:         "/anything",
			rawQuery:     "",
			wantPath:     "/anything",
			wantRawQuery: "",
		},
		{
			name:         "no question mark preserves raw_query",
			path:         "/anything",
			rawQuery:     "a=1&b=2",
			wantPath:     "/anything",
			wantRawQuery: "a=1&b=2",
		},
		{
			name:         "happy path: split on first question mark",
			path:         "/anything?phase=3&case=02&m=GET",
			rawQuery:     "",
			wantPath:     "/anything",
			wantRawQuery: "phase=3&case=02&m=GET",
		},
		{
			name:         "split on first question mark only — later '?' stay in raw_query",
			path:         "/x?a=1?b=2",
			rawQuery:     "",
			wantPath:     "/x",
			wantRawQuery: "a=1?b=2",
		},
		{
			name:        "conflict: both path-with-? and non-empty raw_query → error",
			path:        "/anything?phase=3",
			rawQuery:    "extra=1",
			wantErr:     true,
			wantErrFrag: "path contains '?'",
		},
		{
			name:         "literal %3F in path is NOT a delimiter",
			path:         "/anything%3Fphase=3",
			rawQuery:     "",
			wantPath:     "/anything%3Fphase=3",
			wantRawQuery: "",
		},
		{
			name:         "empty path and empty raw_query pass through unchanged",
			path:         "",
			rawQuery:     "",
			wantPath:     "",
			wantRawQuery: "",
		},
		{
			name:         "only '?' yields empty-prefix path and empty raw_query",
			path:         "?",
			rawQuery:     "",
			wantPath:     "",
			wantRawQuery: "",
		},
		{
			name:         "leading '?' routes everything to raw_query",
			path:         "?a=1",
			rawQuery:     "",
			wantPath:     "",
			wantRawQuery: "a=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath, gotRawQuery, err := splitResendHTTPPathQuery(tt.path, tt.rawQuery)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (path=%q, gotRawQuery=%q)", gotPath, gotRawQuery)
				}
				if tt.wantErrFrag != "" && !strings.Contains(err.Error(), tt.wantErrFrag) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.wantErrFrag)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if gotPath != tt.wantPath {
				t.Errorf("path = %q, want %q", gotPath, tt.wantPath)
			}
			if gotRawQuery != tt.wantRawQuery {
				t.Errorf("rawQuery = %q, want %q", gotRawQuery, tt.wantRawQuery)
			}
		})
	}
}
