package macro

import (
	"net/http"
	"testing"
)

func intPtr(i int) *int { return &i }

func TestEvaluateGuard(t *testing.T) {
	// Setup step states for guard evaluation.
	stepStates := map[string]*stepState{
		"login": {
			StatusCode: 302,
			Headers: http.Header{
				"Location":   {"/mfa"},
				"Set-Cookie": {"sid=abc123; Path=/"},
			},
			Body: []byte(`{"redirect":"/mfa"}`),
		},
		"success": {
			StatusCode: 200,
			Headers:    http.Header{"Content-Type": {"application/json"}},
			Body:       []byte(`{"status":"ok"}`),
		},
		"skipped": {
			Skipped: true,
		},
	}

	kvStore := map[string]string{
		"csrf_token": "xyz",
	}

	tests := []struct {
		name       string
		guard      *Guard
		states     map[string]*stepState
		kvStore    map[string]string
		want       bool
		wantErr    bool
	}{
		{
			name:    "nil guard always true",
			guard:   nil,
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "status code match",
			guard:   &Guard{Step: "login", StatusCode: intPtr(302)},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "status code mismatch",
			guard:   &Guard{Step: "login", StatusCode: intPtr(200)},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "status code range match",
			guard:   &Guard{Step: "login", StatusCodeRange: [2]int{300, 399}},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "status code range mismatch",
			guard:   &Guard{Step: "login", StatusCodeRange: [2]int{200, 299}},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "header match",
			guard:   &Guard{Step: "login", HeaderMatch: map[string]string{"Location": "/mfa.*"}},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "header match mismatch",
			guard:   &Guard{Step: "login", HeaderMatch: map[string]string{"Location": "/dashboard.*"}},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "header match missing header",
			guard:   &Guard{Step: "login", HeaderMatch: map[string]string{"X-Missing": ".*"}},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "body match",
			guard:   &Guard{Step: "login", BodyMatch: `"redirect":`},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "body match mismatch",
			guard:   &Guard{Step: "login", BodyMatch: `not-in-body`},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "extracted var exists",
			guard:   &Guard{Step: "login", ExtractedVar: "csrf_token"},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "extracted var missing",
			guard:   &Guard{Step: "login", ExtractedVar: "nonexistent"},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "extracted var without step reference",
			guard:   &Guard{ExtractedVar: "csrf_token"},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "AND evaluation: status + header",
			guard:   &Guard{Step: "login", StatusCode: intPtr(302), HeaderMatch: map[string]string{"Location": "/mfa.*"}},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "AND evaluation: one fails",
			guard:   &Guard{Step: "login", StatusCode: intPtr(200), HeaderMatch: map[string]string{"Location": "/mfa.*"}},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "negate true result",
			guard:   &Guard{Step: "login", StatusCode: intPtr(302), Negate: true},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "negate false result",
			guard:   &Guard{Step: "login", StatusCode: intPtr(200), Negate: true},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "unknown step reference returns false",
			guard:   &Guard{Step: "nonexistent", StatusCode: intPtr(200)},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "skipped step reference returns false",
			guard:   &Guard{Step: "skipped", StatusCode: intPtr(200)},
			states:  stepStates,
			kvStore: kvStore,
			want:    false,
		},
		{
			name:    "step ref only checks execution",
			guard:   &Guard{Step: "success"},
			states:  stepStates,
			kvStore: kvStore,
			want:    true,
		},
		{
			name:    "no step no extracted_var returns error",
			guard:   &Guard{StatusCode: intPtr(200)},
			states:  stepStates,
			kvStore: kvStore,
			wantErr: true,
		},
		{
			name:    "invalid header regex",
			guard:   &Guard{Step: "login", HeaderMatch: map[string]string{"Location": "[invalid"}},
			states:  stepStates,
			kvStore: kvStore,
			wantErr: true,
		},
		{
			name:    "invalid body regex",
			guard:   &Guard{Step: "login", BodyMatch: "[invalid"},
			states:  stepStates,
			kvStore: kvStore,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EvaluateGuard(tt.guard, tt.states, tt.kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateGuard() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("EvaluateGuard() = %v, want %v", got, tt.want)
			}
		})
	}
}
