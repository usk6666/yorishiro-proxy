package macro

import (
	"testing"
)

func TestExpandTemplate(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		kvStore map[string]string
		want    string
		wantErr bool
	}{
		{
			name:    "no templates",
			input:   "plain text",
			kvStore: nil,
			want:    "plain text",
		},
		{
			name:    "simple variable",
			input:   "token=§csrf_token§",
			kvStore: map[string]string{"csrf_token": "abc123"},
			want:    "token=abc123",
		},
		{
			name:    "multiple variables",
			input:   "Cookie: §cookie§; Token: §token§",
			kvStore: map[string]string{"cookie": "sid=xyz", "token": "t123"},
			want:    "Cookie: sid=xyz; Token: t123",
		},
		{
			name:    "unknown variable left as-is",
			input:   "value=§unknown§",
			kvStore: map[string]string{},
			want:    "value=§unknown§",
		},
		{
			name:    "variable with encoder",
			input:   "§value | url_encode§",
			kvStore: map[string]string{"value": "hello world"},
			want:    "hello+world",
		},
		{
			name:    "encoder chain",
			input:   "§value | url_encode | base64§",
			kvStore: map[string]string{"value": "hello world"},
			want:    "aGVsbG8rd29ybGQ=",
		},
		{
			name:    "unknown encoder returns error",
			input:   "§value | nonexistent§",
			kvStore: map[string]string{"value": "hello"},
			wantErr: true,
		},
		{
			name:    "empty variable name returns error",
			input:   "§ | upper§",
			kvStore: map[string]string{},
			wantErr: true,
		},
		{
			name:    "empty encoder name returns error",
			input:   "§value | §",
			kvStore: map[string]string{"value": "hello"},
			wantErr: true,
		},
		{
			name:    "unclosed delimiter treated as literal",
			input:   "§unclosed",
			kvStore: map[string]string{},
			want:    "§unclosed",
		},
		{
			name:    "empty input",
			input:   "",
			kvStore: nil,
			want:    "",
		},
		{
			name:    "adjacent templates",
			input:   "§a§§b§",
			kvStore: map[string]string{"a": "hello", "b": "world"},
			want:    "helloworld",
		},
		{
			name:    "template in url",
			input:   "https://example.com/api?token=§token§&user=§user | url_encode§",
			kvStore: map[string]string{"token": "abc123", "user": "john doe"},
			want:    "https://example.com/api?token=abc123&user=john+doe",
		},
		{
			name:    "variable with spaces around pipes",
			input:   "§ value | upper §",
			kvStore: map[string]string{"value": "hello"},
			want:    "HELLO",
		},
		{
			name:    "mixed known and unknown variables",
			input:   "§known§-§unknown§",
			kvStore: map[string]string{"known": "yes"},
			want:    "yes-§unknown§",
		},
		{
			name:    "triple chain",
			input:   "§value | lower | url_encode | base64§",
			kvStore: map[string]string{"value": "Hello World"},
			want:    "aGVsbG8rd29ybGQ=",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandTemplate(tt.input, tt.kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandTemplate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("ExpandTemplate() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExpandHeaders(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		kvStore map[string]string
		want    map[string]string
		wantErr bool
	}{
		{
			name:    "nil headers",
			headers: nil,
			kvStore: map[string]string{},
			want:    nil,
		},
		{
			name:    "empty headers",
			headers: map[string]string{},
			kvStore: map[string]string{},
			want:    map[string]string{},
		},
		{
			name:    "simple expansion",
			headers: map[string]string{"Cookie": "sid=§session§"},
			kvStore: map[string]string{"session": "abc123"},
			want:    map[string]string{"Cookie": "sid=abc123"},
		},
		{
			name: "multiple headers",
			headers: map[string]string{
				"Cookie":       "sid=§session§",
				"X-CSRF-Token": "§csrf§",
			},
			kvStore: map[string]string{"session": "abc", "csrf": "xyz"},
			want: map[string]string{
				"Cookie":       "sid=abc",
				"X-CSRF-Token": "xyz",
			},
		},
		{
			name:    "encoder in header value",
			headers: map[string]string{"Authorization": "Basic §creds | base64§"},
			kvStore: map[string]string{"creds": "user:pass"},
			want:    map[string]string{"Authorization": "Basic dXNlcjpwYXNz"},
		},
		{
			name:    "error propagates",
			headers: map[string]string{"X": "§value | nonexistent§"},
			kvStore: map[string]string{"value": "test"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ExpandHeaders(tt.headers, tt.kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExpandHeaders() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.want != nil {
				for k, wantV := range tt.want {
					if got[k] != wantV {
						t.Errorf("ExpandHeaders()[%q] = %q, want %q", k, got[k], wantV)
					}
				}
			}
		})
	}
}
