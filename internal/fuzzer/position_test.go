package fuzzer

import (
	"net/http"
	"net/url"
	"regexp"
	"testing"
)

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func TestPosition_Validate(t *testing.T) {
	tests := []struct {
		name    string
		pos     Position
		wantErr bool
	}{
		{
			name: "valid header replace",
			pos: Position{
				ID: "pos-0", Location: "header", Name: "Authorization",
				Mode: "replace", PayloadSet: "tokens",
			},
		},
		{
			name: "valid header with match pattern",
			pos: Position{
				ID: "pos-0", Location: "header", Name: "Authorization",
				Mode: "replace", Match: "Bearer (.*)", PayloadSet: "tokens",
			},
		},
		{
			name: "valid query replace with default mode",
			pos: Position{
				ID: "pos-1", Location: "query", Name: "q", PayloadSet: "values",
			},
		},
		{
			name: "valid body_json",
			pos: Position{
				ID: "pos-2", Location: "body_json", JSONPath: "$.password",
				PayloadSet: "passwords",
			},
		},
		{
			name: "valid body_regex",
			pos: Position{
				ID: "pos-3", Location: "body_regex", Match: "token=([^&]+)",
				PayloadSet: "tokens",
			},
		},
		{
			name: "valid cookie replace",
			pos: Position{
				ID: "pos-4", Location: "cookie", Name: "flow_id",
				PayloadSet: "flows",
			},
		},
		{
			name: "valid path replace",
			pos: Position{
				ID: "pos-5", Location: "path", PayloadSet: "paths",
			},
		},
		{
			name: "valid header add",
			pos: Position{
				ID: "pos-6", Location: "header", Name: "X-Custom",
				Mode: "add", PayloadSet: "values",
			},
		},
		{
			name: "valid header remove",
			pos: Position{
				ID: "pos-7", Location: "header", Name: "X-Debug",
				Mode: "remove",
			},
		},
		{
			name: "valid query remove",
			pos: Position{
				ID: "pos-8", Location: "query", Name: "debug",
				Mode: "remove",
			},
		},
		{
			name:    "missing id",
			pos:     Position{Location: "header", Name: "X", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "invalid location",
			pos:     Position{ID: "p0", Location: "invalid", Name: "X", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "invalid mode",
			pos:     Position{ID: "p0", Location: "header", Name: "X", Mode: "invalid", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "header missing name",
			pos:     Position{ID: "p0", Location: "header", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "query missing name",
			pos:     Position{ID: "p0", Location: "query", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "cookie missing name",
			pos:     Position{ID: "p0", Location: "cookie", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "body_json missing json_path",
			pos:     Position{ID: "p0", Location: "body_json", PayloadSet: "p"},
			wantErr: true,
		},
		{
			name:    "replace mode missing payload_set",
			pos:     Position{ID: "p0", Location: "header", Name: "X", Mode: "replace"},
			wantErr: true,
		},
		{
			name:    "add mode missing payload_set",
			pos:     Position{ID: "p0", Location: "header", Name: "X", Mode: "add"},
			wantErr: true,
		},
		{
			name:    "invalid match regex",
			pos:     Position{ID: "p0", Location: "header", Name: "X", Match: "(invalid[", PayloadSet: "p"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pos.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Position.Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestApplyPosition_ReplaceHeader(t *testing.T) {
	tests := []struct {
		name    string
		data    *RequestData
		pos     Position
		payload string
		want    string
	}{
		{
			name: "simple header replace",
			data: &RequestData{
				Headers: map[string][]string{
					"Authorization": {"old-token"},
				},
			},
			pos:     Position{ID: "p0", Location: "header", Name: "Authorization"},
			payload: "new-token",
			want:    "new-token",
		},
		{
			name: "header replace with capture group",
			data: &RequestData{
				Headers: map[string][]string{
					"Authorization": {"Bearer old-token"},
				},
			},
			pos:     Position{ID: "p0", Location: "header", Name: "Authorization", Match: "Bearer (.*)"},
			payload: "new-token",
			want:    "Bearer new-token",
		},
		{
			name: "header replace without capture group",
			data: &RequestData{
				Headers: map[string][]string{
					"Authorization": {"Bearer old-token"},
				},
			},
			pos:     Position{ID: "p0", Location: "header", Name: "Authorization", Match: "Bearer .*"},
			payload: "Basic creds",
			want:    "Basic creds",
		},
		{
			name: "header replace nonexistent creates it",
			data: &RequestData{
				Headers: map[string][]string{},
			},
			pos:     Position{ID: "p0", Location: "header", Name: "X-Custom"},
			payload: "value",
			want:    "value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ApplyPosition(tt.data, tt.pos, tt.payload)
			if err != nil {
				t.Fatalf("ApplyPosition() error = %v", err)
			}
			canonical := http.CanonicalHeaderKey(tt.pos.Name)
			vals, ok := tt.data.Headers[canonical]
			if !ok || len(vals) == 0 {
				t.Fatalf("header %q not found after apply", canonical)
			}
			if vals[0] != tt.want {
				t.Errorf("got %q, want %q", vals[0], tt.want)
			}
		})
	}
}

func TestApplyPosition_ReplaceQuery(t *testing.T) {
	tests := []struct {
		name    string
		data    *RequestData
		pos     Position
		payload string
		wantVal string
	}{
		{
			name: "simple query replace",
			data: &RequestData{
				URL: mustParseURL("http://example.com/path?q=old&other=keep"),
			},
			pos:     Position{ID: "p0", Location: "query", Name: "q"},
			payload: "new",
			wantVal: "new",
		},
		{
			name: "query replace with match",
			data: &RequestData{
				URL: mustParseURL("http://example.com/?token=abc123def"),
			},
			pos:     Position{ID: "p0", Location: "query", Name: "token", Match: "abc(.*)def"},
			payload: "XYZ",
			wantVal: "abcXYZdef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ApplyPosition(tt.data, tt.pos, tt.payload)
			if err != nil {
				t.Fatalf("ApplyPosition() error = %v", err)
			}
			got := tt.data.URL.Query().Get(tt.pos.Name)
			if got != tt.wantVal {
				t.Errorf("query %q = %q, want %q", tt.pos.Name, got, tt.wantVal)
			}
		})
	}
}

func TestApplyPosition_ReplacePath(t *testing.T) {
	data := &RequestData{
		URL: mustParseURL("http://example.com/api/v1/users"),
	}
	pos := Position{ID: "p0", Location: "path", Match: "/api/(v[0-9]+)/"}
	err := ApplyPosition(data, pos, "v2")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	want := "/api/v2/users"
	if data.URL.Path != want {
		t.Errorf("path = %q, want %q", data.URL.Path, want)
	}
}

func TestApplyPosition_ReplaceBodyRegex(t *testing.T) {
	data := &RequestData{
		Body: []byte("user=admin&pass=secret123"),
	}
	pos := Position{ID: "p0", Location: "body_regex", Match: "pass=([^&]+)"}
	err := ApplyPosition(data, pos, "FUZZED")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	want := "user=admin&pass=FUZZED"
	if string(data.Body) != want {
		t.Errorf("body = %q, want %q", string(data.Body), want)
	}
}

func TestApplyPosition_ReplaceBodyJSON(t *testing.T) {
	data := &RequestData{
		Body: []byte(`{"user":"admin","password":"old"}`),
	}
	pos := Position{ID: "p0", Location: "body_json", JSONPath: "$.password"}
	err := ApplyPosition(data, pos, "new-password")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	// Check JSON contains the new value.
	if got := string(data.Body); got == "" {
		t.Fatal("body is empty after patch")
	}
	// Unmarshal and check
	want := "new-password"
	// Simple string check since JSON serialization is deterministic here.
	if got := string(data.Body); !contains(got, `"password":"new-password"`) {
		t.Errorf("body = %s, want to contain password: %q", got, want)
	}
}

func TestApplyPosition_ReplaceCookie(t *testing.T) {
	tests := []struct {
		name       string
		cookieHdr  string
		pos        Position
		payload    string
		wantCookie string
	}{
		{
			name:      "simple cookie replace",
			cookieHdr: "session=old; other=keep",
			pos:       Position{ID: "p0", Location: "cookie", Name: "session"},
			payload:   "new-session",
			wantCookie: "session=new-session; other=keep",
		},
		{
			name:      "cookie not present creates it",
			cookieHdr: "other=keep",
			pos:       Position{ID: "p0", Location: "cookie", Name: "session"},
			payload:   "new-val",
			wantCookie: "other=keep; session=new-val",
		},
		{
			name:      "cookie replace with match pattern",
			cookieHdr: "token=prefix_secret_suffix",
			pos:       Position{ID: "p0", Location: "cookie", Name: "token", Match: "prefix_(.*)_suffix"},
			payload:   "FUZZED",
			wantCookie: "token=prefix_FUZZED_suffix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := &RequestData{
				Headers: map[string][]string{
					"Cookie": {tt.cookieHdr},
				},
			}
			err := ApplyPosition(data, tt.pos, tt.payload)
			if err != nil {
				t.Fatalf("ApplyPosition() error = %v", err)
			}
			got := data.Headers["Cookie"][0]
			if got != tt.wantCookie {
				t.Errorf("cookie = %q, want %q", got, tt.wantCookie)
			}
		})
	}
}

func TestApplyPosition_AddHeader(t *testing.T) {
	data := &RequestData{
		Headers: map[string][]string{
			"X-Existing": {"val1"},
		},
	}
	pos := Position{ID: "p0", Location: "header", Name: "X-Existing", Mode: "add"}
	err := ApplyPosition(data, pos, "val2")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	got := data.Headers["X-Existing"]
	if len(got) != 2 || got[1] != "val2" {
		t.Errorf("headers = %v, want [val1, val2]", got)
	}
}

func TestApplyPosition_AddQuery(t *testing.T) {
	data := &RequestData{
		URL: mustParseURL("http://example.com/path?existing=yes"),
	}
	pos := Position{ID: "p0", Location: "query", Name: "new_param", Mode: "add"}
	err := ApplyPosition(data, pos, "value")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	if got := data.URL.Query().Get("new_param"); got != "value" {
		t.Errorf("new_param = %q, want %q", got, "value")
	}
	if got := data.URL.Query().Get("existing"); got != "yes" {
		t.Errorf("existing = %q, want %q", got, "yes")
	}
}

func TestApplyPosition_AddCookie(t *testing.T) {
	data := &RequestData{
		Headers: map[string][]string{
			"Cookie": {"existing=val"},
		},
	}
	pos := Position{ID: "p0", Location: "cookie", Name: "new_cookie", Mode: "add"}
	err := ApplyPosition(data, pos, "new_val")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	got := data.Headers["Cookie"][0]
	want := "existing=val; new_cookie=new_val"
	if got != want {
		t.Errorf("cookie = %q, want %q", got, want)
	}
}

func TestApplyPosition_RemoveHeader(t *testing.T) {
	data := &RequestData{
		Headers: map[string][]string{
			"X-Debug": {"true"},
			"X-Keep":  {"yes"},
		},
	}
	pos := Position{ID: "p0", Location: "header", Name: "X-Debug", Mode: "remove"}
	err := ApplyPosition(data, pos, "")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	if _, ok := data.Headers["X-Debug"]; ok {
		t.Error("X-Debug header still present after remove")
	}
	if _, ok := data.Headers["X-Keep"]; !ok {
		t.Error("X-Keep header should still be present")
	}
}

func TestApplyPosition_RemoveQuery(t *testing.T) {
	data := &RequestData{
		URL: mustParseURL("http://example.com/path?debug=true&keep=yes"),
	}
	pos := Position{ID: "p0", Location: "query", Name: "debug", Mode: "remove"}
	err := ApplyPosition(data, pos, "")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	if got := data.URL.Query().Get("debug"); got != "" {
		t.Errorf("debug still present: %q", got)
	}
	if got := data.URL.Query().Get("keep"); got != "yes" {
		t.Errorf("keep = %q, want %q", got, "yes")
	}
}

func TestApplyPosition_RemoveCookie(t *testing.T) {
	data := &RequestData{
		Headers: map[string][]string{
			"Cookie": {"session=abc; debug=true; other=keep"},
		},
	}
	pos := Position{ID: "p0", Location: "cookie", Name: "debug", Mode: "remove"}
	err := ApplyPosition(data, pos, "")
	if err != nil {
		t.Fatalf("ApplyPosition() error = %v", err)
	}
	got := data.Headers["Cookie"][0]
	if contains(got, "debug") {
		t.Errorf("cookie still contains debug: %q", got)
	}
}

func TestRequestData_Clone(t *testing.T) {
	original := &RequestData{
		Method: "POST",
		URL:    mustParseURL("http://example.com/path?q=val"),
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
		},
		Body: []byte(`{"key":"value"}`),
	}

	clone := original.Clone()

	// Modify clone and verify original is untouched.
	clone.Method = "PUT"
	clone.URL.Path = "/new-path"
	clone.Headers["Content-Type"] = []string{"text/plain"}
	clone.Body[0] = 'X'

	if original.Method != "POST" {
		t.Errorf("original method changed to %q", original.Method)
	}
	if original.URL.Path != "/path" {
		t.Errorf("original URL path changed to %q", original.URL.Path)
	}
	if original.Headers["Content-Type"][0] != "application/json" {
		t.Errorf("original header changed to %q", original.Headers["Content-Type"][0])
	}
	if original.Body[0] != '{' {
		t.Errorf("original body changed: first byte is %d", original.Body[0])
	}
}

func TestReplaceWithCapture(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		input   string
		payload string
		want    string
	}{
		{
			name:    "no capture group - replace entire match",
			pattern: "Bearer .*",
			input:   "Bearer old-token",
			payload: "Basic new-creds",
			want:    "Basic new-creds",
		},
		{
			name:    "with capture group - replace only group",
			pattern: "Bearer (.*)",
			input:   "Bearer old-token",
			payload: "new-token",
			want:    "Bearer new-token",
		},
		{
			name:    "multiple capture groups - replace first",
			pattern: "user=(\\w+)&pass=(\\w+)",
			input:   "user=admin&pass=secret",
			payload: "FUZZED",
			want:    "user=FUZZED&pass=secret",
		},
		{
			name:    "no match - return unchanged",
			pattern: "Bearer (.*)",
			input:   "Token abc",
			payload: "new",
			want:    "Token abc",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re := mustCompileRegex(tt.pattern)
			got := replaceWithCapture(re, tt.input, tt.payload)
			if got != tt.want {
				t.Errorf("replaceWithCapture() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestParseSimpleJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		want    []string
		wantErr bool
	}{
		{name: "simple path", path: "$.user.name", want: []string{"user", "name"}},
		{name: "without dollar", path: "user.name", want: []string{"user", "name"}},
		{name: "single key", path: "$.key", want: []string{"key"}},
		{name: "empty", path: "", wantErr: true},
		{name: "only dollar", path: "$", wantErr: true},
		{name: "empty key", path: "$.a..b", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseSimpleJSONPath(tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseSimpleJSONPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("got %v, want %v", got, tt.want)
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestApplyPosition_NilURL(t *testing.T) {
	data := &RequestData{
		Headers: map[string][]string{},
	}

	// Query replace with nil URL should error.
	pos := Position{ID: "p0", Location: "query", Name: "q"}
	err := ApplyPosition(data, pos, "val")
	if err == nil {
		t.Error("expected error for nil URL with query replace")
	}

	// Path replace with nil URL should error.
	pos2 := Position{ID: "p1", Location: "path"}
	err = ApplyPosition(data, pos2, "/new")
	if err == nil {
		t.Error("expected error for nil URL with path replace")
	}
}

// contains checks if s contains substr (helper for test assertions).
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func mustCompileRegex(pattern string) *regexp.Regexp {
	re, err := regexp.Compile(pattern)
	if err != nil {
		panic(err)
	}
	return re
}
