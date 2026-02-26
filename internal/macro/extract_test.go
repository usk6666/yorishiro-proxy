package macro

import (
	"net/http"
	"strings"
	"testing"
)

func TestExtractValues_Header(t *testing.T) {
	resp := &SendResponse{
		StatusCode: 200,
		Headers: http.Header{
			"Set-Cookie":   {"PHPSESSID=abc123; Path=/"},
			"Content-Type": {"application/json"},
		},
		Body: []byte(`{"status":"ok"}`),
	}

	tests := []struct {
		name    string
		rules   []ExtractionRule
		wantKV  map[string]string
		wantErr bool
	}{
		{
			name: "extract header with regex",
			rules: []ExtractionRule{
				{
					Name:       "session_cookie",
					From:       ExtractionFromResponse,
					Source:     ExtractionSourceHeader,
					HeaderName: "Set-Cookie",
					Regex:      `PHPSESSID=([^;]+)`,
					Group:      1,
				},
			},
			wantKV: map[string]string{"session_cookie": "abc123"},
		},
		{
			name: "extract header without regex returns full value",
			rules: []ExtractionRule{
				{
					Name:       "content_type",
					From:       ExtractionFromResponse,
					Source:     ExtractionSourceHeader,
					HeaderName: "Content-Type",
				},
			},
			wantKV: map[string]string{"content_type": "application/json"},
		},
		{
			name: "missing header with default",
			rules: []ExtractionRule{
				{
					Name:       "missing",
					From:       ExtractionFromResponse,
					Source:     ExtractionSourceHeader,
					HeaderName: "X-Missing",
					Default:    "fallback",
				},
			},
			wantKV: map[string]string{"missing": "fallback"},
		},
		{
			name: "missing required header fails",
			rules: []ExtractionRule{
				{
					Name:       "missing",
					From:       ExtractionFromResponse,
					Source:     ExtractionSourceHeader,
					HeaderName: "X-Missing",
					Required:   true,
				},
			},
			wantErr: true,
		},
		{
			name: "missing header_name fails",
			rules: []ExtractionRule{
				{
					Name:   "bad",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceHeader,
				},
			},
			wantKV: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvStore := make(map[string]string)
			err := ExtractValues(tt.rules, nil, resp, kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for k, want := range tt.wantKV {
				if got := kvStore[k]; got != want {
					t.Errorf("kvStore[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestExtractValues_Body(t *testing.T) {
	resp := &SendResponse{
		StatusCode: 200,
		Body:       []byte(`<input name="csrf" value="token123">`),
	}

	tests := []struct {
		name    string
		rules   []ExtractionRule
		wantKV  map[string]string
		wantErr bool
	}{
		{
			name: "extract body with regex",
			rules: []ExtractionRule{
				{
					Name:   "csrf",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceBody,
					Regex:  `name="csrf" value="([^"]+)"`,
					Group:  1,
				},
			},
			wantKV: map[string]string{"csrf": "token123"},
		},
		{
			name: "body regex no match with default",
			rules: []ExtractionRule{
				{
					Name:    "nomatch",
					From:    ExtractionFromResponse,
					Source:  ExtractionSourceBody,
					Regex:   `not-found-pattern`,
					Default: "default_val",
				},
			},
			wantKV: map[string]string{"nomatch": "default_val"},
		},
		{
			name: "body regex no match required",
			rules: []ExtractionRule{
				{
					Name:     "nomatch",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBody,
					Regex:    `not-found-pattern`,
					Required: true,
				},
			},
			wantErr: true,
		},
		{
			name: "body without regex returns full body",
			rules: []ExtractionRule{
				{
					Name:   "full_body",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceBody,
				},
			},
			wantKV: map[string]string{"full_body": `<input name="csrf" value="token123">`},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvStore := make(map[string]string)
			err := ExtractValues(tt.rules, nil, resp, kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for k, want := range tt.wantKV {
				if got := kvStore[k]; got != want {
					t.Errorf("kvStore[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestExtractValues_BodyJSON(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		rules   []ExtractionRule
		wantKV  map[string]string
		wantErr bool
	}{
		{
			name: "simple json path",
			body: `{"csrf_token":"xyz789"}`,
			rules: []ExtractionRule{
				{
					Name:     "token",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.csrf_token",
				},
			},
			wantKV: map[string]string{"token": "xyz789"},
		},
		{
			name: "nested json path",
			body: `{"data":{"user":{"id":42}}}`,
			rules: []ExtractionRule{
				{
					Name:     "user_id",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.data.user.id",
				},
			},
			wantKV: map[string]string{"user_id": "42"},
		},
		{
			name: "array index",
			body: `{"items":["a","b","c"]}`,
			rules: []ExtractionRule{
				{
					Name:     "second",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.items[1]",
				},
			},
			wantKV: map[string]string{"second": "b"},
		},
		{
			name: "missing path with default",
			body: `{"other":"value"}`,
			rules: []ExtractionRule{
				{
					Name:     "missing",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.nonexistent",
					Default:  "fallback",
				},
			},
			wantKV: map[string]string{"missing": "fallback"},
		},
		{
			name: "invalid json",
			body: `not json`,
			rules: []ExtractionRule{
				{
					Name:     "val",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.foo",
					Default:  "fallback",
				},
			},
			wantKV: map[string]string{"val": "fallback"},
		},
		{
			name: "boolean value",
			body: `{"active":true}`,
			rules: []ExtractionRule{
				{
					Name:     "active",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.active",
				},
			},
			wantKV: map[string]string{"active": "true"},
		},
		{
			name: "float value",
			body: `{"price":19.99}`,
			rules: []ExtractionRule{
				{
					Name:     "price",
					From:     ExtractionFromResponse,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.price",
				},
			},
			wantKV: map[string]string{"price": "19.99"},
		},
		{
			name: "missing json_path",
			body: `{"foo":"bar"}`,
			rules: []ExtractionRule{
				{
					Name:   "val",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceBodyJSON,
					Default: "fb",
				},
			},
			wantKV: map[string]string{"val": "fb"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &SendResponse{
				StatusCode: 200,
				Body:       []byte(tt.body),
			}
			kvStore := make(map[string]string)
			err := ExtractValues(tt.rules, nil, resp, kvStore)
			if (err != nil) != tt.wantErr {
				t.Errorf("ExtractValues() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			for k, want := range tt.wantKV {
				if got := kvStore[k]; got != want {
					t.Errorf("kvStore[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestExtractValues_Status(t *testing.T) {
	resp := &SendResponse{StatusCode: 302}
	kvStore := make(map[string]string)
	rules := []ExtractionRule{
		{
			Name:   "status",
			From:   ExtractionFromResponse,
			Source: ExtractionSourceStatus,
		},
	}
	if err := ExtractValues(rules, nil, resp, kvStore); err != nil {
		t.Fatalf("ExtractValues() error = %v", err)
	}
	if got := kvStore["status"]; got != "302" {
		t.Errorf("kvStore[\"status\"] = %q, want %q", got, "302")
	}
}

func TestExtractValues_URL(t *testing.T) {
	tests := []struct {
		name    string
		req     *SendRequest
		resp    *SendResponse
		rules   []ExtractionRule
		wantKV  map[string]string
	}{
		{
			name: "extract from request URL",
			req:  &SendRequest{URL: "https://example.com/api/v1/users"},
			resp: &SendResponse{StatusCode: 200},
			rules: []ExtractionRule{
				{
					Name:   "url",
					From:   ExtractionFromRequest,
					Source: ExtractionSourceURL,
				},
			},
			wantKV: map[string]string{"url": "https://example.com/api/v1/users"},
		},
		{
			name: "extract from request URL with regex",
			req:  &SendRequest{URL: "https://example.com/api/v1/users/42"},
			resp: &SendResponse{StatusCode: 200},
			rules: []ExtractionRule{
				{
					Name:   "user_id",
					From:   ExtractionFromRequest,
					Source: ExtractionSourceURL,
					Regex:  `/users/(\d+)`,
					Group:  1,
				},
			},
			wantKV: map[string]string{"user_id": "42"},
		},
		{
			name: "extract from response Location header",
			req:  &SendRequest{URL: "https://example.com/login"},
			resp: &SendResponse{
				StatusCode: 302,
				Headers:    http.Header{"Location": {"https://example.com/dashboard?token=abc"}},
			},
			rules: []ExtractionRule{
				{
					Name:   "redirect_token",
					From:   ExtractionFromResponse,
					Source: ExtractionSourceURL,
					Regex:  `token=([^&]+)`,
					Group:  1,
				},
			},
			wantKV: map[string]string{"redirect_token": "abc"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvStore := make(map[string]string)
			err := ExtractValues(tt.rules, tt.req, tt.resp, kvStore)
			if err != nil {
				t.Fatalf("ExtractValues() error = %v", err)
			}
			for k, want := range tt.wantKV {
				if got := kvStore[k]; got != want {
					t.Errorf("kvStore[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestExtractValues_FromRequest(t *testing.T) {
	req := &SendRequest{
		Method: "POST",
		URL:    "https://example.com/api",
		Headers: map[string][]string{
			"Authorization": {"Bearer token123"},
		},
		Body: []byte(`{"user":"admin"}`),
	}
	resp := &SendResponse{StatusCode: 200}

	tests := []struct {
		name   string
		rules  []ExtractionRule
		wantKV map[string]string
	}{
		{
			name: "extract request header",
			rules: []ExtractionRule{
				{
					Name:       "auth_token",
					From:       ExtractionFromRequest,
					Source:     ExtractionSourceHeader,
					HeaderName: "Authorization",
					Regex:      `Bearer (.+)`,
					Group:      1,
				},
			},
			wantKV: map[string]string{"auth_token": "token123"},
		},
		{
			name: "extract request body json",
			rules: []ExtractionRule{
				{
					Name:     "user",
					From:     ExtractionFromRequest,
					Source:   ExtractionSourceBodyJSON,
					JSONPath: "$.user",
				},
			},
			wantKV: map[string]string{"user": "admin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kvStore := make(map[string]string)
			err := ExtractValues(tt.rules, req, resp, kvStore)
			if err != nil {
				t.Fatalf("ExtractValues() error = %v", err)
			}
			for k, want := range tt.wantKV {
				if got := kvStore[k]; got != want {
					t.Errorf("kvStore[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestMatchRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		pattern string
		group   int
		want    string
		wantErr bool
	}{
		{
			name:    "group 0 full match",
			input:   "abc123def",
			pattern: `\d+`,
			group:   0,
			want:    "123",
		},
		{
			name:    "capture group 1",
			input:   "token=abc123; path=/",
			pattern: `token=([^;]+)`,
			group:   1,
			want:    "abc123",
		},
		{
			name:    "group out of range",
			input:   "abc",
			pattern: `abc`,
			group:   1,
			wantErr: true,
		},
		{
			name:    "no match",
			input:   "abc",
			pattern: `\d+`,
			group:   0,
			wantErr: true,
		},
		{
			name:    "invalid regex",
			input:   "abc",
			pattern: `[invalid`,
			group:   0,
			wantErr: true,
		},
		{
			name:    "pattern too long",
			input:   "abc",
			pattern: strings.Repeat("a", MaxRegexPatternLen+1),
			group:   0,
			wantErr: true,
		},
		{
			name:    "pattern at max length is accepted",
			input:   strings.Repeat("a", MaxRegexPatternLen+100),
			pattern: strings.Repeat("a", MaxRegexPatternLen),
			group:   0,
			want:    strings.Repeat("a", MaxRegexPatternLen),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := matchRegex(tt.input, tt.pattern, tt.group)
			if (err != nil) != tt.wantErr {
				t.Errorf("matchRegex() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("matchRegex() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchRegex_InputSizeCap(t *testing.T) {
	// Create an input larger than MaxRegexInputSize with a match only after the limit.
	prefix := strings.Repeat("x", MaxRegexInputSize)
	input := prefix + "FINDME"

	// The match is beyond the cap, so it should not be found.
	_, err := matchRegex(input, "FINDME", 0)
	if err == nil {
		t.Error("matchRegex() should not find match beyond MaxRegexInputSize")
	}

	// A match within the cap should still work.
	input2 := "FINDME" + prefix
	got, err := matchRegex(input2, "FINDME", 0)
	if err != nil {
		t.Fatalf("matchRegex() error = %v", err)
	}
	if got != "FINDME" {
		t.Errorf("matchRegex() = %q, want %q", got, "FINDME")
	}
}

func TestEvaluateJSONPath(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		path    string
		want    string
		wantErr bool
	}{
		{
			name: "root object key",
			data: `{"name":"test"}`,
			path: "$.name",
			want: "test",
		},
		{
			name: "nested key",
			data: `{"a":{"b":{"c":"deep"}}}`,
			path: "$.a.b.c",
			want: "deep",
		},
		{
			name: "array index",
			data: `{"arr":[10,20,30]}`,
			path: "$.arr[0]",
			want: "10",
		},
		{
			name: "array nested object",
			data: `{"users":[{"name":"alice"},{"name":"bob"}]}`,
			path: "$.users[1].name",
			want: "bob",
		},
		{
			name:    "missing key",
			data:    `{"a":"b"}`,
			path:    "$.nonexistent",
			wantErr: true,
		},
		{
			name:    "index out of bounds",
			data:    `{"arr":[1,2]}`,
			path:    "$.arr[5]",
			wantErr: true,
		},
		{
			name:    "path must start with $",
			data:    `{"a":"b"}`,
			path:    "a",
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			data:    `not json`,
			path:    "$.foo",
			wantErr: true,
		},
		{
			name: "root is $",
			data: `"hello"`,
			path: "$",
			want: "hello",
		},
		{
			name:    "null value",
			data:    `{"a":null}`,
			path:    "$.a",
			wantErr: true,
		},
		{
			name: "object value marshals to json",
			data: `{"a":{"nested":true}}`,
			path: "$.a",
			want: `{"nested":true}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := evaluateJSONPath([]byte(tt.data), tt.path)
			if (err != nil) != tt.wantErr {
				t.Errorf("evaluateJSONPath() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("evaluateJSONPath() = %q, want %q", got, tt.want)
			}
		})
	}
}
