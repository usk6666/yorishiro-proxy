package httputil

import (
	"io"
	gohttp "net/http"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

func TestValidateCRLFHeaders(t *testing.T) {
	tests := []struct {
		name     string
		override map[string]string
		add      map[string]string
		remove   []string
		wantErr  bool
		errMsg   string
	}{
		{
			name:     "valid headers",
			override: map[string]string{"X-Foo": "bar"},
			add:      map[string]string{"X-Baz": "qux"},
			remove:   []string{"X-Remove"},
			wantErr:  false,
		},
		{
			name:     "nil maps",
			override: nil,
			add:      nil,
			remove:   nil,
			wantErr:  false,
		},
		{
			name:     "CRLF in override key",
			override: map[string]string{"X-Bad\r\n": "val"},
			wantErr:  true,
			errMsg:   "CR/LF",
		},
		{
			name:     "CRLF in override value",
			override: map[string]string{"X-Bad": "val\r\n"},
			wantErr:  true,
			errMsg:   "CR/LF",
		},
		{
			name:    "CRLF in add key",
			add:     map[string]string{"X-Bad\n": "val"},
			wantErr: true,
			errMsg:  "CR/LF",
		},
		{
			name:    "CRLF in add value",
			add:     map[string]string{"X-Bad": "val\r"},
			wantErr: true,
			errMsg:  "CR/LF",
		},
		{
			name:    "CRLF in remove key",
			remove:  []string{"X-Bad\r\n"},
			wantErr: true,
			errMsg:  "CR/LF",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCRLFHeaders(tt.override, tt.add, tt.remove)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" && !containsStr(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestApplyHeaderModifications(t *testing.T) {
	h := gohttp.Header{}
	h.Set("X-Existing", "old")
	h.Set("X-Remove", "gone")

	ApplyHeaderModifications(
		h,
		map[string]string{"X-Existing": "new"},
		map[string]string{"X-Add": "added"},
		[]string{"X-Remove"},
	)

	if got := h.Get("X-Existing"); got != "new" {
		t.Errorf("X-Existing = %q, want %q", got, "new")
	}
	if got := h.Get("X-Add"); got != "added" {
		t.Errorf("X-Add = %q, want %q", got, "added")
	}
	if got := h.Get("X-Remove"); got != "" {
		t.Errorf("X-Remove = %q, want empty", got)
	}
}

func TestApplyRequestModifications(t *testing.T) {
	t.Run("override method", func(t *testing.T) {
		req := &gohttp.Request{
			Method: "GET",
			Header: gohttp.Header{},
		}
		action := intercept.InterceptAction{OverrideMethod: "POST"}
		got, err := ApplyRequestModifications(req, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Method != "POST" {
			t.Errorf("Method = %q, want %q", got.Method, "POST")
		}
	})

	t.Run("override URL", func(t *testing.T) {
		req := &gohttp.Request{
			Method: "GET",
			Header: gohttp.Header{},
		}
		action := intercept.InterceptAction{OverrideURL: "https://example.com/path"}
		got, err := ApplyRequestModifications(req, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.URL.String() != "https://example.com/path" {
			t.Errorf("URL = %q, want %q", got.URL.String(), "https://example.com/path")
		}
		if got.Host != "example.com" {
			t.Errorf("Host = %q, want %q", got.Host, "example.com")
		}
	})

	t.Run("invalid URL scheme", func(t *testing.T) {
		req := &gohttp.Request{
			Method: "GET",
			Header: gohttp.Header{},
		}
		action := intercept.InterceptAction{OverrideURL: "ftp://evil.com"}
		_, err := ApplyRequestModifications(req, action)
		if err == nil {
			t.Fatal("expected error for ftp scheme")
		}
	})

	t.Run("override body", func(t *testing.T) {
		req := &gohttp.Request{
			Method: "POST",
			Header: gohttp.Header{},
		}
		body := "new body"
		action := intercept.InterceptAction{OverrideBody: &body}
		got, err := ApplyRequestModifications(req, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		b, _ := io.ReadAll(got.Body)
		if string(b) != "new body" {
			t.Errorf("body = %q, want %q", string(b), "new body")
		}
		if got.ContentLength != 8 {
			t.Errorf("ContentLength = %d, want 8", got.ContentLength)
		}
	})

	t.Run("CRLF in headers rejected", func(t *testing.T) {
		req := &gohttp.Request{
			Method: "GET",
			Header: gohttp.Header{},
		}
		action := intercept.InterceptAction{
			OverrideHeaders: map[string]string{"X-Bad\r\n": "val"},
		}
		_, err := ApplyRequestModifications(req, action)
		if err == nil {
			t.Fatal("expected CRLF error")
		}
	})
}

func TestApplyResponseModifications(t *testing.T) {
	t.Run("override status", func(t *testing.T) {
		resp := &gohttp.Response{
			StatusCode: 200,
			Status:     "200 OK",
			Header:     gohttp.Header{},
		}
		action := intercept.InterceptAction{OverrideStatus: 404}
		got, _, err := ApplyResponseModifications(resp, action, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StatusCode != 404 {
			t.Errorf("StatusCode = %d, want 404", got.StatusCode)
		}
	})

	t.Run("invalid status code", func(t *testing.T) {
		resp := &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{},
		}
		action := intercept.InterceptAction{OverrideStatus: 50}
		_, _, err := ApplyResponseModifications(resp, action, nil)
		if err == nil {
			t.Fatal("expected error for status 50")
		}
	})

	t.Run("override response body", func(t *testing.T) {
		resp := &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{},
		}
		body := "new response"
		action := intercept.InterceptAction{OverrideResponseBody: &body}
		_, gotBody, err := ApplyResponseModifications(resp, action, []byte("old"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(gotBody) != "new response" {
			t.Errorf("body = %q, want %q", string(gotBody), "new response")
		}
		if resp.Header.Get("Content-Length") != "12" {
			t.Errorf("Content-Length = %q, want %q", resp.Header.Get("Content-Length"), "12")
		}
	})

	t.Run("CRLF in response headers rejected", func(t *testing.T) {
		resp := &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{},
		}
		action := intercept.InterceptAction{
			OverrideResponseHeaders: map[string]string{"X-Bad\n": "val"},
		}
		_, _, err := ApplyResponseModifications(resp, action, nil)
		if err == nil {
			t.Fatal("expected CRLF error")
		}
		if !containsStr(err.Error(), "response") {
			t.Errorf("error %q should contain 'response'", err.Error())
		}
	})

	t.Run("header modifications applied", func(t *testing.T) {
		resp := &gohttp.Response{
			StatusCode: 200,
			Header:     gohttp.Header{},
		}
		resp.Header.Set("X-Old", "old")
		action := intercept.InterceptAction{
			OverrideResponseHeaders: map[string]string{"X-Old": "new"},
			AddResponseHeaders:      map[string]string{"X-Add": "added"},
			RemoveResponseHeaders:   []string{"X-Gone"},
		}
		resp.Header.Set("X-Gone", "remove-me")
		got, _, err := ApplyResponseModifications(resp, action, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Header.Get("X-Old") != "new" {
			t.Errorf("X-Old = %q, want %q", got.Header.Get("X-Old"), "new")
		}
		if got.Header.Get("X-Add") != "added" {
			t.Errorf("X-Add = %q, want %q", got.Header.Get("X-Add"), "added")
		}
		if got.Header.Get("X-Gone") != "" {
			t.Errorf("X-Gone = %q, want empty", got.Header.Get("X-Gone"))
		}
	})
}

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
