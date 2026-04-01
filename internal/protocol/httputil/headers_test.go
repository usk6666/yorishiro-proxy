package httputil

import (
	"bytes"
	"io"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
	h := parser.RawHeaders{
		{Name: "X-Existing", Value: "old"},
		{Name: "X-Remove", Value: "gone"},
	}

	ApplyHeaderModifications(
		&h,
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
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideMethod: "POST"}
		got, _, _, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Method != "POST" {
			t.Errorf("Method = %q, want %q", got.Method, "POST")
		}
	})

	t.Run("override URL", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/original",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "Host", Value: "original.com"},
			},
		}
		action := intercept.InterceptAction{OverrideURL: "https://example.com/path"}
		got, _, modURL, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if modURL == nil {
			t.Fatal("expected non-nil modURL")
		}
		if modURL.String() != "https://example.com/path" {
			t.Errorf("modURL = %q, want %q", modURL.String(), "https://example.com/path")
		}
		// RequestURI should be the full URL (absolute-form).
		if got.RequestURI != "https://example.com/path" {
			t.Errorf("RequestURI = %q, want %q", got.RequestURI, "https://example.com/path")
		}
		// Host header should be updated.
		if got.Headers.Get("Host") != "example.com" {
			t.Errorf("Host = %q, want %q", got.Headers.Get("Host"), "example.com")
		}
	})

	t.Run("invalid URL scheme", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideURL: "ftp://evil.com"}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected error for ftp scheme")
		}
	})

	t.Run("override body", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "POST",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		body := "new body"
		action := intercept.InterceptAction{OverrideBody: &body}
		got, gotBody, _, err := ApplyRequestModifications(req, []byte("old body"), action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(gotBody) != "new body" {
			t.Errorf("body = %q, want %q", string(gotBody), "new body")
		}
		// Body reader should also reflect the new body.
		b, _ := io.ReadAll(got.Body)
		if string(b) != "new body" {
			t.Errorf("Body reader = %q, want %q", string(b), "new body")
		}
		// Content-Length header should be updated.
		if got.Headers.Get("Content-Length") != "8" {
			t.Errorf("Content-Length = %q, want %q", got.Headers.Get("Content-Length"), "8")
		}
	})

	t.Run("CRLF in headers rejected", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{
			OverrideHeaders: map[string]string{"X-Bad\r\n": "val"},
		}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected CRLF error")
		}
	})

	t.Run("CRLF validation before mutation", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/original",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{
			OverrideMethod:  "POST",
			OverrideHeaders: map[string]string{"X-Bad\r\n": "val"},
		}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected CRLF error")
		}
		// Method must not be mutated when validation fails.
		if req.Method != "GET" {
			t.Errorf("Method = %q, want %q (should not be mutated on validation error)", req.Method, "GET")
		}
	})

	t.Run("URL with empty host rejected", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideURL: "https:///path"}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected error for URL with empty host")
		}
	})

	t.Run("opaque URL rejected", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideURL: "https:example.com/path"}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected error for opaque URL")
		}
	})

	t.Run("URL with fragment rejected", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideURL: "https://example.com/path#frag"}
		_, _, _, err := ApplyRequestModifications(req, nil, action)
		if err == nil {
			t.Fatal("expected error for URL with fragment")
		}
	})

	t.Run("no URL override returns nil modURL", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideMethod: "POST"}
		_, _, modURL, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if modURL != nil {
			t.Errorf("modURL = %v, want nil when no URL override", modURL)
		}
	})

	t.Run("transfer-encoding removed and content-length synced", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "POST",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Length", Value: "999"},
			},
		}
		body := []byte("hello")
		action := intercept.InterceptAction{}
		got, _, _, err := ApplyRequestModifications(req, body, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Headers.Get("Transfer-Encoding") != "" {
			t.Errorf("Transfer-Encoding should be removed, got %q", got.Headers.Get("Transfer-Encoding"))
		}
		if got.Headers.Get("Content-Length") != "5" {
			t.Errorf("Content-Length = %q, want %q", got.Headers.Get("Content-Length"), "5")
		}
	})

	t.Run("empty body removes content-length", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "Content-Length", Value: "42"},
			},
		}
		action := intercept.InterceptAction{}
		got, _, _, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Headers.Get("Content-Length") != "" {
			t.Errorf("Content-Length should be removed for empty body, got %q", got.Headers.Get("Content-Length"))
		}
	})

	t.Run("header modifications applied", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "X-Old", Value: "old"},
				{Name: "X-Gone", Value: "remove-me"},
			},
		}
		action := intercept.InterceptAction{
			OverrideHeaders: map[string]string{"X-Old": "new"},
			AddHeaders:      map[string]string{"X-Add": "added"},
			RemoveHeaders:   []string{"X-Gone"},
		}
		got, _, _, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Headers.Get("X-Old") != "new" {
			t.Errorf("X-Old = %q, want %q", got.Headers.Get("X-Old"), "new")
		}
		if got.Headers.Get("X-Add") != "added" {
			t.Errorf("X-Add = %q, want %q", got.Headers.Get("X-Add"), "added")
		}
		if got.Headers.Get("X-Gone") != "" {
			t.Errorf("X-Gone = %q, want empty", got.Headers.Get("X-Gone"))
		}
	})
}

func TestApplyResponseModifications(t *testing.T) {
	t.Run("override status", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Status:     "200 OK",
			Headers:    parser.RawHeaders{},
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
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideStatus: 50}
		_, _, err := ApplyResponseModifications(resp, action, nil)
		if err == nil {
			t.Fatal("expected error for status 50")
		}
	})

	t.Run("override response body", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers:    parser.RawHeaders{},
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
		if resp.Headers.Get("Content-Length") != "12" {
			t.Errorf("Content-Length = %q, want %q", resp.Headers.Get("Content-Length"), "12")
		}
	})

	t.Run("CRLF in response headers rejected", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers:    parser.RawHeaders{},
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
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers: parser.RawHeaders{
				{Name: "X-Old", Value: "old"},
				{Name: "X-Gone", Value: "remove-me"},
			},
		}
		action := intercept.InterceptAction{
			OverrideResponseHeaders: map[string]string{"X-Old": "new"},
			AddResponseHeaders:      map[string]string{"X-Add": "added"},
			RemoveResponseHeaders:   []string{"X-Gone"},
		}
		got, _, err := ApplyResponseModifications(resp, action, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Headers.Get("X-Old") != "new" {
			t.Errorf("X-Old = %q, want %q", got.Headers.Get("X-Old"), "new")
		}
		if got.Headers.Get("X-Add") != "added" {
			t.Errorf("X-Add = %q, want %q", got.Headers.Get("X-Add"), "added")
		}
		if got.Headers.Get("X-Gone") != "" {
			t.Errorf("X-Gone = %q, want empty", got.Headers.Get("X-Gone"))
		}
	})

	t.Run("zero status means no override", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Status:     "200 OK",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideStatus: 0}
		got, _, err := ApplyResponseModifications(resp, action, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StatusCode != 200 {
			t.Errorf("StatusCode = %d, want 200", got.StatusCode)
		}
	})

	t.Run("nil body unchanged", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideResponseBody: nil}
		_, gotBody, err := ApplyResponseModifications(resp, action, []byte("original"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(gotBody) != "original" {
			t.Errorf("body = %q, want %q", string(gotBody), "original")
		}
	})

	t.Run("all fields combined", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Status:     "200 OK",
			Headers: parser.RawHeaders{
				{Name: "Content-Type", Value: "text/html"},
				{Name: "X-Remove-This", Value: "gone"},
			},
		}
		overrideBody := `{"error":"forbidden"}`
		action := intercept.InterceptAction{
			OverrideStatus: 403,
			OverrideResponseHeaders: map[string]string{
				"Content-Type": "application/json",
			},
			AddResponseHeaders: map[string]string{
				"X-Custom": "added",
			},
			RemoveResponseHeaders: []string{"X-Remove-This"},
			OverrideResponseBody:  &overrideBody,
		}
		body := []byte("<html>original</html>")

		got, gotBody, err := ApplyResponseModifications(resp, action, body)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.StatusCode != 403 {
			t.Errorf("StatusCode = %d, want 403", got.StatusCode)
		}
		if got.Headers.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got.Headers.Get("Content-Type"), "application/json")
		}
		if got.Headers.Get("X-Custom") != "added" {
			t.Errorf("X-Custom = %q, want %q", got.Headers.Get("X-Custom"), "added")
		}
		if got.Headers.Get("X-Remove-This") != "" {
			t.Errorf("X-Remove-This should be removed")
		}
		if string(gotBody) != `{"error":"forbidden"}` {
			t.Errorf("body = %q, want %q", string(gotBody), `{"error":"forbidden"}`)
		}
	})

	t.Run("CRLF validation before status mutation", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Status:     "200 OK",
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{
			OverrideStatus:          403,
			OverrideResponseHeaders: map[string]string{"X-Bad\r\n": "val"},
		}
		_, _, err := ApplyResponseModifications(resp, action, nil)
		if err == nil {
			t.Fatal("expected CRLF error")
		}
		// Status must not be mutated when validation fails.
		if resp.StatusCode != 200 {
			t.Errorf("StatusCode = %d, want 200 (should not be mutated on validation error)", resp.StatusCode)
		}
		if resp.Status != "200 OK" {
			t.Errorf("Status = %q, want %q (should not be mutated on validation error)", resp.Status, "200 OK")
		}
	})

	t.Run("response body override removes transfer-encoding", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Length", Value: "999"},
			},
		}
		body := "new body"
		action := intercept.InterceptAction{OverrideResponseBody: &body}
		got, gotBody, err := ApplyResponseModifications(resp, action, []byte("old"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(gotBody) != "new body" {
			t.Errorf("body = %q, want %q", string(gotBody), "new body")
		}
		if got.Headers.Get("Transfer-Encoding") != "" {
			t.Errorf("Transfer-Encoding should be removed, got %q", got.Headers.Get("Transfer-Encoding"))
		}
		if got.Headers.Get("Content-Length") != "8" {
			t.Errorf("Content-Length = %q, want %q", got.Headers.Get("Content-Length"), "8")
		}
	})

	t.Run("response body override with empty body removes content-length", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers: parser.RawHeaders{
				{Name: "Transfer-Encoding", Value: "chunked"},
				{Name: "Content-Length", Value: "42"},
			},
		}
		emptyBody := ""
		action := intercept.InterceptAction{OverrideResponseBody: &emptyBody}
		got, gotBody, err := ApplyResponseModifications(resp, action, []byte("old"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if string(gotBody) != "" {
			t.Errorf("body = %q, want empty", string(gotBody))
		}
		if got.Headers.Get("Transfer-Encoding") != "" {
			t.Errorf("Transfer-Encoding should be removed, got %q", got.Headers.Get("Transfer-Encoding"))
		}
		if got.Headers.Get("Content-Length") != "" {
			t.Errorf("Content-Length should be removed for empty body, got %q", got.Headers.Get("Content-Length"))
		}
	})

	t.Run("invalid status above 999", func(t *testing.T) {
		resp := &parser.RawResponse{
			StatusCode: 200,
			Headers:    parser.RawHeaders{},
		}
		action := intercept.InterceptAction{OverrideStatus: 1000}
		_, _, err := ApplyResponseModifications(resp, action, nil)
		if err == nil {
			t.Fatal("expected error for status 1000")
		}
	})
}

func TestApplyRequestModifications_UserHostOverridePreservedWithOverrideURL(t *testing.T) {
	// MITM proxy must allow pentester to set Host != URL for Host header
	// injection testing. When OverrideURL sets Host initially, a subsequent
	// AddHeaders Host must win (user intent takes priority).
	t.Run("AddHeaders Host overrides URL-derived Host", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "Host", Value: "original.com"},
			},
		}
		action := intercept.InterceptAction{
			OverrideURL: "https://backend.example.com/path",
			AddHeaders:  map[string]string{"Host": "attacker.com"},
		}
		got, _, modURL, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if modURL == nil {
			t.Fatal("expected non-nil modURL")
		}
		// The user-specified Host via AddHeaders must be preserved for
		// pentesting Host header injection scenarios.
		hosts := got.Headers.Values("Host")
		found := false
		for _, h := range hosts {
			if h == "attacker.com" {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("user-specified Host 'attacker.com' not found in headers: %v", hosts)
		}
	})

	t.Run("OverrideHeaders Host overrides URL-derived Host", func(t *testing.T) {
		req := &parser.RawRequest{
			Method:     "GET",
			RequestURI: "/test",
			Proto:      "HTTP/1.1",
			Headers: parser.RawHeaders{
				{Name: "Host", Value: "original.com"},
			},
		}
		action := intercept.InterceptAction{
			OverrideURL:     "https://backend.example.com/path",
			OverrideHeaders: map[string]string{"Host": "attacker.com"},
		}
		got, _, _, err := ApplyRequestModifications(req, nil, action)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		// OverrideHeaders replaces the URL-derived Host with user value.
		if got.Headers.Get("Host") != "attacker.com" {
			t.Errorf("Host = %q, want %q", got.Headers.Get("Host"), "attacker.com")
		}
	})
}

func TestApplyResponseModifications_BodyReaderUpdated(t *testing.T) {
	// When OverrideResponseBody is set, resp.Body must reflect the new body.
	resp := &parser.RawResponse{
		StatusCode: 200,
		Status:     "200 OK",
		Headers:    parser.RawHeaders{},
		Body:       bytes.NewReader([]byte("old body")),
	}
	newBody := "new response body"
	action := intercept.InterceptAction{OverrideResponseBody: &newBody}
	got, gotBody, err := ApplyResponseModifications(resp, action, []byte("old body"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(gotBody) != "new response body" {
		t.Errorf("body = %q, want %q", string(gotBody), "new response body")
	}
	// Verify resp.Body reader contains the overridden body.
	b, readErr := io.ReadAll(got.Body)
	if readErr != nil {
		t.Fatalf("failed to read Body: %v", readErr)
	}
	if string(b) != "new response body" {
		t.Errorf("Body reader = %q, want %q", string(b), "new response body")
	}
}

func TestApplyRequestModificationsRaw_Delegates(t *testing.T) {
	// Verify that ApplyRequestModificationsRaw delegates to ApplyRequestModifications.
	req := &parser.RawRequest{
		Method:     "GET",
		RequestURI: "/test",
		Proto:      "HTTP/1.1",
		Headers:    parser.RawHeaders{},
	}
	action := intercept.InterceptAction{OverrideMethod: "PUT"}
	got, _, _, err := ApplyRequestModificationsRaw(req, nil, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Method != "PUT" {
		t.Errorf("Method = %q, want %q", got.Method, "PUT")
	}
}

func TestApplyResponseModificationsRaw_Delegates(t *testing.T) {
	// Verify that ApplyResponseModificationsRaw delegates to ApplyResponseModifications.
	resp := &parser.RawResponse{
		StatusCode: 200,
		Status:     "200 OK",
		Headers:    parser.RawHeaders{},
	}
	action := intercept.InterceptAction{OverrideStatus: 503}
	got, _, err := ApplyResponseModificationsRaw(resp, nil, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.StatusCode != 503 {
		t.Errorf("StatusCode = %d, want 503", got.StatusCode)
	}
}

func TestApplyRequestModifications_BodyReader(t *testing.T) {
	// Verify that the Body reader on the returned RawRequest reflects the body.
	req := &parser.RawRequest{
		Method:     "POST",
		RequestURI: "/submit",
		Proto:      "HTTP/1.1",
		Headers:    parser.RawHeaders{},
	}
	bodyBytes := []byte("request-body")
	action := intercept.InterceptAction{}
	got, gotBody, _, err := ApplyRequestModifications(req, bodyBytes, action)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(gotBody, bodyBytes) {
		t.Errorf("body = %q, want %q", gotBody, bodyBytes)
	}
	b, _ := io.ReadAll(got.Body)
	if !bytes.Equal(b, bodyBytes) {
		t.Errorf("Body reader = %q, want %q", b, bodyBytes)
	}
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
