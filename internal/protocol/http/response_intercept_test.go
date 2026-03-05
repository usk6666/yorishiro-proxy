package http

import (
	gohttp "net/http"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

func TestApplyResponseModifications_OverrideStatus(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     gohttp.Header{},
	}
	action := intercept.InterceptAction{
		Type:           intercept.ActionModifyAndForward,
		OverrideStatus: 403,
	}
	body := []byte("original")

	resp, body, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", resp.StatusCode)
	}
	if resp.Status != "403 Forbidden" {
		t.Errorf("expected status text '403 Forbidden', got %q", resp.Status)
	}
	if string(body) != "original" {
		t.Errorf("body should be unchanged, got %q", string(body))
	}
}

func TestApplyResponseModifications_OverrideHeaders(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header: gohttp.Header{
			"Content-Type": []string{"text/html"},
			"X-Old":        []string{"value"},
		},
	}
	action := intercept.InterceptAction{
		Type: intercept.ActionModifyAndForward,
		OverrideResponseHeaders: map[string]string{
			"Content-Type": "application/json",
		},
	}
	body := []byte("original")

	resp, _, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Old") != "value" {
		t.Errorf("X-Old should be unchanged, got %q", resp.Header.Get("X-Old"))
	}
}

func TestApplyResponseModifications_AddHeaders(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header: gohttp.Header{
			"X-Existing": []string{"v1"},
		},
	}
	action := intercept.InterceptAction{
		Type: intercept.ActionModifyAndForward,
		AddResponseHeaders: map[string]string{
			"X-Existing": "v2",
			"X-New":      "new-value",
		},
	}
	body := []byte("body")

	resp, _, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	vals := resp.Header.Values("X-Existing")
	if len(vals) != 2 {
		t.Fatalf("expected 2 values for X-Existing, got %d", len(vals))
	}
	if vals[0] != "v1" || vals[1] != "v2" {
		t.Errorf("unexpected X-Existing values: %v", vals)
	}
	if resp.Header.Get("X-New") != "new-value" {
		t.Errorf("expected X-New header, got %q", resp.Header.Get("X-New"))
	}
}

func TestApplyResponseModifications_RemoveHeaders(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header: gohttp.Header{
			"X-Remove": []string{"value"},
			"X-Keep":   []string{"keep"},
		},
	}
	action := intercept.InterceptAction{
		Type:                  intercept.ActionModifyAndForward,
		RemoveResponseHeaders: []string{"X-Remove"},
	}
	body := []byte("body")

	resp, _, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Header.Get("X-Remove") != "" {
		t.Errorf("X-Remove should be removed, got %q", resp.Header.Get("X-Remove"))
	}
	if resp.Header.Get("X-Keep") != "keep" {
		t.Errorf("X-Keep should be unchanged, got %q", resp.Header.Get("X-Keep"))
	}
}

func TestApplyResponseModifications_OverrideBody(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{},
	}
	overrideBody := "new body content"
	action := intercept.InterceptAction{
		Type:                 intercept.ActionModifyAndForward,
		OverrideResponseBody: &overrideBody,
	}
	body := []byte("original")

	resp, body, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(body) != "new body content" {
		t.Errorf("expected body %q, got %q", "new body content", string(body))
	}
	// F-1: Content-Length should be updated to match new body.
	if resp.Header.Get("Content-Length") != "16" {
		t.Errorf("expected Content-Length 16, got %q", resp.Header.Get("Content-Length"))
	}
}

func TestApplyResponseModifications_AllFields(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header: gohttp.Header{
			"Content-Type":  []string{"text/html"},
			"X-Remove-This": []string{"gone"},
		},
	}
	overrideBody := `{"error":"forbidden"}`
	action := intercept.InterceptAction{
		Type:           intercept.ActionModifyAndForward,
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

	resp, body, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 403 {
		t.Errorf("expected status 403, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("X-Custom") != "added" {
		t.Errorf("expected X-Custom header, got %q", resp.Header.Get("X-Custom"))
	}
	if resp.Header.Get("X-Remove-This") != "" {
		t.Errorf("X-Remove-This should be removed")
	}
	if string(body) != `{"error":"forbidden"}` {
		t.Errorf("expected modified body, got %q", string(body))
	}
}

func TestApplyResponseModifications_ZeroStatus(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Status:     "200 OK",
		Header:     gohttp.Header{},
	}
	action := intercept.InterceptAction{
		Type:           intercept.ActionModifyAndForward,
		OverrideStatus: 0, // Zero means no override.
	}
	body := []byte("body")

	resp, _, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.StatusCode != 200 {
		t.Errorf("status should be unchanged when OverrideStatus is 0, got %d", resp.StatusCode)
	}
}

func TestApplyResponseModifications_NilBody(t *testing.T) {
	resp := &gohttp.Response{
		StatusCode: 200,
		Header:     gohttp.Header{},
	}
	action := intercept.InterceptAction{
		Type:                 intercept.ActionModifyAndForward,
		OverrideResponseBody: nil,
	}
	body := []byte("original")

	_, body, err := applyResponseModifications(resp, action, body)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if string(body) != "original" {
		t.Errorf("body should be unchanged when OverrideResponseBody is nil, got %q", string(body))
	}
}

func TestApplyResponseModifications_InvalidStatusCode(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{"status below 100", 50},
		{"status above 999", 1000},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &gohttp.Response{
				StatusCode: 200,
				Status:     "200 OK",
				Header:     gohttp.Header{},
			}
			action := intercept.InterceptAction{
				Type:           intercept.ActionModifyAndForward,
				OverrideStatus: tt.status,
			}
			_, _, err := applyResponseModifications(resp, action, []byte("body"))
			if err == nil {
				t.Error("expected error for invalid status code")
			}
		})
	}
}

func TestApplyResponseModifications_CRLFValidation(t *testing.T) {
	tests := []struct {
		name   string
		action intercept.InterceptAction
		errMsg string
	}{
		{
			name: "override header key with CRLF",
			action: intercept.InterceptAction{
				Type:                    intercept.ActionModifyAndForward,
				OverrideResponseHeaders: map[string]string{"X-Bad\r\n": "value"},
			},
			errMsg: "CR/LF",
		},
		{
			name: "override header value with CRLF",
			action: intercept.InterceptAction{
				Type:                    intercept.ActionModifyAndForward,
				OverrideResponseHeaders: map[string]string{"X-Bad": "val\r\nue"},
			},
			errMsg: "CR/LF",
		},
		{
			name: "add header key with CRLF",
			action: intercept.InterceptAction{
				Type:               intercept.ActionModifyAndForward,
				AddResponseHeaders: map[string]string{"X-Add\n": "value"},
			},
			errMsg: "CR/LF",
		},
		{
			name: "add header value with CRLF",
			action: intercept.InterceptAction{
				Type:               intercept.ActionModifyAndForward,
				AddResponseHeaders: map[string]string{"X-Add": "val\rue"},
			},
			errMsg: "CR/LF",
		},
		{
			name: "remove header key with CRLF",
			action: intercept.InterceptAction{
				Type:                  intercept.ActionModifyAndForward,
				RemoveResponseHeaders: []string{"X-Remove\r\n"},
			},
			errMsg: "CR/LF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &gohttp.Response{
				StatusCode: 200,
				Header:     gohttp.Header{},
			}
			_, _, err := applyResponseModifications(resp, tt.action, []byte("body"))
			if err == nil {
				t.Error("expected error for CRLF injection")
			}
			if err != nil && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("expected error containing %q, got %q", tt.errMsg, err.Error())
			}
		})
	}
}
