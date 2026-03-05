package http

import (
	gohttp "net/http"
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

	resp, body = applyResponseModifications(resp, action, body)

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

	resp, _ = applyResponseModifications(resp, action, body)

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

	resp, _ = applyResponseModifications(resp, action, body)

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

	resp, _ = applyResponseModifications(resp, action, body)

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

	_, body = applyResponseModifications(resp, action, body)

	if string(body) != "new body content" {
		t.Errorf("expected body %q, got %q", "new body content", string(body))
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

	resp, body = applyResponseModifications(resp, action, body)

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

	resp, _ = applyResponseModifications(resp, action, body)

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

	_, body = applyResponseModifications(resp, action, body)

	if string(body) != "original" {
		t.Errorf("body should be unchanged when OverrideResponseBody is nil, got %q", string(body))
	}
}
