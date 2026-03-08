package httputil

import (
	"bytes"
	"fmt"
	"io"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// ValidateCRLFHeaders checks that none of the header keys or values in
// override, add, or remove maps contain CR or LF characters (CWE-113).
func ValidateCRLFHeaders(override, add map[string]string, remove []string) error {
	for key, val := range override {
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
			return fmt.Errorf("header %q contains CR/LF characters (header injection attempt)", key)
		}
	}
	for key, val := range add {
		if strings.ContainsAny(key, "\r\n") || strings.ContainsAny(val, "\r\n") {
			return fmt.Errorf("header %q contains CR/LF characters (header injection attempt)", key)
		}
	}
	for _, key := range remove {
		if strings.ContainsAny(key, "\r\n") {
			return fmt.Errorf("remove header key %q contains CR/LF characters (header injection attempt)", key)
		}
	}
	return nil
}

// ApplyHeaderModifications applies remove, override (set), and add operations
// to the given http.Header in that order.
func ApplyHeaderModifications(h gohttp.Header, override, add map[string]string, remove []string) {
	for _, key := range remove {
		h.Del(key)
	}
	for key, val := range override {
		h.Set(key, val)
	}
	for key, val := range add {
		h.Add(key, val)
	}
}

// ApplyRequestModifications applies the modifications from a modify_and_forward
// action to an HTTP request. It validates URL scheme, CRLF injection, and then
// applies method/URL/header/body overrides.
func ApplyRequestModifications(req *gohttp.Request, action intercept.InterceptAction) (*gohttp.Request, error) {
	if action.OverrideMethod != "" {
		req.Method = action.OverrideMethod
	}

	if err := validateAndApplyURL(req, action.OverrideURL); err != nil {
		return req, err
	}

	if err := ValidateCRLFHeaders(action.OverrideHeaders, action.AddHeaders, action.RemoveHeaders); err != nil {
		return req, err
	}

	ApplyHeaderModifications(req.Header, action.OverrideHeaders, action.AddHeaders, action.RemoveHeaders)

	if action.OverrideBody != nil {
		bodyBytes := []byte(*action.OverrideBody)
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		req.ContentLength = int64(len(bodyBytes))
	}

	return req, nil
}

// ApplyResponseModifications applies the modifications from a modify_and_forward
// action to an HTTP response. It validates status code range, CRLF injection,
// and then applies status/header/body overrides.
func ApplyResponseModifications(resp *gohttp.Response, action intercept.InterceptAction, body []byte) (*gohttp.Response, []byte, error) {
	if action.OverrideStatus > 0 {
		if action.OverrideStatus < 100 || action.OverrideStatus > 999 {
			return resp, body, fmt.Errorf("invalid override status code %d: must be between 100 and 999", action.OverrideStatus)
		}
		resp.StatusCode = action.OverrideStatus
		resp.Status = fmt.Sprintf("%d %s", action.OverrideStatus, gohttp.StatusText(action.OverrideStatus))
	}

	if err := ValidateCRLFHeaders(action.OverrideResponseHeaders, action.AddResponseHeaders, action.RemoveResponseHeaders); err != nil {
		return resp, body, fmt.Errorf("response %w", err)
	}

	ApplyHeaderModifications(resp.Header, action.OverrideResponseHeaders, action.AddResponseHeaders, action.RemoveResponseHeaders)

	if action.OverrideResponseBody != nil {
		body = []byte(*action.OverrideResponseBody)
		resp.Header.Set("Content-Length", strconv.Itoa(len(body)))
	}

	return resp, body, nil
}

// validateAndApplyURL validates and applies a URL override to the request.
// It enforces http/https-only scheme restriction to prevent SSRF (CWE-918).
func validateAndApplyURL(req *gohttp.Request, overrideURL string) error {
	if overrideURL == "" {
		return nil
	}
	parsed, err := url.Parse(overrideURL)
	if err != nil {
		return fmt.Errorf("invalid override URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("unsupported override URL scheme %q: only http and https are allowed", parsed.Scheme)
	}
	req.URL = parsed
	req.Host = parsed.Host
	return nil
}
