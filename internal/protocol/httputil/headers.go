package httputil

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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
// to the given RawHeaders in that order.
func ApplyHeaderModifications(h *parser.RawHeaders, override, add map[string]string, remove []string) {
	for _, key := range remove {
		h.Del(key)
	}
	for key, val := range override {
		h.Del(key)
		h.Set(key, val)
	}
	for key, val := range add {
		*h = append(*h, parser.RawHeader{Name: key, Value: val})
	}
}

// ApplyRequestModifications applies the modifications from a modify_and_forward
// action directly on a RawRequest. It validates URL scheme, CRLF injection,
// and then applies method/URL/header/body overrides.
//
// Returns the modified RawRequest, the (possibly overridden) body bytes, the
// parsed URL after override (nil when no URL override was applied), and any error.
func ApplyRequestModifications(req *parser.RawRequest, bodyBytes []byte, action intercept.InterceptAction) (*parser.RawRequest, []byte, *url.URL, error) {
	// Validate all inputs before mutating the request (CWE-113 / Copilot C-1).
	if err := ValidateCRLFHeaders(action.OverrideHeaders, action.AddHeaders, action.RemoveHeaders); err != nil {
		return req, bodyBytes, nil, err
	}

	var modURL *url.URL
	if action.OverrideURL != "" {
		parsed, err := validateURL(action.OverrideURL)
		if err != nil {
			return req, bodyBytes, nil, err
		}
		modURL = parsed
	}

	// All validations passed — apply mutations.
	if action.OverrideMethod != "" {
		req.Method = action.OverrideMethod
	}

	if modURL != nil {
		// Update RequestURI. Preserve absolute-form when scheme+host are present.
		if modURL.Scheme != "" && modURL.Host != "" {
			req.RequestURI = modURL.String()
		} else {
			req.RequestURI = modURL.RequestURI()
		}
		// Update Host header to match the override URL.
		req.Headers.Set("Host", modURL.Host)
	}

	ApplyHeaderModifications(&req.Headers, action.OverrideHeaders, action.AddHeaders, action.RemoveHeaders)

	// When OverrideURL is set, enforce Host to match the validated URL
	// after header modifications. Prevents Host from diverging via header rules.
	// Use Del+Set to ensure exactly one Host header on the wire (AddHeaders
	// may have appended a duplicate that Set alone would not remove).
	if modURL != nil {
		req.Headers.Del("Host")
		req.Headers.Set("Host", modURL.Host)
	}

	if action.OverrideBody != nil {
		bodyBytes = []byte(*action.OverrideBody)
	}

	// Sync Content-Length and Transfer-Encoding headers with the actual body.
	// Use Del+Set to ensure exactly one Content-Length on the wire even if
	// AddHeaders appended a duplicate that Set alone would not remove.
	req.Headers.Del("Transfer-Encoding")
	req.Headers.Del("Content-Length")
	if len(bodyBytes) > 0 {
		req.Headers.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	}

	req.Body = bytes.NewReader(bodyBytes)

	return req, bodyBytes, modURL, nil
}

// ApplyResponseModifications applies the modifications from a modify_and_forward
// action directly on a RawResponse. It validates status code range, CRLF
// injection, and then applies status/header/body overrides.
func ApplyResponseModifications(resp *parser.RawResponse, action intercept.InterceptAction, body []byte) (*parser.RawResponse, []byte, error) {
	// Validate all inputs before mutating the response.
	if action.OverrideStatus > 0 {
		if action.OverrideStatus < 100 || action.OverrideStatus > 999 {
			return resp, body, fmt.Errorf("invalid override status code %d: must be between 100 and 999", action.OverrideStatus)
		}
	}

	if err := ValidateCRLFHeaders(action.OverrideResponseHeaders, action.AddResponseHeaders, action.RemoveResponseHeaders); err != nil {
		return resp, body, fmt.Errorf("response %w", err)
	}

	// All validations passed — apply mutations.
	if action.OverrideStatus > 0 {
		resp.StatusCode = action.OverrideStatus
		resp.Status = FormatStatus(action.OverrideStatus)
	}

	ApplyHeaderModifications(&resp.Headers, action.OverrideResponseHeaders, action.AddResponseHeaders, action.RemoveResponseHeaders)

	if action.OverrideResponseBody != nil {
		body = []byte(*action.OverrideResponseBody)
		resp.Headers.Del("Transfer-Encoding")
		resp.Headers.Del("Content-Length")
		if len(body) > 0 {
			resp.Headers.Set("Content-Length", strconv.Itoa(len(body)))
		}
		resp.Body = bytes.NewReader(body)
	}

	return resp, body, nil
}

// validateURL validates a URL override string and enforces http/https-only
// scheme restriction to prevent SSRF (CWE-918). It also rejects malformed
// URLs such as those with empty host, opaque form, or fragments.
func validateURL(overrideURL string) (*url.URL, error) {
	parsed, err := url.Parse(overrideURL)
	if err != nil {
		return nil, fmt.Errorf("invalid override URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return nil, fmt.Errorf("unsupported override URL scheme %q: only http and https are allowed", parsed.Scheme)
	}
	if parsed.Host == "" {
		return nil, fmt.Errorf("invalid override URL %q: host is required", overrideURL)
	}
	if parsed.Opaque != "" {
		return nil, fmt.Errorf("invalid override URL %q: opaque URLs are not allowed", overrideURL)
	}
	if parsed.Fragment != "" {
		return nil, fmt.Errorf("invalid override URL %q: fragments are not allowed", overrideURL)
	}
	return parsed, nil
}
