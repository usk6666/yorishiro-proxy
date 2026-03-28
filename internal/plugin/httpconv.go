package plugin

import (
	"fmt"
	gohttp "net/http"
	"net/url"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// HTTPRequestToMap converts an HTTP request and its associated metadata into
// a map[string]any suitable for passing to plugin hooks via Dispatch.
// The resulting map contains the following keys:
//   - method: HTTP method (string)
//   - url: full URL string (string)
//   - scheme: URL scheme (string)
//   - host: request host (string)
//   - path: URL path (string)
//   - query: raw query string (string)
//   - headers: map of header name to list of values (map[string]any with []any values)
//   - body: request body bytes ([]byte)
//   - conn_info: connection metadata (map[string]any)
//   - protocol: protocol identifier (string, e.g. "HTTP/1.x")
func HTTPRequestToMap(req *gohttp.Request, body []byte, connInfo *ConnInfo, protocol string) map[string]any {
	if req == nil {
		return map[string]any{}
	}
	headers := headersToMap(httputil.HTTPHeaderToRawHeaders(req.Header))
	// Ensure Host header is present (Go strips it from Header and stores in req.Host).
	if req.Host != "" {
		headers["Host"] = []any{req.Host}
	}

	urlStr := ""
	scheme := ""
	host := req.Host
	path := ""
	query := ""
	if req.URL != nil {
		urlStr = req.URL.String()
		scheme = req.URL.Scheme
		if req.URL.Host != "" {
			host = req.URL.Host
		}
		path = req.URL.Path
		query = req.URL.RawQuery
	}

	m := map[string]any{
		"method":   req.Method,
		"url":      urlStr,
		"scheme":   scheme,
		"host":     host,
		"path":     path,
		"query":    query,
		"headers":  headers,
		"body":     body,
		"protocol": protocol,
	}
	if connInfo != nil {
		m["conn_info"] = connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}
	return m
}

// HTTPResponseToMap converts an HTTP response and its associated metadata into
// a map[string]any suitable for passing to plugin hooks via Dispatch.
// The resulting map contains the following keys:
//   - status_code: HTTP status code (int)
//   - headers: map of header name to list of values (map[string]any with []any values)
//   - trailers: map of trailer name to list of values (map[string]any with []any values)
//   - body: response body bytes ([]byte)
//   - conn_info: connection metadata (map[string]any)
//   - protocol: protocol identifier (string)
//   - request: read-only request summary (map[string]any with method, url, host)
func HTTPResponseToMap(resp *gohttp.Response, body []byte, req *gohttp.Request, connInfo *ConnInfo, protocol string) map[string]any {
	if resp == nil {
		return map[string]any{}
	}

	m := map[string]any{
		"status_code": resp.StatusCode,
		"headers":     headersToMap(httputil.HTTPHeaderToRawHeaders(resp.Header)),
		"trailers":    headersToMap(httputil.HTTPHeaderToRawHeaders(resp.Trailer)),
		"body":        body,
		"protocol":    protocol,
	}
	if connInfo != nil {
		m["conn_info"] = connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}

	// Include a read-only request summary for correlation.
	if req != nil {
		reqSummary := map[string]any{
			"method": req.Method,
			"host":   req.Host,
		}
		if req.URL != nil {
			reqSummary["url"] = req.URL.String()
		}
		m["request"] = reqSummary
	}
	return m
}

// InjectRawFrames adds raw frame bytes to a hook data map under the
// "raw_frames" key. Each element is a []byte representing a single HTTP/2
// frame. If rawFrames is nil or empty, the key is not added, maintaining
// backward compatibility with existing plugins that do not use raw_frames.
func InjectRawFrames(data map[string]any, rawFrames [][]byte) {
	if len(rawFrames) == 0 {
		return
	}
	// Convert [][]byte to []any for Starlark compatibility.
	frames := make([]any, len(rawFrames))
	for i, f := range rawFrames {
		frames[i] = f
	}
	data["raw_frames"] = frames
}

// ApplyHTTPRequestChanges applies modifications from a plugin hook result
// back to an HTTP request. It updates method, URL, host, headers, and body
// from the data map. Only keys present in the data map are applied.
func ApplyHTTPRequestChanges(req *gohttp.Request, data map[string]any) (*gohttp.Request, []byte, error) {
	if data == nil {
		return req, nil, nil
	}

	applyMethod(req, data)

	if err := applyURL(req, data); err != nil {
		return req, nil, err
	}

	applyHost(req, data)
	applyRequestHeaders(req, data)
	body := extractBody(data)

	return req, body, nil
}

// applyMethod updates the request method from the data map if present.
func applyMethod(req *gohttp.Request, data map[string]any) {
	if v, ok := data["method"].(string); ok && v != "" {
		req.Method = v
	}
}

// applyURL updates the request URL from the data map if present.
// Only http, https, and empty schemes are allowed to prevent SSRF.
func applyURL(req *gohttp.Request, data map[string]any) error {
	v, ok := data["url"].(string)
	if !ok || v == "" {
		return nil
	}
	parsed, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("plugin returned invalid URL: %w", err)
	}
	// Only allow http and https schemes to prevent SSRF via plugin URL rewrite.
	// Empty scheme is permitted for relative URLs.
	switch parsed.Scheme {
	case "http", "https", "":
		req.URL = parsed
		if parsed.Host != "" {
			req.Host = parsed.Host
		}
	default:
		// Ignore URL change with disallowed scheme — keep original URL.
	}
	return nil
}

// applyHost updates the request host from the data map if present.
func applyHost(req *gohttp.Request, data map[string]any) {
	if v, ok := data["host"].(string); ok && v != "" {
		req.Host = v
		if req.URL != nil {
			req.URL.Host = v
		}
	}
}

// applyRequestHeaders updates the request headers from the data map if present.
func applyRequestHeaders(req *gohttp.Request, data map[string]any) {
	if v, ok := data["headers"]; ok {
		newHeaders := mapToHeaders(v)
		if newHeaders != nil {
			req.Header = httputil.RawHeadersToHTTPHeader(newHeaders)
		}
	}
}

// extractBody extracts body bytes from the data map, supporting both []byte and string.
func extractBody(data map[string]any) []byte {
	v, ok := data["body"]
	if !ok {
		return nil
	}
	switch b := v.(type) {
	case []byte:
		return b
	case string:
		return []byte(b)
	}
	return nil
}

// ApplyHTTPResponseChanges applies modifications from a plugin hook result
// back to an HTTP response. It updates status code, headers, and body
// from the data map. Only keys present in the data map are applied.
func ApplyHTTPResponseChanges(resp *gohttp.Response, data map[string]any) (*gohttp.Response, []byte, error) {
	if data == nil {
		return resp, nil, nil
	}

	var body []byte

	if v, ok := data["status_code"]; ok {
		switch sc := v.(type) {
		case int:
			resp.StatusCode = validStatusCode(sc, resp.StatusCode)
		case int64:
			resp.StatusCode = validStatusCode(int(sc), resp.StatusCode)
		case float64:
			resp.StatusCode = validStatusCode(int(sc), resp.StatusCode)
		}
	}

	if v, ok := data["headers"]; ok {
		newHeaders := mapToHeaders(v)
		if newHeaders != nil {
			resp.Header = httputil.RawHeadersToHTTPHeader(newHeaders)
		}
	}

	if v, ok := data["trailers"]; ok {
		newTrailers := mapToHeaders(v)
		if newTrailers != nil {
			resp.Trailer = httputil.RawHeadersToHTTPHeader(newTrailers)
		}
	}

	if v, ok := data["body"]; ok {
		switch b := v.(type) {
		case []byte:
			body = b
		case string:
			body = []byte(b)
		}
	}

	return resp, body, nil
}

// headersToMap converts parser.RawHeaders to a map[string]any where each value
// is a []any of strings. This format is compatible with Starlark dict conversion.
func headersToMap(h parser.RawHeaders) map[string]any {
	if h == nil {
		return map[string]any{}
	}
	// Group by header name preserving first-seen casing.
	ordered := make([]string, 0, len(h))
	groups := make(map[string][]any, len(h))
	for _, hdr := range h {
		key := hdr.Name
		if _, exists := groups[key]; !exists {
			ordered = append(ordered, key)
		}
		groups[key] = append(groups[key], hdr.Value)
	}
	m := make(map[string]any, len(ordered))
	for _, key := range ordered {
		m[key] = groups[key]
	}
	return m
}

// mapToHeaders converts a map (from Starlark) back to parser.RawHeaders.
// Supports map[string]any with []any string values or []string values.
func mapToHeaders(v any) parser.RawHeaders {
	m, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	var h parser.RawHeaders
	for k, val := range m {
		safeKey := sanitizeHeaderToken(k)
		switch vals := val.(type) {
		case []any:
			for _, item := range vals {
				if s, ok := item.(string); ok {
					h = append(h, parser.RawHeader{Name: safeKey, Value: sanitizeHeaderToken(s)})
				}
			}
		case []string:
			for _, s := range vals {
				h = append(h, parser.RawHeader{Name: safeKey, Value: sanitizeHeaderToken(s)})
			}
		case string:
			h = append(h, parser.RawHeader{Name: safeKey, Value: sanitizeHeaderToken(vals)})
		}
	}
	return h
}

// BuildRespondResponse constructs an HTTP response map from a RESPOND action's
// ResponseData. Returns status code, headers map, and body bytes.
func BuildRespondResponse(responseData map[string]any) (statusCode int, headers parser.RawHeaders, body []byte) {
	statusCode = gohttp.StatusOK // default

	if v, ok := responseData["status_code"]; ok {
		switch sc := v.(type) {
		case int:
			statusCode = sc
		case int64:
			statusCode = int(sc)
		case float64:
			statusCode = int(sc)
		}
	}

	if v, ok := responseData["headers"]; ok {
		if h := mapToHeaders(v); h != nil {
			headers = h
		}
	}

	if v, ok := responseData["body"]; ok {
		switch b := v.(type) {
		case []byte:
			body = b
		case string:
			body = []byte(b)
		}
	}

	statusCode = validStatusCode(statusCode, gohttp.StatusOK)

	return statusCode, headers, body
}

// sanitizeHeaderToken removes \r and \n from a string to prevent
// HTTP header injection (CRLF response splitting).
func sanitizeHeaderToken(s string) string {
	if !strings.ContainsAny(s, "\r\n") {
		return s
	}
	r := strings.NewReplacer("\r", "", "\n", "")
	return r.Replace(s)
}

// validStatusCode returns code if it is within the valid HTTP range
// (100-599), otherwise returns the provided fallback.
func validStatusCode(code, fallback int) int {
	if code >= 100 && code <= 599 {
		return code
	}
	return fallback
}
