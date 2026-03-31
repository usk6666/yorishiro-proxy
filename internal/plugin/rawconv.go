package plugin

import (
	"bytes"
	"fmt"
	"net/url"
	"strconv"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// RawRequestToMap converts a parser.RawRequest directly into a map[string]any
// suitable for passing to plugin hooks via Dispatch, without going through
// net/http.Request. This preserves header order, header name casing, and
// duplicate header distinction that would be lost via the gohttp.Request path.
//
// The headers field uses an ordered array format: []map[string]any where each
// element has "name" and "value" keys. This differs from HTTPRequestToMap which
// uses map[string][]any (lossy: no order, normalized casing).
func RawRequestToMap(req *parser.RawRequest, body []byte, connInfo *ConnInfo, protocol string) map[string]any {
	if req == nil {
		return map[string]any{}
	}

	headers := rawHeadersToOrderedList(req.Headers)

	// Parse request_uri for convenience fields.
	urlStr := req.RequestURI
	scheme := ""
	host := req.Headers.Get("Host")
	path := ""
	query := ""

	if u, err := url.ParseRequestURI(req.RequestURI); err == nil {
		if u.Scheme != "" {
			scheme = u.Scheme
		}
		if u.Host != "" {
			host = u.Host
		}
		path = u.Path
		query = u.RawQuery
	}

	m := map[string]any{
		"method":      req.Method,
		"request_uri": req.RequestURI,
		"url":         urlStr,
		"scheme":      scheme,
		"host":        host,
		"path":        path,
		"query":       query,
		"proto":       req.Proto,
		"headers":     headers,
		"body":        body,
		"protocol":    protocol,
	}
	if connInfo != nil {
		m["conn_info"] = connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}
	return m
}

// RawResponseToMap converts a parser.RawResponse directly into a map[string]any
// suitable for passing to plugin hooks via Dispatch, without going through
// net/http.Response. This preserves header order, header name casing, and
// duplicate header distinction.
//
// The headers field uses the same ordered array format as RawRequestToMap.
func RawResponseToMap(resp *parser.RawResponse, body []byte, req *parser.RawRequest, connInfo *ConnInfo, protocol string) map[string]any {
	if resp == nil {
		return map[string]any{}
	}

	m := map[string]any{
		"status_code": resp.StatusCode,
		"headers":     rawHeadersToOrderedList(resp.Headers),
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
			"method":      req.Method,
			"request_uri": req.RequestURI,
		}
		host := req.Headers.Get("Host")
		if host != "" {
			reqSummary["host"] = host
		}
		m["request"] = reqSummary
	}
	return m
}

// ApplyRawRequestChanges applies modifications from a plugin hook result
// back to a parser.RawRequest. It updates method, URL, headers, and body
// from the data map. Only keys present in the data map are applied.
func ApplyRawRequestChanges(req *parser.RawRequest, data map[string]any) (*parser.RawRequest, []byte, error) {
	if data == nil {
		return req, nil, nil
	}

	// Apply method.
	if v, ok := data["method"].(string); ok && v != "" {
		req.Method = v
	}

	// Apply URL / request_uri.
	if err := applyRawURL(req, data); err != nil {
		return req, nil, err
	}

	// Apply headers.
	if v, ok := data["headers"]; ok {
		newHeaders := mapToHeaders(v)
		if newHeaders != nil {
			req.Headers = newHeaders
		}
	}

	// Apply host from explicit "host" key (overrides Host header).
	if v, ok := data["host"].(string); ok && v != "" {
		req.Headers.Set("Host", v)
	}

	// Extract body.
	body := extractBody(data)

	// Sync Content-Length / Transfer-Encoding with actual body.
	if body != nil {
		req.Headers.Del("Transfer-Encoding")
		if len(body) > 0 {
			req.Headers.Set("Content-Length", strconv.Itoa(len(body)))
		} else {
			req.Headers.Del("Content-Length")
		}
		req.Body = bytes.NewReader(body)
	}

	return req, body, nil
}

// applyRawURL updates the request URI from the data map if present.
// Only http, https, and empty schemes are allowed to prevent SSRF.
func applyRawURL(req *parser.RawRequest, data map[string]any) error {
	// Prefer "url" key (same as HTTPRequestToMap).
	v, ok := data["url"].(string)
	if !ok || v == "" {
		// Fall back to "request_uri" key.
		v, ok = data["request_uri"].(string)
		if !ok || v == "" {
			return nil
		}
	}

	parsed, err := url.Parse(v)
	if err != nil {
		return fmt.Errorf("plugin returned invalid URL: %w", err)
	}

	// Only allow http and https schemes to prevent SSRF via plugin URL rewrite.
	// Empty scheme is permitted for relative URLs.
	switch parsed.Scheme {
	case "http", "https", "":
		req.RequestURI = v
		// Update Host header when the URL contains a host.
		if parsed.Host != "" {
			req.Headers.Set("Host", parsed.Host)
		}
	default:
		// Ignore URL change with disallowed scheme — keep original URL.
	}
	return nil
}

// ApplyRawResponseChanges applies modifications from a plugin hook result
// back to a parser.RawResponse. It updates status code, headers, and body
// from the data map. Only keys present in the data map are applied.
func ApplyRawResponseChanges(resp *parser.RawResponse, data map[string]any) (*parser.RawResponse, []byte, error) {
	if data == nil {
		return resp, nil, nil
	}

	// Apply status code.
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

	// Apply headers.
	if v, ok := data["headers"]; ok {
		newHeaders := mapToHeaders(v)
		if newHeaders != nil {
			resp.Headers = newHeaders
		}
	}

	// Extract body.
	var body []byte
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

// rawHeadersToOrderedList converts parser.RawHeaders to an ordered list of
// maps, where each map has "name" and "value" keys. This preserves header
// order, casing, and duplicate headers.
func rawHeadersToOrderedList(h parser.RawHeaders) []any {
	if h == nil {
		return []any{}
	}
	list := make([]any, 0, len(h))
	for _, hdr := range h {
		list = append(list, map[string]any{
			"name":  hdr.Name,
			"value": hdr.Value,
		})
	}
	return list
}

// orderedArrayToRawHeaders converts a []any of {name, value} maps to RawHeaders.
func orderedArrayToRawHeaders(list []any) parser.RawHeaders {
	if len(list) == 0 {
		return nil
	}
	h := make(parser.RawHeaders, 0, len(list))
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		value, _ := m["value"].(string)
		if name == "" {
			continue
		}
		h = append(h, parser.RawHeader{
			Name:  sanitizeHeaderToken(name),
			Value: sanitizeHeaderToken(value),
		})
	}
	if len(h) == 0 {
		return nil
	}
	return h
}
