package plugin

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
)

// H2RequestToMap converts HTTP/2 request fields (hpack native types) directly
// into a map[string]any suitable for passing to plugin hooks via Dispatch.
// This avoids going through gohttp.Request and preserves:
//   - Header order (wire order)
//   - Header casing (HTTP/2 requires lowercase per RFC 9113)
//   - Duplicate headers as independent entries
//   - Pseudo-header separation
//
// The headers field uses the same ordered array format as RawRequestToMap:
// []map[string]any where each element has "name" and "value" keys.
// Pseudo-headers are excluded from the headers array; they are represented
// via top-level fields (method, scheme, authority, path).
func H2RequestToMap(
	method, scheme, authority, path string,
	allHeaders []hpack.HeaderField,
	body []byte,
	connInfo *ConnInfo,
	protocol string,
) map[string]any {
	headers := h2HeadersToOrderedList(allHeaders)

	// Build URL from pseudo-headers.
	urlStr := ""
	query := ""
	pathOnly := path
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		pathOnly = path[:idx]
		query = path[idx+1:]
	}
	if scheme != "" && authority != "" {
		urlStr = scheme + "://" + authority + path
	} else {
		urlStr = path
	}

	m := map[string]any{
		"method":    method,
		"url":       urlStr,
		"scheme":    scheme,
		"host":      authority,
		"authority": authority,
		"path":      pathOnly,
		"query":     query,
		"headers":   headers,
		"body":      body,
		"protocol":  protocol,
	}
	if connInfo != nil {
		m["conn_info"] = connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}
	return m
}

// H2ResponseToMap converts HTTP/2 response fields (status code + hpack header
// fields) directly into a map[string]any suitable for passing to plugin hooks.
// This avoids going through gohttp.Response and preserves header order/casing.
//
// reqSummary provides a read-only request summary for correlation (method,
// authority, path). Pass nil method to omit the request summary.
func H2ResponseToMap(
	statusCode int,
	headers []hpack.HeaderField,
	trailers []hpack.HeaderField,
	body []byte,
	reqMethod, reqAuthority, reqPath string,
	connInfo *ConnInfo,
	protocol string,
) map[string]any {
	m := map[string]any{
		"status_code": statusCode,
		"headers":     h2HeadersToOrderedList(headers),
		"trailers":    h2HeadersToOrderedList(trailers),
		"body":        body,
		"protocol":    protocol,
	}
	if connInfo != nil {
		m["conn_info"] = connInfo.ToMap()
	} else {
		m["conn_info"] = map[string]any{}
	}

	if reqMethod != "" {
		reqSummary := map[string]any{
			"method": reqMethod,
		}
		if reqAuthority != "" {
			reqSummary["host"] = reqAuthority
		}
		urlStr := reqPath
		if reqAuthority != "" {
			urlStr = "https://" + reqAuthority + reqPath
		}
		reqSummary["url"] = urlStr
		m["request"] = reqSummary
	}
	return m
}

// ApplyH2RequestChanges applies modifications from a plugin hook result back
// to HTTP/2 request fields. It returns the updated method, authority, path,
// hpack headers, and body. Only keys present in the data map are applied.
func ApplyH2RequestChanges(
	method, scheme, authority, path string,
	allHeaders []hpack.HeaderField,
	data map[string]any,
) (newMethod, newScheme, newAuthority, newPath string, newHeaders []hpack.HeaderField, body []byte, err error) {
	newMethod = method
	newScheme = scheme
	newAuthority = authority
	newPath = path
	newHeaders = allHeaders

	if data == nil {
		return
	}

	// Apply method.
	if v, ok := data["method"].(string); ok && v != "" {
		newMethod = v
	}

	// Apply URL.
	newScheme, newAuthority, newPath, err = applyH2URL(newScheme, newAuthority, newPath, data)
	if err != nil {
		return
	}

	// Apply authority/host.
	newAuthority = applyH2Authority(newAuthority, data)

	// Apply headers.
	if v, ok := data["headers"]; ok {
		if h2h := mapToH2Headers(v); h2h != nil {
			newHeaders = h2h
		}
	}

	// Extract body.
	body = extractBody(data)

	return
}

// applyH2URL extracts and validates a URL from the data map, updating scheme,
// authority, and path. Only http, https, and empty schemes are allowed.
func applyH2URL(scheme, authority, path string, data map[string]any) (string, string, string, error) {
	v, ok := data["url"].(string)
	if !ok || v == "" {
		return scheme, authority, path, nil
	}
	parsed, err := url.Parse(v)
	if err != nil {
		return scheme, authority, path, fmt.Errorf("plugin returned invalid URL: %w", err)
	}
	switch parsed.Scheme {
	case "http", "https", "":
		if parsed.Scheme != "" {
			scheme = parsed.Scheme
		}
		if parsed.Host != "" {
			authority = parsed.Host
		}
		path = parsed.RequestURI()
	default:
		// Ignore URL change with disallowed scheme.
	}
	return scheme, authority, path, nil
}

// applyH2Authority extracts authority from the data map, preferring
// "authority" key over "host" key.
func applyH2Authority(authority string, data map[string]any) string {
	if v, ok := data["authority"].(string); ok && v != "" {
		return v
	}
	if v, ok := data["host"].(string); ok && v != "" {
		return v
	}
	return authority
}

// ApplyH2ResponseChanges applies modifications from a plugin hook result back
// to HTTP/2 response fields. Returns the updated status code, headers,
// trailers, and body.
func ApplyH2ResponseChanges(
	statusCode int,
	headers []hpack.HeaderField,
	trailers []hpack.HeaderField,
	data map[string]any,
) (newStatusCode int, newHeaders []hpack.HeaderField, newTrailers []hpack.HeaderField, body []byte, err error) {
	newStatusCode = statusCode
	newHeaders = headers
	newTrailers = trailers

	if data == nil {
		return
	}

	// Apply status code.
	if v, ok := data["status_code"]; ok {
		switch sc := v.(type) {
		case int:
			newStatusCode = validStatusCode(sc, newStatusCode)
		case int64:
			newStatusCode = validStatusCode(int(sc), newStatusCode)
		case float64:
			newStatusCode = validStatusCode(int(sc), newStatusCode)
		}
	}

	// Apply headers.
	if v, ok := data["headers"]; ok {
		h2h := mapToH2Headers(v)
		if h2h != nil {
			newHeaders = h2h
		}
	}

	// Apply trailers.
	if v, ok := data["trailers"]; ok {
		h2t := mapToH2Headers(v)
		if h2t != nil {
			newTrailers = h2t
		}
	}

	// Extract body.
	if v, ok := data["body"]; ok {
		switch b := v.(type) {
		case []byte:
			body = b
		case string:
			body = []byte(b)
		}
	}

	return
}

// h2HeadersToOrderedList converts hpack header fields to an ordered list of
// maps, where each map has "name" and "value" keys. Pseudo-headers (names
// starting with ":") are excluded since they are represented via top-level
// fields in the hook data map.
func h2HeadersToOrderedList(fields []hpack.HeaderField) []any {
	if fields == nil {
		return []any{}
	}
	list := make([]any, 0, len(fields))
	for _, hf := range fields {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		list = append(list, map[string]any{
			"name":  hf.Name,
			"value": hf.Value,
		})
	}
	return list
}

// mapToH2Headers converts a plugin-returned header value to hpack header
// fields. Supports two formats:
//   - Ordered array: []any of map[string]any with "name" and "value" keys
//   - Legacy map: map[string]any with []any string values
//
// All header names are lowercased per HTTP/2 requirements (RFC 9113 section 8.2).
func mapToH2Headers(v any) []hpack.HeaderField {
	switch val := v.(type) {
	case []any:
		return orderedArrayToH2Headers(val)
	case map[string]any:
		return mapFormatToH2Headers(val)
	}
	return nil
}

// orderedArrayToH2Headers converts a []any of {name, value} maps to hpack
// header fields. Names are lowercased per HTTP/2 spec.
func orderedArrayToH2Headers(list []any) []hpack.HeaderField {
	fields := make([]hpack.HeaderField, 0, len(list))
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
		fields = append(fields, hpack.HeaderField{
			Name:  strings.ToLower(sanitizeHeaderToken(name)),
			Value: sanitizeHeaderToken(value),
		})
	}
	return fields
}

// mapFormatToH2Headers converts a map[string]any (legacy format) to hpack
// header fields. Names are lowercased per HTTP/2 spec.
func mapFormatToH2Headers(m map[string]any) []hpack.HeaderField {
	var fields []hpack.HeaderField
	for k, val := range m {
		safeKey := strings.ToLower(sanitizeHeaderToken(k))
		switch vals := val.(type) {
		case []any:
			for _, item := range vals {
				if s, ok := item.(string); ok {
					fields = append(fields, hpack.HeaderField{
						Name:  safeKey,
						Value: sanitizeHeaderToken(s),
					})
				}
			}
		case []string:
			for _, s := range vals {
				fields = append(fields, hpack.HeaderField{
					Name:  safeKey,
					Value: sanitizeHeaderToken(s),
				})
			}
		case string:
			fields = append(fields, hpack.HeaderField{
				Name:  safeKey,
				Value: sanitizeHeaderToken(vals),
			})
		}
	}
	return fields
}
