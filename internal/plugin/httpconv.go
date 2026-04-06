package plugin

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

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

// BuildRespondResponse constructs an HTTP response map from a RESPOND action's
// ResponseData. Returns status code, headers map, and body bytes.
func BuildRespondResponse(responseData map[string]any) (statusCode int, headers parser.RawHeaders, body []byte) {
	statusCode = httputil.StatusOK // default

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

	statusCode = validStatusCode(statusCode, httputil.StatusOK)

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

// mapToHeaders converts a plugin-returned header value back to parser.RawHeaders.
// Supports two formats:
//   - Ordered array: []any of map[string]any with "name" and "value" keys
//     (lossless format from RawRequestToMap/RawResponseToMap)
//   - Legacy map: map[string]any with []any string values or []string values
//     (lossy format, supported for backward compatibility with existing plugins)
func mapToHeaders(v any) parser.RawHeaders {
	switch val := v.(type) {
	case []any:
		return orderedArrayToRawHeaders(val)
	case map[string]any:
		return mapFormatToHeaders(val)
	}
	return nil
}

// mapFormatToHeaders converts a map[string]any (legacy format) to parser.RawHeaders.
func mapFormatToHeaders(m map[string]any) parser.RawHeaders {
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
