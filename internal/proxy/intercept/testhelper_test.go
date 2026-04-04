package intercept

import (
	gohttp "net/http"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// h2kv converts net/http.Header to []exchange.KeyValue for test convenience.
func h2kv(h gohttp.Header) []exchange.KeyValue {
	if h == nil {
		return nil
	}
	var kv []exchange.KeyValue
	for name, vals := range h {
		for _, v := range vals {
			kv = append(kv, exchange.KeyValue{Name: name, Value: v})
		}
	}
	return kv
}

// kvGetTest returns the value of the first entry matching name (case-insensitive).
// Test-only helper to replace parser.RawHeaders.Get().
func kvGetTest(headers []exchange.KeyValue, name string) string {
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			return h.Value
		}
	}
	return ""
}
