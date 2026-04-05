package rules

import (
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
)

// h2r converts net/http.Header to []exchange.KeyValue for test convenience.
func h2r(h gohttp.Header) []exchange.KeyValue {
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
