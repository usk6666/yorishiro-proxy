package rules

import (
	gohttp "net/http"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// h2r converts net/http.Header to parser.RawHeaders for test convenience.
func h2r(h gohttp.Header) parser.RawHeaders {
	if h == nil {
		return nil
	}
	var rh parser.RawHeaders
	for name, vals := range h {
		for _, v := range vals {
			rh = append(rh, parser.RawHeader{Name: name, Value: v})
		}
	}
	return rh
}
