package http

import (
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// rawHeadersToKeyValues converts parser.RawHeaders to []exchange.KeyValue.
// Used to bridge between the HTTP/1.x parser types and the exchange types
// required by the rules.Pipeline API.
func rawHeadersToKeyValues(rh parser.RawHeaders) []exchange.KeyValue {
	if rh == nil {
		return nil
	}
	kv := make([]exchange.KeyValue, len(rh))
	for i, h := range rh {
		kv[i] = exchange.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kv
}

// keyValuesToRawHeaders converts []exchange.KeyValue back to parser.RawHeaders.
// RawValue is left empty since transformed headers have no OWS context.
func keyValuesToRawHeaders(kv []exchange.KeyValue) parser.RawHeaders {
	if kv == nil {
		return nil
	}
	rh := make(parser.RawHeaders, len(kv))
	for i, h := range kv {
		rh[i] = parser.RawHeader{Name: h.Name, Value: h.Value}
	}
	return rh
}
