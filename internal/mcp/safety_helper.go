package mcp

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// kvToRawHeaders converts []exchange.KeyValue to parser.RawHeaders.
func kvToRawHeaders(kv []exchange.KeyValue) parser.RawHeaders {
	if kv == nil {
		return nil
	}
	rh := make(parser.RawHeaders, len(kv))
	for i, h := range kv {
		rh[i] = parser.RawHeader{Name: h.Name, Value: h.Value}
	}
	return rh
}

// kvToHTTPHeader converts []exchange.KeyValue to net/http.Header.
func kvToHTTPHeader(kv []exchange.KeyValue) http.Header {
	if kv == nil {
		return make(http.Header)
	}
	h := make(http.Header, len(kv))
	for _, hdr := range kv {
		h.Add(hdr.Name, hdr.Value)
	}
	return h
}

// filterOutputKVHeaders applies SafetyFilter output masking to []exchange.KeyValue headers
// by converting through parser.RawHeaders. If no safety engine is configured, returns the
// headers converted to HTTP headers unchanged.
func (s *Server) filterOutputKVHeaders(headers []exchange.KeyValue) http.Header {
	rh := kvToRawHeaders(headers)
	filtered := s.filterOutputRawHeaders(rh)
	return rawHeadersToHTTPHeader(filtered)
}

// httpHeaderToKeyValues converts net/http.Header (map[string][]string) to
// []exchange.KeyValue. Header name casing is preserved as-is.
func httpHeaderToKeyValues(h http.Header) []exchange.KeyValue {
	if h == nil {
		return nil
	}
	var kvs []exchange.KeyValue
	for name, vals := range h {
		for _, v := range vals {
			kvs = append(kvs, exchange.KeyValue{Name: name, Value: v})
		}
	}
	return kvs
}

// rawHeadersToKeyValues converts parser.RawHeaders to []exchange.KeyValue.
func rawHeadersToKeyValues(rh parser.RawHeaders) []exchange.KeyValue {
	if rh == nil {
		return nil
	}
	kvs := make([]exchange.KeyValue, len(rh))
	for i, h := range rh {
		kvs[i] = exchange.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kvs
}

// keyValuesToRawHeaders converts []exchange.KeyValue to parser.RawHeaders.
func keyValuesToRawHeaders(kvs []exchange.KeyValue) parser.RawHeaders {
	if kvs == nil {
		return nil
	}
	rh := make(parser.RawHeaders, len(kvs))
	for i, kv := range kvs {
		rh[i] = parser.RawHeader{Name: kv.Name, Value: kv.Value}
	}
	return rh
}

// keyValuesToHTTPHeader converts []exchange.KeyValue to net/http.Header.
func keyValuesToHTTPHeader(kvs []exchange.KeyValue) http.Header {
	if kvs == nil {
		return make(http.Header)
	}
	h := make(http.Header, len(kvs))
	for _, kv := range kvs {
		h.Add(kv.Name, kv.Value)
	}
	return h
}

// rawHeadersToHTTPHeader converts parser.RawHeaders to net/http.Header.
func rawHeadersToHTTPHeader(rh parser.RawHeaders) http.Header {
	if rh == nil {
		return make(http.Header)
	}
	h := make(http.Header, len(rh))
	for _, hdr := range rh {
		h.Add(hdr.Name, hdr.Value)
	}
	return h
}

// filterOutputBody applies the SafetyFilter output masking to the given body data.
// If no safety engine is configured, it returns the body unchanged.
func (s *Server) filterOutputBody(body []byte) []byte {
	if s.deps.safetyEngine == nil {
		return body
	}
	result := s.deps.safetyEngine.FilterOutput(body)
	if result.Masked {
		slog.Debug("SafetyFilter output masking applied to body",
			"matches", len(result.Matches),
		)
	}
	return result.Data
}

// filterOutputHeaders applies the SafetyFilter output masking to the given HTTP headers.
// If no safety engine is configured, it returns the headers unchanged.
func (s *Server) filterOutputHeaders(headers http.Header) http.Header {
	if s.deps.safetyEngine == nil {
		return headers
	}
	filtered, matches := s.deps.safetyEngine.FilterOutputHeaders(httpHeaderToKeyValues(headers))
	if len(matches) > 0 {
		slog.Debug("SafetyFilter output masking applied to headers",
			"matches", len(matches),
		)
	}
	return keyValuesToHTTPHeader(filtered)
}

// filterOutputRawHeaders applies the SafetyFilter output masking to parser.RawHeaders.
// If no safety engine is configured, it returns the headers unchanged.
func (s *Server) filterOutputRawHeaders(headers parser.RawHeaders) parser.RawHeaders {
	if s.deps.safetyEngine == nil {
		return headers
	}
	filtered, matches := s.deps.safetyEngine.FilterOutputHeaders(rawHeadersToKeyValues(headers))
	if len(matches) > 0 {
		slog.Debug("SafetyFilter output masking applied to headers",
			"matches", len(matches),
		)
	}
	return keyValuesToRawHeaders(filtered)
}

// filterOutputMessages applies SafetyFilter output masking to query message entries.
// It masks the body and headers of each message in place. If no safety engine is
// configured, this is a no-op.
func (s *Server) filterOutputMessages(entries []queryMessageEntry) {
	if s.deps.safetyEngine == nil {
		return
	}
	for i := range entries {
		// Mask body: decode from text/base64, filter, re-encode.
		bodyData := decodeEntryBody(entries[i].Body, entries[i].BodyEncoding)
		maskedBody := s.filterOutputBody(bodyData)
		entries[i].Body, entries[i].BodyEncoding = encodeBody(maskedBody)

		// Mask headers.
		if len(entries[i].Headers) > 0 {
			entries[i].Headers = map[string][]string(
				s.filterOutputHeaders(http.Header(entries[i].Headers)),
			)
		}
	}
}

// filterOutputInterceptEntries applies SafetyFilter output masking to intercept queue entries.
// It masks the body and headers of each entry in place. If no safety engine is
// configured, this is a no-op.
func (s *Server) filterOutputInterceptEntries(entries []queryInterceptQueueEntry) {
	if s.deps.safetyEngine == nil {
		return
	}
	for i := range entries {
		// Mask body: decode from text/base64, filter, re-encode.
		bodyData := decodeEntryBody(entries[i].Body, entries[i].BodyEncoding)
		maskedBody := s.filterOutputBody(bodyData)
		entries[i].Body, entries[i].BodyEncoding = encodeBody(maskedBody)

		// Mask headers.
		if len(entries[i].Headers) > 0 {
			entries[i].Headers = map[string][]string(
				s.filterOutputHeaders(http.Header(entries[i].Headers)),
			)
		}
	}
}

// filterOutputVariantRequest applies SafetyFilter output masking to a queryVariantRequest.
// If the variant is nil, this is a no-op.
func (s *Server) filterOutputVariantRequest(v *queryVariantRequest) {
	if v == nil {
		return
	}
	bodyData := decodeEntryBody(v.Body, v.BodyEncoding)
	maskedBody := s.filterOutputBody(bodyData)
	v.Body, v.BodyEncoding = encodeBody(maskedBody)
	if len(v.Headers) > 0 {
		v.Headers = map[string][]string(
			s.filterOutputHeaders(http.Header(v.Headers)),
		)
	}
}

// filterOutputVariantResponse applies SafetyFilter output masking to a queryVariantResponse.
// If the variant is nil, this is a no-op.
func (s *Server) filterOutputVariantResponse(v *queryVariantResponse) {
	if v == nil {
		return
	}
	bodyData := decodeEntryBody(v.Body, v.BodyEncoding)
	maskedBody := s.filterOutputBody(bodyData)
	v.Body, v.BodyEncoding = encodeBody(maskedBody)
	if len(v.Headers) > 0 {
		v.Headers = map[string][]string(
			s.filterOutputHeaders(http.Header(v.Headers)),
		)
	}
}

// decodeEntryBody decodes a body string from its encoding format back to raw bytes.
// For "base64" encoding, it Base64-decodes the string.
// For "text" or any other encoding, it returns the string as bytes.
func decodeEntryBody(body, encoding string) []byte {
	if encoding == "base64" {
		decoded, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			// If decode fails, fall back to treating as text.
			return []byte(body)
		}
		return decoded
	}
	return []byte(body)
}
