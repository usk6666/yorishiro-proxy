package mcp

import (
	"encoding/base64"
	"log/slog"
	"net/http"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

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
	filtered, matches := s.deps.safetyEngine.FilterOutputHeaders(httputil.HTTPHeaderToRawHeaders(headers))
	if len(matches) > 0 {
		slog.Debug("SafetyFilter output masking applied to headers",
			"matches", len(matches),
		)
	}
	return httputil.RawHeadersToHTTPHeader(filtered)
}

// filterOutputRawHeaders applies the SafetyFilter output masking to parser.RawHeaders.
// If no safety engine is configured, it returns the headers unchanged.
func (s *Server) filterOutputRawHeaders(headers parser.RawHeaders) parser.RawHeaders {
	if s.deps.safetyEngine == nil {
		return headers
	}
	filtered, matches := s.deps.safetyEngine.FilterOutputHeaders(headers)
	if len(matches) > 0 {
		slog.Debug("SafetyFilter output masking applied to headers",
			"matches", len(matches),
		)
	}
	return filtered
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
