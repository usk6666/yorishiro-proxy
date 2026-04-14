package job

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	http1 "github.com/usk6666/yorishiro-proxy/internal/layer/http1"
)

// HTTPResendOverrides holds user-specified overrides for an HTTP resend.
type HTTPResendOverrides struct {
	// Method overrides the HTTP method. Empty means use the original.
	Method string
	// URL overrides the full request URL. Empty means use the original.
	// Parsed into Scheme/Authority/Path/RawQuery components.
	URL string
	// Headers overrides specific headers. Keys are header names; existing
	// headers with the same name (case-insensitive match) are replaced.
	// New headers are appended. nil means no header overrides.
	Headers map[string]string
	// Body overrides the request body. nil means use the original.
	Body []byte
	// BodySet distinguishes nil Body (no override) from empty Body (override to empty).
	BodySet bool
}

// HTTPResendSource is an EnvelopeSource that yields a single HTTPMessage
// Envelope reconstructed from a recorded flow with optional overrides.
type HTTPResendSource struct {
	reader    flow.Reader
	streamID  string
	overrides HTTPResendOverrides
	yielded   bool
}

// NewHTTPResendSource creates a source that fetches the send flow for the
// given stream and yields it as an HTTPMessage Envelope with overrides applied.
func NewHTTPResendSource(reader flow.Reader, streamID string, overrides HTTPResendOverrides) *HTTPResendSource {
	return &HTTPResendSource{
		reader:    reader,
		streamID:  streamID,
		overrides: overrides,
	}
}

// Next returns the Envelope on first call, io.EOF on subsequent calls.
func (s *HTTPResendSource) Next(ctx context.Context) (*envelope.Envelope, error) {
	if s.yielded {
		return nil, io.EOF
	}
	s.yielded = true

	sendFlow, err := s.fetchSendFlow(ctx)
	if err != nil {
		return nil, fmt.Errorf("http resend source: %w", err)
	}

	env := s.buildEnvelope(sendFlow)
	return env, nil
}

// fetchSendFlow retrieves the first send-direction flow for the stream.
func (s *HTTPResendSource) fetchSendFlow(ctx context.Context) (*flow.Flow, error) {
	flows, err := s.reader.GetFlows(ctx, s.streamID, flow.FlowListOptions{
		Direction: "send",
	})
	if err != nil {
		return nil, fmt.Errorf("get flows for stream %s: %w", s.streamID, err)
	}
	if len(flows) == 0 {
		return nil, fmt.Errorf("no send flow found for stream %s", s.streamID)
	}
	return flows[0], nil
}

// buildEnvelope constructs an HTTPMessage Envelope from the flow data with
// overrides applied.
func (s *HTTPResendSource) buildEnvelope(f *flow.Flow) *envelope.Envelope {
	method := f.Method
	if s.overrides.Method != "" {
		method = s.overrides.Method
	}

	scheme, authority, path, rawQuery := extractURLParts(f)
	if s.overrides.URL != "" {
		scheme, authority, path, rawQuery = parseOverrideURL(s.overrides.URL, scheme)
	}

	headers := flowHeadersToKeyValues(f.Headers)
	if s.overrides.Headers != nil {
		headers = applyHeaderOverrides(headers, s.overrides.Headers)
	}

	body := f.Body
	if s.overrides.BodySet {
		body = s.overrides.Body
	}

	return http1.BuildSendEnvelope(method, scheme, authority, path, rawQuery, headers, body)
}

// extractURLParts extracts scheme, authority, path, and rawQuery from a flow's URL.
func extractURLParts(f *flow.Flow) (scheme, authority, path, rawQuery string) {
	if f.URL == nil {
		return "http", "", "/", ""
	}
	scheme = f.URL.Scheme
	if scheme == "" {
		scheme = "http"
	}
	authority = f.URL.Host
	path = f.URL.Path
	if path == "" {
		path = "/"
	}
	rawQuery = f.URL.RawQuery
	return
}

// parseOverrideURL parses a URL override string into components.
// If the override URL has no scheme, the defaultScheme is used.
func parseOverrideURL(rawURL, defaultScheme string) (scheme, authority, path, rawQuery string) {
	scheme = defaultScheme

	// Handle scheme.
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		scheme = rawURL[:idx]
		rawURL = rawURL[idx+3:]
	}

	// Split host from path.
	pathStart := strings.IndexByte(rawURL, '/')
	if pathStart < 0 {
		authority = rawURL
		path = "/"
		return
	}
	authority = rawURL[:pathStart]
	rest := rawURL[pathStart:]

	// Split path from query.
	if qIdx := strings.IndexByte(rest, '?'); qIdx >= 0 {
		path = rest[:qIdx]
		rawQuery = rest[qIdx+1:]
	} else {
		path = rest
	}
	return
}

// flowHeadersToKeyValues converts flow's map[string][]string headers to
// envelope.KeyValue slice. Order within each header name is preserved;
// names are emitted in map iteration order (non-deterministic, but
// acceptable for resend since original wire order is already lost in the
// flow store's map representation).
func flowHeadersToKeyValues(headers map[string][]string) []envelope.KeyValue {
	if headers == nil {
		return nil
	}
	var kvs []envelope.KeyValue
	for name, values := range headers {
		for _, v := range values {
			kvs = append(kvs, envelope.KeyValue{Name: name, Value: v})
		}
	}
	return kvs
}

// applyHeaderOverrides merges override headers into the base header list.
// For each override key, existing headers with a case-insensitive name match
// are replaced (first occurrence replaced, subsequent removed). New headers
// are appended at the end.
func applyHeaderOverrides(base []envelope.KeyValue, overrides map[string]string) []envelope.KeyValue {
	// Track which overrides have been applied.
	applied := make(map[string]bool, len(overrides))

	var result []envelope.KeyValue
	for _, kv := range base {
		lowerName := strings.ToLower(kv.Name)
		if newVal, ok := overrideLookup(overrides, lowerName); ok {
			if !applied[lowerName] {
				// Replace first occurrence with override value, keeping original case.
				result = append(result, envelope.KeyValue{Name: kv.Name, Value: newVal})
				applied[lowerName] = true
			}
			// Skip subsequent occurrences of the same header.
		} else {
			result = append(result, kv)
		}
	}

	// Append new headers that weren't in the base.
	for name, value := range overrides {
		if !applied[strings.ToLower(name)] {
			result = append(result, envelope.KeyValue{Name: name, Value: value})
		}
	}

	return result
}

// overrideLookup finds a value in the override map by case-insensitive key match.
func overrideLookup(overrides map[string]string, lowerKey string) (string, bool) {
	for k, v := range overrides {
		if strings.ToLower(k) == lowerKey {
			return v, true
		}
	}
	return "", false
}
