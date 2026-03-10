package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// compareParams holds the parameters for the compare action.
type compareParams struct {
	FlowIDA string `json:"flow_id_a"`
	FlowIDB string `json:"flow_id_b"`
}

// compareResult is the structured output of the compare action.
type compareResult struct {
	StatusCode     *statusCodeDiff       `json:"status_code,omitempty"`
	BodyLength     *bodyLengthDiff       `json:"body_length,omitempty"`
	HeadersAdded   []string              `json:"headers_added,omitempty"`
	HeadersRemoved []string              `json:"headers_removed,omitempty"`
	HeadersChanged map[string]headerDiff `json:"headers_changed,omitempty"`
	TimingMs       *timingDiff           `json:"timing_ms,omitempty"`
	Body           *bodyDiff             `json:"body"`
}

// statusCodeDiff represents the status code comparison.
type statusCodeDiff struct {
	A       int  `json:"a"`
	B       int  `json:"b"`
	Changed bool `json:"changed"`
}

// bodyLengthDiff represents the body length comparison.
type bodyLengthDiff struct {
	A     int `json:"a"`
	B     int `json:"b"`
	Delta int `json:"delta"`
}

// headerDiff represents a changed header value.
type headerDiff struct {
	A string `json:"a"`
	B string `json:"b"`
}

// timingDiff represents the timing comparison.
type timingDiff struct {
	A     int64 `json:"a"`
	B     int64 `json:"b"`
	Delta int64 `json:"delta"`
}

// bodyDiff represents the body comparison.
type bodyDiff struct {
	ContentType string    `json:"content_type"`
	Identical   bool      `json:"identical"`
	JSONDiff    *jsonDiff `json:"json_diff,omitempty"`
}

// jsonDiff represents the JSON key-level diff.
type jsonDiff struct {
	KeysAdded   []string `json:"keys_added,omitempty"`
	KeysRemoved []string `json:"keys_removed,omitempty"`
	KeysChanged []string `json:"keys_changed,omitempty"`
}

// handleCompare handles the compare action within the resend tool.
func (s *Server) handleCompare(ctx context.Context, params compareParams) (*gomcp.CallToolResult, any, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if params.FlowIDA == "" {
		return nil, nil, fmt.Errorf("flow_id_a is required for compare action")
	}
	if params.FlowIDB == "" {
		return nil, nil, fmt.Errorf("flow_id_b is required for compare action")
	}

	flowA, err := s.deps.store.GetFlow(ctx, params.FlowIDA)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow A (%s): %w", params.FlowIDA, err)
	}
	flowB, err := s.deps.store.GetFlow(ctx, params.FlowIDB)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow B (%s): %w", params.FlowIDB, err)
	}

	recvA, err := getLastReceiveMessage(ctx, s.deps.store, flowA.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("flow A (%s): %w", params.FlowIDA, err)
	}
	recvB, err := getLastReceiveMessage(ctx, s.deps.store, flowB.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("flow B (%s): %w", params.FlowIDB, err)
	}

	result := buildCompareResult(flowA, flowB, recvA, recvB)
	return nil, result, nil
}

// getLastReceiveMessage retrieves the last receive message for a flow.
func getLastReceiveMessage(ctx context.Context, store flow.FlowReader, flowID string) (*flow.Message, error) {
	msgs, err := store.GetMessages(ctx, flowID, flow.MessageListOptions{Direction: "receive"})
	if err != nil {
		return nil, fmt.Errorf("get receive messages: %w", err)
	}
	if len(msgs) == 0 {
		return nil, fmt.Errorf("no receive messages found")
	}
	// Return the last receive message (highest sequence).
	return msgs[len(msgs)-1], nil
}

// buildCompareResult constructs the structured comparison result.
func buildCompareResult(flowA, flowB *flow.Flow, recvA, recvB *flow.Message) *compareResult {
	result := &compareResult{}

	// Status code comparison.
	result.StatusCode = &statusCodeDiff{
		A:       recvA.StatusCode,
		B:       recvB.StatusCode,
		Changed: recvA.StatusCode != recvB.StatusCode,
	}

	// Body length comparison.
	result.BodyLength = &bodyLengthDiff{
		A:     len(recvA.Body),
		B:     len(recvB.Body),
		Delta: len(recvB.Body) - len(recvA.Body),
	}

	// Header comparison.
	added, removed, changed := compareHeaders(recvA.Headers, recvB.Headers)
	if len(added) > 0 {
		result.HeadersAdded = added
	}
	if len(removed) > 0 {
		result.HeadersRemoved = removed
	}
	if len(changed) > 0 {
		result.HeadersChanged = changed
	}

	// Timing comparison.
	aMs := flowA.Duration.Milliseconds()
	bMs := flowB.Duration.Milliseconds()
	result.TimingMs = &timingDiff{
		A:     aMs,
		B:     bMs,
		Delta: bMs - aMs,
	}

	// Body comparison.
	result.Body = buildBodyDiff(recvA, recvB)

	return result
}

// compareHeaders compares two sets of HTTP headers and returns the added, removed,
// and changed headers. Only the first value of each header is compared.
func compareHeaders(a, b map[string][]string) (added, removed []string, changed map[string]headerDiff) {
	changed = make(map[string]headerDiff)

	// Find removed and changed headers.
	for key := range a {
		canonical := http.CanonicalHeaderKey(key)
		bVals, exists := lookupHeader(b, canonical)
		if !exists {
			removed = append(removed, canonical)
		} else {
			aVal := firstHeaderValue(a[key])
			bVal := firstHeaderValue(bVals)
			if aVal != bVal {
				changed[canonical] = headerDiff{A: aVal, B: bVal}
			}
		}
	}

	// Find added headers.
	for key := range b {
		canonical := http.CanonicalHeaderKey(key)
		if _, exists := lookupHeader(a, canonical); !exists {
			added = append(added, canonical)
		}
	}

	sort.Strings(added)
	sort.Strings(removed)

	if len(changed) == 0 {
		changed = nil
	}

	return added, removed, changed
}

// lookupHeader looks up a header by canonical key in a header map.
func lookupHeader(headers map[string][]string, canonical string) ([]string, bool) {
	for key, vals := range headers {
		if http.CanonicalHeaderKey(key) == canonical {
			return vals, true
		}
	}
	return nil, false
}

// firstHeaderValue returns the first value from a header value slice, or empty string.
func firstHeaderValue(vals []string) string {
	if len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// buildBodyDiff constructs the body diff section of the compare result.
func buildBodyDiff(recvA, recvB *flow.Message) *bodyDiff {
	contentType := detectResponseContentType(recvA, recvB)
	identical := bytes.Equal(recvA.Body, recvB.Body)

	diff := &bodyDiff{
		ContentType: contentType,
		Identical:   identical,
	}

	// Only add JSON key diff for JSON content type and non-identical bodies.
	if !identical && isJSONContentType(contentType) {
		diff.JSONDiff = computeJSONKeyDiff(recvA.Body, recvB.Body)
	}

	return diff
}

// detectResponseContentType returns the Content-Type from the responses.
// Prefers the Content-Type from response A; falls back to B.
func detectResponseContentType(recvA, recvB *flow.Message) string {
	ct := firstHeaderValue(getHeaderValues(recvA.Headers, "Content-Type"))
	if ct == "" {
		ct = firstHeaderValue(getHeaderValues(recvB.Headers, "Content-Type"))
	}
	return ct
}

// getHeaderValues retrieves header values by canonical key lookup.
func getHeaderValues(headers map[string][]string, key string) []string {
	canonical := http.CanonicalHeaderKey(key)
	for k, v := range headers {
		if http.CanonicalHeaderKey(k) == canonical {
			return v
		}
	}
	return nil
}

// isJSONContentType checks if a content type string indicates JSON.
func isJSONContentType(ct string) bool {
	// Match "application/json" and variants like "application/json; charset=utf-8".
	if ct == "" {
		return false
	}
	// Strip parameters (e.g. "; charset=utf-8").
	mediaType, _, _ := strings.Cut(ct, ";")
	mediaType = strings.TrimSpace(mediaType)
	return mediaType == "application/json" || mediaType == "text/json" || strings.HasSuffix(mediaType, "+json")
}

// computeJSONKeyDiff computes the key-level diff between two JSON objects.
// Returns nil if either body is not a valid JSON object.
func computeJSONKeyDiff(bodyA, bodyB []byte) *jsonDiff {
	keysA := flattenJSONKeys(bodyA)
	keysB := flattenJSONKeys(bodyB)
	if keysA == nil || keysB == nil {
		return nil
	}

	setA := toStringSet(keysA)
	setB := toStringSet(keysB)

	added := sortedDifference(keysB, setA)
	removed := sortedDifference(keysA, setB)
	changed := findChangedKeys(bodyA, bodyB, keysA, setB)

	if len(added) == 0 && len(removed) == 0 && len(changed) == 0 {
		return nil
	}

	return &jsonDiff{
		KeysAdded:   added,
		KeysRemoved: removed,
		KeysChanged: changed,
	}
}

// toStringSet converts a string slice to a set (map[string]bool).
func toStringSet(ss []string) map[string]bool {
	set := make(map[string]bool, len(ss))
	for _, s := range ss {
		set[s] = true
	}
	return set
}

// sortedDifference returns sorted keys from 'keys' that are not in 'exclude'.
func sortedDifference(keys []string, exclude map[string]bool) []string {
	var result []string
	for _, k := range keys {
		if !exclude[k] {
			result = append(result, k)
		}
	}
	sort.Strings(result)
	return result
}

// findChangedKeys returns sorted keys that exist in both JSON objects but have different values.
func findChangedKeys(bodyA, bodyB []byte, keysA []string, setB map[string]bool) []string {
	valuesA := flattenJSONValues(bodyA)
	valuesB := flattenJSONValues(bodyB)
	var changed []string
	for _, k := range keysA {
		if !setB[k] {
			continue
		}
		if valuesA[k] != valuesB[k] {
			changed = append(changed, k)
		}
	}
	sort.Strings(changed)
	return changed
}

// flattenJSONKeys extracts top-level keys from a JSON object.
// Returns nil if the body is not a valid JSON object.
func flattenJSONKeys(body []byte) []string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	keys := make([]string, 0, len(obj))
	for k := range obj {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// flattenJSONValues extracts top-level key-value pairs from a JSON object,
// with values serialized as strings for comparison.
// Returns nil if the body is not a valid JSON object.
func flattenJSONValues(body []byte) map[string]string {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(body, &obj); err != nil {
		return nil
	}
	result := make(map[string]string, len(obj))
	for k, v := range obj {
		result[k] = string(v)
	}
	return result
}
