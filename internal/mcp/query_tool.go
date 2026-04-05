package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// defaultRequestTimeoutMs is the default request timeout in milliseconds
// used when no protocol handler is registered.
const defaultRequestTimeoutMs = 60000

// queryInput is the typed input for the query tool.
type queryInput struct {
	// Resource specifies what to query: flows, flow, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results, technologies.
	Resource string `json:"resource" jsonschema:"resource to query: flows, flow, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results, technologies"`

	// ID is required for flow and messages resources.
	// For flow: the flow ID. For messages: the flow_id.
	ID string `json:"id,omitempty" jsonschema:"flow ID (required for flow and messages resources)"`

	// FuzzID is required for the fuzz_results resource (fuzz job ID).
	FuzzID string `json:"fuzz_id,omitempty" jsonschema:"fuzz job ID (required for fuzz_results resource)"`

	// Filter is used with the flows and fuzz resources for filtering results.
	Filter *queryFilter `json:"filter,omitempty" jsonschema:"filter options for flows and fuzz resources"`

	// Fields controls which fields are returned in the response.
	// If empty, all fields are returned.
	Fields []string `json:"fields,omitempty" jsonschema:"list of field names to include in the response"`

	// SortBy specifies the field to sort results by (used by flows and fuzz_results).
	SortBy string `json:"sort_by,omitempty" jsonschema:"field name to sort results by"`

	// Limit is the maximum number of items to return (default 50, max 1000).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of items to return (default 50, max 1000)"`

	// Offset is the number of items to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"number of items to skip for pagination (must be >= 0)"`
}

// queryFilter contains filter options for the flows and fuzz resources.
type queryFilter struct {
	// Protocol filters flows by exact protocol label. Note: protocol=HTTPS matches only HTTP/1.x over TLS.
	// HTTPS MITM connections negotiated as HTTP/2 are recorded as protocol=HTTP/2, not HTTPS.
	// To find all flows over TLS regardless of protocol, use scheme=https instead.
	Protocol string `json:"protocol,omitempty" jsonschema:"exact protocol label filter (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, gRPC-Web, TCP, SOCKS5+HTTPS, SOCKS5+HTTP). HTTPS matches only HTTP/1.x over TLS; HTTP/2 over TLS is recorded as HTTP/2. To find all TLS flows use scheme=https instead."`
	// Scheme filters flows by URL scheme / transport (e.g. "https", "http", "wss", "ws", "tcp").
	// Use scheme to find TLS flows: filter={scheme: "https"} returns HTTP/1.x, HTTP/2, gRPC flows over TLS.
	// WebSocket over TLS uses scheme="wss", not "https".
	Scheme string `json:"scheme,omitempty" jsonschema:"URL scheme / transport filter (https, http, wss, ws, tcp)"`
	// Method filters flows by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters flows by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters flows/fuzz_results by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
	// BlockedBy filters flows by blocked_by value (e.g. "target_scope", "intercept_drop", "rate_limit").
	BlockedBy string `json:"blocked_by,omitempty" jsonschema:"blocked_by filter (e.g. target_scope, intercept_drop, rate_limit)"`
	// State filters flows by lifecycle state ("active", "complete", or "error").
	State string `json:"state,omitempty" jsonschema:"flow lifecycle state filter (active, complete, error)"`
	// Direction filters messages by direction ("send" or "receive").
	Direction string `json:"direction,omitempty" jsonschema:"message direction filter (send or receive)"`
	// Technology filters flows by detected technology name (case-insensitive substring match).
	Technology string `json:"technology,omitempty" jsonschema:"technology name filter for flows (e.g. nginx, wordpress)"`
	// ConnID filters flows by connection ID (exact match).
	ConnID string `json:"conn_id,omitempty" jsonschema:"connection ID filter for flows (exact match)"`
	// Host filters flows by host (matches server_addr or URL host).
	Host string `json:"host,omitempty" jsonschema:"host filter for flows (matches server_addr or URL host, e.g. example.com)"`
	// BodyContains filters fuzz_results by response body substring.
	BodyContains string `json:"body_contains,omitempty" jsonschema:"response body substring filter (fuzz_results)"`
	// OutliersOnly filters fuzz_results to return only outlier results.
	OutliersOnly bool `json:"outliers_only,omitempty" jsonschema:"return only outlier fuzz results (by status_code, body_length, or timing)"`
	// Status filters fuzz_jobs by status (e.g. "running", "completed").
	Status string `json:"status,omitempty" jsonschema:"fuzz job status filter (e.g. running, completed)"`
	// Tag filters fuzz_jobs by tag (exact match).
	Tag string `json:"tag,omitempty" jsonschema:"fuzz job tag filter (exact match)"`
}

// availableResources lists all valid resource names for error messages.
var availableResources = []string{"flows", "flow", "messages", "status", "config", "ca_cert", "intercept_queue", "macros", "macro", "fuzz_jobs", "fuzz_results", "technologies"}

// validFilterProtocols lists valid values for filter.protocol.
var validFilterProtocols = []string{"HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "gRPC-Web", "TCP", "SOCKS5+HTTPS", "SOCKS5+HTTP"}

// validFilterSchemes lists valid values for filter.scheme.
var validFilterSchemes = []string{"https", "http", "wss", "ws", "tcp"}

// validFilterStates lists valid values for filter.state.
var validFilterStates = []string{"active", "complete", "error"}

// validFilterBlockedBy lists valid values for filter.blocked_by.
var validFilterBlockedBy = []string{"target_scope", "intercept_drop", "rate_limit", "safety_filter"}

// validFilterFuzzJobStatuses lists valid values for filter.status (fuzz_jobs).
var validFilterFuzzJobStatuses = []string{"running", "paused", "completed", "cancelled", "error"}

// validFlowSortByValues lists valid values for sort_by (flows).
var validFlowSortByValues = []string{"timestamp", "duration_ms"}

// validFuzzResultSortByValues lists valid values for sort_by (fuzz_results).
var validFuzzResultSortByValues = []string{"index_num", "status_code", "duration_ms", "response_length"}

// validateEnum checks whether value is in the allowed set and returns an error with valid values listed.
func validateEnum(param, value string, valid []string) error {
	if value == "" {
		return nil
	}
	for _, v := range valid {
		if value == v {
			return nil
		}
	}
	return fmt.Errorf("invalid %s %q: valid values are %s", param, value, strings.Join(valid, ", "))
}

// validateFlowFilters validates enum filter parameters for the flows resource.
func validateFlowFilters(input queryInput) error {
	if input.Filter != nil {
		if err := validateEnum("protocol", input.Filter.Protocol, validFilterProtocols); err != nil {
			return err
		}
		if err := validateEnum("scheme", input.Filter.Scheme, validFilterSchemes); err != nil {
			return err
		}
		if err := validateEnum("state", input.Filter.State, validFilterStates); err != nil {
			return err
		}
		if err := validateEnum("blocked_by", input.Filter.BlockedBy, validFilterBlockedBy); err != nil {
			return err
		}
	}
	if err := validateEnum("sort_by", input.SortBy, validFlowSortByValues); err != nil {
		return err
	}
	return nil
}

// validateFuzzJobFilters validates enum filter parameters for the fuzz_jobs resource.
func validateFuzzJobFilters(input queryInput) error {
	if input.Filter != nil {
		if err := validateEnum("status", input.Filter.Status, validFilterFuzzJobStatuses); err != nil {
			return err
		}
	}
	return nil
}

// validateFuzzResultFilters validates enum filter parameters for the fuzz_results resource.
func validateFuzzResultFilters(input queryInput) error {
	if err := validateEnum("sort_by", input.SortBy, validFuzzResultSortByValues); err != nil {
		return err
	}
	return nil
}

// registerQuery registers the query MCP tool.
func (s *Server) registerQuery() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "query",
		Description: "Unified information query tool. Retrieve flows, flow details, messages, " +
			"proxy status, configuration, CA certificate, intercept queue, macro definitions, fuzz results, or technology stack detections. " +
			"Set 'resource' to one of: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results, technologies. " +
			"The 'id' parameter is required for flow, messages, and macro resources. " +
			"The 'fuzz_id' parameter is required for fuzz_results resource. " +
			"The 'filter' parameter supports filtering flows by protocol (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP, SOCKS5+HTTPS, SOCKS5+HTTP), scheme (https, http, wss, ws, tcp — use scheme to find all TLS flows: scheme=https returns HTTP/1.x+HTTP/2+gRPC over TLS), method, url_pattern, status_code, blocked_by (target_scope, intercept_drop, rate_limit), state (active, complete, error), technology (e.g. nginx, wordpress), conn_id (connection ID, exact match), and host (matches server_addr or URL host); " +
			"messages by direction (send or receive); " +
			"fuzz_jobs by status and tag; fuzz_results by status_code, body_contains, and outliers_only (returns only outlier results). " +
			"Flows include protocol_summary with protocol-specific information. " +
			"Flow state indicates lifecycle: 'active' (in progress), 'complete' (finished), 'error' (failed with 502 etc.). " +
			"Streaming protocols (more than 2 flows) include message_preview with the first 10 messages. " +
			"Messages include metadata with protocol-specific fields (e.g. WebSocket opcode, gRPC service/method/grpc_status, variant original/modified). " +
			"When intercept/transform modifies a request, the flow contains variant messages: original (seq=0, variant=original) and modified (seq=1, variant=modified). " +
			"Similarly, when intercept modifies a response, the flow contains variant receive messages with original_response in the flow detail. " +
			"The 'fields' parameter controls which fields are returned in the response (fuzz_jobs, fuzz_results). " +
			"The 'sort_by' parameter sorts flows (timestamp, duration_ms) and fuzz_results by the specified field. " +
			"Results are paginated with limit/offset for flows, messages, fuzz_jobs, and fuzz_results resources. " +
			"fuzz_results include aggregate statistics (status_code_distribution, body_length, timing_ms with min/max/median/stddev) and outlier detection (by_status_code, by_body_length, by_timing). " +
			"'intercept_queue' returns currently blocked requests and responses (with phase field) waiting for release/modify_and_forward/drop actions. " +
			"'technologies' aggregates detected technology stacks per host across all flows.",
	}, s.handleQuery)
}

// validateQueryInput dispatches enum validation by resource type.
func validateQueryInput(input queryInput) error {
	switch input.Resource {
	case "flows":
		return validateFlowFilters(input)
	case "fuzz_jobs":
		return validateFuzzJobFilters(input)
	case "fuzz_results":
		return validateFuzzResultFilters(input)
	default:
		return nil
	}
}

// handleQuery dispatches the query request to the appropriate resource handler.
func (s *Server) handleQuery(ctx context.Context, req *gomcp.CallToolRequest, input queryInput) (*gomcp.CallToolResult, any, error) {
	start := time.Now()
	slog.DebugContext(ctx, "MCP tool invoked",
		"tool", "query",
		"resource", input.Resource,
		"id", input.ID,
		"fuzz_id", input.FuzzID,
	)
	defer func() {
		slog.DebugContext(ctx, "MCP tool completed",
			"tool", "query",
			"resource", input.Resource,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	}()

	if err := validateQueryInput(input); err != nil {
		return nil, nil, err
	}
	switch input.Resource {
	case "flows":
		return s.handleQueryFlows(ctx, input)
	case "flow":
		return s.handleQueryFlow(ctx, input)
	case "messages":
		return s.handleQueryMessages(ctx, input)
	case "status":
		return s.handleQueryStatus(ctx)
	case "config":
		return s.handleQueryConfig()
	case "ca_cert":
		return s.handleQueryCACert()
	case "intercept_queue":
		return s.handleQueryInterceptQueue(input)
	case "macros":
		return s.handleQueryMacros(ctx)
	case "macro":
		return s.handleQueryMacro(ctx, input)
	case "fuzz_jobs":
		return s.handleQueryFuzzJobs(ctx, input)
	case "fuzz_results":
		return s.handleQueryFuzzResults(ctx, input)
	case "technologies":
		return s.handleQueryTechnologies(ctx, input)
	case "":
		return nil, nil, fmt.Errorf("resource is required: available resources are %s", strings.Join(availableResources, ", "))
	default:
		return nil, nil, fmt.Errorf("unknown resource %q: available resources are %s", input.Resource, strings.Join(availableResources, ", "))
	}
}

// --- anomaly extraction ---

// queryAnomaly represents a structured anomaly entry extracted from flow tags.
// Anomalies are HTTP protocol-level deviations detected during parsing, such as
// CL/TE conflicts, duplicate Content-Length headers, or header injection attempts.
type queryAnomaly struct {
	// Type is the anomaly classification (e.g., "CLTE", "DuplicateCL", "HeaderInjection").
	Type string `json:"type"`
	// Detail provides a human-readable description of the anomaly.
	Detail string `json:"detail"`
}

// smugglingTagToAnomalyType maps smuggling tag keys to their anomaly type names.
var smugglingTagToAnomalyType = map[string]string{
	"smuggling:cl_te_conflict":   "CLTE",
	"smuggling:duplicate_cl":     "DuplicateCL",
	"smuggling:ambiguous_te":     "AmbiguousTE",
	"smuggling:invalid_te":       "InvalidTE",
	"smuggling:header_injection": "HeaderInjection",
	"smuggling:obs_fold":         "ObsFold",
}

// extractAnomalies converts smuggling:* tags into a structured anomaly list.
// Returns nil if no anomalies are present, avoiding unnecessary JSON array allocation.
func extractAnomalies(tags map[string]string) []queryAnomaly {
	if len(tags) == 0 {
		return nil
	}

	var anomalies []queryAnomaly
	warnings := tags["smuggling:warnings"]

	for tagKey, anomalyType := range smugglingTagToAnomalyType {
		if tags[tagKey] == "true" {
			detail := ""
			if warnings != "" {
				detail = warnings
			}
			anomalies = append(anomalies, queryAnomaly{
				Type:   anomalyType,
				Detail: detail,
			})
		}
	}

	if len(anomalies) == 0 {
		return nil
	}

	// Sort for deterministic output.
	sort.Slice(anomalies, func(i, j int) bool {
		return anomalies[i].Type < anomalies[j].Type
	})
	return anomalies
}

// --- flows resource ---

// queryFlowsEntry is a single flow entry in the flows query response.
type queryFlowsEntry struct {
	ID              string            `json:"id"`
	Protocol        string            `json:"protocol"`
	Scheme          string            `json:"scheme,omitempty"`
	State           string            `json:"state"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	MessageCount    int               `json:"message_count"`
	BlockedBy       string            `json:"blocked_by,omitempty"`
	ProtocolSummary map[string]string `json:"protocol_summary,omitempty"`
	Tags            map[string]string `json:"tags,omitempty"`
	Anomalies       []queryAnomaly    `json:"anomalies,omitempty"`
	Timestamp       string            `json:"timestamp"`
	DurationMs      int64             `json:"duration_ms"`
	SendMs          *int64            `json:"send_ms,omitempty"`
	WaitMs          *int64            `json:"wait_ms,omitempty"`
	ReceiveMs       *int64            `json:"receive_ms,omitempty"`
}

// queryFlowsResult is the response for the flows resource.
type queryFlowsResult struct {
	Flows []queryFlowsEntry `json:"flows"`
	Count int               `json:"count"`
	Total int               `json:"total"`
}

// buildFlowListOptions constructs flow.StreamListOptions from query input parameters.
func buildFlowListOptions(input queryInput) flow.StreamListOptions {
	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := flow.StreamListOptions{
		Limit:  limit,
		Offset: input.Offset,
		SortBy: input.SortBy,
	}
	if input.Filter != nil {
		opts.Protocol = input.Filter.Protocol
		opts.Scheme = input.Filter.Scheme
		opts.Method = input.Filter.Method
		opts.URLPattern = input.Filter.URLPattern
		opts.StatusCode = input.Filter.StatusCode
		opts.BlockedBy = input.Filter.BlockedBy
		opts.State = input.Filter.State
		opts.Technology = input.Filter.Technology
		opts.ConnID = input.Filter.ConnID
		opts.Host = input.Filter.Host
	}
	return opts
}

// extractFlowSummary extracts the effective method, URL, and status code from flow messages.
// It prefers "modified" variant messages as they represent the actually transmitted data.
func extractFlowSummary(msgs []*flow.Flow) (method, urlStr string, statusCode int) {
	for _, msg := range msgs {
		if msg.Direction == "send" {
			variant := msg.Metadata["variant"]
			if method == "" || variant == "modified" {
				method = msg.Method
				if msg.URL != nil {
					urlStr = msg.URL.String()
				}
			}
		}
		if msg.Direction == "receive" {
			variant := msg.Metadata["variant"]
			if statusCode == 0 || variant == "modified" {
				statusCode = msg.StatusCode
			}
		}
	}
	return method, urlStr, statusCode
}

// handleQueryFlows returns a paginated list of flows with message summary data.
func (s *Server) handleQueryFlows(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowsResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	opts := buildFlowListOptions(input)

	flowList, err := s.deps.store.ListStreams(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list flows: %w", err)
	}

	total, err := s.deps.store.CountStreams(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count flows: %w", err)
	}

	entries := make([]queryFlowsEntry, 0, len(flowList))
	for _, fl := range flowList {
		// Fetch messages for method/url/status_code/message_count via JOIN data.
		msgs, err := s.deps.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("get messages for flow %s: %w", fl.ID, err)
		}

		method, urlStr, statusCode := extractFlowSummary(msgs)
		summary := buildProtocolSummary(fl.Protocol, msgs)

		entries = append(entries, queryFlowsEntry{
			ID:              fl.ID,
			Protocol:        fl.Protocol,
			Scheme:          fl.Scheme,
			State:           fl.State,
			Method:          method,
			URL:             urlStr,
			StatusCode:      statusCode,
			MessageCount:    len(msgs),
			BlockedBy:       fl.BlockedBy,
			ProtocolSummary: summary,
			Tags:            fl.Tags,
			Anomalies:       extractAnomalies(fl.Tags),
			Timestamp:       fl.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			DurationMs:      fl.Duration.Milliseconds(),
			SendMs:          fl.SendMs,
			WaitMs:          fl.WaitMs,
			ReceiveMs:       fl.ReceiveMs,
		})
	}

	result := &queryFlowsResult{
		Flows: entries,
		Count: len(entries),
		Total: total,
	}
	return nil, result, nil
}

// --- flow resource ---

// queryFlowResult is the response for the flow resource.
type queryFlowResult struct {
	ID                    string              `json:"id"`
	ConnID                string              `json:"conn_id"`
	Protocol              string              `json:"protocol"`
	Scheme                string              `json:"scheme,omitempty"`
	State                 string              `json:"state"`
	Method                string              `json:"method"`
	URL                   string              `json:"url"`
	RequestHeaders        map[string][]string `json:"request_headers"`
	RequestBody           string              `json:"request_body"`
	RequestBodyEncoding   string              `json:"request_body_encoding"`
	ResponseStatusCode    int                 `json:"response_status_code"`
	ResponseHeaders       map[string][]string `json:"response_headers"`
	ResponseBody          string              `json:"response_body"`
	ResponseBodyEncoding  string              `json:"response_body_encoding"`
	RequestBodyTruncated  bool                `json:"request_body_truncated"`
	ResponseBodyTruncated bool                `json:"response_body_truncated"`
	Timestamp             string              `json:"timestamp"`
	DurationMs            int64               `json:"duration_ms"`
	SendMs                *int64              `json:"send_ms,omitempty"`
	WaitMs                *int64              `json:"wait_ms,omitempty"`
	ReceiveMs             *int64              `json:"receive_ms,omitempty"`
	Tags                  map[string]string   `json:"tags,omitempty"`
	Anomalies             []queryAnomaly      `json:"anomalies,omitempty"`
	BlockedBy             string              `json:"blocked_by,omitempty"`
	RawRequest            string              `json:"raw_request,omitempty"`
	RawResponse           string              `json:"raw_response,omitempty"`
	ConnInfo              *connInfoResult     `json:"conn_info,omitempty"`
	MessageCount          int                 `json:"message_count"`
	ProtocolSummary       map[string]string   `json:"protocol_summary,omitempty"`
	MessagePreview        []queryMessageEntry `json:"message_preview,omitempty"`
	// OriginalRequest holds the original (pre-modification) request data
	// when a variant exists (intercept/transform modified the request).
	// Only populated when the flow contains variant messages.
	OriginalRequest *queryVariantRequest `json:"original_request,omitempty"`
	// OriginalResponse holds the original (pre-modification) response data
	// when a variant exists (intercept modified the response).
	// Only populated when the flow contains variant receive messages.
	OriginalResponse *queryVariantResponse `json:"original_response,omitempty"`
}

// queryVariantRequest represents the original request before intercept/transform modification.
type queryVariantRequest struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
}

// queryVariantResponse represents the original response before intercept modification.
type queryVariantResponse struct {
	StatusCode    int                 `json:"status_code"`
	Headers       map[string][]string `json:"headers"`
	Body          string              `json:"body"`
	BodyEncoding  string              `json:"body_encoding"`
	BodyTruncated bool                `json:"body_truncated"`
}

// streamPreviewLimit is the maximum number of messages to include in a streaming flow preview.
const streamPreviewLimit = 10

// categorizedMessages holds messages split by direction with variant resolution.
type categorizedMessages struct {
	// sendMsg is the effective send message (modified variant if present).
	sendMsg *flow.Flow
	// originalSendMsg is the original send message before modification (nil if no variant).
	originalSendMsg *flow.Flow
	// recvMsg is the effective receive message (modified variant if present).
	recvMsg *flow.Flow
	// originalRecvMsg is the original receive message before modification (nil if no variant).
	originalRecvMsg *flow.Flow
}

// categorizeMessages splits messages by direction and resolves variant pairs.
// For each direction, if multiple messages exist, the "modified" variant is the effective
// message and the "original" variant is preserved for diff display.
func categorizeMessages(msgs []*flow.Flow) categorizedMessages {
	var sendMsgs []*flow.Flow
	var recvMsgs []*flow.Flow
	for _, msg := range msgs {
		if msg.Direction == "send" {
			sendMsgs = append(sendMsgs, msg)
		}
		if msg.Direction == "receive" {
			recvMsgs = append(recvMsgs, msg)
		}
	}

	var result categorizedMessages
	result.sendMsg, result.originalSendMsg = resolveVariantPair(sendMsgs)
	result.recvMsg, result.originalRecvMsg = resolveVariantPair(recvMsgs)
	return result
}

// resolveVariantPair determines the effective and original messages from a slice of
// directional messages. If variants exist, "modified" is the effective message and
// "original" is preserved for diff display.
func resolveVariantPair(msgs []*flow.Flow) (effective, original *flow.Flow) {
	if len(msgs) == 0 {
		return nil, nil
	}
	if len(msgs) == 1 {
		return msgs[0], nil
	}
	for _, m := range msgs {
		variant := m.Metadata["variant"]
		if variant == "modified" {
			effective = m
		} else if variant == "original" {
			original = m
		}
	}
	// Fallback: if no variant metadata, use the last as effective and first as original.
	if effective == nil {
		effective = msgs[len(msgs)-1]
		original = msgs[0]
	}
	return effective, original
}

// buildOriginalRequest builds a queryVariantRequest from the original send message.
// Returns nil if originalMsg is nil.
func buildOriginalRequest(originalMsg *flow.Flow) *queryVariantRequest {
	if originalMsg == nil {
		return nil
	}
	origBodyStr, origBodyEnc := encodeBody(originalMsg.Body)
	var origURLStr string
	if originalMsg.URL != nil {
		origURLStr = originalMsg.URL.String()
	}
	return &queryVariantRequest{
		Method:       originalMsg.Method,
		URL:          origURLStr,
		Headers:      originalMsg.Headers,
		Body:         origBodyStr,
		BodyEncoding: origBodyEnc,
	}
}

// buildOriginalResponse builds a queryVariantResponse from the original receive message.
// Returns nil if originalMsg is nil.
func buildOriginalResponse(originalMsg *flow.Flow) *queryVariantResponse {
	if originalMsg == nil {
		return nil
	}
	origBodyStr, origBodyEnc := encodeBody(originalMsg.Body)
	return &queryVariantResponse{
		StatusCode:    originalMsg.StatusCode,
		Headers:       originalMsg.Headers,
		Body:          origBodyStr,
		BodyEncoding:  origBodyEnc,
		BodyTruncated: originalMsg.BodyTruncated,
	}
}

// buildMessagePreview creates a preview of messages for streaming flows, limited to streamPreviewLimit.
func buildMessagePreview(msgs []*flow.Flow) []queryMessageEntry {
	previewLimit := streamPreviewLimit
	if previewLimit > len(msgs) {
		previewLimit = len(msgs)
	}
	return convertMessagesToEntries(msgs[:previewLimit])
}

// handleQueryFlow returns detailed information about a single flow.
func (s *Server) handleQueryFlow(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for flow resource")
	}

	fl, err := s.deps.store.GetStream(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	msgs, err := s.deps.store.GetFlows(ctx, fl.ID, flow.FlowListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	cat := categorizeMessages(msgs)

	var urlStr, method string
	var reqHeaders, respHeaders map[string][]string
	var reqBody, respBody []byte
	var reqTruncated, respTruncated bool
	var statusCode int
	var rawReqStr, rawRespStr string

	if cat.sendMsg != nil {
		method = cat.sendMsg.Method
		if cat.sendMsg.URL != nil {
			urlStr = cat.sendMsg.URL.String()
		}
		reqHeaders = map[string][]string(s.filterOutputHeaders(http.Header(cat.sendMsg.Headers)))
		reqBody = s.filterOutputBody(cat.sendMsg.Body)
		reqTruncated = cat.sendMsg.BodyTruncated
		if len(cat.sendMsg.RawBytes) > 0 {
			rawReqStr = base64.StdEncoding.EncodeToString(s.filterOutputBody(cat.sendMsg.RawBytes))
		}
	}
	if cat.recvMsg != nil {
		statusCode = cat.recvMsg.StatusCode
		respHeaders = map[string][]string(s.filterOutputHeaders(http.Header(cat.recvMsg.Headers)))
		respBody = s.filterOutputBody(cat.recvMsg.Body)
		respTruncated = cat.recvMsg.BodyTruncated
		if len(cat.recvMsg.RawBytes) > 0 {
			rawRespStr = base64.StdEncoding.EncodeToString(s.filterOutputBody(cat.recvMsg.RawBytes))
		}
	}

	// Ensure headers are never nil to avoid null in JSON serialization.
	if reqHeaders == nil {
		reqHeaders = map[string][]string{}
	}
	if respHeaders == nil {
		respHeaders = map[string][]string{}
	}

	reqBodyStr, reqEncoding := encodeBody(reqBody)
	respBodyStr, respEncoding := encodeBody(respBody)

	var connInfo *connInfoResult
	if fl.ConnInfo != nil {
		connInfo = &connInfoResult{
			ClientAddr:           fl.ConnInfo.ClientAddr,
			ServerAddr:           fl.ConnInfo.ServerAddr,
			TLSVersion:           fl.ConnInfo.TLSVersion,
			TLSCipher:            fl.ConnInfo.TLSCipher,
			TLSALPN:              fl.ConnInfo.TLSALPN,
			TLSServerCertSubject: fl.ConnInfo.TLSServerCertSubject,
		}
	}

	summary := buildProtocolSummary(fl.Protocol, msgs)

	result := &queryFlowResult{
		ID:                    fl.ID,
		ConnID:                fl.ConnID,
		Protocol:              fl.Protocol,
		Scheme:                fl.Scheme,
		State:                 fl.State,
		Method:                method,
		URL:                   urlStr,
		RequestHeaders:        reqHeaders,
		RequestBody:           reqBodyStr,
		RequestBodyEncoding:   reqEncoding,
		ResponseStatusCode:    statusCode,
		ResponseHeaders:       respHeaders,
		ResponseBody:          respBodyStr,
		ResponseBodyEncoding:  respEncoding,
		RequestBodyTruncated:  reqTruncated,
		ResponseBodyTruncated: respTruncated,
		Timestamp:             fl.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs:            fl.Duration.Milliseconds(),
		SendMs:                fl.SendMs,
		WaitMs:                fl.WaitMs,
		ReceiveMs:             fl.ReceiveMs,
		Tags:                  fl.Tags,
		Anomalies:             extractAnomalies(fl.Tags),
		BlockedBy:             fl.BlockedBy,
		RawRequest:            rawReqStr,
		RawResponse:           rawRespStr,
		ConnInfo:              connInfo,
		MessageCount:          len(msgs),
		ProtocolSummary:       summary,
		OriginalRequest:       buildOriginalRequest(cat.originalSendMsg),
		OriginalResponse:      buildOriginalResponse(cat.originalRecvMsg),
	}

	// Apply output filter to original request/response variants.
	s.filterOutputVariantRequest(result.OriginalRequest)
	s.filterOutputVariantResponse(result.OriginalResponse)

	// For streaming protocols, include a message preview instead of full request/response.
	// Streams with more than 2 flows are streaming (unary has exactly 1 send + 1 receive).
	if len(msgs) > 2 {
		result.MessagePreview = buildMessagePreview(msgs)
		s.filterOutputMessages(result.MessagePreview)
	}

	return nil, result, nil
}

// --- messages resource ---

// queryMessageEntry is a single message in the messages query response.
type queryMessageEntry struct {
	ID           string              `json:"id"`
	Sequence     int                 `json:"sequence"`
	Direction    string              `json:"direction"`
	Method       string              `json:"method,omitempty"`
	URL          string              `json:"url,omitempty"`
	StatusCode   int                 `json:"status_code,omitempty"`
	Headers      map[string][]string `json:"headers,omitempty"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
	Metadata     map[string]string   `json:"metadata,omitempty"`
	Timestamp    string              `json:"timestamp"`
}

// queryMessagesResult is the response for the messages resource.
type queryMessagesResult struct {
	Messages []queryMessageEntry `json:"messages"`
	Count    int                 `json:"count"`
	Total    int                 `json:"total"`
}

// convertMessagesToEntries converts flow messages to queryMessageEntry slice.
// It uses Body for text content and falls back to RawBytes for binary protocols.
func convertMessagesToEntries(msgs []*flow.Flow) []queryMessageEntry {
	entries := make([]queryMessageEntry, 0, len(msgs))
	for _, msg := range msgs {
		bodyData := msg.Body
		if len(bodyData) == 0 && len(msg.RawBytes) > 0 {
			bodyData = msg.RawBytes
		}
		bodyStr, bodyEnc := encodeBody(bodyData)

		var urlStr string
		if msg.URL != nil {
			urlStr = msg.URL.String()
		}

		entries = append(entries, queryMessageEntry{
			ID:           msg.ID,
			Sequence:     msg.Sequence,
			Direction:    msg.Direction,
			Method:       msg.Method,
			URL:          urlStr,
			StatusCode:   msg.StatusCode,
			Headers:      msg.Headers,
			Body:         bodyStr,
			BodyEncoding: bodyEnc,
			Metadata:     msg.Metadata,
			Timestamp:    msg.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}
	return entries
}

// buildMessageListOptions validates and builds message list options from query input.
// Returns an error if the direction filter value is invalid.
func buildMessageListOptions(input queryInput) (flow.FlowListOptions, error) {
	opts := flow.FlowListOptions{}
	if input.Filter != nil && input.Filter.Direction != "" {
		if input.Filter.Direction != "send" && input.Filter.Direction != "receive" {
			return opts, fmt.Errorf("direction filter must be \"send\" or \"receive\", got %q", input.Filter.Direction)
		}
		opts.Direction = input.Filter.Direction
	}
	return opts, nil
}

// paginateMessages applies offset and limit to a message slice, returning the page.
func paginateMessages(msgs []*flow.Flow, offset, limit int) []*flow.Flow {
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}
	if offset > len(msgs) {
		offset = len(msgs)
	}
	end := offset + limit
	if end > len(msgs) {
		end = len(msgs)
	}
	return msgs[offset:end]
}

// handleQueryMessages returns paginated messages for a flow.
func (s *Server) handleQueryMessages(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryMessagesResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for messages resource")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	// Verify the flow exists and resolve prefix IDs.
	fl, err := s.deps.store.GetStream(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	// Get total message count for pagination.
	total, err := s.deps.store.CountFlows(ctx, fl.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("count messages: %w", err)
	}

	msgOpts, err := buildMessageListOptions(input)
	if err != nil {
		return nil, nil, err
	}

	allMsgs, err := s.deps.store.GetFlows(ctx, fl.ID, msgOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	// Use filtered count as total for pagination when direction filter is active.
	filteredTotal := total
	if msgOpts.Direction != "" {
		filteredTotal = len(allMsgs)
	}

	pageMsgs := paginateMessages(allMsgs, input.Offset, input.Limit)
	entries := convertMessagesToEntries(pageMsgs)

	// Apply SafetyFilter output masking to message bodies and headers.
	s.filterOutputMessages(entries)

	result := &queryMessagesResult{
		Messages: entries,
		Count:    len(entries),
		Total:    filteredTotal,
	}
	return nil, result, nil
}

// --- status resource ---

// queryListenerStatusEntry is a single listener entry in the status response.
type queryListenerStatusEntry struct {
	Name              string `json:"name"`
	ListenAddr        string `json:"listen_addr"`
	ActiveConnections int    `json:"active_connections"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
}

// queryStatusResult is the response for the status resource.
type queryStatusResult struct {
	Running           bool                       `json:"running"`
	ListenAddr        string                     `json:"listen_addr"`
	Listeners         []queryListenerStatusEntry `json:"listeners,omitempty"`
	ListenerCount     int                        `json:"listener_count"`
	UpstreamProxy     string                     `json:"upstream_proxy"`
	ActiveConnections int                        `json:"active_connections"`
	MaxConnections    int                        `json:"max_connections"`
	PeekTimeoutMs     int64                      `json:"peek_timeout_ms"`
	RequestTimeoutMs  int64                      `json:"request_timeout_ms"`
	TotalFlows        int                        `json:"total_flows"`
	DBSizeBytes       int64                      `json:"db_size_bytes"`
	UptimeSeconds     int64                      `json:"uptime_seconds"`
	CAInitialized     bool                       `json:"ca_initialized"`
	SOCKS5Enabled     bool                       `json:"socks5_enabled"`
	SOCKS5Auth        string                     `json:"socks5_auth,omitempty"`
	TLSFingerprint    string                     `json:"tls_fingerprint"`
	RateLimits        *queryRateLimitStatus      `json:"rate_limits,omitempty"`
	Budget            *queryBudgetStatus         `json:"budget,omitempty"`
}

// queryRateLimitStatus holds rate limit information for the status response.
type queryRateLimitStatus struct {
	Effective proxy.RateLimitConfig `json:"effective"`
	Enabled   bool                  `json:"enabled"`
}

// queryBudgetStatus holds budget information for the status response.
type queryBudgetStatus struct {
	Effective    proxy.BudgetConfig `json:"effective"`
	Enabled      bool               `json:"enabled"`
	RequestCount int64              `json:"request_count"`
	StopReason   string             `json:"stop_reason,omitempty"`
}

// populateManagerStatus fills manager-related fields in the status result.
func (s *Server) populateManagerStatus(result *queryStatusResult) {
	if s.deps.manager == nil {
		return
	}
	running, addr := s.deps.manager.Status()
	result.Running = running
	result.ListenAddr = addr
	result.UpstreamProxy = proxy.RedactProxyURL(s.deps.manager.UpstreamProxy())
	result.ActiveConnections = s.deps.manager.ActiveConnections()
	result.MaxConnections = s.deps.manager.MaxConnections()
	result.PeekTimeoutMs = s.deps.manager.PeekTimeout().Milliseconds()
	result.UptimeSeconds = int64(s.deps.manager.Uptime().Seconds())
	result.ListenerCount = s.deps.manager.ListenerCount()

	// Populate per-listener statuses.
	statuses := s.deps.manager.ListenerStatuses()
	if len(statuses) > 0 {
		result.Listeners = make([]queryListenerStatusEntry, 0, len(statuses))
		for _, st := range statuses {
			result.Listeners = append(result.Listeners, queryListenerStatusEntry{
				Name:              st.Name,
				ListenAddr:        st.ListenAddr,
				ActiveConnections: st.ActiveConnections,
				UptimeSeconds:     st.UptimeSeconds,
			})
		}
		// Update Running to true if any listener is running (not just default).
		if !result.Running && len(statuses) > 0 {
			result.Running = true
		}
	}
}

// handleQueryStatus returns the current proxy status and health metrics.
func (s *Server) handleQueryStatus(ctx context.Context) (*gomcp.CallToolResult, *queryStatusResult, error) {
	result := &queryStatusResult{
		DBSizeBytes: -1,
	}

	s.populateManagerStatus(result)

	// Report request timeout from the first registered handler.
	if rt := s.currentRequestTimeout(); rt > 0 {
		result.RequestTimeoutMs = rt.Milliseconds()
	} else {
		// Default request timeout when no handler is registered.
		result.RequestTimeoutMs = defaultRequestTimeoutMs
	}

	if s.deps.store != nil {
		count, err := s.deps.store.CountStreams(ctx, flow.StreamListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("count flows: %w", err)
		}
		result.TotalFlows = count
	}

	if s.deps.dbPath != "" {
		info, err := os.Stat(s.deps.dbPath)
		if err == nil {
			result.DBSizeBytes = info.Size()
		}
	}

	if s.deps.ca != nil && s.deps.ca.Certificate() != nil {
		result.CAInitialized = true
	}

	// SOCKS5 availability: enabled if the handler is registered.
	if s.deps.socks5AuthSetter != nil {
		result.SOCKS5Enabled = true
	}

	result.TLSFingerprint = s.currentTLSFingerprint()

	if s.deps.rateLimiter != nil {
		effective := s.deps.rateLimiter.EffectiveLimits()
		result.RateLimits = &queryRateLimitStatus{
			Effective: effective,
			Enabled:   s.deps.rateLimiter.HasLimits(),
		}
	}

	if s.deps.budgetManager != nil {
		effective := s.deps.budgetManager.EffectiveBudget()
		result.Budget = &queryBudgetStatus{
			Effective:    effective,
			Enabled:      s.deps.budgetManager.HasBudget(),
			RequestCount: s.deps.budgetManager.RequestCount(),
			StopReason:   s.deps.budgetManager.ShutdownReason(),
		}
	}

	return nil, result, nil
}

// --- config resource ---

// queryConfigResult is the response for the config resource.
type queryConfigResult struct {
	UpstreamProxy    string                           `json:"upstream_proxy"`
	CaptureScope     *queryScopeResult                `json:"capture_scope"`
	TLSPassthrough   *queryPassthroughResult          `json:"tls_passthrough"`
	TCPForwards      map[string]*config.ForwardConfig `json:"tcp_forwards,omitempty"`
	EnabledProtocols []string                         `json:"enabled_protocols,omitempty"`
	SOCKS5Enabled    bool                             `json:"socks5_enabled"`
	ClientCert       *queryClientCertResult           `json:"client_cert,omitempty"`
	SafetyFilter     *querySafetyFilterResult         `json:"safety_filter,omitempty"`
	MaxConnections   int                              `json:"max_connections"`
	PeekTimeoutMs    int64                            `json:"peek_timeout_ms"`
	RequestTimeoutMs int64                            `json:"request_timeout_ms"`
	TLSFingerprint   string                           `json:"tls_fingerprint"`
}

// querySafetyFilterResult holds SafetyFilter status in the config response.
type querySafetyFilterResult struct {
	Enabled     bool `json:"enabled"`
	InputRules  int  `json:"input_rules"`
	OutputRules int  `json:"output_rules"`
}

// queryClientCertResult holds client certificate info in the config response.
type queryClientCertResult struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// queryScopeResult holds capture scope rules in the config response.
type queryScopeResult struct {
	Includes []scopeRuleOutput `json:"includes"`
	Excludes []scopeRuleOutput `json:"excludes"`
}

// queryPassthroughResult holds TLS passthrough patterns in the config response.
type queryPassthroughResult struct {
	Patterns []string `json:"patterns"`
	Count    int      `json:"count"`
}

// handleQueryConfig returns the current configuration (capture scope + TLS passthrough).
func (s *Server) handleQueryConfig() (*gomcp.CallToolResult, *queryConfigResult, error) {
	result := &queryConfigResult{}

	if s.deps.manager != nil {
		result.UpstreamProxy = proxy.RedactProxyURL(s.deps.manager.UpstreamProxy())
	}

	if s.deps.scope != nil {
		includes, excludes := s.deps.scope.Rules()
		result.CaptureScope = &queryScopeResult{
			Includes: fromScopeRules(includes),
			Excludes: fromScopeRules(excludes),
		}
	} else {
		result.CaptureScope = &queryScopeResult{
			Includes: []scopeRuleOutput{},
			Excludes: []scopeRuleOutput{},
		}
	}

	if s.deps.passthrough != nil {
		patterns := s.deps.passthrough.List()
		sort.Strings(patterns)
		result.TLSPassthrough = &queryPassthroughResult{
			Patterns: patterns,
			Count:    len(patterns),
		}
	} else {
		result.TLSPassthrough = &queryPassthroughResult{
			Patterns: []string{},
			Count:    0,
		}
	}

	if len(s.deps.tcpForwards) > 0 {
		result.TCPForwards = s.deps.tcpForwards
	}
	if len(s.deps.enabledProtocols) > 0 {
		result.EnabledProtocols = s.deps.enabledProtocols
	}

	if s.deps.socks5AuthSetter != nil {
		result.SOCKS5Enabled = true
	}

	certPath, keyPath := s.currentClientCert()
	if certPath != "" {
		result.ClientCert = &queryClientCertResult{
			CertPath: certPath,
			KeyPath:  keyPath,
		}
	}

	if s.deps.safetyEngine != nil {
		result.SafetyFilter = &querySafetyFilterResult{
			Enabled:     true,
			InputRules:  len(s.deps.safetyEngine.InputRules()),
			OutputRules: len(s.deps.safetyEngine.OutputRules()),
		}
	} else {
		result.SafetyFilter = &querySafetyFilterResult{
			Enabled: false,
		}
	}

	if s.deps.manager != nil {
		result.MaxConnections = s.deps.manager.MaxConnections()
		result.PeekTimeoutMs = s.deps.manager.PeekTimeout().Milliseconds()
	}

	if rt := s.currentRequestTimeout(); rt > 0 {
		result.RequestTimeoutMs = rt.Milliseconds()
	} else {
		// Default request timeout when no handler is registered.
		result.RequestTimeoutMs = defaultRequestTimeoutMs
	}

	result.TLSFingerprint = s.currentTLSFingerprint()

	return nil, result, nil
}

// --- ca_cert resource ---

// queryCACertResult is the response for the ca_cert resource.
type queryCACertResult struct {
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
	Persisted   bool   `json:"persisted"`
	CertPath    string `json:"cert_path,omitempty"`
	InstallHint string `json:"install_hint,omitempty"`
}

// handleQueryCACert returns the CA certificate PEM and metadata.
func (s *Server) handleQueryCACert() (*gomcp.CallToolResult, *queryCACertResult, error) {
	if s.deps.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized: no CA has been configured for this server")
	}

	cert := s.deps.ca.Certificate()
	if cert == nil {
		return nil, nil, fmt.Errorf("CA certificate is not available: CA has not been generated or loaded")
	}

	certPEM := s.deps.ca.CertPEM()
	if certPEM == nil {
		return nil, nil, fmt.Errorf("CA certificate PEM is not available")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	source := s.deps.ca.Source()
	result := &queryCACertResult{
		PEM:         string(certPEM),
		Fingerprint: fingerprintHex,
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
		Persisted:   source.Persisted,
		CertPath:    source.CertPath,
	}

	if source.Persisted && source.CertPath != "" {
		result.InstallHint = "Install the CA certificate from " + source.CertPath + " into your OS/browser trust store for HTTPS interception"
	}

	return nil, result, nil
}

// --- intercept_queue resource ---

// queryInterceptQueueEntry is a single entry in the intercept queue query response.
type queryInterceptQueueEntry struct {
	// ID is the unique identifier for the intercepted item.
	ID string `json:"id"`
	// Phase indicates whether this is a "request", "response", or "websocket_frame" intercept.
	Phase string `json:"phase"`
	// Protocol is the protocol type: "http" or "websocket".
	Protocol string `json:"protocol"`
	// Method is the HTTP method (HTTP only).
	Method string `json:"method,omitempty"`
	// URL is the request URL (HTTP only).
	URL string `json:"url,omitempty"`
	// StatusCode is the HTTP status code (only set for response phase).
	StatusCode int `json:"status_code,omitempty"`
	// Headers are the request/response headers (HTTP only).
	Headers map[string][]string `json:"headers,omitempty"`
	// BodyEncoding indicates the encoding of the body/payload ("text" or "base64").
	BodyEncoding string `json:"body_encoding"`
	// Body is the request/response body or WebSocket payload as text or Base64-encoded string.
	Body string `json:"body"`
	// Timestamp is when the item was intercepted.
	Timestamp string `json:"timestamp"`
	// MatchedRules lists the IDs of the rules that matched.
	MatchedRules []string `json:"matched_rules"`

	// Metadata holds protocol-specific metadata (e.g. gRPC encoding info).
	Metadata map[string]string `json:"metadata,omitempty"`

	// --- WebSocket frame metadata (phase=websocket_frame only) ---

	// Opcode is the WebSocket frame opcode name (e.g. "Text", "Binary").
	Opcode string `json:"opcode,omitempty"`
	// Direction is the frame direction: "client_to_server" or "server_to_client".
	Direction string `json:"direction,omitempty"`
	// StreamID is the WebSocket flow ID this frame belongs to.
	StreamID string `json:"flow_id,omitempty"`
	// UpgradeURL is the URL from the original WebSocket upgrade request.
	UpgradeURL string `json:"upgrade_url,omitempty"`
	// Sequence is the frame sequence number within the WebSocket connection.
	Sequence int64 `json:"sequence,omitempty"`
}

// queryInterceptQueueResult is the response for the intercept_queue resource.
type queryInterceptQueueResult struct {
	// Items contains the currently blocked requests.
	Items []queryInterceptQueueEntry `json:"items"`
	// Count is the number of items returned.
	Count int `json:"count"`
}

// handleQueryInterceptQueue returns the list of currently intercepted (blocked) requests.
func (s *Server) handleQueryInterceptQueue(input queryInput) (*gomcp.CallToolResult, *queryInterceptQueueResult, error) {
	if s.deps.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}

	items := s.deps.interceptQueue.List()

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	// Sort by timestamp (oldest first) for consistent ordering.
	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp.Before(items[j].Timestamp)
	})

	// Apply limit.
	if len(items) > limit {
		items = items[:limit]
	}

	entries := make([]queryInterceptQueueEntry, 0, len(items))
	for _, item := range items {
		bodyStr, bodyEncoding := encodeBody(item.Body)

		entry := queryInterceptQueueEntry{
			ID:           item.ID,
			Phase:        string(item.Phase),
			Body:         bodyStr,
			BodyEncoding: bodyEncoding,
			Timestamp:    item.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			MatchedRules: item.MatchedRules,
		}

		if len(item.Metadata) > 0 {
			entry.Metadata = item.Metadata
		}

		if item.Phase == intercept.PhaseWebSocketFrame {
			entry.Protocol = "websocket"
			entry.Opcode = wsOpcodeNameFromInt(item.WSOpcode)
			entry.Direction = item.WSDirection
			entry.StreamID = item.WSFlowID
			entry.UpgradeURL = item.WSUpgradeURL
			entry.Sequence = item.WSSequence
		} else {
			entry.Protocol = "http"
			entry.Method = item.Method
			entry.StatusCode = item.StatusCode
			if item.URL != nil {
				entry.URL = item.URL.String()
			}
			// Convert KeyValue headers to map for JSON output.
			entry.Headers = map[string][]string(kvToHTTPHeader(item.Headers))
		}

		entries = append(entries, entry)
	}

	// Apply SafetyFilter output masking to intercept queue bodies and headers.
	s.filterOutputInterceptEntries(entries)

	return nil, &queryInterceptQueueResult{
		Items: entries,
		Count: len(entries),
	}, nil
}

// --- macros resource ---

// queryMacrosEntry is a single macro entry in the macros query response.
type queryMacrosEntry struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StepCount   int    `json:"step_count"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// queryMacrosResult is the response for the macros resource.
type queryMacrosResult struct {
	Macros []queryMacrosEntry `json:"macros"`
	Count  int                `json:"count"`
}

// handleQueryMacros returns a list of all stored macro definitions.
func (s *Server) handleQueryMacros(ctx context.Context) (*gomcp.CallToolResult, *queryMacrosResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	records, err := s.deps.store.ListMacros(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("list macros: %w", err)
	}

	entries := make([]queryMacrosEntry, 0, len(records))
	for _, rec := range records {
		stepCount := 0
		var cfg macroConfig
		if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err == nil {
			stepCount = len(cfg.Steps)
		}

		entries = append(entries, queryMacrosEntry{
			Name:        rec.Name,
			Description: rec.Description,
			StepCount:   stepCount,
			CreatedAt:   rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
			UpdatedAt:   rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	return nil, &queryMacrosResult{
		Macros: entries,
		Count:  len(entries),
	}, nil
}

// --- macro resource ---

// queryMacroResult is the response for the macro resource (single macro detail).
type queryMacroResult struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Steps       []macroStepInput  `json:"steps"`
	InitialVars map[string]string `json:"initial_vars,omitempty"`
	TimeoutMs   int               `json:"timeout_ms,omitempty"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

// handleQueryMacro returns detailed information about a single macro definition.
func (s *Server) handleQueryMacro(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryMacroResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for macro resource (macro name)")
	}

	rec, err := s.deps.store.GetMacro(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get macro: %w", err)
	}

	var cfg macroConfig
	if err := json.Unmarshal([]byte(rec.ConfigJSON), &cfg); err != nil {
		return nil, nil, fmt.Errorf("parse macro config: %w", err)
	}

	result := &queryMacroResult{
		Name:        rec.Name,
		Description: rec.Description,
		Steps:       cfg.Steps,
		InitialVars: cfg.InitialVars,
		TimeoutMs:   cfg.TimeoutMs,
		CreatedAt:   rec.CreatedAt.UTC().Format("2006-01-02T15:04:05Z"),
		UpdatedAt:   rec.UpdatedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return nil, result, nil
}
