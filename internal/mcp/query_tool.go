package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// queryInput is the typed input for the query tool.
type queryInput struct {
	// Resource specifies what to query: flows, flow, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results.
	Resource string `json:"resource" jsonschema:"resource to query: flows, flow, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results"`

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

	// SortBy specifies the field to sort results by (used by fuzz_results).
	SortBy string `json:"sort_by,omitempty" jsonschema:"field name to sort results by"`

	// Limit is the maximum number of items to return (default 50, max 1000).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of items to return (default 50, max 1000)"`

	// Offset is the number of items to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"number of items to skip for pagination (must be >= 0)"`
}

// queryFilter contains filter options for the flows and fuzz resources.
type queryFilter struct {
	// Protocol filters flows by protocol (e.g. "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP").
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter (e.g. HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP)"`
	// Method filters flows by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters flows by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters flows/fuzz_results by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
	// BlockedBy filters flows by blocked_by value (e.g. "target_scope", "intercept_drop").
	BlockedBy string `json:"blocked_by,omitempty" jsonschema:"blocked_by filter (e.g. target_scope, intercept_drop)"`
	// State filters flows by lifecycle state ("active", "complete", or "error").
	State string `json:"state,omitempty" jsonschema:"flow lifecycle state filter (active, complete, error)"`
	// Direction filters messages by direction ("send" or "receive").
	Direction string `json:"direction,omitempty" jsonschema:"message direction filter (send or receive)"`
	// BodyContains filters fuzz_results by response body substring.
	BodyContains string `json:"body_contains,omitempty" jsonschema:"response body substring filter (fuzz_results)"`
	// Status filters fuzz_jobs by status (e.g. "running", "completed").
	Status string `json:"status,omitempty" jsonschema:"fuzz job status filter (e.g. running, completed)"`
	// Tag filters fuzz_jobs by tag (exact match).
	Tag string `json:"tag,omitempty" jsonschema:"fuzz job tag filter (exact match)"`
}

// availableResources lists all valid resource names for error messages.
var availableResources = []string{"flows", "flow", "messages", "status", "config", "ca_cert", "intercept_queue", "macros", "macro", "fuzz_jobs", "fuzz_results"}

// registerQuery registers the query MCP tool.
func (s *Server) registerQuery() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "query",
		Description: "Unified information query tool. Retrieve flows, flow details, messages, " +
			"proxy status, configuration, CA certificate, intercept queue, macro definitions, or fuzz results. " +
			"Set 'resource' to one of: flows, flow, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results. " +
			"The 'id' parameter is required for flow, messages, and macro resources. " +
			"The 'fuzz_id' parameter is required for fuzz_results resource. " +
			"The 'filter' parameter supports filtering flows by protocol (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP), method, url_pattern, status_code, blocked_by (target_scope, intercept_drop), and state (active, complete, error); " +
			"messages by direction (send or receive); " +
			"fuzz_jobs by status and tag; fuzz_results by status_code and body_contains. " +
			"Flows include protocol_summary with protocol-specific information. " +
			"Flow state indicates lifecycle: 'active' (in progress), 'complete' (finished), 'error' (failed with 502 etc.). " +
			"Streaming flows (flow_type != unary) include message_preview with the first 10 messages. " +
			"Messages include metadata with protocol-specific fields (e.g. WebSocket opcode, gRPC service/method/grpc_status, variant original/modified). " +
			"When intercept/transform modifies a request, the flow contains variant messages: original (seq=0, variant=original) and modified (seq=1, variant=modified). " +
			"The 'fields' parameter controls which fields are returned in the response (fuzz_jobs, fuzz_results). " +
			"The 'sort_by' parameter sorts fuzz_results by the specified field. " +
			"Results are paginated with limit/offset for flows, messages, fuzz_jobs, and fuzz_results resources. " +
			"'intercept_queue' returns currently blocked requests waiting for release/modify_and_forward/drop actions.",
	}, s.handleQuery)
}

// handleQuery dispatches the query request to the appropriate resource handler.
func (s *Server) handleQuery(ctx context.Context, req *gomcp.CallToolRequest, input queryInput) (*gomcp.CallToolResult, any, error) {
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
	case "":
		return nil, nil, fmt.Errorf("resource is required: available resources are %s", strings.Join(availableResources, ", "))
	default:
		return nil, nil, fmt.Errorf("unknown resource %q: available resources are %s", input.Resource, strings.Join(availableResources, ", "))
	}
}

// --- flows resource ---

// queryFlowsEntry is a single flow entry in the flows query response.
type queryFlowsEntry struct {
	ID              string            `json:"id"`
	Protocol        string            `json:"protocol"`
	FlowType     string            `json:"flow_type"`
	State           string            `json:"state"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	MessageCount    int               `json:"message_count"`
	BlockedBy       string            `json:"blocked_by,omitempty"`
	ProtocolSummary map[string]string `json:"protocol_summary,omitempty"`
	Timestamp       string            `json:"timestamp"`
	DurationMs      int64             `json:"duration_ms"`
}

// queryFlowsResult is the response for the flows resource.
type queryFlowsResult struct {
	Flows []queryFlowsEntry `json:"flows"`
	Count    int                  `json:"count"`
	Total    int                  `json:"total"`
}

// handleQueryFlows returns a paginated list of flows with message summary data.
func (s *Server) handleQueryFlows(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowsResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := flow.ListOptions{
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.Protocol = input.Filter.Protocol
		opts.Method = input.Filter.Method
		opts.URLPattern = input.Filter.URLPattern
		opts.StatusCode = input.Filter.StatusCode
		opts.BlockedBy = input.Filter.BlockedBy
		opts.State = input.Filter.State
	}

	flowList, err := s.deps.store.ListFlows(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list flows: %w", err)
	}

	total, err := s.deps.store.CountFlows(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count flows: %w", err)
	}

	entries := make([]queryFlowsEntry, 0, len(flowList))
	for _, fl := range flowList {
		// Fetch messages for method/url/status_code/message_count via JOIN data.
		msgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("get messages for flow %s: %w", fl.ID, err)
		}

		var method, urlStr string
		var statusCode int
		for _, msg := range msgs {
			if msg.Direction == "send" {
				// For variant messages, prefer the "modified" variant
				// as it represents what was actually sent.
				variant := msg.Metadata["variant"]
				if method == "" || variant == "modified" {
					method = msg.Method
					if msg.URL != nil {
						urlStr = msg.URL.String()
					}
				}
			}
			if msg.Direction == "receive" && statusCode == 0 {
				statusCode = msg.StatusCode
			}
		}

		summary := buildProtocolSummary(fl.Protocol, fl.FlowType, msgs)

		entries = append(entries, queryFlowsEntry{
			ID:              fl.ID,
			Protocol:        fl.Protocol,
			FlowType:     fl.FlowType,
			State:           fl.State,
			Method:          method,
			URL:             urlStr,
			StatusCode:      statusCode,
			MessageCount:    len(msgs),
			BlockedBy:       fl.BlockedBy,
			ProtocolSummary: summary,
			Timestamp:       fl.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			DurationMs:      fl.Duration.Milliseconds(),
		})
	}

	result := &queryFlowsResult{
		Flows: entries,
		Count:    len(entries),
		Total:    total,
	}
	return nil, result, nil
}

// --- flow resource ---

// queryFlowResult is the response for the flow resource.
type queryFlowResult struct {
	ID                    string              `json:"id"`
	ConnID                string              `json:"conn_id"`
	Protocol              string              `json:"protocol"`
	FlowType           string              `json:"flow_type"`
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
	Tags                  map[string]string   `json:"tags,omitempty"`
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
}

// queryVariantRequest represents the original request before intercept/transform modification.
type queryVariantRequest struct {
	Method       string              `json:"method"`
	URL          string              `json:"url"`
	Headers      map[string][]string `json:"headers"`
	Body         string              `json:"body"`
	BodyEncoding string              `json:"body_encoding"`
}

// streamPreviewLimit is the maximum number of messages to include in a streaming flow preview.
const streamPreviewLimit = 10

// handleQueryFlow returns detailed information about a single flow.
func (s *Server) handleQueryFlow(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryFlowResult, error) {
	if s.deps.store == nil {
		return nil, nil, fmt.Errorf("flow store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for flow resource")
	}

	fl, err := s.deps.store.GetFlow(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	msgs, err := s.deps.store.GetMessages(ctx, fl.ID, flow.MessageListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	// Collect send messages (may include original + modified variants) and the first receive.
	var sendMsgs []*flow.Message
	var recvMsg *flow.Message
	for _, msg := range msgs {
		if msg.Direction == "send" {
			sendMsgs = append(sendMsgs, msg)
		}
		if msg.Direction == "receive" && recvMsg == nil {
			recvMsg = msg
		}
	}

	// Determine the effective send message (the one actually sent to the server).
	// If variants exist, the "modified" variant is the effective request.
	// The "original" variant is preserved separately for diff display.
	var sendMsg, originalSendMsg *flow.Message
	if len(sendMsgs) > 1 {
		for _, m := range sendMsgs {
			variant := m.Metadata["variant"]
			if variant == "modified" {
				sendMsg = m
			} else if variant == "original" {
				originalSendMsg = m
			}
		}
		// Fallback: if no variant metadata, use the last send message.
		if sendMsg == nil {
			sendMsg = sendMsgs[len(sendMsgs)-1]
			originalSendMsg = sendMsgs[0]
		}
	} else if len(sendMsgs) == 1 {
		sendMsg = sendMsgs[0]
	}

	var urlStr, method string
	var reqHeaders, respHeaders map[string][]string
	var reqBody, respBody []byte
	var reqTruncated, respTruncated bool
	var statusCode int
	var rawReqStr, rawRespStr string

	if sendMsg != nil {
		method = sendMsg.Method
		if sendMsg.URL != nil {
			urlStr = sendMsg.URL.String()
		}
		reqHeaders = sendMsg.Headers
		reqBody = sendMsg.Body
		reqTruncated = sendMsg.BodyTruncated
		if len(sendMsg.RawBytes) > 0 {
			rawReqStr = base64.StdEncoding.EncodeToString(sendMsg.RawBytes)
		}
	}
	if recvMsg != nil {
		statusCode = recvMsg.StatusCode
		respHeaders = recvMsg.Headers
		respBody = recvMsg.Body
		respTruncated = recvMsg.BodyTruncated
		if len(recvMsg.RawBytes) > 0 {
			rawRespStr = base64.StdEncoding.EncodeToString(recvMsg.RawBytes)
		}
	}

	// Build original request variant if available.
	var originalReq *queryVariantRequest
	if originalSendMsg != nil {
		origBodyStr, origBodyEnc := encodeBody(originalSendMsg.Body)
		var origURLStr string
		if originalSendMsg.URL != nil {
			origURLStr = originalSendMsg.URL.String()
		}
		originalReq = &queryVariantRequest{
			Method:       originalSendMsg.Method,
			URL:          origURLStr,
			Headers:      originalSendMsg.Headers,
			Body:         origBodyStr,
			BodyEncoding: origBodyEnc,
		}
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

	summary := buildProtocolSummary(fl.Protocol, fl.FlowType, msgs)

	result := &queryFlowResult{
		ID:                    fl.ID,
		ConnID:                fl.ConnID,
		Protocol:              fl.Protocol,
		FlowType:           fl.FlowType,
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
		Tags:                  fl.Tags,
		BlockedBy:             fl.BlockedBy,
		RawRequest:            rawReqStr,
		RawResponse:           rawRespStr,
		ConnInfo:              connInfo,
		MessageCount:          len(msgs),
		ProtocolSummary:       summary,
		OriginalRequest:       originalReq,
	}

	// For streaming flows, include a message preview instead of full request/response.
	if fl.FlowType != "unary" {
		previewLimit := streamPreviewLimit
		if previewLimit > len(msgs) {
			previewLimit = len(msgs)
		}
		preview := make([]queryMessageEntry, 0, previewLimit)
		for _, msg := range msgs[:previewLimit] {
			// Use Body for text content; fall back to RawBytes for binary protocols.
			bodyData := msg.Body
			if len(bodyData) == 0 && len(msg.RawBytes) > 0 {
				bodyData = msg.RawBytes
			}
			bodyStr, bodyEnc := encodeBody(bodyData)
			var msgURLStr string
			if msg.URL != nil {
				msgURLStr = msg.URL.String()
			}
			entry := queryMessageEntry{
				ID:           msg.ID,
				Sequence:     msg.Sequence,
				Direction:    msg.Direction,
				Method:       msg.Method,
				URL:          msgURLStr,
				StatusCode:   msg.StatusCode,
				Headers:      msg.Headers,
				Body:         bodyStr,
				BodyEncoding: bodyEnc,
				Timestamp:    msg.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
				Metadata:     msg.Metadata,
			}
			preview = append(preview, entry)
		}
		result.MessagePreview = preview
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

	// Verify the flow exists.
	if _, err := s.deps.store.GetFlow(ctx, input.ID); err != nil {
		return nil, nil, fmt.Errorf("get flow: %w", err)
	}

	// Get total message count for pagination.
	total, err := s.deps.store.CountMessages(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("count messages: %w", err)
	}

	// Build message list options with direction filter if specified.
	msgOpts := flow.MessageListOptions{}
	if input.Filter != nil && input.Filter.Direction != "" {
		if input.Filter.Direction != "send" && input.Filter.Direction != "receive" {
			return nil, nil, fmt.Errorf("direction filter must be \"send\" or \"receive\", got %q", input.Filter.Direction)
		}
		msgOpts.Direction = input.Filter.Direction
	}

	// Fetch messages with optional direction filter.
	allMsgs, err := s.deps.store.GetMessages(ctx, input.ID, msgOpts)
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	// Use filtered count as total for pagination when direction filter is active.
	filteredTotal := total
	if msgOpts.Direction != "" {
		filteredTotal = len(allMsgs)
	}

	// Apply pagination in-memory.
	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	offset := input.Offset
	if offset > len(allMsgs) {
		offset = len(allMsgs)
	}
	end := offset + limit
	if end > len(allMsgs) {
		end = len(allMsgs)
	}
	pageMsgs := allMsgs[offset:end]

	entries := make([]queryMessageEntry, 0, len(pageMsgs))
	for _, msg := range pageMsgs {
		// Use Body for text content; fall back to RawBytes for binary protocols
		// (e.g. WebSocket binary/control frames store payload in RawBytes).
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
	Listeners         []queryListenerStatusEntry  `json:"listeners,omitempty"`
	ListenerCount     int                        `json:"listener_count"`
	UpstreamProxy     string                     `json:"upstream_proxy"`
	ActiveConnections int                        `json:"active_connections"`
	MaxConnections    int                        `json:"max_connections"`
	PeekTimeoutMs     int64                      `json:"peek_timeout_ms"`
	RequestTimeoutMs  int64                      `json:"request_timeout_ms"`
	TotalFlows     int                        `json:"total_flows"`
	DBSizeBytes       int64                      `json:"db_size_bytes"`
	UptimeSeconds     int64                      `json:"uptime_seconds"`
	CAInitialized     bool                       `json:"ca_initialized"`
}

// handleQueryStatus returns the current proxy status and health metrics.
func (s *Server) handleQueryStatus(ctx context.Context) (*gomcp.CallToolResult, *queryStatusResult, error) {
	result := &queryStatusResult{
		DBSizeBytes: -1,
	}

	if s.deps.manager != nil {
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

	// Report request timeout from the first registered handler.
	if rt := s.currentRequestTimeout(); rt > 0 {
		result.RequestTimeoutMs = rt.Milliseconds()
	} else {
		// Default request timeout when no handler is registered.
		result.RequestTimeoutMs = 60000
	}

	if s.deps.store != nil {
		count, err := s.deps.store.CountFlows(ctx, flow.ListOptions{})
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

	return nil, result, nil
}

// --- config resource ---

// queryConfigResult is the response for the config resource.
type queryConfigResult struct {
	UpstreamProxy    string                  `json:"upstream_proxy"`
	CaptureScope     *queryScopeResult       `json:"capture_scope"`
	TLSPassthrough   *queryPassthroughResult `json:"tls_passthrough"`
	TCPForwards      map[string]string       `json:"tcp_forwards,omitempty"`
	EnabledProtocols []string                `json:"enabled_protocols,omitempty"`
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

	return nil, result, nil
}

// --- ca_cert resource ---

// queryCACertResult is the response for the ca_cert resource.
type queryCACertResult struct {
	PEM          string `json:"pem"`
	Fingerprint  string `json:"fingerprint"`
	Subject      string `json:"subject"`
	NotAfter     string `json:"not_after"`
	Persisted    bool   `json:"persisted"`
	CertPath     string `json:"cert_path,omitempty"`
	InstallHint  string `json:"install_hint,omitempty"`
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
	// ID is the unique identifier for the intercepted request.
	ID string `json:"id"`
	// Method is the HTTP method.
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// Headers are the request headers.
	Headers map[string][]string `json:"headers"`
	// BodyEncoding indicates the encoding of the body ("text" or "base64").
	BodyEncoding string `json:"body_encoding"`
	// Body is the request body as text or Base64-encoded string.
	Body string `json:"body"`
	// Timestamp is when the request was intercepted.
	Timestamp string `json:"timestamp"`
	// MatchedRules lists the IDs of the rules that matched this request.
	MatchedRules []string `json:"matched_rules"`
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
		var urlStr string
		if item.URL != nil {
			urlStr = item.URL.String()
		}

		bodyStr, bodyEncoding := encodeBody(item.Body)

		// Convert http.Header to map for JSON output.
		headers := make(map[string][]string)
		for k, vs := range item.Headers {
			headers[k] = vs
		}

		entries = append(entries, queryInterceptQueueEntry{
			ID:           item.ID,
			Method:       item.Method,
			URL:          urlStr,
			Headers:      headers,
			Body:         bodyStr,
			BodyEncoding: bodyEncoding,
			Timestamp:    item.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			MatchedRules: item.MatchedRules,
		})
	}

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

