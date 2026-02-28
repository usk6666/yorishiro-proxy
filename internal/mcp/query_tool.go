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
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// queryInput is the typed input for the query tool.
type queryInput struct {
	// Resource specifies what to query: sessions, session, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results.
	Resource string `json:"resource" jsonschema:"resource to query: sessions, session, messages, status, config, ca_cert, macros, macro, fuzz_jobs, fuzz_results"`

	// ID is required for session and messages resources.
	// For session: the session ID. For messages: the session_id.
	ID string `json:"id,omitempty" jsonschema:"session ID (required for session and messages resources)"`

	// FuzzID is required for the fuzz_results resource (fuzz job ID).
	FuzzID string `json:"fuzz_id,omitempty" jsonschema:"fuzz job ID (required for fuzz_results resource)"`

	// Filter is used with the sessions and fuzz resources for filtering results.
	Filter *queryFilter `json:"filter,omitempty" jsonschema:"filter options for sessions and fuzz resources"`

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

// queryFilter contains filter options for the sessions and fuzz resources.
type queryFilter struct {
	// Protocol filters sessions by protocol (e.g. "HTTP/1.x", "HTTPS", "WebSocket", "HTTP/2", "gRPC", "TCP").
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter (e.g. HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP)"`
	// Method filters sessions by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters sessions by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters sessions/fuzz_results by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
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
var availableResources = []string{"sessions", "session", "messages", "status", "config", "ca_cert", "intercept_queue", "macros", "macro", "fuzz_jobs", "fuzz_results"}

// registerQuery registers the query MCP tool.
func (s *Server) registerQuery() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "query",
		Description: "Unified information query tool. Retrieve sessions, session details, messages, " +
			"proxy status, configuration, CA certificate, intercept queue, macro definitions, or fuzz results. " +
			"Set 'resource' to one of: sessions, session, messages, status, config, ca_cert, intercept_queue, macros, macro, fuzz_jobs, fuzz_results. " +
			"The 'id' parameter is required for session, messages, and macro resources. " +
			"The 'fuzz_id' parameter is required for fuzz_results resource. " +
			"The 'filter' parameter supports filtering sessions by protocol (HTTP/1.x, HTTPS, WebSocket, HTTP/2, gRPC, TCP), method, url_pattern, and status_code; " +
			"messages by direction (send or receive); " +
			"fuzz_jobs by status and tag; fuzz_results by status_code and body_contains. " +
			"Sessions include protocol_summary with protocol-specific information. " +
			"Streaming sessions (session_type != unary) include message_preview with the first 10 messages. " +
			"Messages include metadata with protocol-specific fields (e.g. WebSocket opcode, gRPC service/method/grpc_status). " +
			"The 'fields' parameter controls which fields are returned in the response (fuzz_jobs, fuzz_results). " +
			"The 'sort_by' parameter sorts fuzz_results by the specified field. " +
			"Results are paginated with limit/offset for sessions, messages, fuzz_jobs, and fuzz_results resources. " +
			"'intercept_queue' returns currently blocked requests waiting for release/modify_and_forward/drop actions.",
	}, s.handleQuery)
}

// handleQuery dispatches the query request to the appropriate resource handler.
func (s *Server) handleQuery(ctx context.Context, req *gomcp.CallToolRequest, input queryInput) (*gomcp.CallToolResult, any, error) {
	switch input.Resource {
	case "sessions":
		return s.handleQuerySessions(ctx, input)
	case "session":
		return s.handleQuerySession(ctx, input)
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

// --- sessions resource ---

// querySessionsEntry is a single session entry in the sessions query response.
type querySessionsEntry struct {
	ID              string            `json:"id"`
	Protocol        string            `json:"protocol"`
	SessionType     string            `json:"session_type"`
	State           string            `json:"state"`
	Method          string            `json:"method"`
	URL             string            `json:"url"`
	StatusCode      int               `json:"status_code"`
	MessageCount    int               `json:"message_count"`
	ProtocolSummary map[string]string `json:"protocol_summary,omitempty"`
	Timestamp       string            `json:"timestamp"`
	DurationMs      int64             `json:"duration_ms"`
}

// querySessionsResult is the response for the sessions resource.
type querySessionsResult struct {
	Sessions []querySessionsEntry `json:"sessions"`
	Count    int                  `json:"count"`
	Total    int                  `json:"total"`
}

// handleQuerySessions returns a paginated list of sessions with message summary data.
func (s *Server) handleQuerySessions(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *querySessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := session.ListOptions{
		Limit:  limit,
		Offset: input.Offset,
	}
	if input.Filter != nil {
		opts.Protocol = input.Filter.Protocol
		opts.Method = input.Filter.Method
		opts.URLPattern = input.Filter.URLPattern
		opts.StatusCode = input.Filter.StatusCode
	}

	sessionList, err := s.store.ListSessions(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list sessions: %w", err)
	}

	total, err := s.store.CountSessions(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count sessions: %w", err)
	}

	entries := make([]querySessionsEntry, 0, len(sessionList))
	for _, sess := range sessionList {
		// Fetch messages for method/url/status_code/message_count via JOIN data.
		msgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("get messages for session %s: %w", sess.ID, err)
		}

		var method, urlStr string
		var statusCode int
		for _, msg := range msgs {
			if msg.Direction == "send" && method == "" {
				method = msg.Method
				if msg.URL != nil {
					urlStr = msg.URL.String()
				}
			}
			if msg.Direction == "receive" && statusCode == 0 {
				statusCode = msg.StatusCode
			}
		}

		summary := buildProtocolSummary(sess.Protocol, sess.SessionType, msgs)

		entries = append(entries, querySessionsEntry{
			ID:              sess.ID,
			Protocol:        sess.Protocol,
			SessionType:     sess.SessionType,
			State:           sess.State,
			Method:          method,
			URL:             urlStr,
			StatusCode:      statusCode,
			MessageCount:    len(msgs),
			ProtocolSummary: summary,
			Timestamp:       sess.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			DurationMs:      sess.Duration.Milliseconds(),
		})
	}

	result := &querySessionsResult{
		Sessions: entries,
		Count:    len(entries),
		Total:    total,
	}
	return nil, result, nil
}

// --- session resource ---

// querySessionResult is the response for the session resource.
type querySessionResult struct {
	ID                    string              `json:"id"`
	ConnID                string              `json:"conn_id"`
	Protocol              string              `json:"protocol"`
	SessionType           string              `json:"session_type"`
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
	RawRequest            string              `json:"raw_request,omitempty"`
	RawResponse           string              `json:"raw_response,omitempty"`
	ConnInfo              *connInfoResult     `json:"conn_info,omitempty"`
	MessageCount          int                 `json:"message_count"`
	ProtocolSummary       map[string]string   `json:"protocol_summary,omitempty"`
	MessagePreview        []queryMessageEntry `json:"message_preview,omitempty"`
}

// streamPreviewLimit is the maximum number of messages to include in a streaming session preview.
const streamPreviewLimit = 10

// handleQuerySession returns detailed information about a single session.
func (s *Server) handleQuerySession(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *querySessionResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for session resource")
	}

	sess, err := s.store.GetSession(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	msgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	var sendMsg, recvMsg *session.Message
	for _, msg := range msgs {
		if msg.Direction == "send" && sendMsg == nil {
			sendMsg = msg
		}
		if msg.Direction == "receive" && recvMsg == nil {
			recvMsg = msg
		}
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

	reqBodyStr, reqEncoding := encodeBody(reqBody)
	respBodyStr, respEncoding := encodeBody(respBody)

	var connInfo *connInfoResult
	if sess.ConnInfo != nil {
		connInfo = &connInfoResult{
			ClientAddr:           sess.ConnInfo.ClientAddr,
			ServerAddr:           sess.ConnInfo.ServerAddr,
			TLSVersion:           sess.ConnInfo.TLSVersion,
			TLSCipher:            sess.ConnInfo.TLSCipher,
			TLSALPN:              sess.ConnInfo.TLSALPN,
			TLSServerCertSubject: sess.ConnInfo.TLSServerCertSubject,
		}
	}

	summary := buildProtocolSummary(sess.Protocol, sess.SessionType, msgs)

	result := &querySessionResult{
		ID:                    sess.ID,
		ConnID:                sess.ConnID,
		Protocol:              sess.Protocol,
		SessionType:           sess.SessionType,
		State:                 sess.State,
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
		Timestamp:             sess.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		DurationMs:            sess.Duration.Milliseconds(),
		Tags:                  sess.Tags,
		RawRequest:            rawReqStr,
		RawResponse:           rawRespStr,
		ConnInfo:              connInfo,
		MessageCount:          len(msgs),
		ProtocolSummary:       summary,
	}

	// For streaming sessions, include a message preview instead of full request/response.
	if sess.SessionType != "unary" {
		previewLimit := streamPreviewLimit
		if previewLimit > len(msgs) {
			previewLimit = len(msgs)
		}
		preview := make([]queryMessageEntry, 0, previewLimit)
		for _, msg := range msgs[:previewLimit] {
			bodyStr, bodyEnc := encodeBody(msg.Body)
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

// handleQueryMessages returns paginated messages for a session.
func (s *Server) handleQueryMessages(ctx context.Context, input queryInput) (*gomcp.CallToolResult, *queryMessagesResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for messages resource")
	}

	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	// Verify the session exists.
	if _, err := s.store.GetSession(ctx, input.ID); err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	// Get total message count for pagination.
	total, err := s.store.CountMessages(ctx, input.ID)
	if err != nil {
		return nil, nil, fmt.Errorf("count messages: %w", err)
	}

	// Build message list options with direction filter if specified.
	msgOpts := session.MessageListOptions{}
	if input.Filter != nil && input.Filter.Direction != "" {
		if input.Filter.Direction != "send" && input.Filter.Direction != "receive" {
			return nil, nil, fmt.Errorf("direction filter must be \"send\" or \"receive\", got %q", input.Filter.Direction)
		}
		msgOpts.Direction = input.Filter.Direction
	}

	// Fetch messages with optional direction filter.
	allMsgs, err := s.store.GetMessages(ctx, input.ID, msgOpts)
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
		bodyStr, bodyEnc := encodeBody(msg.Body)

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

// queryStatusResult is the response for the status resource.
type queryStatusResult struct {
	Running           bool   `json:"running"`
	ListenAddr        string `json:"listen_addr"`
	UpstreamProxy     string `json:"upstream_proxy"`
	ActiveConnections int    `json:"active_connections"`
	TotalSessions     int    `json:"total_sessions"`
	DBSizeBytes       int64  `json:"db_size_bytes"`
	UptimeSeconds     int64  `json:"uptime_seconds"`
	CAInitialized     bool   `json:"ca_initialized"`
}

// handleQueryStatus returns the current proxy status and health metrics.
func (s *Server) handleQueryStatus(ctx context.Context) (*gomcp.CallToolResult, *queryStatusResult, error) {
	result := &queryStatusResult{
		DBSizeBytes: -1,
	}

	if s.manager != nil {
		running, addr := s.manager.Status()
		result.Running = running
		result.ListenAddr = addr
		result.UpstreamProxy = s.manager.UpstreamProxy()
		result.ActiveConnections = s.manager.ActiveConnections()
		result.UptimeSeconds = int64(s.manager.Uptime().Seconds())
	}

	if s.store != nil {
		count, err := s.store.CountSessions(ctx, session.ListOptions{})
		if err != nil {
			return nil, nil, fmt.Errorf("count sessions: %w", err)
		}
		result.TotalSessions = count
	}

	if s.dbPath != "" {
		info, err := os.Stat(s.dbPath)
		if err == nil {
			result.DBSizeBytes = info.Size()
		}
	}

	if s.ca != nil && s.ca.Certificate() != nil {
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

	if s.manager != nil {
		result.UpstreamProxy = s.manager.UpstreamProxy()
	}

	if s.scope != nil {
		includes, excludes := s.scope.Rules()
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

	if s.passthrough != nil {
		patterns := s.passthrough.List()
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

	if len(s.tcpForwards) > 0 {
		result.TCPForwards = s.tcpForwards
	}
	if len(s.enabledProtocols) > 0 {
		result.EnabledProtocols = s.enabledProtocols
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
	if s.ca == nil {
		return nil, nil, fmt.Errorf("CA is not initialized: no CA has been configured for this server")
	}

	cert := s.ca.Certificate()
	if cert == nil {
		return nil, nil, fmt.Errorf("CA certificate is not available: CA has not been generated or loaded")
	}

	certPEM := s.ca.CertPEM()
	if certPEM == nil {
		return nil, nil, fmt.Errorf("CA certificate PEM is not available")
	}

	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	source := s.ca.Source()
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
	if s.interceptQueue == nil {
		return nil, nil, fmt.Errorf("intercept queue is not initialized")
	}

	items := s.interceptQueue.List()

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
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	records, err := s.store.ListMacros(ctx)
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
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}
	if input.ID == "" {
		return nil, nil, fmt.Errorf("id is required for macro resource (macro name)")
	}

	rec, err := s.store.GetMacro(ctx, input.ID)
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

