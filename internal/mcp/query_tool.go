package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"os"
	"sort"
	"strings"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// queryInput is the typed input for the query tool.
type queryInput struct {
	// Resource specifies what to query: sessions, session, messages, status, config, ca_cert.
	Resource string `json:"resource" jsonschema:"resource to query: sessions, session, messages, status, config, ca_cert"`

	// ID is required for session and messages resources.
	// For session: the session ID. For messages: the session_id.
	ID string `json:"id,omitempty" jsonschema:"session ID (required for session and messages resources)"`

	// Filter is used with the sessions resource for filtering results.
	Filter *queryFilter `json:"filter,omitempty" jsonschema:"filter options for sessions resource"`

	// Limit is the maximum number of items to return (default 50, max 1000).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of items to return (default 50, max 1000)"`

	// Offset is the number of items to skip for pagination.
	Offset int `json:"offset,omitempty" jsonschema:"number of items to skip for pagination (must be >= 0)"`
}

// queryFilter contains filter options for the sessions resource.
type queryFilter struct {
	// Protocol filters sessions by protocol (e.g. "HTTP/1.x", "HTTPS").
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter (e.g. HTTP/1.x, HTTPS)"`
	// Method filters sessions by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters sessions by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters sessions by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
}

// availableResources lists all valid resource names for error messages.
var availableResources = []string{"sessions", "session", "messages", "status", "config", "ca_cert"}

// registerQuery registers the query MCP tool.
func (s *Server) registerQuery() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "query",
		Description: "Unified information query tool. Retrieve sessions, session details, messages, " +
			"proxy status, configuration, or CA certificate. " +
			"Set 'resource' to one of: sessions, session, messages, status, config, ca_cert. " +
			"The 'id' parameter is required for session and messages resources. " +
			"The 'filter' parameter supports filtering sessions by protocol, method, url_pattern, and status_code. " +
			"Results are paginated with limit/offset for sessions and messages resources.",
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
	case "":
		return nil, nil, fmt.Errorf("resource is required: available resources are %s", strings.Join(availableResources, ", "))
	default:
		return nil, nil, fmt.Errorf("unknown resource %q: available resources are %s", input.Resource, strings.Join(availableResources, ", "))
	}
}

// --- sessions resource ---

// querySessionsEntry is a single session entry in the sessions query response.
type querySessionsEntry struct {
	ID           string `json:"id"`
	Protocol     string `json:"protocol"`
	SessionType  string `json:"session_type"`
	State        string `json:"state"`
	Method       string `json:"method"`
	URL          string `json:"url"`
	StatusCode   int    `json:"status_code"`
	MessageCount int    `json:"message_count"`
	Timestamp    string `json:"timestamp"`
	DurationMs   int64  `json:"duration_ms"`
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

		entries = append(entries, querySessionsEntry{
			ID:           sess.ID,
			Protocol:     sess.Protocol,
			SessionType:  sess.SessionType,
			State:        sess.State,
			Method:       method,
			URL:          urlStr,
			StatusCode:   statusCode,
			MessageCount: len(msgs),
			Timestamp:    sess.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
			DurationMs:   sess.Duration.Milliseconds(),
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
}

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

	// Fetch all messages (store does not support limit/offset natively for messages).
	allMsgs, err := s.store.GetMessages(ctx, input.ID, session.MessageListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
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
			Timestamp:    msg.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	result := &queryMessagesResult{
		Messages: entries,
		Count:    len(entries),
		Total:    total,
	}
	return nil, result, nil
}

// --- status resource ---

// queryStatusResult is the response for the status resource.
type queryStatusResult struct {
	Running           bool   `json:"running"`
	ListenAddr        string `json:"listen_addr"`
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
	CaptureScope  *queryScopeResult       `json:"capture_scope"`
	TLSPassthrough *queryPassthroughResult `json:"tls_passthrough"`
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

	return nil, result, nil
}

// --- ca_cert resource ---

// queryCACertResult is the response for the ca_cert resource.
type queryCACertResult struct {
	PEM         string `json:"pem"`
	Fingerprint string `json:"fingerprint"`
	Subject     string `json:"subject"`
	NotAfter    string `json:"not_after"`
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

	result := &queryCACertResult{
		PEM:         string(certPEM),
		Fingerprint: fingerprintHex,
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return nil, result, nil
}

