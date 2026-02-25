package mcp

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// executeInput is the typed input for the execute tool.
type executeInput struct {
	// Action specifies the action to execute.
	// Available actions: replay, replay_raw, delete_sessions.
	Action string `json:"action"`
	// Params holds action-specific parameters.
	Params executeParams `json:"params"`
}

// executeParams holds the union of all action-specific parameters.
// Only the fields relevant to the specified action are used.
type executeParams struct {
	// SessionID is used by replay, replay_raw, and delete_sessions (single deletion).
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID for replay/replay_raw/delete"`

	// replay overrides
	OverrideMethod  string            `json:"override_method,omitempty" jsonschema:"HTTP method override for replay"`
	OverrideURL     string            `json:"override_url,omitempty" jsonschema:"URL override for replay"`
	OverrideHeaders map[string]string `json:"override_headers,omitempty" jsonschema:"header overrides for replay"`
	OverrideBody    *string           `json:"override_body,omitempty" jsonschema:"body override for replay"`

	// replay_raw parameters
	TargetAddr string `json:"target_addr,omitempty" jsonschema:"target address (host:port) for replay_raw"`
	UseTLS     *bool  `json:"use_tls,omitempty" jsonschema:"use TLS for replay_raw connection"`

	// delete_sessions parameters
	OlderThanDays *int `json:"older_than_days,omitempty" jsonschema:"delete sessions older than this many days"`
	Confirm       bool `json:"confirm,omitempty" jsonschema:"confirm bulk deletion"`
}

// availableActions lists the valid action names for error messages.
var availableActions = []string{"replay", "replay_raw", "delete_sessions"}

// registerExecute registers the execute MCP tool.
func (s *Server) registerExecute() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name: "execute",
		Description: "Execute an action on recorded proxy data. " +
			"Available actions: " +
			"'replay' replays a recorded HTTP request with optional method/URL/header/body overrides; " +
			"'replay_raw' replays raw bytes from a recorded session over TCP/TLS; " +
			"'delete_sessions' deletes sessions by ID, by age (older_than_days), or all (confirm required).",
	}, s.handleExecute)
}

// handleExecute routes the execute tool invocation to the appropriate action handler.
func (s *Server) handleExecute(ctx context.Context, req *gomcp.CallToolRequest, input executeInput) (*gomcp.CallToolResult, any, error) {
	switch input.Action {
	case "replay":
		return s.handleExecuteReplay(ctx, input.Params)
	case "replay_raw":
		return s.handleExecuteReplayRaw(ctx, input.Params)
	case "delete_sessions":
		return s.handleExecuteDeleteSessions(ctx, input.Params)
	default:
		return nil, nil, fmt.Errorf("invalid action %q: available actions are %v", input.Action, availableActions)
	}
}

// executeReplayResult is the structured output of the replay action.
type executeReplayResult struct {
	// NewSessionID is the session ID of the replayed request.
	NewSessionID string `json:"new_session_id"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// ResponseHeaders is the response headers.
	ResponseHeaders map[string][]string `json:"response_headers"`
	// ResponseBody is the response body as text or Base64-encoded string.
	ResponseBody string `json:"response_body"`
	// ResponseBodyEncoding indicates the encoding of the response body ("text" or "base64").
	ResponseBodyEncoding string `json:"response_body_encoding"`
	// DurationMs is the request duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
}

// handleExecuteReplay handles the replay action within the execute tool.
// It retrieves the original session, applies any overrides, sends the request,
// and records the result as a new session.
func (s *Server) handleExecuteReplay(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeReplayResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for replay action")
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, params.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", params.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Build the replay request with overrides applied.
	method := sendMsg.Method
	if params.OverrideMethod != "" {
		method = params.OverrideMethod
	}

	targetURL := sendMsg.URL
	if params.OverrideURL != "" {
		parsed, err := url.Parse(params.OverrideURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, nil, fmt.Errorf("invalid override_url %q: must include scheme and host", params.OverrideURL)
		}
		// Validate URL scheme (http/https only) to prevent SSRF via non-HTTP protocols.
		if err := validateURLScheme(parsed); err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", params.OverrideURL, err)
		}
		targetURL = parsed
	}

	if targetURL == nil {
		return nil, nil, fmt.Errorf("original session has no URL and no override_url was provided")
	}

	// Validate the final target URL scheme (covers both original and overridden URLs).
	if err := validateURLScheme(targetURL); err != nil {
		return nil, nil, err
	}

	var body io.Reader
	var reqBody []byte
	if params.OverrideBody != nil {
		reqBody = []byte(*params.OverrideBody)
		body = bytes.NewReader(reqBody)
	} else if len(sendMsg.Body) > 0 {
		reqBody = sendMsg.Body
		body = bytes.NewReader(reqBody)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("create replay request: %w", err)
	}

	// Copy original headers.
	for key, values := range sendMsg.Headers {
		for _, v := range values {
			httpReq.Header.Add(key, v)
		}
	}

	// Apply header overrides (single-value replacement).
	for key, value := range params.OverrideHeaders {
		httpReq.Header.Set(key, value)
	}

	// Build the final request headers snapshot for recording.
	recordedHeaders := make(map[string][]string)
	for key, values := range httpReq.Header {
		recordedHeaders[key] = values
	}

	// Execute the request.
	client := s.httpClient()
	start := time.Now()
	resp, err := client.Do(httpReq)
	if err != nil {
		return nil, nil, fmt.Errorf("replay request: %w", err)
	}
	defer resp.Body.Close()

	// Limit response body read to prevent OOM from unbounded responses.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxReplayResponseSize))
	if err != nil {
		return nil, nil, fmt.Errorf("read replay response body: %w", err)
	}
	duration := time.Since(start)

	// Build response headers snapshot.
	respHeaders := make(map[string][]string)
	for key, values := range resp.Header {
		respHeaders[key] = values
	}

	// Record the replay as a new session.
	newSess := &session.Session{
		Protocol:    sess.Protocol,
		SessionType: "unary",
		State:       "complete",
		Timestamp:   start,
		Duration:    duration,
	}

	if err := s.store.SaveSession(ctx, newSess); err != nil {
		return nil, nil, fmt.Errorf("save replay session: %w", err)
	}

	// Save send message.
	newSendMsg := &session.Message{
		SessionID: newSess.ID,
		Sequence:  0,
		Direction: "send",
		Timestamp: start,
		Method:    method,
		URL:       targetURL,
		Headers:   recordedHeaders,
		Body:      reqBody,
	}
	if err := s.store.AppendMessage(ctx, newSendMsg); err != nil {
		return nil, nil, fmt.Errorf("save replay send message: %w", err)
	}

	// Save receive message.
	newRecvMsg := &session.Message{
		SessionID:  newSess.ID,
		Sequence:   1,
		Direction:  "receive",
		Timestamp:  start.Add(duration),
		StatusCode: resp.StatusCode,
		Headers:    respHeaders,
		Body:       respBody,
	}
	if err := s.store.AppendMessage(ctx, newRecvMsg); err != nil {
		return nil, nil, fmt.Errorf("save replay receive message: %w", err)
	}

	respBodyStr, respBodyEncoding := encodeBody(respBody)

	result := &executeReplayResult{
		NewSessionID:         newSess.ID,
		StatusCode:           resp.StatusCode,
		ResponseHeaders:      respHeaders,
		ResponseBody:         respBodyStr,
		ResponseBodyEncoding: respBodyEncoding,
		DurationMs:           duration.Milliseconds(),
	}

	return nil, result, nil
}

// executeReplayRawResult is the structured output of the replay_raw action.
type executeReplayRawResult struct {
	// ResponseData is the raw response bytes, Base64-encoded.
	ResponseData string `json:"response_data"`
	// ResponseSize is the number of response bytes received.
	ResponseSize int `json:"response_size"`
	// DurationMs is the round-trip duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
}

// handleExecuteReplayRaw handles the replay_raw action within the execute tool.
// It retrieves the session's raw request bytes and sends them directly over TCP/TLS.
func (s *Server) handleExecuteReplayRaw(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeReplayRawResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if params.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required for replay_raw action")
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, params.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", params.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Verify raw request bytes are available.
	if len(sendMsg.RawBytes) == 0 {
		return nil, nil, fmt.Errorf("session %s has no raw request bytes", params.SessionID)
	}

	// Determine the target address.
	targetAddr := params.TargetAddr
	if targetAddr == "" {
		if sendMsg.URL == nil {
			return nil, nil, fmt.Errorf("session has no URL and no target_addr was provided")
		}
		host := sendMsg.URL.Hostname()
		port := sendMsg.URL.Port()
		if port == "" {
			if sendMsg.URL.Scheme == "https" {
				port = "443"
			} else {
				port = "80"
			}
		}
		targetAddr = net.JoinHostPort(host, port)
	}

	// Determine whether to use TLS.
	useTLS := sess.Protocol == "HTTPS"
	if params.UseTLS != nil {
		useTLS = *params.UseTLS
	}

	// Establish the connection.
	dialer := s.rawDialerFunc()
	start := time.Now()

	conn, err := dialer.DialContext(ctx, "tcp", targetAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("connect to %s: %w", targetAddr, err)
	}
	defer conn.Close()

	// Upgrade to TLS if needed.
	if useTLS {
		host, _, _ := net.SplitHostPort(targetAddr)
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         host,
			InsecureSkipVerify: true,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return nil, nil, fmt.Errorf("TLS handshake with %s: %w", targetAddr, err)
		}
		conn = tlsConn
	}

	// Set a deadline for the entire operation.
	if err := conn.SetDeadline(time.Now().Add(defaultReplayTimeout)); err != nil {
		return nil, nil, fmt.Errorf("set connection deadline: %w", err)
	}

	// Send the raw request bytes exactly as captured.
	if _, err := conn.Write(sendMsg.RawBytes); err != nil {
		return nil, nil, fmt.Errorf("send raw request: %w", err)
	}

	// Read the raw response (limited to maxReplayResponseSize).
	respData, err := io.ReadAll(io.LimitReader(conn, maxReplayResponseSize))
	if err != nil {
		// Connection may be closed by the server after sending the response.
		// If we already have some data, that's fine.
		if len(respData) == 0 {
			return nil, nil, fmt.Errorf("read raw response: %w", err)
		}
	}
	duration := time.Since(start)

	result := &executeReplayRawResult{
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData),
		DurationMs:   duration.Milliseconds(),
	}

	return nil, result, nil
}

// executeDeleteSessionsResult is the structured output of the delete_sessions action.
type executeDeleteSessionsResult struct {
	// DeletedCount is the number of sessions that were deleted.
	DeletedCount int64 `json:"deleted_count"`
	// CutoffTime is the cutoff timestamp in RFC 3339 format (only set for older_than_days).
	CutoffTime string `json:"cutoff_time,omitempty"`
}

// handleExecuteDeleteSessions handles the delete_sessions action within the execute tool.
// It supports single ID deletion, all-session deletion (with confirm), and age-based deletion.
func (s *Server) handleExecuteDeleteSessions(ctx context.Context, params executeParams) (*gomcp.CallToolResult, *executeDeleteSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	// Age-based deletion (older_than_days).
	if params.OlderThanDays != nil {
		days := *params.OlderThanDays
		if days < 1 {
			return nil, nil, fmt.Errorf("older_than_days must be >= 1, got %d", days)
		}
		if !params.Confirm {
			return nil, nil, fmt.Errorf("confirm must be true to proceed with age-based deletion")
		}
		cutoff := time.Now().UTC().AddDate(0, 0, -days)
		n, err := s.store.DeleteSessionsOlderThan(ctx, cutoff)
		if err != nil {
			return nil, nil, fmt.Errorf("delete old sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{
			DeletedCount: n,
			CutoffTime:   cutoff.Format(time.RFC3339),
		}, nil
	}

	// Single ID deletion.
	if params.SessionID != "" {
		// Verify the session exists before deleting.
		if _, err := s.store.GetSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("session not found: %s", params.SessionID)
		}
		if err := s.store.DeleteSession(ctx, params.SessionID); err != nil {
			return nil, nil, fmt.Errorf("delete session: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: 1}, nil
	}

	// All-session deletion (requires confirm).
	if params.Confirm {
		n, err := s.store.DeleteAllSessions(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all sessions: %w", err)
		}
		return nil, &executeDeleteSessionsResult{DeletedCount: n}, nil
	}

	return nil, nil, fmt.Errorf("delete_sessions requires one of: session_id, older_than_days, or confirm=true for all deletion")
}
