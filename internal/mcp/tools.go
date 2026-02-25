package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"unicode/utf8"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// exportCACertResult is the structured output of the export_ca_cert tool.
type exportCACertResult struct {
	// PEM is the PEM-encoded CA certificate.
	PEM string `json:"pem"`
	// Fingerprint is the SHA-256 fingerprint in colon-separated hex format.
	Fingerprint string `json:"fingerprint"`
	// Subject is the CA certificate's subject distinguished name.
	Subject string `json:"subject"`
	// NotAfter is the certificate expiration date in RFC 3339 format.
	NotAfter string `json:"not_after"`
}

// registerExportCACert registers the export_ca_cert MCP tool.
func (s *Server) registerExportCACert() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "export_ca_cert",
		Description: "Export the CA certificate in PEM format with metadata. Use this to retrieve the proxy's CA certificate for installation into a client trust store, enabling HTTPS interception.",
	}, s.handleExportCACert)
}

// handleExportCACert handles the export_ca_cert tool invocation.
// It returns the CA certificate PEM, SHA-256 fingerprint, subject, and expiration date.
func (s *Server) handleExportCACert(_ context.Context, _ *gomcp.CallToolRequest, _ any) (*gomcp.CallToolResult, *exportCACertResult, error) {
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

	// Compute SHA-256 fingerprint from DER-encoded certificate.
	fingerprint := sha256.Sum256(cert.Raw)
	fingerprintHex := formatFingerprint(fingerprint[:])

	result := &exportCACertResult{
		PEM:         string(certPEM),
		Fingerprint: fingerprintHex,
		Subject:     cert.Subject.String(),
		NotAfter:    cert.NotAfter.UTC().Format("2006-01-02T15:04:05Z"),
	}

	return nil, result, nil
}

// formatFingerprint formats a byte slice as a colon-separated uppercase hex string.
// For example: "AB:CD:EF:01:23:45:...".
func formatFingerprint(b []byte) string {
	parts := make([]string, len(b))
	for i, v := range b {
		parts[i] = fmt.Sprintf("%02X", v)
	}
	return strings.Join(parts, ":")
}

// getSessionInput is the typed input for the get_session tool.
type getSessionInput struct {
	// SessionID is the unique identifier of the session to retrieve.
	SessionID string `json:"session_id"`
}

// getSessionResult is the structured output of the get_session tool.
type getSessionResult struct {
	// ID is the unique identifier of the session.
	ID string `json:"id"`
	// ConnID is the connection ID for log correlation.
	ConnID string `json:"conn_id"`
	// Protocol is the protocol used (e.g., "HTTP/1.x").
	Protocol string `json:"protocol"`
	// Method is the HTTP method (e.g., "GET", "POST").
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// RequestHeaders is the request headers as a JSON object.
	RequestHeaders map[string][]string `json:"request_headers"`
	// RequestBody is the request body as text or Base64-encoded string.
	RequestBody string `json:"request_body"`
	// RequestBodyEncoding indicates the encoding of the request body ("text" or "base64").
	RequestBodyEncoding string `json:"request_body_encoding"`
	// ResponseStatusCode is the HTTP response status code.
	ResponseStatusCode int `json:"response_status_code"`
	// ResponseHeaders is the response headers as a JSON object.
	ResponseHeaders map[string][]string `json:"response_headers"`
	// ResponseBody is the response body as text or Base64-encoded string.
	ResponseBody string `json:"response_body"`
	// ResponseBodyEncoding indicates the encoding of the response body ("text" or "base64").
	ResponseBodyEncoding string `json:"response_body_encoding"`
	// RequestBodyTruncated indicates whether the request body was truncated during recording.
	RequestBodyTruncated bool `json:"request_body_truncated"`
	// ResponseBodyTruncated indicates whether the response body was truncated during recording.
	ResponseBodyTruncated bool `json:"response_body_truncated"`
	// Timestamp is the time the session was recorded in RFC 3339 format.
	Timestamp string `json:"timestamp"`
	// DurationMs is the session duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
	// Tags holds optional key-value metadata such as smuggling detection flags.
	Tags map[string]string `json:"tags,omitempty"`
	// RawRequest is the original raw HTTP request bytes, Base64-encoded.
	// Preserves header ordering, whitespace, and HTTP version for smuggling analysis.
	// Empty string if no raw bytes were captured.
	RawRequest string `json:"raw_request,omitempty"`
	// RawResponse is the original raw HTTP response bytes, Base64-encoded.
	// Empty string if no raw bytes were captured.
	RawResponse string `json:"raw_response,omitempty"`
	// ConnInfo holds network and TLS connection metadata.
	// Nil if no connection information was recorded.
	ConnInfo *connInfoResult `json:"conn_info,omitempty"`
}

// connInfoResult is the connection metadata in the get_session response.
type connInfoResult struct {
	// ClientAddr is the client's remote address (e.g., "192.168.1.100:54321").
	ClientAddr string `json:"client_addr,omitempty"`
	// ServerAddr is the upstream server's resolved address.
	ServerAddr string `json:"server_addr,omitempty"`
	// TLSVersion is the negotiated TLS version (e.g., "TLS 1.3").
	TLSVersion string `json:"tls_version,omitempty"`
	// TLSCipher is the negotiated TLS cipher suite name.
	TLSCipher string `json:"tls_cipher,omitempty"`
	// TLSALPN is the negotiated ALPN protocol.
	TLSALPN string `json:"tls_alpn,omitempty"`
	// TLSServerCertSubject is the subject DN of the upstream server certificate.
	TLSServerCertSubject string `json:"tls_server_cert_subject,omitempty"`
}

// registerGetSession registers the get_session MCP tool.
func (s *Server) registerGetSession() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "get_session",
		Description: "Retrieve the full details of a recorded proxy session by its ID. Returns request/response headers, bodies, timing information, and metadata. Binary bodies are returned as Base64-encoded strings.",
	}, s.handleGetSession)
}

// handleGetSession handles the get_session tool invocation.
// It retrieves a session entry by ID and returns its full details.
func (s *Server) handleGetSession(ctx context.Context, _ *gomcp.CallToolRequest, input getSessionInput) (*gomcp.CallToolResult, *getSessionResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required")
	}

	sess, err := s.store.GetSession(ctx, input.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	// Get messages for this session.
	msgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{})
	if err != nil {
		return nil, nil, fmt.Errorf("get messages: %w", err)
	}

	// Find send and receive messages.
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

	// Build connection info if present.
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

	result := &getSessionResult{
		ID:                    sess.ID,
		ConnID:                sess.ConnID,
		Protocol:              sess.Protocol,
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
	}

	return nil, result, nil
}

// encodeBody returns the body as a string with its encoding type.
// If the body is valid UTF-8 text, it is returned as-is with encoding "text".
// Otherwise, it is Base64-encoded with encoding "base64".
func encodeBody(body []byte) (string, string) {
	if len(body) == 0 {
		return "", "text"
	}
	if utf8.Valid(body) {
		return string(body), "text"
	}
	return base64.StdEncoding.EncodeToString(body), "base64"
}

// listSessionsInput is the input parameters for the list_sessions tool.
type listSessionsInput struct {
	// Protocol filters sessions by protocol (e.g. "HTTP/1.x", "HTTPS").
	Protocol string `json:"protocol,omitempty" jsonschema:"protocol filter (e.g. HTTP/1.x, HTTPS)"`
	// Method filters sessions by HTTP method (e.g. "GET", "POST").
	Method string `json:"method,omitempty" jsonschema:"HTTP method filter (e.g. GET, POST)"`
	// URLPattern filters sessions by URL using a substring search pattern.
	URLPattern string `json:"url_pattern,omitempty" jsonschema:"URL substring search pattern"`
	// StatusCode filters sessions by HTTP response status code.
	StatusCode int `json:"status_code,omitempty" jsonschema:"HTTP response status code filter"`
	// Limit is the maximum number of sessions to return (default 50, max 1000).
	Limit int `json:"limit,omitempty" jsonschema:"maximum number of sessions to return (default 50, max 1000)"`
	// Offset is the number of sessions to skip for pagination (must be >= 0).
	Offset int `json:"offset,omitempty" jsonschema:"number of sessions to skip for pagination (must be >= 0)"`
}

// listSessionsEntry is a single session entry in the list_sessions response.
type listSessionsEntry struct {
	// ID is the unique session identifier.
	ID string `json:"id"`
	// Protocol is the detected protocol (e.g. "HTTP/1.x").
	Protocol string `json:"protocol"`
	// Method is the HTTP method (e.g. "GET", "POST").
	Method string `json:"method"`
	// URL is the request URL.
	URL string `json:"url"`
	// StatusCode is the HTTP response status code.
	StatusCode int `json:"status_code"`
	// Timestamp is the session creation time in RFC 3339 format.
	Timestamp string `json:"timestamp"`
}

// listSessionsResult is the structured output of the list_sessions tool.
type listSessionsResult struct {
	// Sessions is the list of matching session entries.
	Sessions []listSessionsEntry `json:"sessions"`
	// Count is the number of sessions returned in this page.
	Count int `json:"count"`
	// Total is the total number of sessions matching the filter criteria,
	// ignoring limit/offset. AI agents can use this to determine how many
	// pages remain for pagination.
	Total int `json:"total"`
}

// defaultListLimit is the default number of sessions returned when limit is not specified.
const defaultListLimit = 50

// maxListLimit is the maximum allowed value for limit to prevent OOM from unbounded queries.
const maxListLimit = 1000

// registerListSessions registers the list_sessions MCP tool.
func (s *Server) registerListSessions() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "list_sessions",
		Description: "List recorded proxy sessions with optional filtering. Supports filtering by protocol, HTTP method, URL pattern, and status code. Results are paginated with limit/offset.",
	}, s.handleListSessions)
}

// handleListSessions handles the list_sessions tool invocation.
// It queries the session store with the provided filters and returns matching entries.
func (s *Server) handleListSessions(ctx context.Context, _ *gomcp.CallToolRequest, input listSessionsInput) (*gomcp.CallToolResult, *listSessionsResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	// S-3: Validate non-negative offset.
	if input.Offset < 0 {
		return nil, nil, fmt.Errorf("offset must be >= 0, got %d", input.Offset)
	}

	// S-1: Enforce limit bounds to prevent OOM.
	limit := input.Limit
	if limit <= 0 || limit > maxListLimit {
		limit = defaultListLimit
	}

	opts := session.ListOptions{
		Protocol:   input.Protocol,
		Method:     input.Method,
		URLPattern: input.URLPattern,
		StatusCode: input.StatusCode,
		Limit:      limit,
		Offset:     input.Offset,
	}

	sessionList, err := s.store.ListSessions(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("list sessions: %w", err)
	}

	// Fetch the total count of matching sessions (ignoring limit/offset)
	// so that AI agents can determine pagination boundaries.
	total, err := s.store.CountSessions(ctx, opts)
	if err != nil {
		return nil, nil, fmt.Errorf("count sessions: %w", err)
	}

	sessions := make([]listSessionsEntry, 0, len(sessionList))
	for _, sess := range sessionList {
		// Fetch first send and receive messages for method/url/status.
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

		sessions = append(sessions, listSessionsEntry{
			ID:         sess.ID,
			Protocol:   sess.Protocol,
			Method:     method,
			URL:        urlStr,
			StatusCode: statusCode,
			Timestamp:  sess.Timestamp.UTC().Format("2006-01-02T15:04:05Z"),
		})
	}

	result := &listSessionsResult{
		Sessions: sessions,
		Count:    len(sessions),
		Total:    total,
	}

	return nil, result, nil
}

// deleteSessionInput is the typed input for the delete_session tool.
type deleteSessionInput struct {
	// SessionID is the unique identifier of the session to delete.
	SessionID string `json:"session_id,omitempty" jsonschema:"session ID to delete (required unless delete_all is true)"`
	// DeleteAll when true deletes all session entries.
	DeleteAll bool `json:"delete_all,omitempty" jsonschema:"delete all sessions (default false)"`
}

// deleteSessionResult is the structured output of the delete_session tool.
type deleteSessionResult struct {
	// DeletedCount is the number of sessions that were deleted.
	DeletedCount int64 `json:"deleted_count"`
}

// registerDeleteSession registers the delete_session MCP tool.
func (s *Server) registerDeleteSession() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "delete_session",
		Description: "Delete a recorded proxy session by ID or delete all sessions. Provide session_id to delete a single session, or set delete_all to true to remove all sessions.",
	}, s.handleDeleteSession)
}

// handleDeleteSession handles the delete_session tool invocation.
// It deletes a single session by ID or all sessions when delete_all is true.
func (s *Server) handleDeleteSession(ctx context.Context, _ *gomcp.CallToolRequest, input deleteSessionInput) (*gomcp.CallToolResult, *deleteSessionResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.SessionID == "" && !input.DeleteAll {
		return nil, nil, fmt.Errorf("either session_id or delete_all must be specified")
	}

	if input.DeleteAll {
		n, err := s.store.DeleteAllSessions(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("delete all sessions: %w", err)
		}
		return nil, &deleteSessionResult{DeletedCount: n}, nil
	}

	// Verify the session exists before deleting.
	if _, err := s.store.GetSession(ctx, input.SessionID); err != nil {
		return nil, nil, fmt.Errorf("session not found: %s", input.SessionID)
	}

	if err := s.store.DeleteSession(ctx, input.SessionID); err != nil {
		return nil, nil, fmt.Errorf("delete session: %w", err)
	}

	return nil, &deleteSessionResult{DeletedCount: 1}, nil
}
