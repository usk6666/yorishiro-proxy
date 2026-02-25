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
	"syscall"
	"time"

	gomcp "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/usk6666/katashiro-proxy/internal/session"
)

// defaultReplayTimeout is the default timeout for replay HTTP requests.
const defaultReplayTimeout = 30 * time.Second

// maxReplayResponseSize is the maximum response body size (1 MB) to prevent OOM.
const maxReplayResponseSize = 1 << 20

// allowedSchemes are the URL schemes permitted for replay requests.
var allowedSchemes = map[string]bool{
	"http":  true,
	"https": true,
}

// validateURLScheme checks that the URL uses an allowed scheme (http or https).
func validateURLScheme(u *url.URL) error {
	if !allowedSchemes[u.Scheme] {
		return fmt.Errorf("unsupported URL scheme %q: only http and https are allowed", u.Scheme)
	}
	return nil
}

// denyPrivateNetwork returns an error if the resolved IP is a private, loopback,
// link-local, or otherwise internal address. This prevents SSRF attacks.
func denyPrivateNetwork(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("split host port: %w", err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("invalid IP address: %s", host)
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
		return fmt.Errorf("connections to private/internal networks are not allowed: %s", ip)
	}
	return nil
}

// replayRequestInput is the typed input for the replay_request tool.
type replayRequestInput struct {
	// SessionID is the unique identifier of the session to replay.
	SessionID string `json:"session_id"`
	// OverrideHeaders is an optional map of headers to override in the replayed request.
	OverrideHeaders map[string]string `json:"override_headers,omitempty" jsonschema:"headers to override in the replayed request"`
	// OverrideBody is an optional body to use instead of the original request body.
	OverrideBody *string `json:"override_body,omitempty" jsonschema:"body to override in the replayed request"`
	// OverrideURL is an optional URL to use instead of the original request URL.
	OverrideURL string `json:"override_url,omitempty" jsonschema:"URL to override in the replayed request"`
	// OverrideMethod is an optional HTTP method to use instead of the original.
	OverrideMethod string `json:"override_method,omitempty" jsonschema:"HTTP method to override in the replayed request"`
}

// replayRequestResult is the structured output of the replay_request tool.
type replayRequestResult struct {
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

// httpDoer abstracts HTTP request execution for testability.
type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// registerReplayRequest registers the replay_request MCP tool.
func (s *Server) registerReplayRequest() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "replay_request",
		Description: "Replay a previously recorded HTTP request. Optionally override the method, URL, headers, or body. The replayed request and response are recorded as a new session. Useful for re-testing endpoints or modifying parameters during vulnerability assessment.",
	}, s.handleReplayRequest)
}

// handleReplayRequest handles the replay_request tool invocation.
// It retrieves the original session, applies any overrides, sends the request,
// and records the result as a new session.
func (s *Server) handleReplayRequest(ctx context.Context, _ *gomcp.CallToolRequest, input replayRequestInput) (*gomcp.CallToolResult, *replayRequestResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required")
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, input.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", input.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Build the replay request with overrides applied.
	method := sendMsg.Method
	if input.OverrideMethod != "" {
		method = input.OverrideMethod
	}

	targetURL := sendMsg.URL
	if input.OverrideURL != "" {
		parsed, err := url.Parse(input.OverrideURL)
		if err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", input.OverrideURL, err)
		}
		if parsed.Scheme == "" || parsed.Host == "" {
			return nil, nil, fmt.Errorf("invalid override_url %q: must include scheme and host", input.OverrideURL)
		}
		// S-1: Validate URL scheme (http/https only) to prevent SSRF via non-HTTP protocols.
		if err := validateURLScheme(parsed); err != nil {
			return nil, nil, fmt.Errorf("invalid override_url %q: %w", input.OverrideURL, err)
		}
		targetURL = parsed
	}

	if targetURL == nil {
		return nil, nil, fmt.Errorf("original session has no URL and no override_url was provided")
	}

	// S-1: Validate the final target URL scheme (covers both original and overridden URLs).
	if err := validateURLScheme(targetURL); err != nil {
		return nil, nil, err
	}

	var body io.Reader
	var reqBody []byte
	if input.OverrideBody != nil {
		reqBody = []byte(*input.OverrideBody)
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
	for key, value := range input.OverrideHeaders {
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

	// S-3: Limit response body read to prevent OOM from unbounded responses.
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

	result := &replayRequestResult{
		NewSessionID:         newSess.ID,
		StatusCode:           resp.StatusCode,
		ResponseHeaders:      respHeaders,
		ResponseBody:         respBodyStr,
		ResponseBodyEncoding: respBodyEncoding,
		DurationMs:           duration.Milliseconds(),
	}

	return nil, result, nil
}

// httpClient returns the HTTP client to use for replay requests.
// If a custom doer is set (for testing), it wraps it; otherwise,
// it returns a client with the default replay timeout and SSRF protection.
func (s *Server) httpClient() httpDoer {
	if s.replayDoer != nil {
		return s.replayDoer
	}
	// S-2: Use a custom Dialer with a Control function to block connections
	// to private/internal networks, preventing SSRF and DNS rebinding attacks.
	transport := &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: defaultReplayTimeout,
			Control: denyPrivateNetwork,
		}).DialContext,
	}
	return &http.Client{
		Timeout:   defaultReplayTimeout,
		Transport: transport,
		// Do not follow redirects automatically; record the raw redirect response.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// replayRawInput is the typed input for the replay_raw tool.
type replayRawInput struct {
	// SessionID is the unique identifier of the session to replay.
	SessionID string `json:"session_id"`
	// TargetAddr is an optional target address (host:port) to send the raw bytes to.
	// If not specified, the original session's URL host:port is used.
	TargetAddr string `json:"target_addr,omitempty" jsonschema:"target address (host:port) to send raw bytes to"`
	// UseTLS indicates whether to use TLS for the connection.
	// If not specified, it is inferred from the original session's protocol.
	UseTLS *bool `json:"use_tls,omitempty" jsonschema:"use TLS for the connection (default: inferred from session protocol)"`
}

// replayRawResult is the structured output of the replay_raw tool.
type replayRawResult struct {
	// ResponseData is the raw response bytes, Base64-encoded.
	ResponseData string `json:"response_data"`
	// ResponseSize is the number of response bytes received.
	ResponseSize int `json:"response_size"`
	// DurationMs is the round-trip duration in milliseconds.
	DurationMs int64 `json:"duration_ms"`
}

// rawDialer abstracts raw TCP/TLS connection creation for testability.
type rawDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

// registerReplayRaw registers the replay_raw MCP tool.
func (s *Server) registerReplayRaw() {
	gomcp.AddTool(s.server, &gomcp.Tool{
		Name:        "replay_raw",
		Description: "Replay raw HTTP bytes from a recorded session exactly as captured, without re-parsing or modifying them. This preserves header ordering, whitespace, and HTTP version for byte-faithful replay. Useful for reproducing HTTP request smuggling attacks and other protocol-level vulnerabilities.",
	}, s.handleReplayRaw)
}

// handleReplayRaw handles the replay_raw tool invocation.
// It retrieves the session's raw request bytes and sends them directly over TCP/TLS.
func (s *Server) handleReplayRaw(ctx context.Context, _ *gomcp.CallToolRequest, input replayRawInput) (*gomcp.CallToolResult, *replayRawResult, error) {
	if s.store == nil {
		return nil, nil, fmt.Errorf("session store is not initialized")
	}

	if input.SessionID == "" {
		return nil, nil, fmt.Errorf("session_id is required")
	}

	// Retrieve the original session and its send message.
	sess, err := s.store.GetSession(ctx, input.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	sendMsgs, err := s.store.GetMessages(ctx, sess.ID, session.MessageListOptions{Direction: "send"})
	if err != nil {
		return nil, nil, fmt.Errorf("get send messages: %w", err)
	}
	if len(sendMsgs) == 0 {
		return nil, nil, fmt.Errorf("session %s has no send messages", input.SessionID)
	}
	sendMsg := sendMsgs[0]

	// Verify raw request bytes are available.
	if len(sendMsg.RawBytes) == 0 {
		return nil, nil, fmt.Errorf("session %s has no raw request bytes", input.SessionID)
	}

	// Determine the target address.
	targetAddr := input.TargetAddr
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
	if input.UseTLS != nil {
		useTLS = *input.UseTLS
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
	conn.SetDeadline(time.Now().Add(defaultReplayTimeout))

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

	result := &replayRawResult{
		ResponseData: base64.StdEncoding.EncodeToString(respData),
		ResponseSize: len(respData),
		DurationMs:   duration.Milliseconds(),
	}

	return nil, result, nil
}

// rawDialerFunc returns the raw dialer to use for replay_raw connections.
// If a custom dialer is set (for testing), it is returned; otherwise,
// a dialer with SSRF protection is returned.
func (s *Server) rawDialerFunc() rawDialer {
	if s.rawReplayDialer != nil {
		return s.rawReplayDialer
	}
	return &net.Dialer{
		Timeout: defaultReplayTimeout,
		Control: denyPrivateNetwork,
	}
}
