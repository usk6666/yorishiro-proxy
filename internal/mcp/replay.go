package mcp

import (
	"bytes"
	"context"
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

	// Retrieve the original session.
	entry, err := s.store.Get(ctx, input.SessionID)
	if err != nil {
		return nil, nil, fmt.Errorf("get session: %w", err)
	}

	// Build the replay request with overrides applied.
	method := entry.Request.Method
	if input.OverrideMethod != "" {
		method = input.OverrideMethod
	}

	targetURL := entry.Request.URL
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
	} else if len(entry.Request.Body) > 0 {
		reqBody = entry.Request.Body
		body = bytes.NewReader(reqBody)
	}

	httpReq, err := http.NewRequestWithContext(ctx, method, targetURL.String(), body)
	if err != nil {
		return nil, nil, fmt.Errorf("create replay request: %w", err)
	}

	// Copy original headers.
	for key, values := range entry.Request.Headers {
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
	newEntry := &session.Entry{
		Protocol:  entry.Protocol,
		Timestamp: start,
		Duration:  duration,
		Request: session.RecordedRequest{
			Method:  method,
			URL:     targetURL,
			Headers: recordedHeaders,
			Body:    reqBody,
		},
		Response: session.RecordedResponse{
			StatusCode: resp.StatusCode,
			Headers:    respHeaders,
			Body:       respBody,
		},
	}

	if err := s.store.Save(ctx, newEntry); err != nil {
		return nil, nil, fmt.Errorf("save replay session: %w", err)
	}

	respBodyStr, respBodyEncoding := encodeBody(respBody)

	result := &replayRequestResult{
		NewSessionID:         newEntry.ID,
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
