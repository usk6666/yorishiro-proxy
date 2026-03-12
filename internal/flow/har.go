package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// HARVersion is the HAR specification version produced by this exporter.
const HARVersion = "1.2"

// HAR is the top-level HTTP Archive structure.
type HAR struct {
	Log *HARLog `json:"log"`
}

// HARLog represents the root of the HAR data.
type HARLog struct {
	Version string      `json:"version"`
	Creator *HARCreator `json:"creator"`
	Entries []*HAREntry `json:"entries"`
}

// HARCreator identifies the tool that generated the HAR.
type HARCreator struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// HAREntry represents a single HTTP transaction.
type HAREntry struct {
	StartedDateTime string       `json:"startedDateTime"`
	Time            float64      `json:"time"`
	Request         *HARRequest  `json:"request"`
	Response        *HARResponse `json:"response"`
	Timings         *HARTimings  `json:"timings"`
	ServerIPAddress string       `json:"serverIPAddress,omitempty"`
	Connection      string       `json:"connection,omitempty"`

	// WebSocket custom field (Chrome DevTools convention).
	WebSocketMessages []*HARWebSocketMessage `json:"_webSocketMessages,omitempty"`
}

// HARRequest represents an HTTP request in HAR format.
type HARRequest struct {
	Method      string          `json:"method"`
	URL         string          `json:"url"`
	HTTPVersion string          `json:"httpVersion"`
	Headers     []*HARNameValue `json:"headers"`
	QueryString []*HARNameValue `json:"queryString"`
	PostData    *HARPostData    `json:"postData,omitempty"`
	HeadersSize int64           `json:"headersSize"`
	BodySize    int64           `json:"bodySize"`
}

// HARResponse represents an HTTP response in HAR format.
type HARResponse struct {
	Status      int             `json:"status"`
	StatusText  string          `json:"statusText"`
	HTTPVersion string          `json:"httpVersion"`
	Headers     []*HARNameValue `json:"headers"`
	Content     *HARContent     `json:"content"`
	HeadersSize int64           `json:"headersSize"`
	BodySize    int64           `json:"bodySize"`
}

// HARContent describes the response body content.
type HARContent struct {
	Size     int64  `json:"size"`
	MimeType string `json:"mimeType"`
	Text     string `json:"text,omitempty"`
	Encoding string `json:"encoding,omitempty"`
}

// HARPostData describes the request body.
type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

// HARTimings contains timing information for the request.
type HARTimings struct {
	Send    float64 `json:"send"`
	Wait    float64 `json:"wait"`
	Receive float64 `json:"receive"`
}

// HARNameValue is a generic name-value pair used for headers and query parameters.
type HARNameValue struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// HARWebSocketMessage represents a WebSocket message (Chrome DevTools convention).
type HARWebSocketMessage struct {
	Type   string  `json:"type"`
	Time   float64 `json:"time"`
	Opcode int     `json:"opcode"`
	Data   string  `json:"data"`
}

// ExportHAR exports flows matching the filter to a HAR JSON file.
// It uses streaming JSON encoding to handle large flow sets efficiently.
// Returns the number of entries exported.
func ExportHAR(ctx context.Context, store FlowReader, w io.Writer, opts ExportOptions, creatorVersion string) (int, error) {
	listOpts := ListOptions{
		Protocol:   opts.Filter.Protocol,
		URLPattern: opts.Filter.URLPattern,
	}

	flows, err := store.ListFlows(ctx, listOpts)
	if err != nil {
		return 0, fmt.Errorf("list flows for HAR export: %w", err)
	}

	if creatorVersion == "" {
		creatorVersion = "dev"
	}

	entries, exported, err := buildHAREntries(ctx, store, flows, opts)
	if err != nil {
		return exported, err
	}

	har := &HAR{
		Log: &HARLog{
			Version: HARVersion,
			Creator: &HARCreator{
				Name:    "yorishiro-proxy",
				Version: creatorVersion,
			},
			Entries: entries,
		},
	}

	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(har); err != nil {
		return exported, fmt.Errorf("encode HAR: %w", err)
	}

	return exported, nil
}

// buildHAREntries iterates over flows, applies filters, and converts each
// eligible flow to a HAR entry. Returns the entries, the count of exported
// flows, and any error encountered.
func buildHAREntries(ctx context.Context, store FlowReader, flows []*Flow, opts ExportOptions) ([]*HAREntry, int, error) {
	// Initialize as empty slice so JSON serialization produces [] not null.
	entries := make([]*HAREntry, 0)
	exported := 0

	for _, fl := range flows {
		if err := ctx.Err(); err != nil {
			return entries, exported, err
		}

		if opts.MaxFlows > 0 && exported >= opts.MaxFlows {
			break
		}

		if !harFlowIncluded(fl, opts.Filter) {
			continue
		}

		messages, err := store.GetMessages(ctx, fl.ID, MessageListOptions{})
		if err != nil {
			return entries, exported, fmt.Errorf("get messages for flow %s: %w", fl.ID, err)
		}

		entry := convertFlowToHAREntry(fl, messages, opts.IncludeBodies)
		if entry != nil {
			entries = append(entries, entry)
			exported++
		}
	}

	return entries, exported, nil
}

// harFlowIncluded returns true if the flow passes HAR-specific filters.
func harFlowIncluded(fl *Flow, filter ExportFilter) bool {
	// Skip Raw TCP and gRPC binary frames per spec.
	if fl.Protocol == "TCP" || fl.Protocol == "gRPC" {
		return false
	}
	if filter.TimeAfter != nil && fl.Timestamp.Before(*filter.TimeAfter) {
		return false
	}
	if filter.TimeBefore != nil && fl.Timestamp.After(*filter.TimeBefore) {
		return false
	}
	return true
}

// convertFlowToHAREntry dispatches flow-to-HAR conversion based on protocol.
func convertFlowToHAREntry(fl *Flow, messages []*Message, includeBodies bool) *HAREntry {
	if fl.Protocol == "WebSocket" {
		return flowToHARWebSocket(fl, messages)
	}
	return flowToHAREntry(fl, messages, includeBodies)
}

// flowToHAREntry converts a Flow and its messages to a HAR entry.
// Returns nil if the flow cannot be converted (e.g., missing request message).
func flowToHAREntry(fl *Flow, messages []*Message, includeBodies bool) *HAREntry {
	var reqMsg, respMsg *Message
	for _, m := range messages {
		switch m.Direction {
		case "send":
			if reqMsg == nil {
				reqMsg = m
			}
		case "receive":
			if respMsg == nil {
				respMsg = m
			}
		}
	}

	if reqMsg == nil {
		return nil
	}

	entry := &HAREntry{
		StartedDateTime: fl.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:            float64(fl.Duration.Milliseconds()),
		Request:         buildHARRequest(reqMsg, fl.Protocol, includeBodies),
		Response:        buildHARResponse(respMsg, fl.Protocol, includeBodies),
		Timings:         buildHARTimings(fl),
	}

	if fl.ConnInfo != nil {
		entry.ServerIPAddress = extractIP(fl.ConnInfo.ServerAddr)
		entry.Connection = fl.ConnID
	}

	return entry
}

// flowToHARWebSocket converts a WebSocket flow to a HAR entry with
// the _webSocketMessages custom field.
func flowToHARWebSocket(fl *Flow, messages []*Message) *HAREntry {
	// Find the initial HTTP upgrade request/response.
	var reqMsg, respMsg *Message
	var wsMessages []*HARWebSocketMessage

	for _, m := range messages {
		switch m.Direction {
		case "send":
			if reqMsg == nil && m.Method != "" {
				reqMsg = m
			} else {
				wsMessages = append(wsMessages, &HARWebSocketMessage{
					Type:   "send",
					Time:   float64(m.Timestamp.UnixMilli()) / 1000.0,
					Opcode: parseOpcode(m.Metadata),
					Data:   wsMessageData(m),
				})
			}
		case "receive":
			if respMsg == nil && m.StatusCode != 0 {
				respMsg = m
			} else {
				wsMessages = append(wsMessages, &HARWebSocketMessage{
					Type:   "receive",
					Time:   float64(m.Timestamp.UnixMilli()) / 1000.0,
					Opcode: parseOpcode(m.Metadata),
					Data:   wsMessageData(m),
				})
			}
		}
	}

	// Build the entry from the upgrade request if available.
	entry := &HAREntry{
		StartedDateTime:   fl.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:              float64(fl.Duration.Milliseconds()),
		Request:           buildHARRequest(reqMsg, fl.Protocol, false),
		Response:          buildHARResponse(respMsg, fl.Protocol, false),
		Timings:           buildHARTimings(fl),
		WebSocketMessages: wsMessages,
	}

	if fl.ConnInfo != nil {
		entry.ServerIPAddress = extractIP(fl.ConnInfo.ServerAddr)
		entry.Connection = fl.ConnID
	}

	return entry
}

// buildHARRequest constructs a HARRequest from a send message.
func buildHARRequest(msg *Message, protocol string, includeBodies bool) *HARRequest {
	if msg == nil {
		return &HARRequest{
			Method:      "GET",
			URL:         "",
			HTTPVersion: protocolToHTTPVersion(protocol),
			Headers:     []*HARNameValue{},
			QueryString: []*HARNameValue{},
			HeadersSize: -1,
			BodySize:    -1,
		}
	}

	reqURL := ""
	var queryParams []*HARNameValue
	if msg.URL != nil {
		reqURL = msg.URL.String()
		queryParams = urlQueryToHAR(msg.URL.Query())
	}
	if queryParams == nil {
		queryParams = []*HARNameValue{}
	}

	method := msg.Method
	if method == "" {
		method = "GET"
	}

	req := &HARRequest{
		Method:      method,
		URL:         reqURL,
		HTTPVersion: protocolToHTTPVersion(protocol),
		Headers:     headersToHAR(msg.Headers),
		QueryString: queryParams,
		HeadersSize: -1,
		BodySize:    int64(len(msg.Body)),
	}

	if includeBodies && len(msg.Body) > 0 {
		mimeType := "application/octet-stream"
		if ct := headerValue(msg.Headers, "Content-Type"); ct != "" {
			mimeType = ct
		}
		req.PostData = &HARPostData{
			MimeType: mimeType,
			Text:     bodyToText(msg.Body),
		}
	}

	return req
}

// buildHARResponse constructs a HARResponse from a receive message.
func buildHARResponse(msg *Message, protocol string, includeBodies bool) *HARResponse {
	if msg == nil {
		return &HARResponse{
			Status:      0,
			StatusText:  "",
			HTTPVersion: protocolToHTTPVersion(protocol),
			Headers:     []*HARNameValue{},
			Content: &HARContent{
				Size:     0,
				MimeType: "",
			},
			HeadersSize: -1,
			BodySize:    -1,
		}
	}

	resp := &HARResponse{
		Status:      msg.StatusCode,
		StatusText:  http.StatusText(msg.StatusCode),
		HTTPVersion: protocolToHTTPVersion(protocol),
		Headers:     headersToHAR(msg.Headers),
		HeadersSize: -1,
		BodySize:    int64(len(msg.Body)),
	}

	mimeType := "application/octet-stream"
	if ct := headerValue(msg.Headers, "Content-Type"); ct != "" {
		mimeType = ct
	}

	content := &HARContent{
		Size:     int64(len(msg.Body)),
		MimeType: mimeType,
	}

	if includeBodies && len(msg.Body) > 0 {
		if isBinaryContent(mimeType, msg.Body) {
			content.Text = base64.StdEncoding.EncodeToString(msg.Body)
			content.Encoding = "base64"
		} else {
			content.Text = string(msg.Body)
		}
	}

	resp.Content = content
	return resp
}

// buildHARTimings constructs HAR timings from flow timing data.
func buildHARTimings(fl *Flow) *HARTimings {
	t := &HARTimings{
		Send:    -1,
		Wait:    -1,
		Receive: -1,
	}
	if fl.SendMs != nil {
		t.Send = float64(*fl.SendMs)
	}
	if fl.WaitMs != nil {
		t.Wait = float64(*fl.WaitMs)
	}
	if fl.ReceiveMs != nil {
		t.Receive = float64(*fl.ReceiveMs)
	}
	return t
}

// headersToHAR converts HTTP headers to HAR name-value pairs.
func headersToHAR(headers map[string][]string) []*HARNameValue {
	if len(headers) == 0 {
		return []*HARNameValue{}
	}

	// Sort header names for deterministic output.
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)

	var result []*HARNameValue
	for _, name := range names {
		for _, value := range headers[name] {
			result = append(result, &HARNameValue{
				Name:  name,
				Value: value,
			})
		}
	}
	return result
}

// urlQueryToHAR converts URL query parameters to HAR name-value pairs.
func urlQueryToHAR(values url.Values) []*HARNameValue {
	if len(values) == 0 {
		return []*HARNameValue{}
	}

	// Sort keys for deterministic output.
	keys := make([]string, 0, len(values))
	for k := range values {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var result []*HARNameValue
	for _, k := range keys {
		for _, v := range values[k] {
			result = append(result, &HARNameValue{
				Name:  k,
				Value: v,
			})
		}
	}
	return result
}

// headerValue returns the first value for the given header name (case-insensitive).
func headerValue(headers map[string][]string, name string) string {
	if headers == nil {
		return ""
	}
	// Try exact match first.
	if vals, ok := headers[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	// Case-insensitive fallback.
	lowerName := strings.ToLower(name)
	for k, vals := range headers {
		if strings.ToLower(k) == lowerName && len(vals) > 0 {
			return vals[0]
		}
	}
	return ""
}

// protocolToHTTPVersion maps proxy protocol names to HAR httpVersion strings.
func protocolToHTTPVersion(protocol string) string {
	switch protocol {
	case "HTTP/1.x":
		return "HTTP/1.1"
	case "HTTPS":
		return "HTTP/1.1"
	case "HTTP/2":
		return "h2"
	case "WebSocket":
		return "HTTP/1.1"
	default:
		if strings.HasPrefix(protocol, "SOCKS5+") {
			return protocolToHTTPVersion(strings.TrimPrefix(protocol, "SOCKS5+"))
		}
		return "HTTP/1.1"
	}
}

// isBinaryContent determines if content should be base64-encoded in HAR.
func isBinaryContent(mimeType string, body []byte) bool {
	// Parse the media type, ignoring parameters.
	mediaType, _, _ := mime.ParseMediaType(mimeType)
	if mediaType == "" {
		mediaType = mimeType
	}

	// Text-based MIME types.
	if strings.HasPrefix(mediaType, "text/") {
		return false
	}
	textTypes := []string{
		"application/json",
		"application/xml",
		"application/xhtml+xml",
		"application/javascript",
		"application/x-javascript",
		"application/ecmascript",
		"application/x-www-form-urlencoded",
		"application/soap+xml",
		"application/graphql",
		"application/ld+json",
		"application/manifest+json",
	}
	for _, t := range textTypes {
		if mediaType == t {
			return false
		}
	}
	// Suffix-based detection (e.g., application/vnd.api+json).
	if strings.HasSuffix(mediaType, "+json") || strings.HasSuffix(mediaType, "+xml") {
		return false
	}

	// Known binary MIME prefixes — always base64-encode regardless of body content.
	binaryPrefixes := []string{"image/", "audio/", "video/", "font/"}
	for _, prefix := range binaryPrefixes {
		if strings.HasPrefix(mediaType, prefix) {
			return true
		}
	}

	// Check if the body is valid UTF-8 without control characters.
	if utf8.Valid(body) {
		return false
	}

	return true
}

// extractIP extracts the IP address from a host:port string.
func extractIP(addr string) string {
	if addr == "" {
		return ""
	}
	// Try to split host:port.
	if idx := strings.LastIndex(addr, ":"); idx >= 0 {
		host := addr[:idx]
		// Handle IPv6 bracket notation.
		if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
			return host[1 : len(host)-1]
		}
		return host
	}
	return addr
}

// parseOpcode extracts the WebSocket opcode from message metadata.
func parseOpcode(metadata map[string]string) int {
	if metadata == nil {
		return 0
	}
	if s, ok := metadata["opcode"]; ok {
		if v, err := strconv.Atoi(s); err == nil {
			return v
		}
	}
	return 0
}

// wsMessageData returns the WebSocket message data as a string.
// Binary data is base64-encoded.
func wsMessageData(m *Message) string {
	if len(m.Body) == 0 {
		return ""
	}
	if utf8.Valid(m.Body) {
		return string(m.Body)
	}
	return base64.StdEncoding.EncodeToString(m.Body)
}

// bodyToText converts a request body to text for HAR postData.
// Binary data is base64-encoded.
func bodyToText(body []byte) string {
	if utf8.Valid(body) {
		return string(body)
	}
	return base64.StdEncoding.EncodeToString(body)
}
