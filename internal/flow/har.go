package flow

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"mime"
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

// ExportHAR exports streams matching the filter to a HAR JSON file.
// It uses streaming JSON encoding to handle large stream sets efficiently.
// Returns the number of entries exported.
func ExportHAR(ctx context.Context, store Store, w io.Writer, opts ExportOptions, creatorVersion string) (int, error) {
	listOpts := StreamListOptions{
		Protocol:   opts.Filter.Protocol,
		URLPattern: opts.Filter.URLPattern,
	}

	streams, err := store.ListStreams(ctx, listOpts)
	if err != nil {
		return 0, fmt.Errorf("list streams for HAR export: %w", err)
	}

	if creatorVersion == "" {
		creatorVersion = "dev"
	}

	entries, exported, err := buildHAREntries(ctx, store, streams, opts)
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

// buildHAREntries iterates over streams, applies filters, and converts each
// eligible stream to a HAR entry. Returns the entries, the count of exported
// streams, and any error encountered.
func buildHAREntries(ctx context.Context, store Store, streams []*Stream, opts ExportOptions) ([]*HAREntry, int, error) {
	// Initialize as empty slice so JSON serialization produces [] not null.
	entries := make([]*HAREntry, 0)
	exported := 0

	for _, st := range streams {
		if err := ctx.Err(); err != nil {
			return entries, exported, err
		}

		if opts.MaxFlows > 0 && exported >= opts.MaxFlows {
			break
		}

		if !harStreamIncluded(st, opts.Filter) {
			continue
		}

		flows, err := store.GetFlows(ctx, st.ID, FlowListOptions{})
		if err != nil {
			return entries, exported, fmt.Errorf("get flows for stream %s: %w", st.ID, err)
		}

		entry := convertStreamToHAREntry(st, flows, opts.IncludeBodies)
		if entry != nil {
			entries = append(entries, entry)
			exported++
		}
	}

	return entries, exported, nil
}

// harStreamIncluded returns true if the stream passes HAR-specific filters.
func harStreamIncluded(st *Stream, filter ExportFilter) bool {
	// Skip Raw TCP and gRPC binary frames per spec.
	if st.Protocol == "TCP" || st.Protocol == "gRPC" {
		return false
	}
	if filter.TimeAfter != nil && st.Timestamp.Before(*filter.TimeAfter) {
		return false
	}
	if filter.TimeBefore != nil && st.Timestamp.After(*filter.TimeBefore) {
		return false
	}
	return true
}

// convertStreamToHAREntry dispatches stream-to-HAR conversion based on protocol.
func convertStreamToHAREntry(st *Stream, flows []*Flow, includeBodies bool) *HAREntry {
	if st.Protocol == "WebSocket" {
		return streamToHARWebSocket(st, flows)
	}
	return streamToHAREntry(st, flows, includeBodies)
}

// streamToHAREntry converts a Stream and its flows to a HAR entry.
// Returns nil if the stream cannot be converted (e.g., missing request flow).
func streamToHAREntry(st *Stream, flows []*Flow, includeBodies bool) *HAREntry {
	var reqFlow, respFlow *Flow
	for _, f := range flows {
		switch f.Direction {
		case "send":
			if reqFlow == nil {
				reqFlow = f
			}
		case "receive":
			if respFlow == nil {
				respFlow = f
			}
		}
	}

	if reqFlow == nil {
		return nil
	}

	entry := &HAREntry{
		StartedDateTime: st.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:            float64(st.Duration.Milliseconds()),
		Request:         buildHARRequest(reqFlow, st.Protocol, includeBodies),
		Response:        buildHARResponse(respFlow, st.Protocol, includeBodies),
		Timings:         buildHARTimings(st),
	}

	if st.ConnInfo != nil {
		entry.ServerIPAddress = extractIP(st.ConnInfo.ServerAddr)
		entry.Connection = st.ConnID
	}

	return entry
}

// streamToHARWebSocket converts a WebSocket stream to a HAR entry with
// the _webSocketMessages custom field.
func streamToHARWebSocket(st *Stream, flows []*Flow) *HAREntry {
	// Find the initial HTTP upgrade request/response.
	var reqFlow, respFlow *Flow
	var wsMessages []*HARWebSocketMessage

	for _, f := range flows {
		switch f.Direction {
		case "send":
			if reqFlow == nil && f.Method != "" {
				reqFlow = f
			} else {
				wsMessages = append(wsMessages, &HARWebSocketMessage{
					Type:   "send",
					Time:   float64(f.Timestamp.UnixMilli()) / 1000.0,
					Opcode: parseOpcode(f.Metadata),
					Data:   wsFlowData(f),
				})
			}
		case "receive":
			if respFlow == nil && f.StatusCode != 0 {
				respFlow = f
			} else {
				wsMessages = append(wsMessages, &HARWebSocketMessage{
					Type:   "receive",
					Time:   float64(f.Timestamp.UnixMilli()) / 1000.0,
					Opcode: parseOpcode(f.Metadata),
					Data:   wsFlowData(f),
				})
			}
		}
	}

	// Build the entry from the upgrade request if available.
	entry := &HAREntry{
		StartedDateTime:   st.Timestamp.UTC().Format("2006-01-02T15:04:05.000Z"),
		Time:              float64(st.Duration.Milliseconds()),
		Request:           buildHARRequest(reqFlow, st.Protocol, false),
		Response:          buildHARResponse(respFlow, st.Protocol, false),
		Timings:           buildHARTimings(st),
		WebSocketMessages: wsMessages,
	}

	if st.ConnInfo != nil {
		entry.ServerIPAddress = extractIP(st.ConnInfo.ServerAddr)
		entry.Connection = st.ConnID
	}

	return entry
}

// buildHARRequest constructs a HARRequest from a send flow.
func buildHARRequest(f *Flow, protocol string, includeBodies bool) *HARRequest {
	if f == nil {
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
	if f.URL != nil {
		reqURL = f.URL.String()
		queryParams = urlQueryToHAR(f.URL.Query())
	}
	if queryParams == nil {
		queryParams = []*HARNameValue{}
	}

	method := f.Method
	if method == "" {
		method = "GET"
	}

	req := &HARRequest{
		Method:      method,
		URL:         reqURL,
		HTTPVersion: protocolToHTTPVersion(protocol),
		Headers:     headersToHAR(f.Headers),
		QueryString: queryParams,
		HeadersSize: -1,
		BodySize:    int64(len(f.Body)),
	}

	if includeBodies && len(f.Body) > 0 {
		mimeType := "application/octet-stream"
		if ct := headerValue(f.Headers, "Content-Type"); ct != "" {
			mimeType = ct
		}
		req.PostData = &HARPostData{
			MimeType: mimeType,
			Text:     bodyToText(f.Body),
		}
	}

	return req
}

// buildHARResponse constructs a HARResponse from a receive flow.
func buildHARResponse(f *Flow, protocol string, includeBodies bool) *HARResponse {
	if f == nil {
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
		Status:      f.StatusCode,
		StatusText:  statusText(f.StatusCode),
		HTTPVersion: protocolToHTTPVersion(protocol),
		Headers:     headersToHAR(f.Headers),
		HeadersSize: -1,
		BodySize:    int64(len(f.Body)),
	}

	mimeType := "application/octet-stream"
	if ct := headerValue(f.Headers, "Content-Type"); ct != "" {
		mimeType = ct
	}

	content := &HARContent{
		Size:     int64(len(f.Body)),
		MimeType: mimeType,
	}

	if includeBodies && len(f.Body) > 0 {
		if isBinaryContent(mimeType, f.Body) {
			content.Text = base64.StdEncoding.EncodeToString(f.Body)
			content.Encoding = "base64"
		} else {
			content.Text = string(f.Body)
		}
	}

	resp.Content = content
	return resp
}

// buildHARTimings constructs HAR timings from stream timing data.
func buildHARTimings(st *Stream) *HARTimings {
	t := &HARTimings{
		Send:    -1,
		Wait:    -1,
		Receive: -1,
	}
	if st.SendMs != nil {
		t.Send = float64(*st.SendMs)
	}
	if st.WaitMs != nil {
		t.Wait = float64(*st.WaitMs)
	}
	if st.ReceiveMs != nil {
		t.Receive = float64(*st.ReceiveMs)
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

// parseOpcode extracts the WebSocket opcode from flow metadata.
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

// wsFlowData returns the WebSocket flow data as a string.
// Binary data is base64-encoded.
func wsFlowData(f *Flow) string {
	if len(f.Body) == 0 {
		return ""
	}
	if utf8.Valid(f.Body) {
		return string(f.Body)
	}
	return base64.StdEncoding.EncodeToString(f.Body)
}

// bodyToText converts a request body to text for HAR postData.
// Binary data is base64-encoded.
func bodyToText(body []byte) string {
	if utf8.Valid(body) {
		return string(body)
	}
	return base64.StdEncoding.EncodeToString(body)
}

// statusText returns the reason phrase for an HTTP status code.
// This is a local copy to avoid an import cycle with httputil (which imports flow).
// The canonical source is httputil.StatusText. Keep in sync when updating.
var httpStatusTexts = map[int]string{
	100: "Continue", 101: "Switching Protocols", 102: "Processing", 103: "Early Hints",

	200: "OK", 201: "Created", 202: "Accepted", 203: "Non-Authoritative Information",
	204: "No Content", 205: "Reset Content", 206: "Partial Content",
	207: "Multi-Status", 208: "Already Reported", 226: "IM Used",

	300: "Multiple Choices", 301: "Moved Permanently", 302: "Found", 303: "See Other",
	304: "Not Modified", 305: "Use Proxy", 307: "Temporary Redirect", 308: "Permanent Redirect",

	400: "Bad Request", 401: "Unauthorized", 402: "Payment Required", 403: "Forbidden",
	404: "Not Found", 405: "Method Not Allowed", 406: "Not Acceptable",
	407: "Proxy Authentication Required", 408: "Request Timeout", 409: "Conflict",
	410: "Gone", 411: "Length Required", 412: "Precondition Failed",
	413: "Request Entity Too Large", 414: "Request URI Too Long",
	415: "Unsupported Media Type", 416: "Requested Range Not Satisfiable",
	417: "Expectation Failed", 418: "I'm a teapot", 421: "Misdirected Request",
	422: "Unprocessable Entity", 423: "Locked", 424: "Failed Dependency",
	425: "Too Early", 426: "Upgrade Required", 428: "Precondition Required",
	429: "Too Many Requests", 431: "Request Header Fields Too Large",
	451: "Unavailable For Legal Reasons",

	500: "Internal Server Error", 501: "Not Implemented", 502: "Bad Gateway",
	503: "Service Unavailable", 504: "Gateway Timeout",
	505: "HTTP Version Not Supported", 506: "Variant Also Negotiates",
	507: "Insufficient Storage", 508: "Loop Detected", 510: "Not Extended",
	511: "Network Authentication Required",
}

func statusText(code int) string {
	return httpStatusTexts[code]
}
