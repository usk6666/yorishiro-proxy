package http1

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// passthroughThreshold is the body size above which passthrough mode is used.
// Bodies larger than this are streamed via HTTPMessage.BodyStream instead of
// being buffered into HTTPMessage.Body.
const passthroughThreshold = 10 << 20 // 10 MiB

// opaqueHTTP1 holds Layer-specific data stored in Envelope.Opaque.
// Pipeline Steps must not type-assert on this.
type opaqueHTTP1 struct {
	rawReq     *parser.RawRequest
	rawResp    *parser.RawResponse
	origKV     []envelope.KeyValue // header snapshot at Next() time
	origBody   []byte              // body snapshot at Next() time (nil for passthrough)
	bodyReader io.Reader           // passthrough body (non-nil when Body == nil)
}

// channel implements layer.Channel for HTTP/1.x.
type channel struct {
	reader    *bufio.Reader // created by Layer
	writer    io.Writer
	streamID  string
	direction envelope.Direction
	scheme    string
	ctxTmpl   envelope.EnvelopeContext

	// Per-request state.
	currentStreamID string // changes per request-response pair
	sequence        int    // 0=request, 1=response within a pair
	connClosed      bool   // set when Connection: close or HTTP/1.0
}

// StreamID returns the connection-level identifier for this channel.
func (c *channel) StreamID() string { return c.streamID }

// Next reads the next HTTP message from the wire and returns it as an Envelope.
//
// For direction=Send, it parses HTTP requests.
// For direction=Receive, it parses HTTP responses.
//
// Returns io.EOF when the connection should close (Connection: close was set
// on the previous message, or HTTP/1.0 without keep-alive).
func (c *channel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if c.connClosed {
		return nil, io.EOF
	}

	switch c.direction {
	case envelope.Send:
		return c.nextRequest(ctx)
	case envelope.Receive:
		return c.nextResponse(ctx)
	default:
		return nil, fmt.Errorf("http1: unknown direction %d", c.direction)
	}
}

// Send writes an Envelope to the wire.
//
// For direction=Send (server-facing), it serializes responses.
// For direction=Receive (upstream-facing), it serializes requests.
//
// Two paths:
//   - Opaque-based: raw-first patching with OWS preservation (normal flow)
//   - Opaque-less: synthetic serialization fallback (for Resend in N5)
func (c *channel) Send(ctx context.Context, env *envelope.Envelope) error {
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("http1: Send requires *HTTPMessage, got %T", env.Message)
	}

	switch c.direction {
	case envelope.Send:
		// Server-facing layer: Next parses requests, Send writes responses.
		return c.sendResponse(msg, env)
	case envelope.Receive:
		// Upstream-facing layer: Next parses responses, Send writes requests.
		return c.sendRequest(msg, env)
	default:
		return fmt.Errorf("http1: unknown direction %d", c.direction)
	}
}

// Close is a no-op. The connection is owned by the Layer, not the Channel.
func (c *channel) Close() error { return nil }

// --- Next() implementation ---

func (c *channel) nextRequest(_ context.Context) (*envelope.Envelope, error) {
	rawReq, err := parser.ParseRequest(c.reader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("http1: parse request: %w", err)
	}

	// Generate new StreamID for each request-response pair.
	c.currentStreamID = uuid.New().String()
	c.sequence = 0

	// Parse RequestURI into structured fields.
	path, rawQuery, authority := parseRequestURI(rawReq.RequestURI, rawReq.Headers)

	// Read body with passthrough threshold.
	body, bodyReader, err := readBodyWithThreshold(rawReq.Body)
	if err != nil {
		return nil, fmt.Errorf("http1: read request body: %w", err)
	}

	// Convert anomalies.
	anomalies := convertAnomalies(rawReq.Anomalies)

	// Build HTTPMessage.
	msg := &envelope.HTTPMessage{
		Method:     rawReq.Method,
		Scheme:     c.scheme,
		Authority:  authority,
		Path:       path,
		RawQuery:   rawQuery,
		Headers:    rawHeadersToKV(rawReq.Headers),
		Body:       body,
		BodyStream: bodyReader,
		Anomalies:  anomalies,
	}

	// Build Envelope.
	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence,
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawReq.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawReq:     rawReq,
			origKV:     cloneKV(msg.Headers),
			origBody:   cloneBytes(body),
			bodyReader: bodyReader,
		},
	}

	// Set connection close semantics.
	c.connClosed = rawReq.Close

	return env, nil
}

func (c *channel) nextResponse(_ context.Context) (*envelope.Envelope, error) {
	rawResp, err := parser.ParseResponse(c.reader)
	if err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, io.EOF
		}
		return nil, fmt.Errorf("http1: parse response: %w", err)
	}

	// Read body with passthrough threshold.
	body, bodyReader, err := readBodyWithThreshold(rawResp.Body)
	if err != nil {
		return nil, fmt.Errorf("http1: read response body: %w", err)
	}

	// Extract status reason from the full status string.
	statusReason := extractStatusReason(rawResp.Status)

	// Convert anomalies.
	anomalies := convertAnomalies(rawResp.Anomalies)

	// Build HTTPMessage.
	msg := &envelope.HTTPMessage{
		Status:       rawResp.StatusCode,
		StatusReason: statusReason,
		Headers:      rawHeadersToKV(rawResp.Headers),
		Body:         body,
		BodyStream:   bodyReader,
		Anomalies:    anomalies,
	}

	// Build Envelope.
	envCtx := c.ctxTmpl
	envCtx.ReceivedAt = time.Now()

	env := &envelope.Envelope{
		StreamID:  c.currentStreamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence + 1,
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       rawResp.RawBytes,
		Message:   msg,
		Context:   envCtx,
		Opaque: &opaqueHTTP1{
			rawResp:    rawResp,
			origKV:     cloneKV(msg.Headers),
			origBody:   cloneBytes(body),
			bodyReader: bodyReader,
		},
	}

	return env, nil
}

// --- Send() implementation ---

func (c *channel) sendRequest(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	// Path 1: Opaque-based (normal flow, raw-first patching).
	if opaque != nil && opaque.rawReq != nil {
		return c.sendRequestOpaque(msg, opaque)
	}

	// Path 2: Synthetic fallback (no Opaque).
	return c.sendRequestSynthetic(msg)
}

func (c *channel) sendResponse(msg *envelope.HTTPMessage, env *envelope.Envelope) error {
	opaque, _ := env.Opaque.(*opaqueHTTP1)

	// Path 1: Opaque-based (normal flow, raw-first patching).
	if opaque != nil && opaque.rawResp != nil {
		return c.sendResponseOpaque(msg, opaque)
	}

	// Path 2: Synthetic fallback (no Opaque).
	return c.sendResponseSynthetic(msg)
}

// --- Send Path 1: Opaque-based ---

func (c *channel) sendRequestOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawReq := opaque.rawReq
	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg.Body, opaque)

	// Zero-copy fast path: nothing changed.
	if !headersChanged && !bodyChanged && len(rawReq.RawBytes) > 0 {
		if _, err := c.writer.Write(rawReq.RawBytes); err != nil {
			return fmt.Errorf("http1: send request raw: %w", err)
		}
		return c.writeBody(msg, opaque)
	}

	// Apply header patches.
	if headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawReq.Headers)
	}

	// Update body headers if changed.
	if bodyChanged && msg.Body != nil {
		rawReq.Headers.Del("Transfer-Encoding")
		rawReq.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		opaque.bodyReader = nil
	}

	// Serialize and write.
	headerBytes := serializeRequestHeader(rawReq)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send request: %w", err)
	}
	return c.writeBody(msg, opaque)
}

func (c *channel) sendResponseOpaque(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	rawResp := opaque.rawResp
	headersChanged := !kvEqual(msg.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(msg.Body, opaque)

	// Zero-copy fast path: nothing changed.
	if !headersChanged && !bodyChanged && len(rawResp.RawBytes) > 0 {
		if _, err := c.writer.Write(rawResp.RawBytes); err != nil {
			return fmt.Errorf("http1: send response raw: %w", err)
		}
		return c.writeBody(msg, opaque)
	}

	// Apply header patches.
	if headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, msg.Headers, rawResp.Headers)
	}

	// Update body headers if changed.
	if bodyChanged && msg.Body != nil {
		rawResp.Headers.Del("Transfer-Encoding")
		rawResp.Headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
		opaque.bodyReader = nil
	}

	// Serialize and write.
	headerBytes := serializeResponseHeader(rawResp)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1: send response: %w", err)
	}
	return c.writeBody(msg, opaque)
}

// --- Send Path 2: Synthetic (no Opaque) ---

func (c *channel) sendRequestSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	// Build request-line.
	requestURI := msg.Path
	if msg.RawQuery != "" {
		requestURI += "?" + msg.RawQuery
	}
	if requestURI == "" {
		requestURI = "/"
	}
	if err := serializeRequestLine(&buf, msg.Method, requestURI, "HTTP/1.1"); err != nil {
		return fmt.Errorf("http1: send synthetic request line: %w", err)
	}

	// Build headers from KeyValue (no OWS preservation — no raw source).
	headers := kvToRawHeaders(msg.Headers)

	// Set Content-Length if body present and header not already set.
	if msg.Body != nil && headers.Get("Content-Length") == "" {
		headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic request headers: %w", err)
	}

	if _, err := c.writer.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic request: %w", err)
	}

	// Write body.
	if msg.Body != nil {
		if _, err := c.writer.Write(msg.Body); err != nil {
			return fmt.Errorf("http1: send synthetic request body: %w", err)
		}
	}
	return nil
}

func (c *channel) sendResponseSynthetic(msg *envelope.HTTPMessage) error {
	var buf bytes.Buffer

	// Build status-line.
	status := fmt.Sprintf("%d %s", msg.Status, msg.StatusReason)
	if msg.StatusReason == "" {
		text := statusText(msg.Status)
		if text == "" {
			text = "Unknown"
		}
		status = fmt.Sprintf("%d %s", msg.Status, text)
	}
	if err := serializeStatusLine(&buf, "HTTP/1.1", status, msg.Status); err != nil {
		return fmt.Errorf("http1: send synthetic status line: %w", err)
	}

	// Build headers from KeyValue.
	headers := kvToRawHeaders(msg.Headers)

	// Set Content-Length if body present and header not already set.
	if msg.Body != nil && headers.Get("Content-Length") == "" {
		headers.Set("Content-Length", strconv.Itoa(len(msg.Body)))
	}

	if err := serializeHeaders(&buf, headers); err != nil {
		return fmt.Errorf("http1: send synthetic response headers: %w", err)
	}

	if _, err := c.writer.Write(buf.Bytes()); err != nil {
		return fmt.Errorf("http1: send synthetic response: %w", err)
	}

	// Write body.
	if msg.Body != nil {
		if _, err := c.writer.Write(msg.Body); err != nil {
			return fmt.Errorf("http1: send synthetic response body: %w", err)
		}
	}
	return nil
}

// --- Helpers ---

// writeBody writes the body portion of a message to the wire.
func (c *channel) writeBody(msg *envelope.HTTPMessage, opaque *opaqueHTTP1) error {
	if msg.Body != nil {
		if _, err := c.writer.Write(msg.Body); err != nil {
			return fmt.Errorf("http1: write body: %w", err)
		}
		return nil
	}
	// Passthrough mode: stream from bodyReader.
	if opaque != nil && opaque.bodyReader != nil {
		if _, err := io.Copy(c.writer, opaque.bodyReader); err != nil {
			return fmt.Errorf("http1: write passthrough body: %w", err)
		}
	}
	return nil
}

// readBodyWithThreshold reads a body up to passthroughThreshold.
// Returns (body, nil, nil) for buffered bodies and (nil, reader, nil) for
// passthrough mode when the body exceeds the threshold.
func readBodyWithThreshold(r io.Reader) (body []byte, bodyReader io.Reader, err error) {
	if r == nil {
		return nil, nil, nil
	}

	buf := make([]byte, passthroughThreshold+1)
	n, readErr := io.ReadFull(r, buf)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		if n == 0 {
			return []byte{}, nil, nil
		}
		return buf[:n], nil, nil
	}
	if readErr != nil {
		return nil, nil, fmt.Errorf("read body: %w", readErr)
	}

	// Body exceeds threshold — passthrough mode.
	combined := io.MultiReader(bytes.NewReader(buf[:n]), r)
	return nil, combined, nil
}

// parseRequestURI extracts path, rawQuery, and authority from a RequestURI.
func parseRequestURI(requestURI string, headers parser.RawHeaders) (path, rawQuery, authority string) {
	authority = headers.Get("Host")

	if requestURI == "*" {
		return "*", "", authority
	}

	u, err := url.ParseRequestURI(requestURI)
	if err != nil {
		// Best-effort: use as-is.
		return requestURI, "", authority
	}

	path = u.Path
	rawQuery = u.RawQuery

	// For absolute-form URIs, extract authority from URI if Host header is absent.
	if u.Host != "" && authority == "" {
		authority = u.Host
	}

	return path, rawQuery, authority
}

// extractStatusReason extracts the reason phrase from a status string like "200 OK".
func extractStatusReason(status string) string {
	// status is "StatusCode ReasonPhrase" (e.g., "200 OK", "404 Not Found").
	if idx := strings.IndexByte(status, ' '); idx >= 0 {
		return status[idx+1:]
	}
	return ""
}

// rawHeadersToKV converts parser.RawHeaders to []envelope.KeyValue.
func rawHeadersToKV(raw parser.RawHeaders) []envelope.KeyValue {
	kv := make([]envelope.KeyValue, len(raw))
	for i, h := range raw {
		kv[i] = envelope.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kv
}

// kvToRawHeaders converts []envelope.KeyValue to parser.RawHeaders (no RawValue).
func kvToRawHeaders(kv []envelope.KeyValue) parser.RawHeaders {
	raw := make(parser.RawHeaders, len(kv))
	for i, h := range kv {
		raw[i] = parser.RawHeader{Name: h.Name, Value: h.Value}
	}
	return raw
}

// cloneKV returns a deep copy of []envelope.KeyValue.
func cloneKV(kv []envelope.KeyValue) []envelope.KeyValue {
	if kv == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(kv))
	copy(out, kv)
	return out
}

// cloneBytes returns a copy of b, or nil if b is nil.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// kvEqual checks if two []envelope.KeyValue slices are identical.
func kvEqual(a, b []envelope.KeyValue) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].Value != b[i].Value {
			return false
		}
	}
	return true
}

// isBodyChanged checks whether the message body was modified from the original.
func isBodyChanged(body []byte, opaque *opaqueHTTP1) bool {
	// Passthrough mode unchanged: body is still nil with a bodyReader.
	if body == nil && opaque.bodyReader != nil {
		return false
	}
	// Both nil: no body at all (unchanged).
	if body == nil && opaque.bodyReader == nil {
		return false
	}
	// If passthrough was active (origBody nil) but Pipeline set Body, it changed.
	if opaque.origBody == nil {
		return true
	}
	return !bytes.Equal(body, opaque.origBody)
}

// convertAnomalies converts parser anomalies to envelope anomalies.
func convertAnomalies(parserAnomalies []parser.Anomaly) []envelope.Anomaly {
	if len(parserAnomalies) == 0 {
		return nil
	}
	anomalies := make([]envelope.Anomaly, len(parserAnomalies))
	for i, a := range parserAnomalies {
		anomalies[i] = envelope.Anomaly{
			Type:   envelope.AnomalyType(a.Type),
			Detail: a.Detail,
		}
	}
	return anomalies
}
