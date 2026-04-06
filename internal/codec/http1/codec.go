package http1

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// passthroughThreshold is the body size above which passthrough mode is used.
// In passthrough mode, Body is nil and the Codec streams the body directly.
const passthroughThreshold = 10 << 20 // 10 MiB

// Role determines the Codec's behavior for Next() and Send().
type Role int

const (
	// ClientRole: Next() parses requests, Send() serializes responses.
	ClientRole Role = iota
	// UpstreamRole: Next() parses responses, Send() serializes requests.
	UpstreamRole
)

// UpgradeHint indicates a detected protocol upgrade.
type UpgradeHint int

const (
	// UpgradeNone means no upgrade was detected.
	UpgradeNone UpgradeHint = iota
	// UpgradeWebSocket indicates an Upgrade: websocket header was detected.
	UpgradeWebSocket
	// UpgradeGRPCWeb indicates a Content-Type: application/grpc-web header was detected.
	UpgradeGRPCWeb
	// UpgradeSSE indicates a Content-Type: text/event-stream header was detected.
	UpgradeSSE
)

// opaqueHTTP1 holds Codec-specific data stored in Exchange.Opaque.
type opaqueHTTP1 struct {
	rawReq     *parser.RawRequest
	rawResp    *parser.RawResponse
	origKV     []exchange.KeyValue // header snapshot at Next() time
	origBody   []byte              // body snapshot at Next() time (nil for passthrough)
	bodyReader io.Reader           // passthrough body (non-nil when Exchange.Body == nil)
}

// Codec implements the codec.Codec interface for HTTP/1.x.
type Codec struct {
	role   Role
	reader *bufio.Reader
	writer io.Writer
	closer io.Closer

	// streamID is generated per request-response pair.
	streamID string
	sequence int

	// connClosed is set when the connection should be closed after the
	// current exchange (Connection: close or HTTP/1.0 default).
	connClosed bool

	// upgradeHint records detected protocol upgrade hints.
	upgradeHint UpgradeHint

	mu     sync.Mutex
	closed bool
}

// NewCodec creates a new HTTP/1.x Codec.
//
// rw must implement io.Reader and io.Writer. If rw also implements io.Closer,
// Close() will close it. The reader is wrapped in a bufio.Reader for efficient
// parsing.
func NewCodec(rw io.ReadWriter, role Role) *Codec {
	var closer io.Closer
	if c, ok := rw.(io.Closer); ok {
		closer = c
	}
	return &Codec{
		role:   role,
		reader: bufio.NewReaderSize(rw, 4096),
		writer: rw,
		closer: closer,
	}
}

// UpgradeHint returns the detected protocol upgrade hint, if any.
// This is checked after Next() returns to decide whether to switch codecs.
func (c *Codec) UpgradeHint() UpgradeHint {
	return c.upgradeHint
}

// Next reads the next Exchange from the wire.
//
// For ClientRole, it parses an HTTP request and returns an Exchange with
// Direction=Send. For UpstreamRole, it parses an HTTP response and returns
// an Exchange with Direction=Receive.
//
// On keep-alive connections, each call to Next() generates a new StreamID.
// When the connection should close (Connection: close or HTTP/1.0), the
// next call to Next() returns io.EOF.
func (c *Codec) Next(_ context.Context) (*exchange.Exchange, error) {
	if c.connClosed {
		return nil, io.EOF
	}

	switch c.role {
	case ClientRole:
		return c.nextRequest()
	case UpstreamRole:
		return c.nextResponse()
	default:
		return nil, fmt.Errorf("http1 codec: unknown role %d", c.role)
	}
}

// Send writes an Exchange to the wire.
//
// For ClientRole, it serializes a response. For UpstreamRole, it serializes
// a request. Wire fidelity is preserved through raw-first patching.
func (c *Codec) Send(_ context.Context, ex *exchange.Exchange) error {
	switch c.role {
	case ClientRole:
		return c.sendResponse(ex)
	case UpstreamRole:
		return c.sendRequest(ex)
	default:
		return fmt.Errorf("http1 codec: unknown role %d", c.role)
	}
}

// Close releases resources held by the Codec.
func (c *Codec) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.closer != nil {
		return c.closer.Close()
	}
	return nil
}

// nextRequest parses an HTTP/1.x request from the wire.
func (c *Codec) nextRequest() (*exchange.Exchange, error) {
	rawReq, err := parser.ParseRequest(c.reader)
	if err != nil {
		return nil, fmt.Errorf("http1 codec next request: %w", err)
	}

	// Generate new StreamID for each request-response pair.
	c.streamID = uuid.New().String()
	c.sequence = 0

	// Build Exchange.
	ex := &exchange.Exchange{
		StreamID:  c.streamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence,
		Direction: exchange.Send,
		Method:    rawReq.Method,
		Protocol:  exchange.HTTP1,
		RawBytes:  rawReq.RawBytes,
	}

	// Parse URL from RequestURI.
	if rawReq.RequestURI != "" {
		u, parseErr := url.ParseRequestURI(rawReq.RequestURI)
		if parseErr != nil {
			// Best-effort: store the raw URI as opaque path.
			u = &url.URL{Path: rawReq.RequestURI}
		}
		ex.URL = u
	}

	// Convert RawHeaders to []KeyValue.
	ex.Headers = rawHeadersToKV(rawReq.Headers)

	// Read body with passthrough threshold.
	body, bodyReader, err := readBodyWithThreshold(rawReq.Body)
	if err != nil {
		return nil, fmt.Errorf("http1 codec read request body: %w", err)
	}
	ex.Body = body

	// Store opaque data for Send().
	opaque := &opaqueHTTP1{
		rawReq:     rawReq,
		origKV:     cloneKV(ex.Headers),
		origBody:   cloneBytes(body),
		bodyReader: bodyReader,
	}
	ex.Opaque = opaque

	// Detect upgrade hints.
	c.detectRequestUpgrade(rawReq.Headers)

	// Set connection close semantics.
	c.connClosed = rawReq.Close

	return ex, nil
}

// nextResponse parses an HTTP/1.x response from the wire.
func (c *Codec) nextResponse() (*exchange.Exchange, error) {
	rawResp, err := parser.ParseResponse(c.reader)
	if err != nil {
		return nil, fmt.Errorf("http1 codec next response: %w", err)
	}

	ex := &exchange.Exchange{
		StreamID:  c.streamID,
		FlowID:    uuid.New().String(),
		Sequence:  c.sequence + 1,
		Direction: exchange.Receive,
		Status:    rawResp.StatusCode,
		Protocol:  exchange.HTTP1,
		RawBytes:  rawResp.RawBytes,
	}

	// Convert RawHeaders to []KeyValue.
	ex.Headers = rawHeadersToKV(rawResp.Headers)

	// Read body with passthrough threshold.
	body, bodyReader, err := readBodyWithThreshold(rawResp.Body)
	if err != nil {
		return nil, fmt.Errorf("http1 codec read response body: %w", err)
	}
	ex.Body = body

	// Store opaque data for Send().
	opaque := &opaqueHTTP1{
		rawResp:    rawResp,
		origKV:     cloneKV(ex.Headers),
		origBody:   cloneBytes(body),
		bodyReader: bodyReader,
	}
	ex.Opaque = opaque

	// Detect response upgrade hints.
	c.detectResponseUpgrade(rawResp.Headers)

	return ex, nil
}

// sendRequest serializes an Exchange as an HTTP/1.x request to the wire.
func (c *Codec) sendRequest(ex *exchange.Exchange) error {
	opaque, ok := ex.Opaque.(*opaqueHTTP1)
	if !ok || opaque == nil || opaque.rawReq == nil {
		return fmt.Errorf("http1 codec send request: missing opaque data")
	}

	// Sync internal state from the Exchange so that the subsequent
	// nextResponse() call produces a response Exchange with the correct
	// StreamID (set by the client-side Codec that parsed the request).
	c.streamID = ex.StreamID
	c.sequence = ex.Sequence

	rawReq := opaque.rawReq

	// Check if anything changed.
	headersChanged := !kvEqual(ex.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(ex, opaque)

	// Zero-copy path: nothing changed, write RawBytes + body as-is.
	if !headersChanged && !bodyChanged && len(rawReq.RawBytes) > 0 {
		if _, err := c.writer.Write(rawReq.RawBytes); err != nil {
			return fmt.Errorf("http1 codec send request raw: %w", err)
		}
		return c.writeBody(ex, opaque)
	}

	// Apply header patches.
	if headersChanged {
		rawReq.Headers = applyHeaderPatch(opaque.origKV, ex.Headers, rawReq.Headers)
	}

	// Update body if changed.
	if bodyChanged {
		c.updateBodyHeaders(rawReq, ex, opaque)
	}

	// Serialize and write.
	headerBytes := serializeRequest(rawReq)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1 codec send request: %w", err)
	}
	return c.writeBody(ex, opaque)
}

// sendResponse serializes an Exchange as an HTTP/1.x response to the wire.
func (c *Codec) sendResponse(ex *exchange.Exchange) error {
	opaque, ok := ex.Opaque.(*opaqueHTTP1)
	if !ok || opaque == nil || opaque.rawResp == nil {
		return fmt.Errorf("http1 codec send response: missing opaque data")
	}

	rawResp := opaque.rawResp

	// Check if anything changed.
	headersChanged := !kvEqual(ex.Headers, opaque.origKV)
	bodyChanged := isBodyChanged(ex, opaque)

	// Zero-copy path: nothing changed, write RawBytes + body as-is.
	if !headersChanged && !bodyChanged && len(rawResp.RawBytes) > 0 {
		if _, err := c.writer.Write(rawResp.RawBytes); err != nil {
			return fmt.Errorf("http1 codec send response raw: %w", err)
		}
		return c.writeBody(ex, opaque)
	}

	// Apply header patches.
	if headersChanged {
		rawResp.Headers = applyHeaderPatch(opaque.origKV, ex.Headers, rawResp.Headers)
	}

	// Update body if changed.
	if bodyChanged {
		c.updateResponseBodyHeaders(rawResp, ex, opaque)
	}

	// Serialize and write.
	headerBytes := serializeResponse(rawResp)
	if _, err := c.writer.Write(headerBytes); err != nil {
		return fmt.Errorf("http1 codec send response: %w", err)
	}
	return c.writeBody(ex, opaque)
}

// writeBody writes the body portion of an Exchange to the wire.
func (c *Codec) writeBody(ex *exchange.Exchange, opaque *opaqueHTTP1) error {
	if ex.Body != nil {
		if _, err := c.writer.Write(ex.Body); err != nil {
			return fmt.Errorf("http1 codec write body: %w", err)
		}
		return nil
	}
	// Passthrough mode: stream from bodyReader.
	if opaque.bodyReader != nil {
		if _, err := io.Copy(c.writer, opaque.bodyReader); err != nil {
			return fmt.Errorf("http1 codec write passthrough body: %w", err)
		}
	}
	return nil
}

// updateBodyHeaders updates Content-Length and Transfer-Encoding headers on a
// request when the body has been modified.
func (c *Codec) updateBodyHeaders(rawReq *parser.RawRequest, ex *exchange.Exchange, opaque *opaqueHTTP1) {
	if ex.Body == nil {
		return
	}
	// Update the raw request body for serialization.
	rawReq.Body = bytes.NewReader(ex.Body)
	opaque.bodyReader = nil

	if shouldAutoContentLength(ex) {
		rawReq.Headers.Del("Transfer-Encoding")
		rawReq.Headers.Set("Content-Length", strconv.Itoa(len(ex.Body)))
	}
}

// updateResponseBodyHeaders updates Content-Length and Transfer-Encoding headers
// on a response when the body has been modified.
func (c *Codec) updateResponseBodyHeaders(rawResp *parser.RawResponse, ex *exchange.Exchange, opaque *opaqueHTTP1) {
	if ex.Body == nil {
		return
	}
	rawResp.Body = bytes.NewReader(ex.Body)
	opaque.bodyReader = nil

	if shouldAutoContentLength(ex) {
		rawResp.Headers.Del("Transfer-Encoding")
		rawResp.Headers.Set("Content-Length", strconv.Itoa(len(ex.Body)))
	}
}

// detectRequestUpgrade checks for protocol upgrade hints in request headers.
func (c *Codec) detectRequestUpgrade(headers parser.RawHeaders) {
	// Check for WebSocket upgrade.
	for _, val := range headers.Values("Upgrade") {
		if strings.EqualFold(strings.TrimSpace(val), "websocket") {
			c.upgradeHint = UpgradeWebSocket
			return
		}
	}

	// Check for gRPC-Web content type.
	ct := headers.Get("Content-Type")
	if strings.HasPrefix(ct, "application/grpc-web") {
		c.upgradeHint = UpgradeGRPCWeb
		return
	}
}

// detectResponseUpgrade checks for protocol upgrade hints in response headers.
func (c *Codec) detectResponseUpgrade(headers parser.RawHeaders) {
	// Check for SSE content type.
	ct := headers.Get("Content-Type")
	if strings.HasPrefix(ct, "text/event-stream") {
		c.upgradeHint = UpgradeSSE
		return
	}
}

// rawHeadersToKV converts parser.RawHeaders to []exchange.KeyValue.
func rawHeadersToKV(raw parser.RawHeaders) []exchange.KeyValue {
	kv := make([]exchange.KeyValue, len(raw))
	for i, h := range raw {
		kv[i] = exchange.KeyValue{Name: h.Name, Value: h.Value}
	}
	return kv
}

// cloneKV returns a deep copy of []exchange.KeyValue.
func cloneKV(kv []exchange.KeyValue) []exchange.KeyValue {
	if kv == nil {
		return nil
	}
	out := make([]exchange.KeyValue, len(kv))
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

// kvEqual checks if two []exchange.KeyValue slices are identical.
func kvEqual(a, b []exchange.KeyValue) bool {
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

// isBodyChanged checks whether the Exchange body was modified compared to
// the original parsed state.
func isBodyChanged(ex *exchange.Exchange, opaque *opaqueHTTP1) bool {
	// Passthrough mode unchanged: body is still nil with a bodyReader.
	if ex.Body == nil && opaque.bodyReader != nil {
		return false
	}
	// Both nil: no body at all (unchanged).
	if ex.Body == nil && opaque.bodyReader == nil {
		return false
	}
	// If passthrough was active (origBody nil) but Pipeline set Body, it changed.
	if opaque.origBody == nil {
		return true
	}
	// Compare current body with the snapshot taken at Next() time.
	return !bytes.Equal(ex.Body, opaque.origBody)
}

// shouldAutoContentLength checks if Content-Length should be auto-recalculated.
func shouldAutoContentLength(ex *exchange.Exchange) bool {
	if ex.Metadata == nil {
		return true
	}
	if v, ok := ex.Metadata["auto_content_length"]; ok {
		if b, isBool := v.(bool); isBool && !b {
			return false
		}
	}
	return true
}

// readBodyWithThreshold reads a body up to passthroughThreshold.
// Returns (body, nil, err) for normal bodies and (nil, reader, nil) for
// passthrough mode when the body exceeds the threshold.
func readBodyWithThreshold(r io.Reader) (body []byte, bodyReader io.Reader, err error) {
	if r == nil {
		return nil, nil, nil
	}

	// Read up to threshold + 1 to detect whether we exceed it.
	buf := make([]byte, passthroughThreshold+1)
	n, readErr := io.ReadFull(r, buf)

	if readErr == io.EOF || readErr == io.ErrUnexpectedEOF {
		// Body fits within threshold.
		if n == 0 {
			return []byte{}, nil, nil
		}
		return buf[:n], nil, nil
	}
	if readErr != nil {
		return nil, nil, fmt.Errorf("read body: %w", readErr)
	}

	// n == passthroughThreshold+1: body exceeds threshold.
	// Return nil body and a reader that replays the buffered data + remainder.
	combined := io.MultiReader(bytes.NewReader(buf[:n]), r)
	return nil, combined, nil
}

// applyHeaderPatch applies a minimal diff from origKV to newKV onto rawHeaders.
//
// The algorithm:
//  1. Walk newKV entries in order.
//  2. For each entry, find a matching RawHeader by index position first (same
//     index, same name = reuse). If name differs, search by name among unused
//     raw headers.
//  3. If value matches, reuse the RawHeader (preserving RawValue = OWS).
//  4. If value changed, update Value and clear RawValue.
//  5. Any origKV entries not consumed are deletions.
//  6. Any newKV entries not matched produce new RawHeaders.
func applyHeaderPatch(origKV, newKV []exchange.KeyValue, raw parser.RawHeaders) parser.RawHeaders {
	used := make([]bool, len(raw))
	result := make(parser.RawHeaders, 0, len(newKV))

	for i, nkv := range newKV {
		// Try index-based match first.
		if i < len(origKV) && i < len(raw) && !used[i] &&
			origKV[i].Name == nkv.Name && raw[i].Name == nkv.Name {
			used[i] = true
			h := raw[i]
			if nkv.Value != h.Value {
				h.Value = nkv.Value
				h.RawValue = ""
			}
			result = append(result, h)
			continue
		}

		// Search by name among unused raw headers.
		found := false
		for j := range raw {
			if !used[j] && strings.EqualFold(raw[j].Name, nkv.Name) {
				used[j] = true
				h := raw[j]
				// Preserve the original header name casing from raw.
				if nkv.Value != h.Value {
					h.Value = nkv.Value
					h.RawValue = ""
				}
				result = append(result, h)
				found = true
				break
			}
		}
		if !found {
			// New header not in original.
			result = append(result, parser.RawHeader{
				Name:  nkv.Name,
				Value: nkv.Value,
			})
		}
	}

	return result
}
