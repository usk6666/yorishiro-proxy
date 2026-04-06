package http2

import (
	"bytes"
	"context"
	"fmt"
	"io"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// Anomaly describes a protocol-level anomaly detected in an HTTP/2 request.
// These are recorded for vulnerability assessment purposes but do not prevent
// the request from being proxied.
type Anomaly struct {
	// Type identifies the anomaly category (e.g., "duplicate_pseudo_header",
	// "pseudo_header_order", "unknown_pseudo_header").
	Type string

	// Detail provides a human-readable description of the anomaly.
	Detail string
}

// h2Request represents an HTTP/2 request using hpack native types as the
// source of truth. It preserves wire-order headers including pseudo-headers,
// duplicate headers, and case information for vulnerability assessment.
type h2Request struct {
	// AllHeaders holds all headers in wire order (pseudo-headers included).
	// This is the source of truth. Duplicate pseudo-headers, unknown
	// pseudo-headers, and ordering anomalies are preserved here.
	AllHeaders []hpack.HeaderField

	// Convenience accessors derived from AllHeaders.
	Method    string // :method
	Scheme    string // :scheme
	Authority string // :authority
	Path      string // :path

	// Body is the request body. May be nil for bodyless requests.
	Body io.ReadCloser
	// EndStream indicates whether END_STREAM was set on the HEADERS frame.
	// When true, no DATA frames follow on the wire; however, the Body field
	// may still be non-nil if data was accumulated before dispatch.
	EndStream bool
	// RawFrames holds the raw HTTP/2 frame bytes received from the client.
	RawFrames [][]byte
	// Anomalies detected during header parsing.
	Anomalies []Anomaly
}

// RegularHeaders returns only the non-pseudo-header fields from AllHeaders,
// preserving wire order.
func (r *h2Request) RegularHeaders() []hpack.HeaderField {
	var result []hpack.HeaderField
	for _, hf := range r.AllHeaders {
		if !strings.HasPrefix(hf.Name, ":") {
			result = append(result, hf)
		}
	}
	return result
}

// h2ResponseWriter is the interface for writing HTTP/2 responses back to the
// client using hpack native types. It replaces gohttp.ResponseWriter for the
// unary HTTP/2 path, enabling direct HPACK header encoding without lossy
// conversion through net/http.Header.
type h2ResponseWriter interface {
	// WriteHeaders sends the response HEADERS frame with the given status code
	// and header fields. Must be called before WriteData.
	WriteHeaders(statusCode int, headers []hpack.HeaderField) error

	// WriteData sends response body data as DATA frames. Chunking to the
	// peer's MaxFrameSize is handled internally.
	WriteData(data []byte) error

	// WriteTrailers sends trailer header fields as a HEADERS frame with
	// END_STREAM.
	WriteTrailers(trailers []hpack.HeaderField) error

	// Flush ensures any buffered HEADERS frame has been sent to the wire.
	Flush()
}

// h2Response represents an HTTP/2 response using hpack native types.
// It carries the response data through the pipeline without gohttp conversion.
type h2Response struct {
	StatusCode int
	Headers    []hpack.HeaderField // regular headers (no pseudo-headers)
	Trailers   []hpack.HeaderField
	Body       []byte
}

// buildH2Request constructs an h2Request from decoded HPACK header fields
// and an optional body. It extracts pseudo-headers as convenience fields and
// detects anomalies (duplicate pseudo-headers, unknown pseudo-headers,
// pseudo-headers after regular headers).
func buildH2Request(headers []hpack.HeaderField, body io.ReadCloser, endStream bool, rawFrames [][]byte) (*h2Request, error) {
	req := &h2Request{
		AllHeaders: headers,
		Body:       body,
		EndStream:  endStream,
		RawFrames:  rawFrames,
	}

	req.extractPseudoHeaders()

	if req.Method == "" {
		return nil, fmt.Errorf("missing :method pseudo-header")
	}
	if req.Path == "" && req.Method != "CONNECT" {
		return nil, fmt.Errorf("missing :path pseudo-header")
	}
	if req.Scheme == "" {
		req.Scheme = "http"
	}

	return req, nil
}

// extractPseudoHeaders scans AllHeaders to populate convenience fields and
// detect anomalies. Separated from buildH2Request to reduce cyclomatic
// complexity.
func (req *h2Request) extractPseudoHeaders() {
	pseudoSeen := make(map[string]int)
	regularStarted := false

	for _, hf := range req.AllHeaders {
		if !strings.HasPrefix(hf.Name, ":") {
			regularStarted = true
			continue
		}
		if regularStarted {
			req.Anomalies = append(req.Anomalies, Anomaly{
				Type:   "pseudo_header_order",
				Detail: fmt.Sprintf("pseudo-header %q appears after regular headers", hf.Name),
			})
		}
		pseudoSeen[hf.Name]++
		if pseudoSeen[hf.Name] > 1 {
			req.Anomalies = append(req.Anomalies, Anomaly{
				Type:   "duplicate_pseudo_header",
				Detail: fmt.Sprintf("pseudo-header %q appears %d times", hf.Name, pseudoSeen[hf.Name]),
			})
		}
		req.setPseudoField(hf.Name, hf.Value)
	}
}

// setPseudoField sets a convenience field from a pseudo-header, recording
// an anomaly for unknown pseudo-headers.
func (req *h2Request) setPseudoField(name, value string) {
	switch name {
	case ":method":
		if req.Method == "" {
			req.Method = value
		}
	case ":scheme":
		if req.Scheme == "" {
			req.Scheme = value
		}
	case ":authority":
		if req.Authority == "" {
			req.Authority = value
		}
	case ":path":
		if req.Path == "" {
			req.Path = value
		}
	default:
		req.Anomalies = append(req.Anomalies, Anomaly{
			Type:   "unknown_pseudo_header",
			Detail: fmt.Sprintf("unknown pseudo-header %q", name),
		})
	}
}

// h2RequestURL builds a *url.URL from the h2Request pseudo-headers.
func h2RequestURL(req *h2Request) *url.URL {
	path := req.Path
	u := &url.URL{
		Scheme: req.Scheme,
		Host:   req.Authority,
		Path:   path,
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		u.Path = path[:idx]
		u.RawQuery = path[idx+1:]
	}
	return u
}

// h2RequestToRaw converts an h2Request to a parser.RawRequest for the intercept
// pipeline. The pseudo-headers are converted to method/requestURI, and regular
// headers are preserved as RawHeaders.
func h2RequestToRaw(req *h2Request, bodyBytes []byte) *parser.RawRequest {
	headers := hpackToRawHeaders(req.AllHeaders)
	// Set Host from :authority if not already present.
	if req.Authority != "" && headers.Get("host") == "" {
		headers.Set("host", req.Authority)
	}
	// Build RequestURI from pseudo-headers.
	reqURI := req.Path
	if req.Scheme != "" && req.Authority != "" {
		u := &url.URL{
			Scheme: req.Scheme,
			Host:   req.Authority,
			Path:   req.Path,
		}
		if idx := strings.IndexByte(req.Path, '?'); idx >= 0 {
			u.Path = req.Path[:idx]
			u.RawQuery = req.Path[idx+1:]
		}
		reqURI = u.String()
	}
	// Sync Content-Length with actual body bytes.
	headers.Del("transfer-encoding")
	if len(bodyBytes) > 0 {
		headers.Set("content-length", strconv.Itoa(len(bodyBytes)))
	} else {
		headers.Del("content-length")
	}

	return &parser.RawRequest{
		Method:     req.Method,
		RequestURI: reqURI,
		Proto:      "HTTP/2.0",
		Headers:    headers,
		Body:       bytes.NewReader(bodyBytes),
	}
}

// h2ResponseToRaw converts h2Response hpack headers + status to a
// parser.RawResponse for the intercept pipeline.
func h2ResponseToRaw(statusCode int, headers []hpack.HeaderField, body []byte) *parser.RawResponse {
	return &parser.RawResponse{
		Proto:      "HTTP/2.0",
		StatusCode: statusCode,
		Status:     httputil.FormatStatus(statusCode),
		Headers:    hpackToRawHeaders(headers),
		Body:       io.NopCloser(bytes.NewReader(body)),
	}
}

// rawHeadersToHpackWithPseudo builds hpack headers including pseudo-headers
// from a RawRequest after intercept modification. The method/scheme/authority/path
// come from the modified request; regular headers come from the modified RawHeaders.
func rawHeadersToHpackWithPseudo(method, scheme, authority, path string, rh parser.RawHeaders) []hpack.HeaderField {
	isConnect := strings.EqualFold(method, "CONNECT")
	headers := make([]hpack.HeaderField, 0, 4+len(rh))
	headers = append(headers, hpack.HeaderField{Name: ":method", Value: method})
	if scheme != "" && !isConnect {
		headers = append(headers, hpack.HeaderField{Name: ":scheme", Value: scheme})
	}
	if authority != "" {
		headers = append(headers, hpack.HeaderField{Name: ":authority", Value: authority})
	}
	if !isConnect || path != "" {
		headers = append(headers, hpack.HeaderField{Name: ":path", Value: path})
	}
	// Append regular headers, skipping host (represented by :authority).
	for _, h := range rh {
		if strings.EqualFold(h.Name, "host") {
			continue
		}
		headers = append(headers, hpack.HeaderField{Name: h.Name, Value: h.Value})
	}
	return headers
}

// buildH2HeadersFromH2Req constructs HTTP/2 HPACK header fields for upstream
// forwarding from an h2Request's fields. Pseudo-headers are included; hop-by-hop
// headers are filtered.
func buildH2HeadersFromH2Req(req *h2Request) []hpack.HeaderField {
	path := req.Path
	if path == "" {
		path = "/"
	}

	scheme := req.Scheme
	if scheme == "" {
		scheme = "https"
	}

	authority := req.Authority

	headers := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}

	for _, hf := range req.AllHeaders {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		lower := hf.Name // HTTP/2 headers are already lowercase per RFC 9113
		if lower == "host" {
			continue
		}
		if isHopByHopHeader(lower) {
			if lower == "te" && strings.EqualFold(hf.Value, "trailers") {
				headers = append(headers, hf)
			}
			continue
		}
		headers = append(headers, hf)
	}

	return headers
}

// removeHpackHopByHop returns hpack fields with HTTP/2 hop-by-hop headers
// removed. TE: trailers is preserved per RFC 9113. Returns the same slice
// if no removals needed.
func removeHpackHopByHop(fields []hpack.HeaderField) []hpack.HeaderField {
	result := make([]hpack.HeaderField, 0, len(fields))
	for _, hf := range fields {
		if isHopByHopHeader(hf.Name) {
			if hf.Name == "te" && strings.EqualFold(hf.Value, "trailers") {
				result = append(result, hf)
			}
			continue
		}
		result = append(result, hf)
	}
	return result
}

// h2RequestToGoHTTP converts an h2Request to a *gohttp.Request for subsystems
// that still require net/http types (legacy transport, gRPC intercept, tests).
// Callers in the data path should prefer hpack native types.
func h2RequestToGoHTTP(ctx context.Context, req *h2Request) (*gohttp.Request, error) {
	httpHeaders := make(gohttp.Header)
	for _, hf := range req.AllHeaders {
		if !strings.HasPrefix(hf.Name, ":") {
			httpHeaders.Add(hf.Name, hf.Value)
		}
	}

	host := req.Authority
	if host == "" {
		host = httpHeaders.Get("Host")
	}

	path := req.Path
	reqURL := &url.URL{
		Scheme:   req.Scheme,
		Host:     host,
		Path:     path,
		RawQuery: "",
	}
	if idx := strings.IndexByte(path, '?'); idx >= 0 {
		reqURL.Path = path[:idx]
		reqURL.RawQuery = path[idx+1:]
	}

	var contentLength int64 = -1
	body := req.Body
	if req.EndStream && body == nil {
		contentLength = 0
		body = gohttp.NoBody
	} else if body == nil {
		body = gohttp.NoBody
	}

	goReq := &gohttp.Request{
		Method:        req.Method,
		URL:           reqURL,
		Proto:         "HTTP/2.0",
		ProtoMajor:    2,
		ProtoMinor:    0,
		Header:        httpHeaders,
		Body:          body,
		Host:          host,
		RequestURI:    path,
		ContentLength: contentLength,
	}
	goReq = goReq.WithContext(ctx)
	return goReq, nil
}

// goHTTPHeaderToHpack converts gohttp.Header to hpack header fields.
// Key order follows map iteration order (non-deterministic).
// This is a bridge for test code and legacy paths; data path code should
// use hpack native types directly.
func goHTTPHeaderToHpack(h gohttp.Header) []hpack.HeaderField {
	keys := make([]string, 0, len(h))
	for name := range h {
		keys = append(keys, name)
	}
	var fields []hpack.HeaderField
	for _, name := range keys {
		for _, v := range h[name] {
			fields = append(fields, hpack.HeaderField{
				Name:  strings.ToLower(name),
				Value: v,
			})
		}
	}
	return fields
}

// buildH2HeadersFromGoHTTP converts a gohttp.Request into HTTP/2 HPACK header
// fields including pseudo-headers. Used for forwarding upstream via the h2 frame
// engine when the request is still in gohttp.Request form (legacy transport path).
func buildH2HeadersFromGoHTTP(req *gohttp.Request) []hpack.HeaderField {
	path := req.URL.RequestURI()
	if path == "" {
		path = "/"
	}

	scheme := req.URL.Scheme
	if scheme == "" {
		scheme = "https"
	}

	authority := req.Host
	if authority == "" && req.URL != nil {
		authority = req.URL.Host
	}

	headers := []hpack.HeaderField{
		{Name: ":method", Value: req.Method},
		{Name: ":scheme", Value: scheme},
		{Name: ":authority", Value: authority},
		{Name: ":path", Value: path},
	}

	for name, vals := range req.Header {
		lower := strings.ToLower(name)
		if lower == "host" {
			continue
		}
		// Filter HTTP/2 hop-by-hop headers (RFC 9113 §8.2.2), but allow
		// "te: trailers" which is the only TE value permitted in HTTP/2.
		if isHopByHopHeader(lower) {
			if lower == "te" {
				for _, v := range vals {
					if strings.EqualFold(v, "trailers") {
						headers = append(headers, hpack.HeaderField{Name: lower, Value: v})
					}
				}
			}
			continue
		}
		for _, v := range vals {
			headers = append(headers, hpack.HeaderField{Name: lower, Value: v})
		}
	}

	return headers
}

// h2ResultToH2Response converts an HTTP/2 RoundTripResult to an h2Response
// with hpack native types (no gohttp conversion).
func h2ResultToH2Response(r *RoundTripResult, body []byte) *h2Response {
	var headers []hpack.HeaderField
	for _, hf := range r.Headers {
		if strings.HasPrefix(hf.Name, ":") {
			continue
		}
		headers = append(headers, hf)
	}
	return &h2Response{
		StatusCode: r.StatusCode,
		Headers:    headers,
		Body:       body,
	}
}

// writeErrorResponse writes a simple error response via h2ResponseWriter.
func writeErrorResponse(w h2ResponseWriter, statusCode int) {
	w.WriteHeaders(statusCode, nil)
}

// asGoHTTPResponseWriter extracts a gohttp.ResponseWriter from an
// h2ResponseWriter. This is used by the gRPC request intercept path and
// tests which still require gohttp.ResponseWriter. Panics if the underlying
// type does not implement gohttp.ResponseWriter (frameResponseWriter always does).
func asGoHTTPResponseWriter(w h2ResponseWriter) gohttp.ResponseWriter {
	if rw, ok := w.(gohttp.ResponseWriter); ok {
		return rw
	}
	panic("h2ResponseWriter does not implement gohttp.ResponseWriter")
}
