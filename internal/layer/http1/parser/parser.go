package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope/bodybuf"
)

// Limits to prevent resource exhaustion.
const (
	// MaxRawCaptureSize is the package-default cap on bytes captured in
	// RawBytes (header section) and memory-mode RawBody (USK-769). Callers
	// that wire ParseOptions.MaxRawCapture override this value per-parse;
	// when ParseOptions.MaxRawCapture is zero, this default applies. The
	// constant remains exported so sibling packages (legacy callers, tests)
	// can reference the default directly.
	//
	// USK-800: kept as a const to preserve the public surface; the runtime
	// override knob is config.MaxRawCaptureSize → http1.WithMaxRawCaptureSize
	// → ParseOptions.MaxRawCapture.
	MaxRawCaptureSize = 2 << 20 // 2 MiB

	// maxRequestLineSize limits the request/status line length.
	maxRequestLineSize = 8192 // 8 KiB

	// maxHeaderSize limits the total header section size (including all lines).
	// Set above MaxRawCaptureSize so raw bytes truncation is tested before
	// header parsing fails outright.
	maxHeaderSize = 4 << 20 // 4 MiB

	// maxHeaderCount limits the number of individual header lines.
	maxHeaderCount = 10000
)

// ParseOptions carries per-parse knobs that the channel layer threads through
// to bound header / body raw-bytes capture in memory mode. The zero value
// means "use the package defaults" — equivalent to calling ParseRequest /
// ParseResponse without options.
type ParseOptions struct {
	// MaxRawCapture caps RawBytes (header section) and the memory-mode
	// RawBody (USK-769) at this byte count. Zero means use the
	// MaxRawCaptureSize package default. Spill-enabled body capture
	// (USK-772) honors the spill MaxSize instead — this knob does not
	// reach it.
	MaxRawCapture int64
}

// rawSink is the minimal write/truncation interface used by readLine and
// parseHeaderLines. Two implementations satisfy it:
//
//   - *captureWriter for header-section capture (RawBytes), capped at
//     MaxRawCaptureSize and memory-only (header sections never spill).
//   - *bodyCaptureSink for body capture (RawBody), where USK-772 added a
//     memory-then-disk-spill mode bounded by MaxBodySize.
//
// A nil rawSink is permitted (treated as a no-op writer) so that
// downstream parser internals can share the same code regardless of whether
// the caller wants capture.
type rawSink interface {
	write(p []byte)
}

// captureWriter records bytes written to it up to cap. cap is the per-parse
// cap injected via ParseOptions.MaxRawCapture; zero means use MaxRawCaptureSize.
type captureWriter struct {
	buf       bytes.Buffer
	truncated bool
	cap       int
}

// effectiveCap returns the active byte cap, falling back to the package
// default when cw.cap is zero.
func (cw *captureWriter) effectiveCap() int {
	if cw.cap > 0 {
		return cw.cap
	}
	return MaxRawCaptureSize
}

func (cw *captureWriter) write(p []byte) {
	if cw == nil || cw.truncated {
		return
	}
	remaining := cw.effectiveCap() - cw.buf.Len()
	if remaining <= 0 {
		cw.truncated = true
		return
	}
	if len(p) > remaining {
		cw.buf.Write(p[:remaining])
		cw.truncated = true
		return
	}
	cw.buf.Write(p)
}

func (cw *captureWriter) bytes() []byte {
	if cw.buf.Len() == 0 {
		return nil
	}
	out := make([]byte, cw.buf.Len())
	copy(out, cw.buf.Bytes())
	return out
}

// ParseRequest reads and parses an HTTP/1.x request from r using the
// package-default capture cap (MaxRawCaptureSize). Equivalent to
// ParseRequestWithOptions(r, ParseOptions{}).
func ParseRequest(r *bufio.Reader) (*RawRequest, error) {
	return ParseRequestWithOptions(r, ParseOptions{})
}

// ParseRequestWithOptions reads and parses an HTTP/1.x request from r with
// per-parse knobs. opts.MaxRawCapture caps RawBytes (header) and the
// memory-mode RawBody; zero falls back to MaxRawCaptureSize.
//
// Returns the parsed request including anomaly information. Invalid or
// malformed requests are parsed on a best-effort basis with anomalies
// recorded rather than returning errors. Errors are returned only for
// unrecoverable I/O failures or when no meaningful request can be extracted
// at all (e.g., connection closed).
func ParseRequestWithOptions(r *bufio.Reader, opts ParseOptions) (*RawRequest, error) {
	cw := &captureWriter{cap: capInt(opts.MaxRawCapture)}

	// Parse request line.
	method, requestURI, proto, err := parseRequestLine(r, cw)
	if err != nil {
		return nil, fmt.Errorf("parse request line: %w", err)
	}

	req := &RawRequest{
		Method:     method,
		RequestURI: requestURI,
		Proto:      proto,
	}

	// Parse headers.
	headers, anomalies, err := parseHeaders(r, cw)
	if err != nil {
		return nil, fmt.Errorf("parse headers: %w", err)
	}
	req.Headers = headers
	req.Anomalies = anomalies

	// Detect smuggling anomalies from headers.
	detectSmugglingAnomalies(req.Headers, &req.Anomalies)

	// Determine body reader. The body sink inherits the same memory cap so
	// header and body capture share the operator-tunable budget.
	req.Body = resolveRequestBody(r, req.Headers, req.Proto, opts.MaxRawCapture)

	// Set connection close semantics.
	req.Close = shouldClose(req.Headers, req.Proto)

	// Finalize raw bytes capture.
	req.RawBytes = cw.bytes()
	req.Truncated = cw.truncated

	return req, nil
}

// ParseResponse reads and parses an HTTP/1.x response from r using the
// package-default capture cap. Equivalent to
// ParseResponseWithOptions(r, ParseOptions{}).
func ParseResponse(r *bufio.Reader) (*RawResponse, error) {
	return ParseResponseWithOptions(r, ParseOptions{})
}

// ParseResponseWithOptions reads and parses an HTTP/1.x response from r with
// per-parse knobs. See ParseRequestWithOptions for the option semantics.
// Like ParseRequest, malformed responses are parsed on a best-effort basis
// with anomalies recorded.
func ParseResponseWithOptions(r *bufio.Reader, opts ParseOptions) (*RawResponse, error) {
	cw := &captureWriter{cap: capInt(opts.MaxRawCapture)}

	// Parse status line.
	proto, statusCode, status, err := parseStatusLine(r, cw)
	if err != nil {
		return nil, fmt.Errorf("parse status line: %w", err)
	}

	resp := &RawResponse{
		Proto:      proto,
		StatusCode: statusCode,
		Status:     status,
	}

	// Parse headers.
	headers, anomalies, err := parseHeaders(r, cw)
	if err != nil {
		return nil, fmt.Errorf("parse headers: %w", err)
	}
	resp.Headers = headers
	resp.Anomalies = anomalies

	// Detect smuggling anomalies.
	detectSmugglingAnomalies(resp.Headers, &resp.Anomalies)

	// Determine body reader.
	resp.Body = resolveResponseBody(r, resp.Headers, resp.Proto, resp.StatusCode, opts.MaxRawCapture)

	// Finalize raw bytes capture.
	resp.RawBytes = cw.bytes()
	resp.Truncated = cw.truncated

	return resp, nil
}

// capInt narrows an int64 cap into the int field used by captureWriter.
// Negative or zero values become zero (treated as "use MaxRawCaptureSize"
// downstream); values above MaxInt clamp to MaxInt to avoid overflow on
// 32-bit hosts. The latter never occurs at our deployment scale but the
// guard keeps the conversion total.
func capInt(n int64) int {
	if n <= 0 {
		return 0
	}
	const maxInt = int64(int(^uint(0) >> 1))
	if n > maxInt {
		return int(maxInt)
	}
	return int(n)
}

// parseRequestLine reads the request line (e.g., "GET /path HTTP/1.1\r\n").
func parseRequestLine(r *bufio.Reader, cw rawSink) (method, requestURI, proto string, err error) {
	line, err := readLine(r, cw, maxRequestLineSize)
	if err != nil {
		return "", "", "", fmt.Errorf("read request line: %w", err)
	}

	// Split into exactly 3 parts: METHOD SP REQUEST-URI SP HTTP-VERSION
	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 3 {
		// Best-effort: try to extract what we can.
		if len(parts) >= 1 {
			method = parts[0]
		}
		if len(parts) >= 2 {
			requestURI = parts[1]
		}
		return method, requestURI, "HTTP/1.1", nil
	}

	return parts[0], parts[1], parts[2], nil
}

// parseStatusLine reads the status line (e.g., "HTTP/1.1 200 OK\r\n").
func parseStatusLine(r *bufio.Reader, cw rawSink) (proto string, statusCode int, status string, err error) {
	line, err := readLine(r, cw, maxRequestLineSize)
	if err != nil {
		return "", 0, "", fmt.Errorf("read status line: %w", err)
	}

	// HTTP-VERSION SP STATUS-CODE SP REASON-PHRASE
	// At minimum we need "HTTP/x.y NNN"
	spIdx := strings.IndexByte(line, ' ')
	if spIdx < 0 {
		return line, 0, "", nil
	}
	proto = line[:spIdx]
	rest := line[spIdx+1:]

	// Extract status code.
	codeStr := rest
	var reason string
	if spIdx2 := strings.IndexByte(rest, ' '); spIdx2 >= 0 {
		codeStr = rest[:spIdx2]
		reason = rest[spIdx2+1:]
	}

	code, parseErr := strconv.Atoi(codeStr)
	if parseErr != nil {
		// Non-numeric status code — record as-is, code stays 0.
		return proto, 0, rest, nil
	}

	// Status includes the code and reason: "200 OK"
	status = strings.TrimSpace(codeStr + " " + reason)
	return proto, code, status, nil
}

// readLine reads a CRLF- or LF-terminated line from r, capturing bytes.
// Returns the line content without the terminator.
// Returns an error if the line exceeds maxLen.
func readLine(r *bufio.Reader, cw rawSink, maxLen int) (string, error) {
	var line []byte
	for {
		segment, err := r.ReadSlice('\n')

		// Check maxLen BEFORE appending to prevent large allocations.
		if len(line)+len(segment) > maxLen {
			remaining := maxLen - len(line)
			if remaining > 0 && cw != nil {
				cw.write(segment[:remaining])
			}
			return "", fmt.Errorf("line exceeds maximum length %d", maxLen)
		}

		line = append(line, segment...)
		if cw != nil {
			cw.write(segment)
		}

		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			// Line is longer than bufio buffer; keep reading.
			continue
		}
		// I/O error or EOF.
		if len(line) > 0 {
			// Return what we have on EOF (partial line).
			break
		}
		return "", err
	}

	// Strip exactly one trailing CRLF or LF terminator, preserving any other
	// trailing CR/LF characters so that embedded CR anomaly detection works.
	if n := len(line); n > 0 {
		if line[n-1] == '\n' {
			n--
			if n > 0 && line[n-1] == '\r' {
				n--
			}
		}
		line = line[:n]
	}
	return string(line), nil
}

// parseHeaders parses HTTP headers until the blank line terminator.
// It handles obs-fold (continuation lines starting with SP or HT).
func parseHeaders(r *bufio.Reader, cw *captureWriter) (RawHeaders, []Anomaly, error) {
	return parseHeaderLines(r, cw, maxHeaderSize)
}

// parseHeaderLines implements the shared line-by-line header/trailer parser.
// Used by parseHeaders for initial header sections (with cw capturing RawBytes)
// and by dechunkedReader.consumeTrailers for chunked trailer sections (with
// the body capture sink). Honors obs-fold, OWS preservation, embedded-CR
// detection, space-before-colon detection, and colon-less line fallback.
//
// cw may be nil — in that case bytes are not captured. Both *captureWriter
// (header capture) and *bodyCaptureSink (body capture; USK-772) satisfy the
// rawSink interface.
//
// maxSize caps the total line bytes (including approximated CRLF overhead).
// Header count is capped at maxHeaderCount.
func parseHeaderLines(r *bufio.Reader, cw rawSink, maxSize int) (RawHeaders, []Anomaly, error) {
	var headers RawHeaders
	var anomalies []Anomaly
	var totalSize int

	for {
		if len(headers) >= maxHeaderCount {
			return headers, anomalies, fmt.Errorf("header count exceeds limit %d", maxHeaderCount)
		}

		line, err := readLine(r, cw, maxSize)
		if err != nil {
			return headers, anomalies, fmt.Errorf("read header line: %w", err)
		}

		totalSize += len(line) + 2 // approximate +2 for CRLF
		if totalSize > maxSize {
			return headers, anomalies, fmt.Errorf("header section exceeds maximum size %d", maxSize)
		}

		// Empty line = end of headers.
		if line == "" {
			break
		}

		// Check for obs-fold (continuation line starting with SP or HT).
		if line[0] == ' ' || line[0] == '\t' {
			if len(headers) > 0 {
				// Append to previous header value.
				headers[len(headers)-1].Value += " " + strings.TrimLeft(line, " \t")
				anomalies = append(anomalies, Anomaly{
					Type:   AnomalyObsFold,
					Detail: "obsolete line folding detected in header",
				})
			} else {
				// Orphan continuation line with no preceding header.
				anomalies = append(anomalies, Anomaly{
					Type:   AnomalyObsFold,
					Detail: "obsolete line folding with no preceding header",
				})
			}
			continue
		}

		// Parse "Name: Value".
		colonIdx := strings.IndexByte(line, ':')
		if colonIdx < 0 {
			// No colon — malformed header; record as best-effort with empty value.
			headers = append(headers, RawHeader{Name: line, Value: ""})
			continue
		}

		name := line[:colonIdx]
		value := line[colonIdx+1:]

		// Check for space before colon (header injection / obfuscation).
		if strings.HasSuffix(name, " ") || strings.HasSuffix(name, "\t") {
			anomalies = append(anomalies, Anomaly{
				Type:   AnomalyHeaderInjection,
				Detail: fmt.Sprintf("whitespace before colon in header name: %q", name),
			})
		}

		// Check for embedded CR in header name or value (bare \r not part of line terminator).
		if strings.ContainsRune(name, '\r') || strings.ContainsRune(value, '\r') {
			anomalies = append(anomalies, Anomaly{
				Type:   AnomalyHeaderInjection,
				Detail: fmt.Sprintf("embedded CR in header: %q", name),
			})
		}

		// Preserve raw value before OWS trimming for anomaly detection.
		rawValue := value
		// Trim optional leading whitespace from value (OWS per RFC 7230).
		value = strings.TrimLeft(value, " \t")
		// Trim trailing OWS.
		value = strings.TrimRight(value, " \t")

		hdr := RawHeader{Name: name, Value: value}
		if rawValue != value {
			hdr.RawValue = rawValue
		}
		headers = append(headers, hdr)
	}

	return headers, anomalies, nil
}

// detectSmugglingAnomalies inspects headers for HTTP request smuggling patterns.
func detectSmugglingAnomalies(headers RawHeaders, anomalies *[]Anomaly) {
	clValues := headers.Values("Content-Length")
	teValues := headers.Values("Transfer-Encoding")

	hasCL := len(clValues) > 0
	hasTE := len(teValues) > 0

	// CL/TE conflict.
	if hasCL && hasTE {
		*anomalies = append(*anomalies, Anomaly{
			Type:   AnomalyCLTE,
			Detail: "both Content-Length and Transfer-Encoding headers present",
		})
	}

	// Duplicate Content-Length with different values.
	if len(clValues) > 1 {
		unique := make(map[string]struct{})
		for _, v := range clValues {
			unique[strings.TrimSpace(v)] = struct{}{}
		}
		if len(unique) > 1 {
			*anomalies = append(*anomalies, Anomaly{
				Type:   AnomalyDuplicateCL,
				Detail: fmt.Sprintf("multiple Content-Length headers with different values: %v", clValues),
			})
		}
	}

	// Check Transfer-Encoding values — validate each token in comma-separated
	// lists per RFC 7230. Standard tokens: chunked, compress, deflate, gzip, identity.
	for _, te := range teValues {
		for _, rawToken := range strings.Split(te, ",") {
			token := strings.ToLower(strings.TrimSpace(rawToken))
			if token == "" {
				continue
			}
			if token != "chunked" && token != "identity" && token != "gzip" && token != "compress" && token != "deflate" {
				*anomalies = append(*anomalies, Anomaly{
					Type:   AnomalyInvalidTE,
					Detail: fmt.Sprintf("non-standard Transfer-Encoding token %q in header value %q", token, te),
				})
			}
		}
	}

	// Check for TE obfuscation using raw (pre-OWS-trim) values.
	detectTEObfuscation(headers, anomalies)

	// Multiple Transfer-Encoding headers.
	if len(teValues) > 1 {
		*anomalies = append(*anomalies, Anomaly{
			Type:   AnomalyAmbiguousTE,
			Detail: fmt.Sprintf("multiple Transfer-Encoding headers: %v", teValues),
		})
	}
}

// detectTEObfuscation checks Transfer-Encoding headers for suspicious whitespace.
// Only flags trailing OWS after the value or tab characters — the standard single
// leading space after the colon (normal OWS) is NOT flagged.
func detectTEObfuscation(headers RawHeaders, anomalies *[]Anomaly) {
	for _, hdr := range headers {
		if !strings.EqualFold(hdr.Name, "transfer-encoding") {
			continue
		}
		if hdr.RawValue == "" {
			continue
		}
		raw := hdr.RawValue
		trimmedRight := strings.TrimRight(raw, " \t")
		if len(trimmedRight) != len(raw) || strings.ContainsRune(raw, '\t') {
			*anomalies = append(*anomalies, Anomaly{
				Type:   AnomalyAmbiguousTE,
				Detail: fmt.Sprintf("Transfer-Encoding value has suspicious whitespace: %q", raw),
			})
		}
	}
}

// hasChunkedTE reports whether the Transfer-Encoding header value contains
// an exact "chunked" token. It splits by comma, trims whitespace, and performs
// case-insensitive comparison to avoid matching invalid values like "xchunked".
func hasChunkedTE(te string) bool {
	for _, token := range strings.Split(te, ",") {
		if strings.EqualFold(strings.TrimSpace(token), "chunked") {
			return true
		}
	}
	return false
}

// shouldClose determines if the connection should be closed after this message.
func shouldClose(headers RawHeaders, proto string) bool {
	if hasConnectionToken(headers, "close") {
		return true
	}

	// HTTP/1.0 defaults to close unless Connection: keep-alive.
	if proto == "HTTP/1.0" {
		return !hasConnectionToken(headers, "keep-alive")
	}

	// HTTP/1.1 defaults to keep-alive.
	return false
}

// resolveRequestBody creates an appropriate body reader for a request.
// Chunked encoding is decoded (chunk markers stripped) so the caller receives
// plain body data ready for forwarding. Raw bytes for recording are captured
// separately via the captureWriter in ParseRequest.
//
// memoryCap caps the memory-mode RawBody capture. Zero means use the package
// default (MaxRawCaptureSize); spill-mode capture honors the spill MaxSize
// instead (USK-769 / USK-772).
func resolveRequestBody(r *bufio.Reader, headers RawHeaders, proto string, memoryCap int64) io.Reader {
	// chunked Transfer-Encoding: decode the chunked body to plain data.
	// HTTP/1.0 does not use chunked TE.
	// Check ALL TE header values to avoid smuggling via multiple TE headers.
	if proto != "HTTP/1.0" {
		for _, te := range headers.Values("Transfer-Encoding") {
			if hasChunkedTE(te) {
				return newDechunkedReaderWithCap(r, memoryCap)
			}
		}
	}

	// Content-Length present: read exactly that many bytes.
	if cl := headers.Get("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			// Invalid Content-Length: return empty body.
			return newIdentityBodyReaderWithCap(io.LimitReader(r, 0), memoryCap)
		}
		return newIdentityBodyReaderWithCap(io.LimitReader(r, n), memoryCap)
	}

	// No Content-Length, no chunked TE.
	// For requests, no body is assumed (unlike responses which use EOF).
	return newIdentityBodyReaderWithCap(io.LimitReader(r, 0), memoryCap)
}

// resolveResponseBody creates an appropriate body reader for a response.
// Chunked encoding is decoded (chunk markers stripped) so the caller receives
// plain body data ready for forwarding.
//
// memoryCap mirrors resolveRequestBody.
func resolveResponseBody(r *bufio.Reader, headers RawHeaders, proto string, statusCode int, memoryCap int64) io.Reader {
	// 1xx, 204, 304 responses have no body.
	if (statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 304 {
		return newIdentityBodyReaderWithCap(io.LimitReader(r, 0), memoryCap)
	}

	// chunked Transfer-Encoding: decode to plain data.
	// Check ALL TE header values to avoid smuggling via multiple TE headers.
	if proto != "HTTP/1.0" {
		for _, te := range headers.Values("Transfer-Encoding") {
			if hasChunkedTE(te) {
				return newDechunkedReaderWithCap(r, memoryCap)
			}
		}
	}

	// Content-Length.
	if cl := headers.Get("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			return newIdentityBodyReaderWithCap(io.LimitReader(r, 0), memoryCap)
		}
		return newIdentityBodyReaderWithCap(io.LimitReader(r, n), memoryCap)
	}

	// HTTP/1.0 or Connection: close: body ends at EOF.
	if proto == "HTTP/1.0" || shouldClose(headers, proto) {
		return newIdentityBodyReaderWithCap(r, memoryCap)
	}

	// HTTP/1.1 with no Content-Length and no chunked TE: no body.
	return newIdentityBodyReaderWithCap(io.LimitReader(r, 0), memoryCap)
}

// identityBodyReader wraps a body io.Reader and tees the bytes it produces
// into a bodyCaptureSink so the consumer can retrieve the on-wire body bytes
// after the body has been fully drained. Used for Content-Length and
// EOF-delimited (HTTP/1.0 / Connection: close) bodies.
//
// For identity bodies the dechunked semantic body and the on-wire RawBody are
// identical, but the tee preserves the property that RawBody is always
// available — uniformly across chunked and identity paths — so opaque
// send paths can always re-emit RawBody.
//
// USK-772: the sink supports memory-then-disk-spill so multi-MiB bodies can be
// captured without losing wire fidelity to the MaxRawCaptureSize cap. Spill is
// configured by the channel layer via EnableRawBodySpill before drain.
type identityBodyReader struct {
	r          io.Reader
	rawCapture *bodyCaptureSink
}

// newIdentityBodyReaderWithCap constructs an identityBodyReader whose body
// capture sink is bounded by memoryCap. Zero memoryCap falls back to
// MaxRawCaptureSize at write time.
func newIdentityBodyReaderWithCap(r io.Reader, memoryCap int64) *identityBodyReader {
	return &identityBodyReader{r: r, rawCapture: newBodyCaptureSinkWithCap(memoryCap)}
}

// EnableRawBodySpill installs the disk-spill knobs on the body capture sink.
// Call before the first Read to allow large bodies to spill to disk above
// threshold while preserving the RawBody wire-fidelity contract.
func (ir *identityBodyReader) EnableRawBodySpill(dir, prefix string, threshold, maxSize int64) {
	if ir == nil || ir.rawCapture == nil {
		return
	}
	ir.rawCapture.enableSpill(rawBodySpillConfig{
		dir:       dir,
		prefix:    prefix,
		threshold: threshold,
		maxSize:   maxSize,
	})
}

// Read implements io.Reader.
func (ir *identityBodyReader) Read(p []byte) (int, error) {
	n, err := ir.r.Read(p)
	if n > 0 {
		ir.rawCapture.write(p[:n])
	}
	return n, err
}

// RawBody returns the on-wire body bytes captured during reads when the body
// fit in memory. Returns nil when the sink spilled to disk (use
// RawBodyBuffer for the disk-backed path). Call after the body has been
// fully drained.
func (ir *identityBodyReader) RawBody() []byte {
	if ir.rawCapture == nil {
		return nil
	}
	return ir.rawCapture.bytes()
}

// RawBodyBuffer returns the disk-backed bodybuf when the body crossed the
// spill threshold during capture. Returns nil otherwise (use RawBody for the
// memory path). The bodybuf carries one outstanding Retain at this point;
// the caller assumes ownership.
func (ir *identityBodyReader) RawBodyBuffer() *bodybuf.BodyBuffer {
	if ir.rawCapture == nil {
		return nil
	}
	return ir.rawCapture.buffer()
}

// RawBodyTruncated reports whether captured RawBody was capped (at
// MaxRawCaptureSize for memory mode, or maxSize for spill mode).
func (ir *identityBodyReader) RawBodyTruncated() bool {
	if ir.rawCapture == nil {
		return false
	}
	return ir.rawCapture.isTruncated()
}
