package parser

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Limits to prevent resource exhaustion.
const (
	// maxRawCaptureSize is the maximum number of bytes captured in RawBytes.
	// Matches the existing captureReader limit in the HTTP handler.
	maxRawCaptureSize = 2 << 20 // 2 MiB

	// maxRequestLineSize limits the request/status line length.
	maxRequestLineSize = 8192 // 8 KiB

	// maxHeaderSize limits the total header section size (including all lines).
	// Set above maxRawCaptureSize so raw bytes truncation is tested before
	// header parsing fails outright.
	maxHeaderSize = 4 << 20 // 4 MiB

	// maxHeaderCount limits the number of individual header lines.
	maxHeaderCount = 10000
)

// captureWriter records bytes written to it up to maxRawCaptureSize.
type captureWriter struct {
	buf       bytes.Buffer
	truncated bool
}

func (cw *captureWriter) write(p []byte) {
	if cw.truncated {
		return
	}
	remaining := maxRawCaptureSize - cw.buf.Len()
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

// ParseRequest reads and parses an HTTP/1.x request from r.
// It returns the parsed request including anomaly information.
// Invalid or malformed requests are parsed on a best-effort basis
// with anomalies recorded rather than returning errors.
//
// Errors are returned only for unrecoverable I/O failures or when
// no meaningful request can be extracted at all (e.g., connection closed).
func ParseRequest(r *bufio.Reader) (*RawRequest, error) {
	cw := &captureWriter{}

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

	// Determine body reader.
	req.Body = resolveRequestBody(r, req.Headers, req.Proto)

	// Set connection close semantics.
	req.Close = shouldClose(req.Headers, req.Proto)

	// Finalize raw bytes capture.
	req.RawBytes = cw.bytes()
	req.Truncated = cw.truncated

	return req, nil
}

// ParseResponse reads and parses an HTTP/1.x response from r.
// Like ParseRequest, malformed responses are parsed on a best-effort basis
// with anomalies recorded.
func ParseResponse(r *bufio.Reader) (*RawResponse, error) {
	cw := &captureWriter{}

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
	resp.Body = resolveResponseBody(r, resp.Headers, resp.Proto, resp.StatusCode)

	// Finalize raw bytes capture.
	resp.RawBytes = cw.bytes()
	resp.Truncated = cw.truncated

	return resp, nil
}

// parseRequestLine reads the request line (e.g., "GET /path HTTP/1.1\r\n").
func parseRequestLine(r *bufio.Reader, cw *captureWriter) (method, requestURI, proto string, err error) {
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
func parseStatusLine(r *bufio.Reader, cw *captureWriter) (proto string, statusCode int, status string, err error) {
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
func readLine(r *bufio.Reader, cw *captureWriter, maxLen int) (string, error) {
	var line []byte
	for {
		segment, err := r.ReadSlice('\n')
		cw.write(segment)

		line = append(line, segment...)
		if err == nil {
			// Found \n — also enforce maxLen for single-read success
			// (bufio buffer may be larger than maxLen).
			if len(line) > maxLen {
				return "", fmt.Errorf("line exceeds maximum length %d", maxLen)
			}
			break
		}
		if err == bufio.ErrBufferFull {
			// Line is longer than bufio buffer; keep reading.
			if len(line) > maxLen {
				return "", fmt.Errorf("line exceeds maximum length %d", maxLen)
			}
			continue
		}
		// I/O error or EOF.
		if len(line) > 0 {
			// Return what we have on EOF (partial line).
			break
		}
		return "", err
	}

	// Trim CRLF or LF.
	s := string(line)
	s = strings.TrimRight(s, "\r\n")
	return s, nil
}

// parseHeaders parses HTTP headers until the blank line terminator.
// It handles obs-fold (continuation lines starting with SP or HT).
func parseHeaders(r *bufio.Reader, cw *captureWriter) (RawHeaders, []Anomaly, error) {
	var headers RawHeaders
	var anomalies []Anomaly
	var totalSize int

	for {
		if len(headers) >= maxHeaderCount {
			return headers, anomalies, fmt.Errorf("header count exceeds limit %d", maxHeaderCount)
		}

		line, err := readLine(r, cw, maxHeaderSize)
		if err != nil {
			return headers, anomalies, fmt.Errorf("read header line: %w", err)
		}

		totalSize += len(line) + 2 // approximate +2 for CRLF
		if totalSize > maxHeaderSize {
			return headers, anomalies, fmt.Errorf("header section exceeds maximum size %d", maxHeaderSize)
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

	// Check Transfer-Encoding values.
	for _, te := range teValues {
		normalized := strings.ToLower(strings.TrimSpace(te))
		if normalized != "chunked" && normalized != "identity" && normalized != "" {
			*anomalies = append(*anomalies, Anomaly{
				Type:   AnomalyInvalidTE,
				Detail: fmt.Sprintf("non-standard Transfer-Encoding value: %q", te),
			})
		}
	}

	// Check for TE obfuscation using raw (pre-OWS-trim) values.
	for _, hdr := range headers {
		if strings.ToLower(hdr.Name) != "transfer-encoding" {
			continue
		}
		if hdr.RawValue != "" {
			// RawValue is set only when OWS was trimmed, indicating whitespace padding.
			*anomalies = append(*anomalies, Anomaly{
				Type:   AnomalyAmbiguousTE,
				Detail: fmt.Sprintf("Transfer-Encoding value has surrounding whitespace: %q", hdr.RawValue),
			})
		}
	}

	// Multiple Transfer-Encoding headers.
	if len(teValues) > 1 {
		*anomalies = append(*anomalies, Anomaly{
			Type:   AnomalyAmbiguousTE,
			Detail: fmt.Sprintf("multiple Transfer-Encoding headers: %v", teValues),
		})
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
	conn := strings.ToLower(headers.Get("Connection"))

	if strings.Contains(conn, "close") {
		return true
	}

	// HTTP/1.0 defaults to close unless Connection: keep-alive.
	if proto == "HTTP/1.0" {
		return !strings.Contains(conn, "keep-alive")
	}

	// HTTP/1.1 defaults to keep-alive.
	return false
}

// resolveRequestBody creates an appropriate body reader for a request.
// The body is NOT decoded — chunked encoding is streamed as-is.
func resolveRequestBody(r *bufio.Reader, headers RawHeaders, proto string) io.Reader {
	// chunked Transfer-Encoding: stream the raw chunked body as-is (no dechunking).
	// HTTP/1.0 does not use chunked TE.
	if hasChunkedTE(headers.Get("Transfer-Encoding")) && proto != "HTTP/1.0" {
		return newRawChunkedReader(r)
	}

	// Content-Length present: read exactly that many bytes.
	if cl := headers.Get("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			// Invalid Content-Length: return empty body.
			return io.LimitReader(r, 0)
		}
		return io.LimitReader(r, n)
	}

	// No Content-Length, no chunked TE.
	// For requests, no body is assumed (unlike responses which use EOF).
	return io.LimitReader(r, 0)
}

// resolveResponseBody creates an appropriate body reader for a response.
// The body is NOT decoded — chunked encoding is streamed as-is.
func resolveResponseBody(r *bufio.Reader, headers RawHeaders, proto string, statusCode int) io.Reader {
	// 1xx, 204, 304 responses have no body.
	if (statusCode >= 100 && statusCode < 200) || statusCode == 204 || statusCode == 304 {
		return io.LimitReader(r, 0)
	}

	// chunked Transfer-Encoding: stream as-is.
	if hasChunkedTE(headers.Get("Transfer-Encoding")) && proto != "HTTP/1.0" {
		return newRawChunkedReader(r)
	}

	// Content-Length.
	if cl := headers.Get("Content-Length"); cl != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(cl), 10, 64)
		if err != nil || n < 0 {
			return io.LimitReader(r, 0)
		}
		return io.LimitReader(r, n)
	}

	// HTTP/1.0 or Connection: close: body ends at EOF.
	if proto == "HTTP/1.0" || shouldClose(headers, proto) {
		return r
	}

	// HTTP/1.1 with no Content-Length and no chunked TE: no body.
	return io.LimitReader(r, 0)
}
