package http

// compat_test.go provides backward-compatible shims so that existing test files
// compile after the net/http removal rewrite (USK-494). These shims delegate
// to the new implementations using local conversion helpers.
//
// Test files are allowed to import net/http (for httptest, test servers, etc.).

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/codec/http1/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
	"github.com/usk6666/yorishiro-proxy/internal/proxy"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// captureReader is a test-only shim preserving the old captureReader type
// that some tests still reference.
type captureReader struct {
	r   io.Reader
	buf bytes.Buffer
}

func (cr *captureReader) Read(p []byte) (int, error) {
	n, err := cr.r.Read(p)
	if n > 0 && cr.buf.Len() < maxRawCaptureSize {
		remaining := maxRawCaptureSize - cr.buf.Len()
		if n <= remaining {
			cr.buf.Write(p[:n])
		} else {
			cr.buf.Write(p[:remaining])
		}
	}
	return n, err
}

func (cr *captureReader) Bytes() []byte {
	if cr.buf.Len() == 0 {
		return nil
	}
	out := make([]byte, cr.buf.Len())
	copy(out, cr.buf.Bytes())
	return out
}

func (cr *captureReader) Reset() {
	cr.buf.Reset()
}

// normalizeRequestURL is a test compatibility shim that mirrors the logic of
// parseRequestURL from handler.go, but operates on *gohttp.Request.
func normalizeRequestURL(ctx context.Context, req *gohttp.Request) {
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if target, ok := proxy.ForwardTargetFromContext(ctx); ok {
		req.URL.Host = target
		req.Host = target
	}
}

// readAndCaptureRequestBody is a test compatibility shim.
func readAndCaptureRequestBody(req *gohttp.Request, logger interface{}) requestBodyResult {
	if req.Body == nil {
		return requestBodyResult{}
	}
	fullBody, _ := io.ReadAll(req.Body)
	req.Body = io.NopCloser(bytes.NewReader(fullBody))
	return requestBodyResult{recordBody: fullBody}
}

// extractRawRequest is a test compatibility shim.
func extractRawRequest(capture *captureReader, captureStart int, reader *bufio.Reader) []byte {
	if capture == nil {
		return nil
	}
	captureEnd := capture.buf.Len()
	buffered := reader.Buffered()
	rawEnd := captureEnd - buffered
	if rawEnd > captureStart && captureStart < capture.buf.Len() {
		raw := make([]byte, rawEnd-captureStart)
		copy(raw, capture.buf.Bytes()[captureStart:rawEnd])
		return raw
	}
	return nil
}

// testGoHTTPHeaderToRawHeaders converts gohttp.Header to parser.RawHeaders for test use.
func testGoHTTPHeaderToRawHeaders(h gohttp.Header) parser.RawHeaders {
	if h == nil {
		return nil
	}
	var rh parser.RawHeaders
	for name, vals := range h {
		for _, v := range vals {
			rh = append(rh, parser.RawHeader{Name: name, Value: v})
		}
	}
	return rh
}

// testRawHeadersToGoHTTPHeader converts parser.RawHeaders to gohttp.Header for test use.
func testRawHeadersToGoHTTPHeader(rh parser.RawHeaders) gohttp.Header {
	if rh == nil {
		return make(gohttp.Header)
	}
	h := make(gohttp.Header, len(rh))
	for _, hdr := range rh {
		h.Add(hdr.Name, hdr.Value)
	}
	return h
}

// testGoHTTPRequestToRaw converts a *gohttp.Request to a *parser.RawRequest for test use.
func testGoHTTPRequestToRaw(goReq *gohttp.Request, bodyBytes []byte) *parser.RawRequest {
	headers := testGoHTTPHeaderToRawHeaders(goReq.Header)
	if goReq.Host != "" {
		headers.Set("Host", goReq.Host)
	}
	reqURI := goReq.URL.RequestURI()
	if goReq.URL.Scheme != "" && goReq.URL.Host != "" {
		reqURI = goReq.URL.String()
	}
	headers.Del("Transfer-Encoding")
	if len(bodyBytes) > 0 {
		headers.Set("Content-Length", strconv.Itoa(len(bodyBytes)))
	} else {
		headers.Del("Content-Length")
	}
	return &parser.RawRequest{
		Method:     goReq.Method,
		RequestURI: reqURI,
		Proto:      goReq.Proto,
		Headers:    headers,
		Body:       bytes.NewReader(bodyBytes),
	}
}

// testRawRequestToGoHTTP converts a *parser.RawRequest to a *gohttp.Request for test use.
func testRawRequestToGoHTTP(req *parser.RawRequest, bodyBytes []byte) *gohttp.Request {
	if req == nil {
		return nil
	}
	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		u = &url.URL{Path: req.RequestURI}
	}
	host := req.Headers.Get("Host")
	headers := testRawHeadersToGoHTTPHeader(req.Headers)
	delete(headers, "Host")

	var body io.ReadCloser
	if len(bodyBytes) > 0 {
		body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		body = gohttp.NoBody
	}
	if host == "" {
		host = u.Host
	}
	httpReq := &gohttp.Request{
		Method:        req.Method,
		URL:           u,
		Proto:         req.Proto,
		Host:          host,
		Header:        headers,
		Body:          body,
		ContentLength: int64(len(bodyBytes)),
	}
	if strings.HasPrefix(req.Proto, "HTTP/") {
		parts := strings.Split(req.Proto[5:], ".")
		if len(parts) == 2 {
			httpReq.ProtoMajor, _ = strconv.Atoi(parts[0])
			httpReq.ProtoMinor, _ = strconv.Atoi(parts[1])
		}
	}
	return httpReq
}

// testGoHTTPResponseToRaw converts a *gohttp.Response to a *parser.RawResponse for test use.
func testGoHTTPResponseToRaw(resp *gohttp.Response, bodyBytes []byte) *parser.RawResponse {
	if resp == nil {
		return nil
	}
	status := resp.Status
	if status == "" {
		status = httputil.FormatStatus(resp.StatusCode)
	}
	return &parser.RawResponse{
		Proto:      resp.Proto,
		StatusCode: resp.StatusCode,
		Status:     status,
		Headers:    testGoHTTPHeaderToRawHeaders(resp.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}
}

// testRawResponseToGoHTTP converts a *parser.RawResponse to a *gohttp.Response for test use.
func testRawResponseToGoHTTP(resp *parser.RawResponse, bodyBytes []byte) *gohttp.Response {
	if resp == nil {
		return nil
	}
	headers := testRawHeadersToGoHTTPHeader(resp.Headers)
	var body io.ReadCloser
	if len(bodyBytes) > 0 {
		body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		body = gohttp.NoBody
	}
	httpResp := &gohttp.Response{
		Status:        resp.Status,
		StatusCode:    resp.StatusCode,
		Proto:         resp.Proto,
		Header:        headers,
		Body:          body,
		ContentLength: int64(len(bodyBytes)),
	}
	if strings.HasPrefix(resp.Proto, "HTTP/") {
		parts := strings.Split(resp.Proto[5:], ".")
		if len(parts) == 2 {
			httpResp.ProtoMajor, _ = strconv.Atoi(parts[0])
			httpResp.ProtoMinor, _ = strconv.Atoi(parts[1])
		}
	}
	return httpResp
}

// applyInterceptModifications is a test compatibility shim.
// It converts gohttp types to raw types, applies modifications, and converts back.
func applyInterceptModifications(req *gohttp.Request, action intercept.InterceptAction, originalBody []byte) (*gohttp.Request, error) {
	rawReq := testGoHTTPRequestToRaw(req, originalBody)
	modRaw, modBody, modURL, err := httputil.ApplyRequestModifications(rawReq, originalBody, action)
	if err != nil {
		return req, err
	}
	modReq := testRawRequestToGoHTTP(modRaw, modBody)
	if modURL != nil {
		modReq.URL = modURL
	}
	return modReq, nil
}

// applyResponseModifications is a test compatibility shim.
// It converts gohttp types to raw types, applies modifications, and converts back.
func applyResponseModifications(resp *gohttp.Response, action intercept.InterceptAction, body []byte) (*gohttp.Response, []byte, error) {
	rawResp := testGoHTTPResponseToRaw(resp, body)
	modRaw, modBody, err := httputil.ApplyResponseModifications(rawResp, action, body)
	if err != nil {
		return resp, body, err
	}
	modResp := testRawResponseToGoHTTP(modRaw, modBody)
	return modResp, modBody, nil
}

// snapshotRequest is a test compatibility shim using gohttp.Header.
func snapshotRequest(headers gohttp.Header, body []byte) requestSnapshot {
	return snapshotRawRequest(testGoHTTPHeaderToRawHeaders(headers), body)
}

// requestModifiedCompat is a test compatibility shim using gohttp.Header.
func requestModifiedCompat(snap requestSnapshot, currentHeaders gohttp.Header, currentBody []byte) bool {
	return requestModified(snap, testGoHTTPHeaderToRawHeaders(currentHeaders), currentBody)
}

// snapshotResponse is a test compatibility shim using gohttp.Header.
func snapshotResponse(statusCode int, headers gohttp.Header, body []byte) responseSnapshot {
	return snapshotRawResponse(statusCode, testGoHTTPHeaderToRawHeaders(headers), body)
}

// responseModified is a test compatibility shim using gohttp.Header.
func responseModified(snap responseSnapshot, currentStatusCode int, currentHeaders gohttp.Header, currentBody []byte) bool {
	return httputil.ResponseModified(
		httputil.ResponseSnapshot{
			StatusCode: snap.statusCode,
			Headers:    snap.headers,
			Body:       snap.body,
		},
		currentStatusCode,
		testGoHTTPHeaderToRawHeaders(currentHeaders),
		currentBody,
	)
}

// headersModified is a test compatibility shim using gohttp.Header.
func headersModified(a, b gohttp.Header) bool {
	return httputil.HeadersModified(
		testGoHTTPHeaderToRawHeaders(a),
		testGoHTTPHeaderToRawHeaders(b),
	)
}

// isWebSocketUpgrade is a test compatibility shim.
func isWebSocketUpgrade(req *gohttp.Request) bool {
	return isWebSocketUpgradeRaw(testGoHTTPHeaderToRawHeaders(req.Header))
}

// isSSEResponse is a test compatibility shim.
func isSSEResponse(resp *gohttp.Response) bool {
	return isSSEResponseRaw(testGoHTTPResponseToRaw(resp, nil))
}

// writeSSEResponseHeaders is a test compatibility shim.
func writeSSEResponseHeaders(conn interface{}, resp *gohttp.Response) error {
	netConn, ok := conn.(net.Conn)
	if !ok {
		return fmt.Errorf("writeSSEResponseHeaders: conn is not net.Conn")
	}
	rawResp := testGoHTTPResponseToRaw(resp, nil)
	return writeRawResponseHeaders(netConn, rawResp)
}

// sseEventToHTTPResponse is a test compatibility shim.
func sseEventToHTTPResponse(event *SSEEvent) (*gohttp.Response, []byte) {
	rawResp, body := sseEventToRawResponse(event)
	goResp := testRawResponseToGoHTTP(rawResp, body)
	return goResp, body
}

// applyHTTPResponseToSSEEvent is a test compatibility shim.
func applyHTTPResponseToSSEEvent(original *SSEEvent, resp *gohttp.Response, body []byte) *SSEEvent {
	rawResp := testGoHTTPResponseToRaw(resp, body)
	return applyRawResponseToSSEEvent(original, rawResp, body)
}

// goRequestToRaw converts a *gohttp.Request to a *parser.RawRequest for test use.
func goRequestToRaw(req *gohttp.Request) *parser.RawRequest {
	return testGoHTTPRequestToRaw(req, nil)
}

// goResponseToRaw converts a *gohttp.Response to a *parser.RawResponse for test use.
func goResponseToRaw(resp *gohttp.Response, body []byte) *parser.RawResponse {
	return testGoHTTPResponseToRaw(resp, body)
}

// testRawResponse creates a *parser.RawResponse for test use from a status code
// and gohttp.Header. This avoids constructing a full *gohttp.Response in tests
// that only need to pass a response to receiveRecordParams.
func testRawResponse(statusCode int, headers gohttp.Header) *parser.RawResponse {
	return &parser.RawResponse{
		StatusCode: statusCode,
		Headers:    testGoHTTPHeaderToRawHeaders(headers),
	}
}

// readRawResponse is a test compatibility shim for the old readRawResponse function.
func readRawResponse(conn net.Conn) (rawResponse []byte, resp *gohttp.Response, respBody []byte, err error) {
	rawResp, rawParsed, rawBody, readErr := readRawResponseFromConn(conn)
	if readErr != nil {
		return rawResp, nil, rawBody, readErr
	}
	if rawParsed != nil {
		goResp := testRawResponseToGoHTTP(rawParsed, rawBody)
		return rawResp, goResp, rawBody, nil
	}
	return rawResp, nil, rawBody, nil
}
