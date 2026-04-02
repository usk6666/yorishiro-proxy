package http

// compat_test.go provides backward-compatible shims so that existing test files
// compile after the net/http removal rewrite (USK-494). These shims delegate
// to the new implementations or to httputil conversion helpers.
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

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
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

// applyInterceptModifications is a test compatibility shim.
// It converts gohttp types to raw types, applies modifications, and converts back.
func applyInterceptModifications(req *gohttp.Request, action intercept.InterceptAction, originalBody []byte) (*gohttp.Request, error) {
	rawReq := httputil.HTTPRequestToRaw(req, originalBody)
	modRaw, modBody, modURL, err := httputil.ApplyRequestModifications(rawReq, originalBody, action)
	if err != nil {
		return req, err
	}
	modReq := httputil.RawRequestToHTTP(modRaw, modBody)
	if modURL != nil {
		modReq.URL = modURL
	}
	return modReq, nil
}

// applyResponseModifications is a test compatibility shim.
// It converts gohttp types to raw types, applies modifications, and converts back.
func applyResponseModifications(resp *gohttp.Response, action intercept.InterceptAction, body []byte) (*gohttp.Response, []byte, error) {
	rawResp := httputil.HTTPResponseToRaw(resp, body)
	modRaw, modBody, err := httputil.ApplyResponseModifications(rawResp, action, body)
	if err != nil {
		return resp, body, err
	}
	modResp := httputil.RawResponseToHTTP(modRaw, modBody)
	return modResp, modBody, nil
}

// snapshotRequest is a test compatibility shim using gohttp.Header.
func snapshotRequest(headers gohttp.Header, body []byte) requestSnapshot {
	return snapshotRawRequest(httputil.HTTPHeaderToRawHeaders(headers), body)
}

// requestModifiedCompat is a test compatibility shim using gohttp.Header.
func requestModifiedCompat(snap requestSnapshot, currentHeaders gohttp.Header, currentBody []byte) bool {
	return requestModified(snap, httputil.HTTPHeaderToRawHeaders(currentHeaders), currentBody)
}

// snapshotResponse is a test compatibility shim using gohttp.Header.
func snapshotResponse(statusCode int, headers gohttp.Header, body []byte) responseSnapshot {
	return snapshotRawResponse(statusCode, httputil.HTTPHeaderToRawHeaders(headers), body)
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
		httputil.HTTPHeaderToRawHeaders(currentHeaders),
		currentBody,
	)
}

// headersModified is a test compatibility shim using gohttp.Header.
func headersModified(a, b gohttp.Header) bool {
	return httputil.HeadersModified(
		httputil.HTTPHeaderToRawHeaders(a),
		httputil.HTTPHeaderToRawHeaders(b),
	)
}

// isWebSocketUpgrade is a test compatibility shim.
func isWebSocketUpgrade(req *gohttp.Request) bool {
	return isWebSocketUpgradeRaw(httputil.HTTPHeaderToRawHeaders(req.Header))
}

// isSSEResponse is a test compatibility shim.
func isSSEResponse(resp *gohttp.Response) bool {
	return isSSEResponseRaw(httputil.HTTPResponseToRaw(resp, nil))
}

// writeSSEResponseHeaders is a test compatibility shim.
func writeSSEResponseHeaders(conn interface{}, resp *gohttp.Response) error {
	netConn, ok := conn.(net.Conn)
	if !ok {
		return fmt.Errorf("writeSSEResponseHeaders: conn is not net.Conn")
	}
	rawResp := httputil.HTTPResponseToRaw(resp, nil)
	return writeRawResponseHeaders(netConn, rawResp)
}

// sseEventToHTTPResponse is a test compatibility shim.
func sseEventToHTTPResponse(event *SSEEvent) (*gohttp.Response, []byte) {
	rawResp, body := sseEventToRawResponse(event)
	goResp := httputil.RawResponseToHTTP(rawResp, body)
	return goResp, body
}

// applyHTTPResponseToSSEEvent is a test compatibility shim.
func applyHTTPResponseToSSEEvent(original *SSEEvent, resp *gohttp.Response, body []byte) *SSEEvent {
	rawResp := httputil.HTTPResponseToRaw(resp, body)
	return applyRawResponseToSSEEvent(original, rawResp, body)
}

// goRequestToRaw converts a *gohttp.Request to a *parser.RawRequest for test use.
func goRequestToRaw(req *gohttp.Request) *parser.RawRequest {
	return httputil.HTTPRequestToRaw(req, nil)
}

// goResponseToRaw converts a *gohttp.Response to a *parser.RawResponse for test use.
func goResponseToRaw(resp *gohttp.Response, body []byte) *parser.RawResponse {
	return httputil.HTTPResponseToRaw(resp, body)
}

// testRawResponse creates a *parser.RawResponse for test use from a status code
// and gohttp.Header. This avoids constructing a full *gohttp.Response in tests
// that only need to pass a response to receiveRecordParams.
func testRawResponse(statusCode int, headers gohttp.Header) *parser.RawResponse {
	return &parser.RawResponse{
		StatusCode: statusCode,
		Headers:    httputil.HTTPHeaderToRawHeaders(headers),
	}
}

// readRawResponse is a test compatibility shim for the old readRawResponse function.
func readRawResponse(conn net.Conn) (rawResponse []byte, resp *gohttp.Response, respBody []byte, err error) {
	rawResp, rawParsed, rawBody, readErr := readRawResponseFromConn(conn)
	if readErr != nil {
		return rawResp, nil, rawBody, readErr
	}
	if rawParsed != nil {
		goResp := httputil.RawResponseToHTTP(rawParsed, rawBody)
		return rawResp, goResp, rawBody, nil
	}
	return rawResp, nil, rawBody, nil
}
