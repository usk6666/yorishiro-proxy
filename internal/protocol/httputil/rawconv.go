package httputil

import (
	"bytes"
	"io"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
)

// RawRequestToHTTP converts a parser.RawRequest to a *net/http.Request.
// This is used at subsystem boundaries where the API still expects
// *net/http.Request (e.g., plugin hooks, intercept modifications).
//
// The Body field is set from the provided bodyBytes parameter rather than
// from req.Body, because req.Body may have been fully consumed during
// upstream forwarding.
func RawRequestToHTTP(req *parser.RawRequest, bodyBytes []byte) *gohttp.Request {
	if req == nil {
		return nil
	}

	// Parse the request URI.
	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		// Fallback: use the raw URI as-is.
		u = &url.URL{Path: req.RequestURI}
	}

	// Extract Host from headers.
	host := req.Headers.Get("Host")

	// Build gohttp.Header from RawHeaders.
	headers := RawHeadersToHTTPHeader(req.Headers)

	// Go's net/http strips Host from Request.Header and stores it in Request.Host.
	// Remove it from headers to match that convention.
	delete(headers, "Host")

	var body io.ReadCloser
	if len(bodyBytes) > 0 {
		body = io.NopCloser(bytes.NewReader(bodyBytes))
	} else {
		body = gohttp.NoBody
	}

	// Fall back to URL host when the Host header is absent (absolute-form URI).
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

	// Parse proto version.
	if strings.HasPrefix(req.Proto, "HTTP/") {
		parts := strings.Split(req.Proto[5:], ".")
		if len(parts) == 2 {
			httpReq.ProtoMajor, _ = strconv.Atoi(parts[0])
			httpReq.ProtoMinor, _ = strconv.Atoi(parts[1])
		}
	}

	return httpReq
}

// RawResponseToHTTP converts a parser.RawResponse to a *net/http.Response.
// This is used at subsystem boundaries where the API still expects
// *net/http.Response (e.g., ReceiveVariantParams, plugin hooks, intercept
// modifications, output filter).
//
// The Body field is set from the provided bodyBytes parameter rather than
// from resp.Body, because resp.Body may have been fully consumed.
func RawResponseToHTTP(resp *parser.RawResponse, bodyBytes []byte) *gohttp.Response {
	if resp == nil {
		return nil
	}

	headers := RawHeadersToHTTPHeader(resp.Headers)

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

	// Parse proto version.
	if strings.HasPrefix(resp.Proto, "HTTP/") {
		parts := strings.Split(resp.Proto[5:], ".")
		if len(parts) == 2 {
			httpResp.ProtoMajor, _ = strconv.Atoi(parts[0])
			httpResp.ProtoMinor, _ = strconv.Atoi(parts[1])
		}
	}

	return httpResp
}

// HTTPResponseToRaw converts a *net/http.Response back to a parser.RawResponse.
// This is used after subsystem boundaries modify a *net/http.Response (e.g.,
// plugin hooks, intercept modifications) and the handler needs the result as
// a parser.RawResponse.
//
// The bodyBytes parameter contains the response body bytes. The caller is
// responsible for reading the body from resp before calling this function.
func HTTPResponseToRaw(resp *gohttp.Response, bodyBytes []byte) *parser.RawResponse {
	if resp == nil {
		return nil
	}

	// Preserve the original status string from resp.Status (e.g. "200 OK")
	// which may include a custom reason phrase. Only fall back to StatusText
	// when resp.Status is empty.
	status := resp.Status
	if status == "" {
		status = FormatStatus(resp.StatusCode)
	}

	raw := &parser.RawResponse{
		Proto:      resp.Proto,
		StatusCode: resp.StatusCode,
		Status:     status,
		Headers:    HTTPHeaderToRawHeaders(resp.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}

	return raw
}

// HTTPRequestToRaw converts a *net/http.Request back to a parser.RawRequest.
func HTTPRequestToRaw(goReq *gohttp.Request, bodyBytes []byte) *parser.RawRequest {
	headers := HTTPHeaderToRawHeaders(goReq.Header)
	// Re-inject Host header (Go strips it from Header).
	if goReq.Host != "" {
		headers.Set("Host", goReq.Host)
	}
	// Use the full absolute URL when scheme and host are present (forward
	// proxy style). RequestURI() only returns path+query which loses the
	// host information needed for forward proxy requests.
	reqURI := goReq.URL.RequestURI()
	if goReq.URL.Scheme != "" && goReq.URL.Host != "" {
		reqURI = goReq.URL.String()
	}
	// Sync Content-Length and Transfer-Encoding headers with the actual body
	// bytes. After plugin/intercept modification the original headers may be
	// inconsistent (e.g. stale Content-Length or TE:chunked still present).
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
