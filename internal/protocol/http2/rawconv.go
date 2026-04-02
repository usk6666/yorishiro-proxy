package http2

import (
	"bytes"
	"io"
	gohttp "net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/protocol/http/parser"
	"github.com/usk6666/yorishiro-proxy/internal/protocol/httputil"
)

// goHTTPRequestToRaw converts a *net/http.Request to a parser.RawRequest.
// This is a local helper for the http2 package intercept pipeline,
// replacing the former httputil.HTTPRequestToRaw bridge function.
func goHTTPRequestToRaw(goReq *gohttp.Request, bodyBytes []byte) *parser.RawRequest {
	headers := httpHeaderToRawHeaders(goReq.Header)
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
	// inconsistent.
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

// rawRequestToGoHTTP converts a parser.RawRequest to a *net/http.Request.
// This is a local helper for the http2 package intercept pipeline,
// replacing the former httputil.RawRequestToHTTP bridge function.
func rawRequestToGoHTTP(req *parser.RawRequest, bodyBytes []byte) *gohttp.Request {
	if req == nil {
		return nil
	}

	u, err := url.ParseRequestURI(req.RequestURI)
	if err != nil {
		u = &url.URL{Path: req.RequestURI}
	}

	host := req.Headers.Get("Host")
	headers := rawHeadersToHTTPHeader(req.Headers)
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

// goHTTPResponseToRaw converts a *net/http.Response to a parser.RawResponse.
// This is a local helper for the http2 package intercept pipeline,
// replacing the former httputil.HTTPResponseToRaw bridge function.
func goHTTPResponseToRaw(resp *gohttp.Response, bodyBytes []byte) *parser.RawResponse {
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
		Headers:    httpHeaderToRawHeaders(resp.Header),
		Body:       io.NopCloser(bytes.NewReader(bodyBytes)),
	}
}

// rawResponseToGoHTTP converts a parser.RawResponse to a *net/http.Response.
// This is a local helper for the http2 package intercept pipeline,
// replacing the former httputil.RawResponseToHTTP bridge function.
func rawResponseToGoHTTP(resp *parser.RawResponse, bodyBytes []byte) *gohttp.Response {
	if resp == nil {
		return nil
	}

	headers := rawHeadersToHTTPHeader(resp.Headers)

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
