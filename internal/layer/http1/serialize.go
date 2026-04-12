package http1

import (
	"bytes"
	"fmt"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// serializeRequestLine writes "METHOD SP RequestURI SP Proto CRLF" to w.
func serializeRequestLine(w io.Writer, method, requestURI, proto string) error {
	if proto == "" {
		proto = "HTTP/1.1"
	}
	_, err := fmt.Fprintf(w, "%s %s %s\r\n", method, requestURI, proto)
	return err
}

// serializeStatusLine writes "Proto SP Status CRLF" to w.
// If status is empty, it is synthesized from statusCode.
func serializeStatusLine(w io.Writer, proto, status string, statusCode int) error {
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if status != "" {
		_, err := fmt.Fprintf(w, "%s %s\r\n", proto, status)
		return err
	}
	text := statusText(statusCode)
	if text == "" {
		text = "Unknown"
	}
	_, err := fmt.Fprintf(w, "%s %d %s\r\n", proto, statusCode, text)
	return err
}

// serializeHeaders writes headers in wire order to w, preserving OWS via
// RawValue. Writes the terminating CRLF after all headers.
func serializeHeaders(w io.Writer, headers parser.RawHeaders) error {
	var buf bytes.Buffer
	writeRawHeaders(&buf, headers)
	buf.WriteString("\r\n")
	_, err := w.Write(buf.Bytes())
	return err
}

// writeRawHeaders writes headers to buf, preserving wire order and OWS.
func writeRawHeaders(buf *bytes.Buffer, headers parser.RawHeaders) {
	for _, h := range headers {
		if h.RawValue != "" {
			buf.WriteString(h.Name)
			buf.WriteByte(':')
			buf.WriteString(h.RawValue)
		} else {
			buf.WriteString(h.Name)
			buf.WriteString(": ")
			buf.WriteString(h.Value)
		}
		buf.WriteString("\r\n")
	}
}

// serializeRequestHeader serializes a RawRequest's header section (request-line
// + headers + CRLF) into bytes. Body is NOT included.
func serializeRequestHeader(req *parser.RawRequest) []byte {
	var buf bytes.Buffer
	proto := req.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	buf.WriteString(req.Method)
	buf.WriteByte(' ')
	buf.WriteString(req.RequestURI)
	buf.WriteByte(' ')
	buf.WriteString(proto)
	buf.WriteString("\r\n")
	writeRawHeaders(&buf, req.Headers)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// serializeResponseHeader serializes a RawResponse's header section
// (status-line + headers + CRLF) into bytes. Body is NOT included.
func serializeResponseHeader(resp *parser.RawResponse) []byte {
	var buf bytes.Buffer
	proto := resp.Proto
	if proto == "" {
		proto = "HTTP/1.1"
	}
	if resp.Status != "" {
		fmt.Fprintf(&buf, "%s %s\r\n", proto, resp.Status)
	} else {
		text := statusText(resp.StatusCode)
		if text == "" {
			text = "Unknown"
		}
		fmt.Fprintf(&buf, "%s %d %s\r\n", proto, resp.StatusCode, text)
	}
	writeRawHeaders(&buf, resp.Headers)
	buf.WriteString("\r\n")
	return buf.Bytes()
}

// statusTextMap maps HTTP status codes to their reason phrases.
// Local lookup table to avoid depending on net/http or internal/protocol/httputil.
var statusTextMap = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	102: "Processing",
	103: "Early Hints",
	200: "OK",
	201: "Created",
	202: "Accepted",
	203: "Non-Authoritative Information",
	204: "No Content",
	205: "Reset Content",
	206: "Partial Content",
	207: "Multi-Status",
	208: "Already Reported",
	226: "IM Used",
	300: "Multiple Choices",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	305: "Use Proxy",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	402: "Payment Required",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	406: "Not Acceptable",
	407: "Proxy Authentication Required",
	408: "Request Timeout",
	409: "Conflict",
	410: "Gone",
	411: "Length Required",
	412: "Precondition Failed",
	413: "Content Too Large",
	414: "URI Too Long",
	415: "Unsupported Media Type",
	416: "Range Not Satisfiable",
	417: "Expectation Failed",
	418: "I'm a teapot",
	421: "Misdirected Request",
	422: "Unprocessable Content",
	423: "Locked",
	424: "Failed Dependency",
	425: "Too Early",
	426: "Upgrade Required",
	428: "Precondition Required",
	429: "Too Many Requests",
	431: "Request Header Fields Too Large",
	451: "Unavailable For Legal Reasons",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
	505: "HTTP Version Not Supported",
	506: "Variant Also Negotiates",
	507: "Insufficient Storage",
	508: "Loop Detected",
	510: "Not Extended",
	511: "Network Authentication Required",
}

// statusText returns the reason phrase for an HTTP status code.
func statusText(code int) string {
	return statusTextMap[code]
}
