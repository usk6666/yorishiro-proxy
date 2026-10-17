package http1

import (
	"bytes"
	"io"
	"log/slog"
	"strconv"
	"time"
)

// Bounds for the proxy-generated 414 / 431 written when a client's request
// line (USK-1137) or header section (USK-1181) exceeds the parser limit.
const (
	// rejectWriteTimeout bounds the 414 / 431 write so a client that never reads
	// cannot pin the Layer's goroutine.
	rejectWriteTimeout = 5 * time.Second

	// rejectLingerMaxBytes caps the bytes discarded while lingering.
	rejectLingerMaxBytes = 1 << 20
)

// rejectLingerTimeout bounds how long the Layer keeps reading (and
// discarding) the rest of the rejected request after the 414 is out.
// Closing a TCP socket with unread received data makes the kernel send
// RST instead of FIN, and an RST can make the client discard the 414
// before reading it. Matches Go net/http's rstAvoidanceDelay (500ms),
// which its server waits out in closeWriteAndWait after a 431.
//
// A var only so tests can stretch it (export_test.go); never reassigned
// in production code.
var rejectLingerTimeout = 500 * time.Millisecond

// uriTooLongBody is the plain-text body of the 414 response.
const uriTooLongBody = "request line too long\r\n"

// uriTooLongResponse is the complete 414 URI Too Long response (RFC 9110
// §15.5.15) the client-facing Layer writes for an over-limit request line.
// Connection: close tells the client this connection is done; the request
// could not be framed, so nothing after it on the wire can be trusted.
// Header set mirrors connector.writeForwardErrorResponse.
var uriTooLongResponse = []byte("HTTP/1.1 414 URI Too Long\r\n" +
	"Server: yorishiro-proxy\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: " + strconv.Itoa(len(uriTooLongBody)) + "\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	uriTooLongBody)

// closeWriter is implemented by *net.TCPConn, *tls.Conn (close_notify) and
// *connector.PeekConn, which forwards to its inner conn (USK-1163). On the
// plain-HTTP forward path (and plain HTTP inside CONNECT / SOCKS5 /
// tcp_forward) l.conn is a PeekConn, so the 414 is followed by a FIN there
// too. PeekConn returns an error (ignored here) when its inner conn cannot
// half-close, which leaves the drain alone for RST avoidance. Pinned by
// TestLayer_Send_RequestLineTooLong_PeekConnHalfCloses.
type closeWriter interface {
	CloseWrite() error
}

// headerTooLargeBody is the plain-text body of the 431 response.
const headerTooLargeBody = "request header fields too large\r\n"

// headerTooLargeResponse is the complete 431 Request Header Fields Too Large
// response (RFC 6585 §5) the client-facing Layer writes for an over-limit
// header section (USK-1181). Same shape and rationale as
// uriTooLongResponse.
var headerTooLargeResponse = []byte("HTTP/1.1 431 Request Header Fields Too Large\r\n" +
	"Server: yorishiro-proxy\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Content-Length: " + strconv.Itoa(len(headerTooLargeBody)) + "\r\n" +
	"Connection: close\r\n" +
	"\r\n" +
	headerTooLargeBody)

// rejectRequestHead answers a request head that exceeded a parser limit
// with resp (the 414 or the 431, both Connection: close), then closes the
// connection. Only the client-facing (envelope.Send) Layer calls it: the
// request was never framed, so there is no envelope. It returns a copy of
// the bytes it wrote and whether the write succeeded, so the caller can
// record the response (USK-1181).
//
// Every step is bounded: the write by rejectWriteTimeout, the linger by
// rejectLingerTimeout and rejectLingerMaxBytes. writeMu is held so the
// response cannot interleave with any other write on this connection.
func (l *Layer) rejectRequestHead(resp []byte) (written []byte, ok bool) {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()

	slog.Debug("http1: request head exceeds limit; answering and closing",
		"stream_id", l.streamID, "conn_id", l.envCtx.ConnID,
		"status_line", statusLineOf(resp))

	_ = l.conn.SetWriteDeadline(time.Now().Add(rejectWriteTimeout))
	if _, err := l.conn.Write(resp); err == nil {
		ok = true
		if cw, isCW := l.conn.(closeWriter); isCW {
			_ = cw.CloseWrite()
		}
		_ = l.conn.SetReadDeadline(time.Now().Add(rejectLingerTimeout))
		// Drain the rest of the rejected request so Close sends FIN, not
		// RST. Pinned by TestLayer_Send_RequestLineTooLong_DrainsBeforeClose.
		_, _ = io.CopyN(io.Discard, l.conn, rejectLingerMaxBytes)
	}
	_ = l.conn.Close()
	return append([]byte(nil), resp...), ok
}

// statusLineOf returns resp's first line without its terminator.
func statusLineOf(resp []byte) string {
	if i := bytes.IndexByte(resp, '\r'); i >= 0 {
		return string(resp[:i])
	}
	return string(resp)
}
