package http1

import (
	"io"
	"log/slog"
	"strconv"
	"time"
)

// Bounds for the proxy-generated 414 written when a client's request line
// exceeds the parser limit (USK-1137).
const (
	// rejectWriteTimeout bounds the 414 write so a client that never reads
	// cannot pin the Layer's goroutine.
	rejectWriteTimeout = 5 * time.Second

	// rejectLingerTimeout bounds how long the Layer keeps reading (and
	// discarding) the rest of the rejected request after the 414 is out.
	// Closing a TCP socket with unread received data makes the kernel send
	// RST instead of FIN, and an RST can make the client discard the 414
	// before reading it. Matches Go net/http's rstAvoidanceDelay (500ms),
	// which its server waits out in closeWriteAndWait after a 431.
	rejectLingerTimeout = 500 * time.Millisecond

	// rejectLingerMaxBytes caps the bytes discarded while lingering.
	rejectLingerMaxBytes = 1 << 20
)

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

// closeWriter is implemented by *net.TCPConn and *tls.Conn (close_notify).
type closeWriter interface {
	CloseWrite() error
}

// rejectRequestLineTooLong answers a request whose request line exceeded
// the parser limit with 414 URI Too Long + Connection: close, then closes
// the connection. Only the client-facing (envelope.Send) Layer calls it:
// the request was never framed, so there is no envelope and nothing is
// recorded (same as an over-limit header section).
//
// Every step is bounded: the write by rejectWriteTimeout, the linger by
// rejectLingerTimeout and rejectLingerMaxBytes. writeMu is held so the 414
// cannot interleave with any other write on this connection.
func (l *Layer) rejectRequestLineTooLong() {
	l.writeMu.Lock()
	defer l.writeMu.Unlock()

	slog.Debug("http1: request line exceeds limit; answering 414 and closing",
		"stream_id", l.streamID, "conn_id", l.envCtx.ConnID)

	_ = l.conn.SetWriteDeadline(time.Now().Add(rejectWriteTimeout))
	if _, err := l.conn.Write(uriTooLongResponse); err == nil {
		if cw, ok := l.conn.(closeWriter); ok {
			_ = cw.CloseWrite()
		}
		_ = l.conn.SetReadDeadline(time.Now().Add(rejectLingerTimeout))
		_, _ = io.CopyN(io.Discard, l.conn, rejectLingerMaxBytes)
	}
	_ = l.conn.Close()
}
