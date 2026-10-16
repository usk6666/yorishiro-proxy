package connector

import (
	"bufio"
	"errors"
	"fmt"
	"net"
)

// PeekConn wraps a net.Conn with a buffered reader, allowing bytes to be
// peeked without consuming them from the stream. Subsequent Read calls
// return the peeked bytes followed by the rest of the stream.
type PeekConn struct {
	net.Conn
	reader *bufio.Reader
}

// NewPeekConn wraps conn with a buffered reader.
func NewPeekConn(conn net.Conn) *PeekConn {
	return &PeekConn{
		Conn:   conn,
		reader: bufio.NewReader(conn),
	}
}

// Peek returns the next n bytes without advancing the reader.
func (pc *PeekConn) Peek(n int) ([]byte, error) {
	return pc.reader.Peek(n)
}

// Buffered returns the number of bytes currently available in the buffer
// without requiring a read from the underlying connection.
func (pc *PeekConn) Buffered() int {
	return pc.reader.Buffered()
}

// Read reads data from the buffered reader, returning any previously peeked
// bytes before reading new data from the underlying connection.
func (pc *PeekConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}

// Reader returns the internal *bufio.Reader. Callers that need line-oriented
// reads (e.g. the HTTP/1.x request parser) use this directly so that
// peeked/buffered bytes and newly read bytes share the same buffer. Creating
// a second bufio.Reader on top of PeekConn risks swallowing bytes intended
// for the post-handoff tunnel (e.g. a TLS ClientHello that arrived in the
// same TCP segment as the CONNECT headers).
func (pc *PeekConn) Reader() *bufio.Reader {
	return pc.reader
}

// CloseWrite half-closes the write side of the underlying connection:
// FIN on a *net.TCPConn, close_notify on a *tls.Conn. The read side,
// including bytes already buffered by Peek, stays readable.
//
// PeekConn embeds net.Conn, which would otherwise hide the inner conn's
// CloseWrite from callers that type-assert interface{ CloseWrite() error }
// (the HTTP/1.x 414 reject path, the TLS passthrough relay). Because
// PeekConn always has the method, such an assertion now always succeeds;
// when the inner conn cannot half-close (e.g. net.Pipe) CloseWrite is a
// no-op returning an error that wraps errors.ErrUnsupported.
func (pc *PeekConn) CloseWrite() error {
	cw, ok := pc.Conn.(interface{ CloseWrite() error })
	if !ok {
		return fmt.Errorf("peekconn: %T does not support CloseWrite: %w", pc.Conn, errors.ErrUnsupported)
	}
	return cw.CloseWrite()
}
