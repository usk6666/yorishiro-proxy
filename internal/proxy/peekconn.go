package proxy

import (
	"bufio"
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

// Read reads data from the buffered reader, returning any previously peeked
// bytes before reading new data from the underlying connection.
func (pc *PeekConn) Read(b []byte) (int, error) {
	return pc.reader.Read(b)
}
