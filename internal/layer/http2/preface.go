package http2

import (
	"bytes"
	"fmt"
	"io"
)

// ClientPreface is the 24-byte connection preface that an HTTP/2 client
// MUST send immediately after establishing a connection. See RFC 9113 §3.4.
const ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// runServerPreface reads the 24-byte client preface from r and verifies it.
// Returns an error if the preface bytes do not match or if reading fails.
func runServerPreface(r io.Reader) error {
	var buf [len(ClientPreface)]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return fmt.Errorf("http2: read client preface: %w", err)
	}
	if !bytes.Equal(buf[:], []byte(ClientPreface)) {
		return fmt.Errorf("http2: invalid client preface: %q", buf[:])
	}
	return nil
}

// runClientPreface writes the 24-byte client preface to w.
// Returns an error if the underlying write fails.
func runClientPreface(w io.Writer) error {
	if _, err := w.Write([]byte(ClientPreface)); err != nil {
		return fmt.Errorf("http2: write client preface: %w", err)
	}
	return nil
}
