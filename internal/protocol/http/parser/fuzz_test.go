package parser

import (
	"bufio"
	"bytes"
	"io"
	"testing"
)

func FuzzParseRequest(f *testing.F) {
	// Seed corpus with valid and edge-case inputs.
	seeds := []string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"POST / HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello",
		"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"GET / HTTP/1.0\r\n\r\n",
		"POST / HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\nhello",
		"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\na",
		"GET / HTTP/1.1\r\nTransfer-Encoding : chunked\r\n\r\n",
		"GET / HTTP/1.1\r\nX-Long: first\r\n second\r\n\r\n",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		req, err := ParseRequest(r)
		if err != nil {
			return
		}
		// Drain body to exercise body reader paths.
		if req.Body != nil {
			_, _ = io.ReadAll(io.LimitReader(req.Body, 1<<20))
		}
	})
}

func FuzzParseResponse(f *testing.F) {
	seeds := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
		"HTTP/1.1 204 No Content\r\n\r\n",
		"HTTP/1.0 200 OK\r\n\r\nbody",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
		"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\nbody",
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		r := bufio.NewReader(bytes.NewReader(data))
		resp, err := ParseResponse(r)
		if err != nil {
			return
		}
		if resp.Body != nil {
			_, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		}
	})
}
