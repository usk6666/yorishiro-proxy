package grpcweb

import (
	"fmt"
	"strings"
)

// ParseTrailers parses the payload of a gRPC-Web embedded trailer frame.
// The payload is expected to contain key-value pairs in HTTP header format:
//
//	grpc-status: 0\r\n
//	grpc-message: OK\r\n
//
// Keys are preserved in their original casing. If duplicate keys exist,
// the last value wins.
//
// Returns an error if the trailer payload is malformed (e.g., a line
// without a colon separator).
func ParseTrailers(payload []byte) (map[string]string, error) {
	if len(payload) == 0 {
		return map[string]string{}, nil
	}

	text := string(payload)
	// Normalize line endings: trailers use \r\n but handle \n as well.
	text = strings.ReplaceAll(text, "\r\n", "\n")
	// Remove trailing newline to avoid empty split element.
	text = strings.TrimRight(text, "\n")

	if text == "" {
		return map[string]string{}, nil
	}

	lines := strings.Split(text, "\n")
	trailers := make(map[string]string, len(lines))

	for _, line := range lines {
		if line == "" {
			continue
		}

		idx := strings.IndexByte(line, ':')
		if idx < 0 {
			return trailers, fmt.Errorf("malformed grpc-web trailer line: %q", line)
		}

		key := line[:idx]
		value := strings.TrimLeft(line[idx+1:], " ")
		trailers[key] = value
	}

	return trailers, nil
}
