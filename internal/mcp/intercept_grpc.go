package mcp

import (
	"fmt"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

// isGRPCInterceptItem returns true if the intercepted item is a gRPC request
// identified by the presence of gRPC metadata (set during gRPC intercept hold).
func isGRPCInterceptItem(item *intercept.InterceptedRequest) bool {
	if item == nil || item.Metadata == nil {
		return false
	}
	_, ok := item.Metadata["grpc_content_type"]
	return ok
}

// reencodeGRPCBody converts a JSON body (from protobuf.Decode) back to a gRPC
// length-prefixed frame. It handles compression if the original frame was
// compressed.
//
// The metadata map must contain "grpc_encoding" and "grpc_compressed" keys
// set during the gRPC intercept hold phase.
func reencodeGRPCBody(jsonBody string, metadata map[string]string) ([]byte, error) {
	// Encode JSON back to protobuf binary.
	pbData, err := protobuf.Encode(jsonBody)
	if err != nil {
		return nil, fmt.Errorf("protobuf encode: %w", err)
	}

	// Re-compress if the original frame was compressed.
	var compressed byte
	encoding := metadata["grpc_encoding"]
	if metadata["grpc_compressed"] == "true" {
		pbData, err = protobuf.Compress(pbData, encoding)
		if err != nil {
			return nil, fmt.Errorf("compress: %w", err)
		}
		compressed = 1
	}

	// Build the gRPC frame (5-byte header + payload).
	frame := protobuf.Frame{
		Compressed: compressed,
		Payload:    pbData,
	}
	wireBytes, err := protobuf.BuildFrame(frame)
	if err != nil {
		return nil, fmt.Errorf("build frame: %w", err)
	}

	return wireBytes, nil
}
