package mcp

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/codec/protobuf"
	"github.com/usk6666/yorishiro-proxy/internal/proxy/intercept"
)

func TestIsGRPCInterceptItem(t *testing.T) {
	tests := []struct {
		name string
		item *intercept.InterceptedRequest
		want bool
	}{
		{
			name: "nil item",
			item: nil,
			want: false,
		},
		{
			name: "no metadata",
			item: &intercept.InterceptedRequest{},
			want: false,
		},
		{
			name: "empty metadata",
			item: &intercept.InterceptedRequest{
				Metadata: map[string]string{},
			},
			want: false,
		},
		{
			name: "non-grpc metadata",
			item: &intercept.InterceptedRequest{
				Metadata: map[string]string{"some_key": "some_value"},
			},
			want: false,
		},
		{
			name: "grpc metadata present",
			item: &intercept.InterceptedRequest{
				Metadata: map[string]string{
					"grpc_content_type": "application/grpc+proto",
					"grpc_encoding":     "identity",
					"grpc_compressed":   "false",
					"original_frames":   "1",
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isGRPCInterceptItem(tt.item)
			if got != tt.want {
				t.Errorf("isGRPCInterceptItem() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReencodeGRPCBody(t *testing.T) {
	// Create a simple protobuf message, decode it, then re-encode.
	// Field 1, String "Hello"
	originalProto := []byte{0x0a, 0x05, 'H', 'e', 'l', 'l', 'o'}

	// Decode to JSON.
	jsonStr, err := protobuf.Decode(originalProto)
	if err != nil {
		t.Fatalf("protobuf.Decode() error: %v", err)
	}

	tests := []struct {
		name     string
		jsonBody string
		metadata map[string]string
		wantErr  bool
		validate func(t *testing.T, result []byte)
	}{
		{
			name:     "uncompressed round-trip",
			jsonBody: jsonStr,
			metadata: map[string]string{
				"grpc_encoding":   "identity",
				"grpc_compressed": "false",
			},
			validate: func(t *testing.T, result []byte) {
				// Should be 5-byte header + protobuf payload.
				if len(result) < 5 {
					t.Fatalf("result too short: %d bytes", len(result))
				}
				// Compressed flag should be 0.
				if result[0] != 0 {
					t.Errorf("compressed flag = %d, want 0", result[0])
				}
				// Parse the frame and verify payload.
				frames, err := protobuf.ParseFrames(result)
				if err != nil {
					t.Fatalf("ParseFrames() error: %v", err)
				}
				if len(frames) != 1 {
					t.Fatalf("frame count = %d, want 1", len(frames))
				}
				// Re-decode the payload to verify round-trip.
				decoded, err := protobuf.Decode(frames[0].Payload)
				if err != nil {
					t.Fatalf("re-decode error: %v", err)
				}
				if decoded != jsonStr {
					t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", decoded, jsonStr)
				}
			},
		},
		{
			name:     "compressed round-trip (gzip)",
			jsonBody: jsonStr,
			metadata: map[string]string{
				"grpc_encoding":   "gzip",
				"grpc_compressed": "true",
			},
			validate: func(t *testing.T, result []byte) {
				if len(result) < 5 {
					t.Fatalf("result too short: %d bytes", len(result))
				}
				// Compressed flag should be 1.
				if result[0] != 1 {
					t.Errorf("compressed flag = %d, want 1", result[0])
				}
				// Parse the frame.
				frames, err := protobuf.ParseFrames(result)
				if err != nil {
					t.Fatalf("ParseFrames() error: %v", err)
				}
				if len(frames) != 1 {
					t.Fatalf("frame count = %d, want 1", len(frames))
				}
				// Decompress and decode to verify round-trip.
				decompressed, err := protobuf.Decompress(frames[0].Payload, "gzip")
				if err != nil {
					t.Fatalf("Decompress() error: %v", err)
				}
				decoded, err := protobuf.Decode(decompressed)
				if err != nil {
					t.Fatalf("re-decode error: %v", err)
				}
				if decoded != jsonStr {
					t.Errorf("round-trip mismatch:\n  got:  %s\n  want: %s", decoded, jsonStr)
				}
			},
		},
		{
			name:     "invalid JSON body",
			jsonBody: "not valid json {{{",
			metadata: map[string]string{
				"grpc_encoding":   "identity",
				"grpc_compressed": "false",
			},
			wantErr: true,
		},
		{
			name:     "modified JSON body",
			jsonBody: `{"0001:0000:String": "World"}`,
			metadata: map[string]string{
				"grpc_encoding":   "identity",
				"grpc_compressed": "false",
			},
			validate: func(t *testing.T, result []byte) {
				frames, err := protobuf.ParseFrames(result)
				if err != nil {
					t.Fatalf("ParseFrames() error: %v", err)
				}
				if len(frames) != 1 {
					t.Fatalf("frame count = %d, want 1", len(frames))
				}
				decoded, err := protobuf.Decode(frames[0].Payload)
				if err != nil {
					t.Fatalf("decode error: %v", err)
				}
				// Verify the modified value is present.
				if decoded != `{
  "0001:0000:String": "World"
}` {
					t.Errorf("unexpected decoded JSON:\n%s", decoded)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := reencodeGRPCBody(tt.jsonBody, tt.metadata)
			if (err != nil) != tt.wantErr {
				t.Errorf("reencodeGRPCBody() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}
