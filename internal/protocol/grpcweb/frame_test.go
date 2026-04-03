package grpcweb

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
)

func TestDecodeBody_BinaryDataFrames(t *testing.T) {
	payload1 := []byte("message-one")
	payload2 := []byte("message-two")

	var data []byte
	data = append(data, EncodeFrame(false, false, payload1)...)
	data = append(data, EncodeFrame(false, false, payload2)...)

	result, err := DecodeBody(data, false)
	if err != nil {
		t.Fatalf("DecodeBody() error = %v", err)
	}
	if len(result.DataFrames) != 2 {
		t.Fatalf("DataFrames count = %d, want 2", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload1) {
		t.Errorf("DataFrames[0].Payload = %q, want %q", result.DataFrames[0].Payload, payload1)
	}
	if !bytes.Equal(result.DataFrames[1].Payload, payload2) {
		t.Errorf("DataFrames[1].Payload = %q, want %q", result.DataFrames[1].Payload, payload2)
	}
	if result.TrailerFrame != nil {
		t.Error("TrailerFrame should be nil when no trailer present")
	}
}

func TestDecodeBody_BinaryWithTrailer(t *testing.T) {
	payload := []byte("hello-grpc-web")
	trailer := []byte("grpc-status: 0\r\ngrpc-message: OK\r\n")

	var data []byte
	data = append(data, EncodeFrame(false, false, payload)...)
	data = append(data, EncodeFrame(true, false, trailer)...)

	result, err := DecodeBody(data, false)
	if err != nil {
		t.Fatalf("DecodeBody() error = %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload) {
		t.Errorf("DataFrames[0].Payload = %q, want %q", result.DataFrames[0].Payload, payload)
	}
	if result.TrailerFrame == nil {
		t.Fatal("TrailerFrame should not be nil")
	}
	if !result.TrailerFrame.IsTrailer {
		t.Error("TrailerFrame.IsTrailer = false, want true")
	}
	if !bytes.Equal(result.TrailerFrame.Payload, trailer) {
		t.Errorf("TrailerFrame.Payload = %q, want %q", result.TrailerFrame.Payload, trailer)
	}

	// Verify parsed trailers.
	if result.Trailers == nil {
		t.Fatal("Trailers should not be nil")
	}
	if result.Trailers["grpc-status"] != "0" {
		t.Errorf("Trailers[grpc-status] = %q, want %q", result.Trailers["grpc-status"], "0")
	}
	if result.Trailers["grpc-message"] != "OK" {
		t.Errorf("Trailers[grpc-message] = %q, want %q", result.Trailers["grpc-message"], "OK")
	}
}

func TestDecodeBody_ErrorTrailer(t *testing.T) {
	trailer := []byte("grpc-status: 13\r\ngrpc-message: internal error\r\n")

	data := EncodeFrame(true, false, trailer)

	result, err := DecodeBody(data, false)
	if err != nil {
		t.Fatalf("DecodeBody() error = %v", err)
	}
	if len(result.DataFrames) != 0 {
		t.Errorf("DataFrames count = %d, want 0", len(result.DataFrames))
	}
	if result.Trailers["grpc-status"] != "13" {
		t.Errorf("Trailers[grpc-status] = %q, want %q", result.Trailers["grpc-status"], "13")
	}
	if result.Trailers["grpc-message"] != "internal error" {
		t.Errorf("Trailers[grpc-message] = %q, want %q", result.Trailers["grpc-message"], "internal error")
	}
}

func TestDecodeBody_Base64Encoded(t *testing.T) {
	payload := []byte("hello-grpc-web")
	trailer := []byte("grpc-status: 0\r\n")

	var binaryData []byte
	binaryData = append(binaryData, EncodeFrame(false, false, payload)...)
	binaryData = append(binaryData, EncodeFrame(true, false, trailer)...)

	base64Data := EncodeBase64Body(binaryData)

	result, err := DecodeBody(base64Data, true)
	if err != nil {
		t.Fatalf("DecodeBody(base64) error = %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload) {
		t.Errorf("DataFrames[0].Payload = %q, want %q", result.DataFrames[0].Payload, payload)
	}
	if result.Trailers["grpc-status"] != "0" {
		t.Errorf("Trailers[grpc-status] = %q, want %q", result.Trailers["grpc-status"], "0")
	}
}

func TestDecodeBody_Base64NoPadding(t *testing.T) {
	payload := []byte("hi") // Short payload to test padding edge cases.
	trailer := []byte("grpc-status: 0\r\n")

	var binaryData []byte
	binaryData = append(binaryData, EncodeFrame(false, false, payload)...)
	binaryData = append(binaryData, EncodeFrame(true, false, trailer)...)

	// Encode without padding.
	base64NoPad := []byte(base64.RawStdEncoding.EncodeToString(binaryData))

	result, err := DecodeBody(base64NoPad, true)
	if err != nil {
		t.Fatalf("DecodeBody(base64 no padding) error = %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload) {
		t.Errorf("DataFrames[0].Payload = %q, want %q", result.DataFrames[0].Payload, payload)
	}
}

func TestDecodeBody_InvalidBase64(t *testing.T) {
	_, err := DecodeBody([]byte("!!!not-base64!!!"), true)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error for invalid base64")
	}
}

func TestDecodeBody_EmptyData(t *testing.T) {
	result, err := DecodeBody(nil, false)
	if err != nil {
		t.Fatalf("DecodeBody(nil) error = %v", err)
	}
	if len(result.DataFrames) != 0 {
		t.Errorf("DataFrames count = %d, want 0", len(result.DataFrames))
	}
	if result.TrailerFrame != nil {
		t.Error("TrailerFrame should be nil for empty data")
	}

	result, err = DecodeBody([]byte{}, false)
	if err != nil {
		t.Fatalf("DecodeBody([]) error = %v", err)
	}
	if len(result.DataFrames) != 0 {
		t.Errorf("DataFrames count = %d, want 0", len(result.DataFrames))
	}
}

func TestDecodeBody_CompressedDataFrame(t *testing.T) {
	payload := []byte{0x1F, 0x8B, 0x08} // Fake gzip header.
	data := EncodeFrame(false, true, payload)

	result, err := DecodeBody(data, false)
	if err != nil {
		t.Fatalf("DecodeBody() error = %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
	if !result.DataFrames[0].Compressed {
		t.Error("DataFrames[0].Compressed = false, want true")
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload) {
		t.Errorf("DataFrames[0].Payload = %x, want %x", result.DataFrames[0].Payload, payload)
	}
}

func TestDecodeBody_IncompleteHeader(t *testing.T) {
	// Valid frame followed by incomplete header.
	data := EncodeFrame(false, false, []byte("valid"))
	data = append(data, 0x00, 0x00) // Only 2 bytes, not enough for header.

	result, err := DecodeBody(data, false)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error")
	}
	if len(result.DataFrames) != 1 {
		t.Errorf("DataFrames count = %d, want 1 (valid frame before error)", len(result.DataFrames))
	}
}

func TestDecodeBody_IncompletePayload(t *testing.T) {
	var data []byte
	data = append(data, EncodeFrame(false, false, []byte("ok"))...)
	// Add header claiming 100 bytes but only provide 10.
	header := make([]byte, 5)
	header[0] = 0x00
	binary.BigEndian.PutUint32(header[1:5], 100)
	data = append(data, header...)
	data = append(data, make([]byte, 10)...)

	result, err := DecodeBody(data, false)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error")
	}
	if len(result.DataFrames) != 1 {
		t.Errorf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
}

func TestDecodeBody_InvalidFlags(t *testing.T) {
	// Flags byte 0x02 has bit 1 set, which is not a known flag.
	data := []byte{0x02, 0x00, 0x00, 0x00, 0x01, 0x00}
	_, err := DecodeBody(data, false)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error for invalid flags")
	}
}

func TestDecodeBody_MessageTooLarge(t *testing.T) {
	data := make([]byte, 5)
	data[0] = 0x00
	binary.BigEndian.PutUint32(data[1:5], config.MaxGRPCMessageSize+1)

	_, err := DecodeBody(data, false)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error for oversized message")
	}
}

func TestDecodeBody_MultipleDataAndTrailer(t *testing.T) {
	payloads := [][]byte{
		[]byte("msg-1"),
		[]byte("msg-2"),
		[]byte("msg-3"),
	}
	trailer := []byte("grpc-status: 0\r\n")

	var data []byte
	for _, p := range payloads {
		data = append(data, EncodeFrame(false, false, p)...)
	}
	data = append(data, EncodeFrame(true, false, trailer)...)

	result, err := DecodeBody(data, false)
	if err != nil {
		t.Fatalf("DecodeBody() error = %v", err)
	}
	if len(result.DataFrames) != 3 {
		t.Fatalf("DataFrames count = %d, want 3", len(result.DataFrames))
	}
	for i, p := range payloads {
		if !bytes.Equal(result.DataFrames[i].Payload, p) {
			t.Errorf("DataFrames[%d].Payload = %q, want %q", i, result.DataFrames[i].Payload, p)
		}
		if result.DataFrames[i].IsTrailer {
			t.Errorf("DataFrames[%d].IsTrailer = true, want false", i)
		}
	}
	if result.TrailerFrame == nil {
		t.Fatal("TrailerFrame should not be nil")
	}
	if result.Trailers["grpc-status"] != "0" {
		t.Errorf("Trailers[grpc-status] = %q, want %q", result.Trailers["grpc-status"], "0")
	}
}

func TestDecodeBody_MalformedTrailer(t *testing.T) {
	// Trailer with a malformed line (no colon).
	trailer := []byte("malformed-trailer-no-colon\r\n")
	data := EncodeFrame(true, false, trailer)

	_, err := DecodeBody(data, false)
	if err == nil {
		t.Fatal("DecodeBody() error = nil, want error for malformed trailer")
	}
}

func TestEncodeFrame_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		isTrailer  bool
		compressed bool
		payload    []byte
	}{
		{
			name:       "data frame",
			isTrailer:  false,
			compressed: false,
			payload:    []byte("test-payload"),
		},
		{
			name:       "compressed data frame",
			isTrailer:  false,
			compressed: true,
			payload:    []byte{0x1f, 0x8b, 0x08},
		},
		{
			name:       "trailer frame",
			isTrailer:  true,
			compressed: false,
			payload:    []byte("grpc-status: 0\r\n"),
		},
		{
			name:       "empty payload",
			isTrailer:  false,
			compressed: false,
			payload:    []byte{},
		},
		{
			name:       "nil payload",
			isTrailer:  false,
			compressed: false,
			payload:    nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			encoded := EncodeFrame(tt.isTrailer, tt.compressed, tt.payload)

			result, err := DecodeBody(encoded, false)
			if err != nil {
				t.Fatalf("DecodeBody() error = %v", err)
			}

			if tt.isTrailer {
				if result.TrailerFrame == nil {
					t.Fatal("TrailerFrame = nil, want non-nil")
				}
				if !result.TrailerFrame.IsTrailer {
					t.Error("TrailerFrame.IsTrailer = false, want true")
				}
				if result.TrailerFrame.Compressed != tt.compressed {
					t.Errorf("TrailerFrame.Compressed = %v, want %v", result.TrailerFrame.Compressed, tt.compressed)
				}
			} else {
				if len(result.DataFrames) != 1 {
					t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
				}
				frame := result.DataFrames[0]
				if frame.Compressed != tt.compressed {
					t.Errorf("Compressed = %v, want %v", frame.Compressed, tt.compressed)
				}
				expectedLen := len(tt.payload)
				if tt.payload == nil {
					expectedLen = 0
				}
				if len(frame.Payload) != expectedLen {
					t.Errorf("Payload length = %d, want %d", len(frame.Payload), expectedLen)
				}
			}
		})
	}
}

func TestEncodeFrame_HeaderFormat(t *testing.T) {
	payload := []byte("hello")

	// Data frame, uncompressed: flags = 0x00.
	encoded := EncodeFrame(false, false, payload)
	if encoded[0] != 0x00 {
		t.Errorf("data frame flags = 0x%02x, want 0x00", encoded[0])
	}

	// Data frame, compressed: flags = 0x01.
	encoded = EncodeFrame(false, true, payload)
	if encoded[0] != 0x01 {
		t.Errorf("compressed data frame flags = 0x%02x, want 0x01", encoded[0])
	}

	// Trailer frame, uncompressed: flags = 0x80.
	encoded = EncodeFrame(true, false, payload)
	if encoded[0] != 0x80 {
		t.Errorf("trailer frame flags = 0x%02x, want 0x80", encoded[0])
	}

	// Trailer frame, compressed: flags = 0x81.
	encoded = EncodeFrame(true, true, payload)
	if encoded[0] != 0x81 {
		t.Errorf("compressed trailer frame flags = 0x%02x, want 0x81", encoded[0])
	}

	// Check length field.
	length := binary.BigEndian.Uint32(encoded[1:5])
	if length != uint32(len(payload)) {
		t.Errorf("length = %d, want %d", length, len(payload))
	}
}

func TestBase64RoundTrip(t *testing.T) {
	payload := []byte("round-trip-test")
	trailer := []byte("grpc-status: 0\r\n")

	var binaryData []byte
	binaryData = append(binaryData, EncodeFrame(false, false, payload)...)
	binaryData = append(binaryData, EncodeFrame(true, false, trailer)...)

	// Encode to base64.
	base64Data := EncodeBase64Body(binaryData)

	// Decode via DecodeBody.
	result, err := DecodeBody(base64Data, true)
	if err != nil {
		t.Fatalf("DecodeBody(base64) error = %v", err)
	}
	if len(result.DataFrames) != 1 {
		t.Fatalf("DataFrames count = %d, want 1", len(result.DataFrames))
	}
	if !bytes.Equal(result.DataFrames[0].Payload, payload) {
		t.Errorf("DataFrames[0].Payload = %q, want %q", result.DataFrames[0].Payload, payload)
	}
	if result.Trailers["grpc-status"] != "0" {
		t.Errorf("Trailers[grpc-status] = %q, want %q", result.Trailers["grpc-status"], "0")
	}
}
