package config

import "testing"

func TestLimits_MaxBodySize(t *testing.T) {
	// MaxBodySize should be 254 MB (1/4 of SQLite's 1 GB BLOB limit).
	const expected int64 = 254 << 20
	if MaxBodySize != expected {
		t.Errorf("MaxBodySize = %d, want %d", MaxBodySize, expected)
	}
}

func TestLimits_MaxGRPCMessageSize(t *testing.T) {
	const expected uint32 = 254 << 20
	if MaxGRPCMessageSize != expected {
		t.Errorf("MaxGRPCMessageSize = %d, want %d", MaxGRPCMessageSize, expected)
	}
}

func TestLimits_MaxWebSocketMessageSize(t *testing.T) {
	const expected int64 = 254 << 20
	if MaxWebSocketMessageSize != expected {
		t.Errorf("MaxWebSocketMessageSize = %d, want %d", MaxWebSocketMessageSize, expected)
	}
}

func TestLimits_MaxWebSocketRecordPayloadSize(t *testing.T) {
	const expected = 254 << 20
	if MaxWebSocketRecordPayloadSize != expected {
		t.Errorf("MaxWebSocketRecordPayloadSize = %d, want %d", MaxWebSocketRecordPayloadSize, expected)
	}
}

func TestLimits_MaxReplayResponseSize(t *testing.T) {
	const expected int64 = 254 << 20
	if MaxReplayResponseSize != expected {
		t.Errorf("MaxReplayResponseSize = %d, want %d", MaxReplayResponseSize, expected)
	}
}

func TestLimits_MaxImportScannerBuffer(t *testing.T) {
	// 350 MB — enough headroom for base64-encoded 254 MB bodies (~339 MB).
	const expected = 350 * 1024 * 1024
	if MaxImportScannerBuffer != expected {
		t.Errorf("MaxImportScannerBuffer = %d, want %d", MaxImportScannerBuffer, expected)
	}
}

func TestLimits_Consistency(t *testing.T) {
	// MaxImportScannerBuffer must be larger than base64-encoded MaxBodySize.
	// base64 expands data by ~4/3, so 254 MB * 4/3 ≈ 339 MB.
	base64MaxBody := MaxBodySize*4/3 + 1 // integer approximation with ceiling
	if int64(MaxImportScannerBuffer) <= base64MaxBody {
		t.Errorf("MaxImportScannerBuffer (%d) is not larger than base64-encoded MaxBodySize (%d)",
			MaxImportScannerBuffer, base64MaxBody)
	}

	// MaxBodySize should be within SQLite BLOB limit (1 GB).
	const sqliteBlobLimit int64 = 1 << 30
	if MaxBodySize > sqliteBlobLimit {
		t.Errorf("MaxBodySize (%d) exceeds SQLite BLOB limit (%d)", MaxBodySize, sqliteBlobLimit)
	}
}
