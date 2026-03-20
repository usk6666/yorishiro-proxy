package config

import "testing"

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
