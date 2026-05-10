package config

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

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

// USK-800: DefaultMaxRawCaptureSize lives in this package (config does not
// import parser to avoid a cross-package import cycle). The value must
// remain in sync with parser.MaxRawCaptureSize so that operators see one
// consistent default regardless of which side they inspect.
func TestLimits_MaxRawCaptureSize_MirrorsParser(t *testing.T) {
	if got, want := DefaultMaxRawCaptureSize, int64(parser.MaxRawCaptureSize); got != want {
		t.Errorf("DefaultMaxRawCaptureSize = %d, want parser.MaxRawCaptureSize = %d", got, want)
	}
}
