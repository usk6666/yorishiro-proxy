package config

import (
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-800: DefaultMaxRawCaptureSize lives in this package (config does not
// import parser to avoid a cross-package import cycle). The value must
// remain in sync with parser.MaxRawCaptureSize so that operators see one
// consistent default regardless of which side they inspect.
func TestLimits_MaxRawCaptureSize_MirrorsParser(t *testing.T) {
	if got, want := DefaultMaxRawCaptureSize, int64(parser.MaxRawCaptureSize); got != want {
		t.Errorf("DefaultMaxRawCaptureSize = %d, want parser.MaxRawCaptureSize = %d", got, want)
	}
}

// USK-805: the package-level default MaxBodySize must remain within the
// SQLite BLOB cap (MaxBodySizeUpperBound = 1 GiB) so that a zero/unset
// ProxyConfig — which routes to this default via ResolveMaxBodySize — does
// not produce rows that the flow store cannot persist. The configured
// upper bound is enforced by ValidateProtocolLimits; this test guards the
// constant literal in case it is ever bumped past the BLOB cap. Replaces
// the assertion previously in TestLimits_Consistency, which was deleted
// when the standalone MaxImportScannerBuffer / MaxReplayResponseSize
// constants were removed in favor of resolver helpers.
func TestLimits_DefaultMaxBodySizeWithinSQLiteCap(t *testing.T) {
	if MaxBodySize > MaxBodySizeUpperBound {
		t.Errorf("MaxBodySize (%d) exceeds MaxBodySizeUpperBound (%d)",
			MaxBodySize, MaxBodySizeUpperBound)
	}
}
