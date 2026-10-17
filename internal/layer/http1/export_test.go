package http1

import (
	"testing"
	"time"
)

// SetRejectLingerTimeoutForTest overrides rejectLingerTimeout for the
// duration of t. Callers must not run in parallel with other tests that
// reach the 414 reject path.
func SetRejectLingerTimeoutForTest(t *testing.T, d time.Duration) {
	t.Helper()
	prev := rejectLingerTimeout
	rejectLingerTimeout = d
	t.Cleanup(func() { rejectLingerTimeout = prev })
}

// URITooLongBodyForTest exposes the 414 body for external tests.
const URITooLongBodyForTest = uriTooLongBody
