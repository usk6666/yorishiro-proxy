package parser

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"testing"
)

// USK-772: tests for the disk-spill path of RawBody capture. Memory-only
// behavior is covered in rawbody_test.go (USK-769); these tests exercise
// the bodyCaptureSink promote-to-file path so multi-MiB chunked or identity
// bodies survive past MaxRawCaptureSize without losing wire fidelity.

// enableSpill installs USK-772 spill knobs on a parser body reader if the
// reader satisfies the optional EnableRawBodySpill interface. Helper used by
// the spill tests below.
func enableSpill(t *testing.T, body io.Reader, dir string, threshold, maxSize int64) {
	t.Helper()
	type spiller interface {
		EnableRawBodySpill(dir, prefix string, threshold, maxSize int64)
	}
	sp, ok := body.(spiller)
	if !ok {
		t.Fatalf("body reader %T does not implement EnableRawBodySpill", body)
	}
	sp.EnableRawBodySpill(dir, "yorishiro-body-raw-test-", threshold, maxSize)
}

// drainAndCapture drains the body fully and returns RawBody / RawBodyBuffer /
// truncated via the RawBodyProvider interface.
func drainAndCapture(t *testing.T, body io.Reader) (raw []byte, fileBytes []byte, truncated, spilled bool) {
	t.Helper()
	if _, err := io.ReadAll(body); err != nil {
		t.Fatalf("ReadAll(body) error: %v", err)
	}
	rp, ok := body.(RawBodyProvider)
	if !ok {
		t.Fatalf("body does not implement RawBodyProvider: %T", body)
	}
	raw = rp.RawBody()
	bb := rp.RawBodyBuffer()
	truncated = rp.RawBodyTruncated()
	if bb != nil {
		spilled = true
		b, err := bb.Bytes(context.Background())
		if err != nil {
			t.Fatalf("BodyBuffer.Bytes error: %v", err)
		}
		fileBytes = b
		// Test takes ownership: release the bodybuf at end of test so the
		// temp file is cleaned and we do not leak.
		t.Cleanup(func() { _ = bb.Release() })
	}
	return raw, fileBytes, truncated, spilled
}

func TestParseResponse_RawBody_LargeChunked_Spilled(t *testing.T) {
	// Body just over a low spill threshold so the test stays fast but the
	// spill path actually triggers.
	const threshold = 4 * 1024 // 4 KiB
	const dataLen = threshold + 8*1024
	body := formatHex(dataLen) + "\r\n" + strings.Repeat("Z", dataLen) + "\r\n0\r\n\r\n"
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body

	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	enableSpill(t, resp.Body, t.TempDir(), threshold, int64(dataLen)*4)

	memBytes, fileBytes, truncated, spilled := drainAndCapture(t, resp.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated for body fitting under maxSize")
	}
	if !spilled {
		t.Fatalf("expected disk-spill (RawBodyBuffer != nil) for body of %d bytes above threshold %d", dataLen, threshold)
	}
	if memBytes != nil {
		t.Errorf("RawBody (memory) = %d bytes, want nil after spill", len(memBytes))
	}
	if !bytes.Equal(fileBytes, []byte(body)) {
		t.Errorf("spilled bytes mismatch: got len=%d sha256=%s, want len=%d sha256=%s",
			len(fileBytes), sha256Hex(fileBytes), len(body), sha256Hex([]byte(body)))
	}
}

func TestParseResponse_RawBody_NotSpilled_BelowThreshold(t *testing.T) {
	// Threshold 4 KiB, body 1 KiB → must remain in memory.
	const threshold = 4 * 1024
	const dataLen = 1024
	bodyOnWire := formatHex(dataLen) + "\r\n" + strings.Repeat("X", dataLen) + "\r\n0\r\n\r\n"
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + bodyOnWire

	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	enableSpill(t, resp.Body, t.TempDir(), threshold, int64(dataLen)*4)

	memBytes, fileBytes, truncated, spilled := drainAndCapture(t, resp.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	if spilled {
		t.Fatalf("unexpected disk-spill for body %d bytes below threshold %d", len(bodyOnWire), threshold)
	}
	if fileBytes != nil {
		t.Errorf("RawBodyBuffer should be nil; got %d bytes", len(fileBytes))
	}
	if !bytes.Equal(memBytes, []byte(bodyOnWire)) {
		t.Errorf("memory bytes mismatch: got len=%d, want len=%d", len(memBytes), len(bodyOnWire))
	}
}

func TestParseResponse_RawBody_SpillToMaxBodySize_Truncated(t *testing.T) {
	// Threshold 4 KiB, maxSize 8 KiB; body 32 KiB → spill fires, then
	// maxSize cap trips truncation flag.
	const threshold = 4 * 1024
	const maxSize = 8 * 1024
	const dataLen = 32 * 1024
	body := formatHex(dataLen) + "\r\n" + strings.Repeat("Q", dataLen) + "\r\n0\r\n\r\n"
	raw := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body

	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	enableSpill(t, resp.Body, t.TempDir(), threshold, maxSize)

	// Drain regardless: the dechunked semantic body is still complete; only
	// the raw capture trips truncation. We also tolerate an early read error
	// because the bodybuf may stop accepting writes mid-stream — but the
	// dechunked Read path itself should not fail.
	if _, err := io.ReadAll(resp.Body); err != nil {
		t.Fatalf("ReadAll(body) error: %v", err)
	}
	rp, ok := resp.Body.(RawBodyProvider)
	if !ok {
		t.Fatalf("body does not implement RawBodyProvider: %T", resp.Body)
	}
	if !rp.RawBodyTruncated() {
		t.Fatalf("expected RawBodyTruncated=true for body %d > maxSize %d", dataLen, maxSize)
	}
	// On truncation the bodybuf is torn down (Write returns ErrMaxSizeExceeded
	// inside the sink, which clears bb). Either branch is acceptable: memory
	// or buffer; importantly, the truncation flag is set.
	if bb := rp.RawBodyBuffer(); bb != nil {
		t.Cleanup(func() { _ = bb.Release() })
	}
}

func TestParseRequest_RawBody_LargeChunked_Spilled(t *testing.T) {
	const threshold = 2 * 1024
	const dataLen = threshold + 4*1024
	body := formatHex(dataLen) + "\r\n" + strings.Repeat("Y", dataLen) + "\r\n0\r\n\r\n"
	raw := "POST /upload HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n" + body

	req, err := ParseRequest(newReader(raw))
	if err != nil {
		t.Fatalf("ParseRequest() error: %v", err)
	}
	enableSpill(t, req.Body, t.TempDir(), threshold, int64(dataLen)*4)

	memBytes, fileBytes, truncated, spilled := drainAndCapture(t, req.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	if !spilled {
		t.Fatalf("expected disk-spill for request body %d bytes above threshold %d", dataLen, threshold)
	}
	if memBytes != nil {
		t.Errorf("RawBody (memory) = %d bytes, want nil after spill", len(memBytes))
	}
	if !bytes.Equal(fileBytes, []byte(body)) {
		t.Errorf("spilled request bytes mismatch: got len=%d, want len=%d", len(fileBytes), len(body))
	}
}

func TestParseResponse_RawBody_Identity_Spilled(t *testing.T) {
	const threshold = 4 * 1024
	const dataLen = threshold + 8*1024
	bodyOnWire := strings.Repeat("M", dataLen)
	raw := "HTTP/1.1 200 OK\r\nContent-Length: " + formatInt(dataLen) + "\r\n\r\n" + bodyOnWire

	resp, err := ParseResponse(newReader(raw))
	if err != nil {
		t.Fatalf("ParseResponse() error: %v", err)
	}
	enableSpill(t, resp.Body, t.TempDir(), threshold, int64(dataLen)*4)

	_, fileBytes, truncated, spilled := drainAndCapture(t, resp.Body)
	if truncated {
		t.Fatalf("unexpected RawBodyTruncated")
	}
	if !spilled {
		t.Fatalf("expected disk-spill for identity body %d bytes above threshold %d", dataLen, threshold)
	}
	if !bytes.Equal(fileBytes, []byte(bodyOnWire)) {
		t.Errorf("identity spilled bytes mismatch: got len=%d, want len=%d", len(fileBytes), len(bodyOnWire))
	}
}

// sha256Hex returns the hex-encoded SHA-256 of b. Used for diff-friendly
// failure messages in the large-body spill tests.
func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
