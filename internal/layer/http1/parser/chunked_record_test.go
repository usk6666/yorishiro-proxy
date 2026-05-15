package parser

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"
)

// TestDechunkedReader_ChunkRecordCallback_FiresPerChunk is the USK-895
// regression guard at the parser level: when a chunk-record callback is
// installed via SetChunkRecordCallback, the reader fires the callback
// once per chunk boundary with the full on-wire chunk bytes (chunk-size
// line + chunk-extension + chunk-data + trailing CRLF). The terminal
// "0\r\n\r\n" chunk is emitted as its own callback.
func TestDechunkedReader_ChunkRecordCallback_FiresPerChunk(t *testing.T) {
	body := "5\r\nhello\r\n" +
		"6;name=val\r\n world\r\n" +
		"A\r\n0123456789\r\n" +
		"0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(body))
	dr := newDechunkedReader(br)

	var calls [][]byte
	dr.SetChunkRecordCallback(func(chunkRaw []byte) {
		copy := make([]byte, len(chunkRaw))
		// Defensive copy for the test buffer.
		for i, b := range chunkRaw {
			copy[i] = b
		}
		calls = append(calls, copy)
	}, 0)

	// Drain the reader.
	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	want := "hello world0123456789"
	if string(got) != want {
		t.Errorf("dechunked body = %q, want %q", got, want)
	}

	// 4 callbacks: 3 data chunks + 1 terminal chunk.
	if len(calls) != 4 {
		t.Fatalf("callback fired %d times, want 4; calls=%q", len(calls), calls)
	}
	// Chunk 1: "5\r\nhello\r\n"
	if string(calls[0]) != "5\r\nhello\r\n" {
		t.Errorf("calls[0] = %q, want %q", calls[0], "5\\r\\nhello\\r\\n")
	}
	// Chunk 2: "6;name=val\r\n world\r\n" — extension preserved.
	if !bytes.Contains(calls[1], []byte(";name=val")) {
		t.Errorf("calls[1] missing chunk extension: %q", calls[1])
	}
	if string(calls[1]) != "6;name=val\r\n world\r\n" {
		t.Errorf("calls[1] = %q", calls[1])
	}
	// Chunk 3: "A\r\n0123456789\r\n"
	if string(calls[2]) != "A\r\n0123456789\r\n" {
		t.Errorf("calls[2] = %q", calls[2])
	}
	// Terminal chunk: "0\r\n\r\n"
	if !bytes.HasPrefix(calls[3], []byte("0\r\n")) {
		t.Errorf("calls[3] is not the terminal chunk: %q", calls[3])
	}
}

// TestDechunkedReader_ChunkRecordCallback_NilCallback verifies that the
// no-callback hot path matches the pre-USK-895 contract exactly: reading
// works, the body is correctly decoded, and chunkBuf is never allocated.
func TestDechunkedReader_ChunkRecordCallback_NilCallback(t *testing.T) {
	body := "5\r\nhello\r\n0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(body))
	dr := newDechunkedReader(br)

	got, err := io.ReadAll(dr)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("dechunked body = %q, want %q", got, "hello")
	}
	// chunkBuf must not be allocated when no callback is installed.
	if dr.chunkBuf != nil {
		t.Errorf("chunkBuf allocated without a callback: %v", dr.chunkBuf)
	}
}

// TestDechunkedReader_ChunkRecordCallback_OverCapSkipped verifies the
// Principle #5 / USK-893 fitness-check defence: a single chunk exceeding
// maxBytes triggers no callback for that chunk; the next under-cap chunk
// still fires normally.
func TestDechunkedReader_ChunkRecordCallback_OverCapSkipped(t *testing.T) {
	body := "20\r\n" + strings.Repeat("x", 0x20) + "\r\n" +
		"3\r\nabc\r\n" +
		"0\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(body))
	dr := newDechunkedReader(br)

	var calls [][]byte
	// Cap of 12 bytes: the first chunk (0x20 = 32 bytes payload + size
	// line + CRLF ~= 36 bytes) exceeds; the second chunk (~9 bytes)
	// fits.
	dr.SetChunkRecordCallback(func(chunkRaw []byte) {
		cp := make([]byte, len(chunkRaw))
		copy(cp, chunkRaw)
		calls = append(calls, cp)
	}, 12)

	if _, err := io.ReadAll(dr); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}

	// Expect 2 callbacks: chunk 2 (under cap) + terminal chunk (under cap).
	if len(calls) != 2 {
		t.Fatalf("callback fired %d times, want 2 (over-cap chunk dropped)", len(calls))
	}
	if string(calls[0]) != "3\r\nabc\r\n" {
		t.Errorf("calls[0] = %q, want %q", calls[0], "3\\r\\nabc\\r\\n")
	}
	if !bytes.HasPrefix(calls[1], []byte("0\r\n")) {
		t.Errorf("calls[1] is not the terminal chunk: %q", calls[1])
	}
}

// TestDechunkedReader_ChunkRecordCallback_TerminalWithTrailers verifies
// that the terminal chunk callback includes the trailer section bytes
// (USK-895: analysts must see the trailer wire form alongside the
// "stream ended" boundary).
func TestDechunkedReader_ChunkRecordCallback_TerminalWithTrailers(t *testing.T) {
	body := "5\r\nhello\r\n" +
		"0\r\nX-Trailer: yes\r\n\r\n"
	br := bufio.NewReader(strings.NewReader(body))
	dr := newDechunkedReader(br)

	var terminal []byte
	dr.SetChunkRecordCallback(func(chunkRaw []byte) {
		if len(chunkRaw) > 0 && chunkRaw[0] == '0' {
			terminal = make([]byte, len(chunkRaw))
			copy(terminal, chunkRaw)
		}
	}, 0)

	if _, err := io.ReadAll(dr); err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if terminal == nil {
		t.Fatal("terminal chunk callback did not fire")
	}
	if !bytes.Contains(terminal, []byte("X-Trailer: yes")) {
		t.Errorf("terminal chunk missing trailer bytes: %q", terminal)
	}
}
