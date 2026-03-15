package grpc

import (
	"errors"
	"sync"
	"testing"
)

func TestFrameBuffer_SingleCompleteFrame(t *testing.T) {
	payload := []byte("hello")
	raw := EncodeFrame(false, payload)

	var got []*Frame
	var gotRaw [][]byte
	fb := NewFrameBuffer(func(r []byte, f *Frame) error {
		gotRaw = append(gotRaw, r)
		got = append(got, f)
		return nil
	})

	if err := fb.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(got))
	}
	if got[0].Compressed {
		t.Error("expected uncompressed")
	}
	if string(got[0].Payload) != "hello" {
		t.Errorf("payload = %q, want %q", got[0].Payload, "hello")
	}
	if string(gotRaw[0]) != string(raw) {
		t.Error("raw bytes mismatch")
	}
	if fb.Buffered() != 0 {
		t.Errorf("Buffered = %d, want 0", fb.Buffered())
	}
}

func TestFrameBuffer_MultipleFramesInOneWrite(t *testing.T) {
	f1 := EncodeFrame(false, []byte("one"))
	f2 := EncodeFrame(true, []byte("two"))
	combined := append(f1, f2...)

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	if err := fb.Write(combined); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(got) != 2 {
		t.Fatalf("expected 2 frames, got %d", len(got))
	}
	if string(got[0].Payload) != "one" || got[0].Compressed {
		t.Errorf("frame 0: payload=%q compressed=%v", got[0].Payload, got[0].Compressed)
	}
	if string(got[1].Payload) != "two" || !got[1].Compressed {
		t.Errorf("frame 1: payload=%q compressed=%v", got[1].Payload, got[1].Compressed)
	}
}

func TestFrameBuffer_SplitAcrossWrites(t *testing.T) {
	payload := []byte("split-test-data")
	raw := EncodeFrame(false, payload)

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	// Send header only.
	if err := fb.Write(raw[:3]); err != nil {
		t.Fatalf("Write(1): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 frames after partial header, got %d", len(got))
	}

	// Send rest of header + partial payload.
	if err := fb.Write(raw[3:10]); err != nil {
		t.Fatalf("Write(2): %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected 0 frames after partial payload, got %d", len(got))
	}

	// Send remaining payload.
	if err := fb.Write(raw[10:]); err != nil {
		t.Fatalf("Write(3): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(got))
	}
	if string(got[0].Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", got[0].Payload, payload)
	}
}

func TestFrameBuffer_EmptyPayload(t *testing.T) {
	raw := EncodeFrame(false, nil)

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	if err := fb.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(got))
	}
	if len(got[0].Payload) != 0 {
		t.Errorf("expected empty payload, got %d bytes", len(got[0].Payload))
	}
}

func TestFrameBuffer_InvalidCompressedFlag(t *testing.T) {
	data := []byte{2, 0, 0, 0, 1, 0x42} // compressed flag = 2 (invalid)

	fb := NewFrameBuffer(func(_ []byte, _ *Frame) error {
		t.Fatal("callback should not be called")
		return nil
	})

	err := fb.Write(data)
	if err == nil {
		t.Fatal("expected error for invalid compressed flag")
	}
}

func TestFrameBuffer_Flush_EmptyBuffer(t *testing.T) {
	fb := NewFrameBuffer(nil)
	remaining := fb.Flush()
	if remaining != nil {
		t.Errorf("expected nil, got %v", remaining)
	}
}

func TestFrameBuffer_Flush_PartialFrame(t *testing.T) {
	fb := NewFrameBuffer(nil)

	// Write an incomplete frame (header + 1 byte of expected 5-byte payload).
	partial := []byte{0, 0, 0, 0, 5, 0x42}
	if err := fb.Write(partial); err != nil {
		t.Fatalf("Write: %v", err)
	}

	remaining := fb.Flush()
	if len(remaining) != len(partial) {
		t.Errorf("Flush returned %d bytes, want %d", len(remaining), len(partial))
	}

	// Buffer should be cleared after Flush.
	if fb.Buffered() != 0 {
		t.Errorf("Buffered = %d after Flush, want 0", fb.Buffered())
	}
}

func TestFrameBuffer_CallbackError(t *testing.T) {
	raw := EncodeFrame(false, []byte("test"))
	callbackErr := errors.New("callback failed")

	fb := NewFrameBuffer(func(_ []byte, _ *Frame) error {
		return callbackErr
	})

	err := fb.Write(raw)
	if err == nil {
		t.Fatal("expected error from callback")
	}
	if !errors.Is(err, callbackErr) {
		t.Errorf("error = %v, want wrapping %v", err, callbackErr)
	}
}

func TestFrameBuffer_SplitBetweenFrames(t *testing.T) {
	// Two frames, split exactly at the boundary.
	f1 := EncodeFrame(false, []byte("aaa"))
	f2 := EncodeFrame(false, []byte("bbb"))

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	if err := fb.Write(f1); err != nil {
		t.Fatalf("Write(f1): %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected 1 frame after f1, got %d", len(got))
	}

	if err := fb.Write(f2); err != nil {
		t.Fatalf("Write(f2): %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 frames total, got %d", len(got))
	}
}

func TestFrameBuffer_ByteByByte(t *testing.T) {
	// Feed one byte at a time — tests extreme fragmentation.
	payload := []byte("byte-by-byte")
	raw := EncodeFrame(false, payload)

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	for i := 0; i < len(raw); i++ {
		if err := fb.Write(raw[i : i+1]); err != nil {
			t.Fatalf("Write byte %d: %v", i, err)
		}
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(got))
	}
	if string(got[0].Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", got[0].Payload, payload)
	}
}

func TestFrameBuffer_ConcurrentWrites(t *testing.T) {
	// Verify mutex safety. We don't verify ordering since concurrent
	// writes have undefined interleaving, but we check no panic/data race.
	var mu sync.Mutex
	var count int

	fb := NewFrameBuffer(func(_ []byte, _ *Frame) error {
		mu.Lock()
		count++
		mu.Unlock()
		return nil
	})

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			raw := EncodeFrame(false, []byte("concurrent"))
			fb.Write(raw)
		}()
	}
	wg.Wait()

	mu.Lock()
	if count != 10 {
		t.Errorf("count = %d, want 10", count)
	}
	mu.Unlock()
}

func TestFrameBuffer_NilCallback(t *testing.T) {
	// FrameBuffer with nil callback should not panic.
	fb := NewFrameBuffer(nil)
	raw := EncodeFrame(false, []byte("test"))

	if err := fb.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if fb.Buffered() != 0 {
		t.Errorf("Buffered = %d, want 0", fb.Buffered())
	}
}

func TestFrameBuffer_CompressedFrame(t *testing.T) {
	payload := []byte("compressed-data")
	raw := EncodeFrame(true, payload)

	var got []*Frame
	fb := NewFrameBuffer(func(_ []byte, f *Frame) error {
		got = append(got, f)
		return nil
	})

	if err := fb.Write(raw); err != nil {
		t.Fatalf("Write: %v", err)
	}

	if len(got) != 1 {
		t.Fatalf("expected 1 frame, got %d", len(got))
	}
	if !got[0].Compressed {
		t.Error("expected compressed frame")
	}
	if string(got[0].Payload) != string(payload) {
		t.Errorf("payload = %q, want %q", got[0].Payload, payload)
	}
}

func TestFrameBuffer_RawBytesPreserved(t *testing.T) {
	// Verify that the raw bytes passed to callback are exactly
	// the wire bytes, even when split across writes.
	payload := []byte("preserve-me")
	raw := EncodeFrame(false, payload)

	var gotRaw []byte
	fb := NewFrameBuffer(func(r []byte, _ *Frame) error {
		gotRaw = r
		return nil
	})

	// Split in the middle of the payload.
	mid := len(raw) / 2
	if err := fb.Write(raw[:mid]); err != nil {
		t.Fatalf("Write(1): %v", err)
	}
	if err := fb.Write(raw[mid:]); err != nil {
		t.Fatalf("Write(2): %v", err)
	}

	if string(gotRaw) != string(raw) {
		t.Error("raw bytes not preserved through split writes")
	}
}
