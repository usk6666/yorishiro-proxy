package envelope

import (
	"bytes"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
)

// fakeBodySource is a BodyStreamSource over a fixed byte slice that reports
// each chunk it returns as raw bytes too (prefixed with "raw:").
type fakeBodySource struct {
	bs      *BodyStream
	data    []byte
	endErr  error // error Read returns at the end (io.EOF by default)
	result  BodyResult
	finishN atomic.Int32
	cause   atomic.Value
}

func (f *fakeBodySource) Read(p []byte) (int, error) {
	if len(f.data) == 0 {
		if f.endErr != nil {
			return 0, f.endErr
		}
		return 0, io.EOF
	}
	n := copy(p, f.data)
	f.data = f.data[n:]
	if f.bs != nil {
		f.bs.EmitRaw(append([]byte("raw:"), p[:n]...))
	}
	return n, nil
}

func (f *fakeBodySource) Finish(cause error) BodyResult {
	f.finishN.Add(1)
	f.cause.Store(cause)
	return f.result
}

func newFakeStream(data string) (*BodyStream, *fakeBodySource) {
	src := &fakeBodySource{data: []byte(data)}
	bs := NewBodyStream(src)
	src.bs = bs
	return bs, src
}

func TestBodyStream_ReadObserveComplete(t *testing.T) {
	bs, src := newFakeStream("hello world")
	var sem, raw bytes.Buffer
	bs.Observe(func(p []byte) { sem.Write(p) }, func(p []byte) { raw.Write(p) })
	var results []BodyResult
	bs.OnComplete(func(r BodyResult) { results = append(results, r) })

	p := make([]byte, 5)
	var got bytes.Buffer
	for {
		n, err := bs.Read(p)
		got.Write(p[:n])
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("Read: %v", err)
		}
	}
	if got.String() != "hello world" {
		t.Errorf("Read body = %q, want %q", got.String(), "hello world")
	}
	if sem.String() != "hello world" {
		t.Errorf("semantic observer = %q, want %q", sem.String(), "hello world")
	}
	if raw.String() != "raw:helloraw: worlraw:d" {
		t.Errorf("raw observer = %q", raw.String())
	}
	if len(results) != 1 {
		t.Fatalf("OnComplete fired %d times, want 1", len(results))
	}
	if results[0].Err != nil || results[0].SemanticBytes != 11 {
		t.Errorf("result = %+v, want Err=nil SemanticBytes=11", results[0])
	}
	if c, _ := src.cause.Load().(error); !errors.Is(c, io.EOF) {
		t.Errorf("Finish cause = %v, want io.EOF", c)
	}
	select {
	case <-bs.Done():
	default:
		t.Error("Done not closed after the body ended")
	}
	if n, err := bs.Read(p); n != 0 || err != io.EOF {
		t.Errorf("Read after end = %d, %v; want 0, io.EOF", n, err)
	}
}

func TestBodyStream_ErrorResultSurfacesFromRead(t *testing.T) {
	bs, src := newFakeStream("ab")
	cut := errors.New("cut")
	src.result = BodyResult{Truncated: true, Err: cut}
	if _, err := io.ReadAll(bs); !errors.Is(err, cut) {
		t.Fatalf("ReadAll err = %v, want the result error", err)
	}
	res, ok := bs.Result()
	if !ok || !res.Truncated {
		t.Errorf("Result = %+v, %v; want Truncated, true", res, ok)
	}
}

func TestBodyStream_CloseIdempotentAndOnCompleteAfterEnd(t *testing.T) {
	bs, src := newFakeStream("unread")
	if err := bs.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := bs.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if n := src.finishN.Load(); n != 1 {
		t.Fatalf("Finish called %d times, want 1", n)
	}
	if c, _ := src.cause.Load().(error); !errors.Is(c, ErrBodyStreamClosed) {
		t.Errorf("Finish cause = %v, want ErrBodyStreamClosed", c)
	}
	fired := 0
	bs.OnComplete(func(BodyResult) { fired++ })
	if fired != 1 {
		t.Errorf("OnComplete registered after the end fired %d times, want 1 (immediately)", fired)
	}
	if _, err := bs.Read(make([]byte, 4)); err == nil {
		t.Error("Read after Close returned nil error")
	}
}

// TestBodyStream_CompletesOnceUnderRace races Close against the reading
// goroutine; completion must fire exactly once (run with -race).
func TestBodyStream_CompletesOnceUnderRace(t *testing.T) {
	for i := 0; i < 200; i++ {
		bs, src := newFakeStream("0123456789abcdef")
		var fired atomic.Int32
		bs.OnComplete(func(BodyResult) { fired.Add(1) })
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			_, _ = io.Copy(io.Discard, bs)
		}()
		go func() { defer wg.Done(); _ = bs.Close() }()
		go func() { defer wg.Done(); _ = bs.Close() }()
		wg.Wait()
		_ = src
		if n := fired.Load(); n != 1 {
			t.Fatalf("iter %d: OnComplete fired %d times, want 1", i, n)
		}
		if n := src.finishN.Load(); n != 1 {
			t.Fatalf("iter %d: Finish called %d times, want 1", i, n)
		}
	}
}
