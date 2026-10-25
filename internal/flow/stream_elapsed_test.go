package flow

import (
	"context"
	"errors"
	"testing"
	"time"
)

// elapsedFakeReader is a minimal StreamReader double for StreamElapsed.
type elapsedFakeReader struct {
	streams map[string]*Stream
	getErr  error
}

func (f *elapsedFakeReader) GetStream(_ context.Context, id string) (*Stream, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	return f.streams[id], nil
}

func (f *elapsedFakeReader) ListStreams(context.Context, StreamListOptions) ([]*Stream, error) {
	return nil, nil
}

func (f *elapsedFakeReader) CountStreams(context.Context, StreamListOptions) (int, error) {
	return 0, nil
}

// TestStreamElapsed_ZeroGuards pins every guard that must project to the
// zero "do not update" sentinel of StreamUpdate.Duration.
func TestStreamElapsed_ZeroGuards(t *testing.T) {
	tests := []struct {
		name   string
		reader StreamReader
		id     string
	}{
		{name: "nil reader", reader: nil, id: "s1"},
		{name: "GetStream error", reader: &elapsedFakeReader{getErr: errors.New("boom")}, id: "s1"},
		{name: "stream not found", reader: &elapsedFakeReader{streams: map[string]*Stream{}}, id: "missing"},
		{name: "zero timestamp", reader: &elapsedFakeReader{streams: map[string]*Stream{"s1": {ID: "s1"}}}, id: "s1"},
		{name: "future timestamp", reader: &elapsedFakeReader{streams: map[string]*Stream{
			"s1": {ID: "s1", Timestamp: time.Now().Add(time.Hour)},
		}}, id: "s1"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StreamElapsed(context.Background(), tt.reader, tt.id); got != 0 {
				t.Errorf("StreamElapsed() = %v, want 0", got)
			}
		})
	}
}

// TestStreamElapsed_PastTimestamp verifies the production case: a Stream
// whose Timestamp is 1.5s old yields an elapsed time of at least 1.5s.
func TestStreamElapsed_PastTimestamp(t *testing.T) {
	r := &elapsedFakeReader{streams: map[string]*Stream{
		"s1": {ID: "s1", Timestamp: time.Now().Add(-1500 * time.Millisecond)},
	}}
	got := StreamElapsed(context.Background(), r, "s1")
	if got < 1500*time.Millisecond {
		t.Errorf("StreamElapsed() = %v, want >= 1.5s (elapsed since Stream.Timestamp)", got)
	}
	if got > 1500*time.Millisecond+5*time.Second {
		t.Errorf("StreamElapsed() = %v, want roughly 1.5s (sanity ceiling 6.5s)", got)
	}
}
