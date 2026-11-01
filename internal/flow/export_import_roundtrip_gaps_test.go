package flow

import (
	"bytes"
	"context"
	"reflect"
	"testing"
	"time"
)

// TestExportImport_RoundTripsFailureReasonTimingsAndTrailers pins the
// export → import round trip for the Stream / Flow fields the JSONL format
// used to lose: Stream.FailureReason (absent from ExportStream), the
// send_ms / wait_ms / receive_ms timings (exported but not imported) and
// Flow.Trailers (exported but not imported). The flow sink reuses this
// format, so a re-imported sink file must reproduce them.
func TestExportImport_RoundTripsFailureReasonTimingsAndTrailers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	src := newTestStore(t)
	ts := time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

	send, wait, recv := int64(3), int64(41), int64(7)
	st := &Stream{
		ID:            "rt-gaps-1",
		ConnID:        "conn-rt",
		Protocol:      "http",
		Scheme:        "https",
		State:         "error",
		FailureReason: "refused",
		Timestamp:     ts,
		Duration:      51 * time.Millisecond,
		SendMs:        &send,
		WaitMs:        &wait,
		ReceiveMs:     &recv,
	}
	if err := src.SaveStream(ctx, st); err != nil {
		t.Fatalf("SaveStream: %v", err)
	}
	trailers := map[string][]string{"grpc-status": {"0"}, "X-Trailer": {"a", "b"}}
	fl := &Flow{
		ID:        "rt-gaps-flow-1",
		StreamID:  st.ID,
		Sequence:  1,
		Direction: "receive",
		Timestamp: ts.Add(time.Millisecond),
		Headers:   map[string][]string{"Content-Type": {"text/plain"}},
		Trailers:  trailers,
		Body:      []byte("ok"),
	}
	if err := src.SaveFlow(ctx, fl); err != nil {
		t.Fatalf("SaveFlow: %v", err)
	}

	var buf bytes.Buffer
	if _, err := ExportStreams(ctx, src, &buf, ExportOptions{IncludeBodies: true}); err != nil {
		t.Fatalf("ExportStreams: %v", err)
	}

	dst := newTestStore(t)
	res, err := ImportStreams(ctx, dst, &buf, ImportOptions{})
	if err != nil {
		t.Fatalf("ImportStreams: %v", err)
	}
	if res.Imported != 1 || res.Errors != 0 {
		t.Fatalf("import result = %+v, want 1 imported / 0 errors", res)
	}

	got, err := dst.GetStream(ctx, st.ID)
	if err != nil {
		t.Fatalf("GetStream: %v", err)
	}
	if got.FailureReason != "refused" {
		t.Errorf("FailureReason = %q, want %q", got.FailureReason, "refused")
	}
	for _, c := range []struct {
		name string
		got  *int64
		want int64
	}{{"SendMs", got.SendMs, send}, {"WaitMs", got.WaitMs, wait}, {"ReceiveMs", got.ReceiveMs, recv}} {
		if c.got == nil || *c.got != c.want {
			t.Errorf("%s = %v, want %d", c.name, c.got, c.want)
		}
	}

	gotFlow, err := dst.GetFlow(ctx, fl.ID)
	if err != nil {
		t.Fatalf("GetFlow: %v", err)
	}
	if !reflect.DeepEqual(gotFlow.Trailers, trailers) {
		t.Errorf("Trailers = %v, want %v", gotFlow.Trailers, trailers)
	}
}
