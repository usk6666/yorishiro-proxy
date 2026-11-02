package http1

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// TestBodyStream_BufferUpToProbe_AllocationBoundedByBody checks that a
// BufferUpTo probe sizes its memory from the body, not from the limit: a
// large plugin_max_body_size must not cost a limit-sized allocation per
// response, and a body above body_spill_threshold (but within the limit)
// must spill rather than be held whole in RAM (USK-1409 review F-1 / S-2).
func TestBodyStream_BufferUpToProbe_AllocationBoundedByBody(t *testing.T) {
	const (
		limit     = 256 << 20 // a valid, large plugin_max_body_size
		threshold = 64 << 10  // body_spill_threshold
		maxAlloc  = 32 << 20  // generous ceiling, far below limit
	)
	cases := []struct {
		name      string
		bodyLen   int
		wantSpill bool
	}{
		{name: "small body", bodyLen: 10},
		{name: "body over spill threshold", bodyLen: 2 << 20, wantSpill: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mode := func(*envelope.Envelope, *envelope.HTTPMessage) layer.BodyMode {
				return layer.BufferUpTo(limit)
			}
			l, peer := newStreamingUpstream(t, mode,
				WithBodySpillDir(t.TempDir()),
				WithBodySpillThreshold(threshold),
				WithMaxBodySize(limit))
			ch := sendExchange(t, l, "GET", "/")

			body := bytes.Repeat([]byte("x"), tc.bodyLen)
			// Chunked: no Content-Length hint for the probe to size from.
			resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n0\r\n\r\n", len(body), body)

			runtime.GC()
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			go func() { _, _ = peer.Write([]byte(resp)) }()
			env := nextWithin(t, ch, 10*time.Second)
			runtime.ReadMemStats(&after)

			if got := after.TotalAlloc - before.TotalAlloc; got > maxAlloc {
				t.Errorf("allocated %d bytes to buffer a %d-byte body (limit %d); want <= %d",
					got, tc.bodyLen, limit, maxAlloc)
			}
			msg := env.Message.(*envelope.HTTPMessage)
			if msg.BodyStream != nil {
				t.Fatal("body within the BufferUpTo limit was streamed; want buffered")
			}
			var gotBody []byte
			if msg.BodyBuffer != nil {
				if tc.wantSpill && !msg.BodyBuffer.IsFileBacked() {
					t.Error("body over body_spill_threshold is not file-backed")
				}
				b, err := msg.BodyBuffer.Bytes(context.Background())
				if err != nil {
					t.Fatalf("BodyBuffer.Bytes: %v", err)
				}
				gotBody = b
			} else {
				if tc.wantSpill {
					t.Error("body over body_spill_threshold was held in memory (no BodyBuffer)")
				}
				gotBody = msg.Body
			}
			if !bytes.Equal(gotBody, body) {
				t.Errorf("body = %d bytes, want %d bytes", len(gotBody), len(body))
			}
		})
	}
}
