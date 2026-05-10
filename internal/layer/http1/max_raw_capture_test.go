package http1

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// USK-800: WithMaxRawCaptureSize installed on the Layer threads through
// bodyOpts → parser.ParseOptions and bounds the header-section RawBytes
// capture. RawBytes for an oversize header section becomes a prefix of
// the configured cap.
//
// (Body capture in production wiring is always under spill control —
// configureRawBodySpill enables spill on every parser body reader — and
// therefore the body branch obeys spill.maxSize rather than the per-Layer
// cap. See WithMaxRawCaptureSize godoc and Config.MaxRawCaptureSize
// godoc for the spill-mode-vs-memory-mode interaction.)
func TestLayer_WithMaxRawCaptureSize_TruncatesHeaderSection(t *testing.T) {
	const cap = 1 << 9 // 512 B

	// Build a request whose header section alone clears 512 B. Many short
	// X-Pad-NN lines accumulate fast; combined with the request line and
	// Host header the section exceeds 512 B before the blank-line
	// terminator.
	var b strings.Builder
	b.WriteString("POST / HTTP/1.1\r\n")
	b.WriteString("Host: x\r\n")
	b.WriteString("Content-Length: 0\r\n")
	b.WriteString("Connection: close\r\n")
	for i := 0; i < 16; i++ {
		b.WriteString(fmt.Sprintf("X-Pad-%02d: %s\r\n", i, strings.Repeat(".", 40)))
	}
	b.WriteString("\r\n")
	req := b.String()
	if len(req) <= cap {
		t.Fatalf("test fixture insufficient: header section len=%d, want >%d", len(req), cap)
	}

	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send, WithMaxRawCaptureSize(cap))
	defer l.Close()

	go func() {
		_, _ = client.Write([]byte(req))
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	rawReq := env.Opaque.(*opaqueHTTP1).rawReq
	if !rawReq.Truncated {
		t.Errorf("rawReq.Truncated = false, want true (header section %d B > cap %d B)",
			len(req), cap)
	}
	if got := len(rawReq.RawBytes); got != cap {
		t.Errorf("len(rawReq.RawBytes) = %d, want %d", got, cap)
	}
}

// USK-800: zero / unset WithMaxRawCaptureSize preserves the existing
// 2 MiB package default — a small request must NOT be truncated.
func TestLayer_DefaultMaxRawCaptureSize_DoesNotTruncateSmallRequest(t *testing.T) {
	req := "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"

	client, server := testConn(t)
	defer client.Close()
	defer server.Close()

	l := New(server, "stream-1", envelope.Send) // no WithMaxRawCaptureSize
	defer l.Close()

	go func() {
		_, _ = client.Write([]byte(req))
	}()

	ch := <-l.Channels()
	env, err := ch.Next(context.Background())
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	rawReq := env.Opaque.(*opaqueHTTP1).rawReq
	if rawReq.Truncated {
		t.Errorf("rawReq.Truncated = true under default cap (2 MiB) for %d-byte request",
			len(req))
	}
}

// USK-800: capForTruncationDetail reads the per-Layer configured cap when
// truncation occurs in memory-only body capture mode (the path used by
// legacy test fixtures and any caller that does not invoke
// configureRawBodySpill). Verifies decision #15 of the design review —
// the anomaly Detail must report the per-Layer cap, not the package
// default.
func TestCapForTruncationDetail_PerLayerCap(t *testing.T) {
	tests := []struct {
		name    string
		opts    bodyOpts
		spilled bool
		want    int64
	}{
		{
			name:    "memory mode with explicit cap",
			opts:    bodyOpts{maxRawCapture: 1024},
			spilled: false,
			want:    1024,
		},
		{
			name:    "memory mode with zero cap falls back to parser default",
			opts:    bodyOpts{},
			spilled: false,
			want:    int64(parser.MaxRawCaptureSize),
		},
		{
			name:    "spill mode honors maxBody (per-Layer)",
			opts:    bodyOpts{maxBody: 4096, maxRawCapture: 1024},
			spilled: true,
			want:    4096,
		},
		{
			name:    "spill mode with zero maxBody falls back to config.MaxBodySize",
			opts:    bodyOpts{maxRawCapture: 1024},
			spilled: true,
			want:    int64(config.MaxBodySize),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := capForTruncationDetail(tt.opts, tt.spilled)
			if got != tt.want {
				t.Errorf("capForTruncationDetail = %d, want %d", got, tt.want)
			}
		})
	}
}
