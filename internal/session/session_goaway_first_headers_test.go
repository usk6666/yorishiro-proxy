package session

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// USK-1175: the upstream stream is opened (OpenStream) before the upstream
// connection's GOAWAY arrives, and the session's first HEADERS Send happens
// after it. The upstream ignores a stream above its last_stream_id (RFC 9113
// §6.8), so the proxy must refuse the stream locally and propagate the
// refusal to the client as RST_STREAM(REFUSED_STREAM) — the same outcome as
// a stream the GOAWAY refused after its HEADERS went out (USK-1157) — so a
// retrying client re-sends it on a fresh connection instead of hanging.

// rawH2Endpoint is a frame-level HTTP/2 endpoint on one end of a net.Pipe.
// A goroutine forwards every frame read to frames until the pipe closes.
type rawH2Endpoint struct {
	conn   net.Conn
	wr     *frame.Writer
	enc    *hpack.Encoder
	frames chan *frame.Frame
}

func newRawH2Endpoint(conn net.Conn) *rawH2Endpoint {
	e := &rawH2Endpoint{
		conn:   conn,
		wr:     frame.NewWriter(conn),
		enc:    hpack.NewEncoder(4096, true),
		frames: make(chan *frame.Frame, 64),
	}
	return e
}

func (e *rawH2Endpoint) startReading() {
	rd := frame.NewReader(e.conn)
	go func() {
		defer close(e.frames)
		for {
			f, err := rd.ReadFrame()
			if err != nil {
				return
			}
			e.frames <- f
		}
	}()
}

// waitFor returns the first frame matching pred within d, or nil. Frames
// that do not match are passed to seen (if non-nil) and dropped.
func (e *rawH2Endpoint) waitFor(d time.Duration, pred func(*frame.Frame) bool, seen func(*frame.Frame)) *frame.Frame {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for {
		select {
		case f, ok := <-e.frames:
			if !ok {
				return nil
			}
			if pred(f) {
				return f
			}
			if seen != nil {
				seen(f)
			}
		case <-timer.C:
			return nil
		}
	}
}

// newH2ClientLeg builds the client-facing leg the live h2 path uses: a
// ServerRole http2.Layer whose peer is a raw frame-level client that sends a
// GET on stream 1. It returns the aggregator-wrapped client Channel and the
// raw client endpoint.
func newH2ClientLeg(t *testing.T) (layer.Channel, *rawH2Endpoint) {
	t.Helper()
	rawConn, layerConn := net.Pipe()
	client := newRawH2Endpoint(rawConn)
	go func() { _, _ = rawConn.Write([]byte(http2.ClientPreface)) }()
	l, err := http2.New(layerConn, "client-leg", http2.ServerRole)
	if err != nil {
		t.Fatalf("http2.New(ServerRole): %v", err)
	}
	t.Cleanup(func() {
		_ = l.Close()
		_ = rawConn.Close()
	})
	client.startReading()
	if err := client.wr.WriteSettings(nil); err != nil {
		t.Fatalf("client write SETTINGS: %v", err)
	}
	block := client.enc.Encode([]hpack.HeaderField{
		{Name: ":method", Value: "GET"},
		{Name: ":scheme", Value: "https"},
		{Name: ":authority", Value: "example.test"},
		{Name: ":path", Value: "/"},
	})
	if err := client.wr.WriteHeaders(1, true, true, block); err != nil {
		t.Fatalf("client write HEADERS: %v", err)
	}
	var stream layer.Channel
	select {
	case stream = <-l.Channels():
	case <-time.After(2 * time.Second):
		t.Fatal("client leg: no stream emitted")
	}
	return httpaggregator.WrapWithDefaults(stream, httpaggregator.RoleServer, nil), client
}

// newH2UpstreamLeg builds a ClientRole http2.Layer whose peer is a raw
// frame-level origin.
func newH2UpstreamLeg(t *testing.T) (*http2.Layer, *rawH2Endpoint) {
	t.Helper()
	layerConn, rawConn := net.Pipe()
	origin := newRawH2Endpoint(rawConn)
	type res struct {
		l   *http2.Layer
		err error
	}
	done := make(chan res, 1)
	go func() {
		l, err := http2.New(layerConn, "upstream-leg", http2.ClientRole)
		done <- res{l, err}
	}()
	preface := make([]byte, len(http2.ClientPreface))
	if _, err := io.ReadFull(rawConn, preface); err != nil {
		t.Fatalf("origin read preface: %v", err)
	}
	r := <-done
	if r.err != nil {
		t.Fatalf("http2.New(ClientRole): %v", r.err)
	}
	t.Cleanup(func() {
		_ = r.l.Close()
		_ = rawConn.Close()
	})
	origin.startReading()
	return r.l, origin
}

func TestRunSession_H2FirstHeadersAfterUpstreamGoAway_ClientRefused(t *testing.T) {
	clientCh, client := newH2ClientLeg(t)
	upstream, origin := newH2UpstreamLeg(t)

	sawUpstreamHeaders := false
	noteHeaders := func(f *frame.Frame) {
		if f.Header.Type == frame.TypeHeaders {
			sawUpstreamHeaders = true
		}
	}

	dial := func(ctx context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		raw, err := upstream.OpenStream(ctx)
		if err != nil {
			return nil, err
		}
		// GOAWAY lands between OpenStream and the first HEADERS Send.
		if err := origin.wr.WriteGoAway(0, http2.ErrCodeNo, nil); err != nil {
			t.Errorf("origin write GOAWAY: %v", err)
		}
		ping := [8]byte{'u', 's', 'k', '1', '1', '7', '5'}
		if err := origin.wr.WritePing(false, ping); err != nil {
			t.Errorf("origin write PING: %v", err)
		}
		ack := origin.waitFor(2*time.Second, func(f *frame.Frame) bool {
			if f.Header.Type != frame.TypePing || !f.Header.Flags.Has(frame.FlagAck) {
				return false
			}
			got, _ := f.PingData()
			return got == ping
		}, noteHeaders)
		if ack == nil {
			t.Error("origin: no PING ACK; GOAWAY not processed")
		}
		return httpaggregator.WrapWithDefaults(raw, httpaggregator.RoleClient, nil), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- RunSession(ctx, clientCh, dial, pipeline.New(passStep{}))
	}()

	var err error
	select {
	case err = <-done:
	case <-time.After(5 * time.Second):
		cancel()
		<-done
		t.Fatal("RunSession did not return: the stream opened after GOAWAY hangs")
	}
	if got := ClassifyError(err); got != "refused" {
		t.Errorf("ClassifyError(RunSession err = %v) = %q, want %q", err, got, "refused")
	}

	rst := client.waitFor(2*time.Second, func(f *frame.Frame) bool {
		return f.Header.Type == frame.TypeRSTStream && f.Header.StreamID == 1
	}, nil)
	if rst == nil {
		t.Fatal("client received no RST_STREAM on stream 1")
	}
	if code, _ := rst.RSTStreamErrorCode(); code != http2.ErrCodeRefusedStream {
		t.Errorf("client RST_STREAM code = %d (%s), want REFUSED_STREAM",
			code, http2.ErrCodeString(code))
	}

	origin.waitFor(200*time.Millisecond, func(*frame.Frame) bool { return false }, noteHeaders)
	if sawUpstreamHeaders {
		t.Error("HEADERS reached the upstream after its GOAWAY")
	}
}
