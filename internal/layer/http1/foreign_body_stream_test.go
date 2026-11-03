package http1

import (
	"context"
	"io"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// foreignBodySource is a BodyStream producer that is not an HTTP/1.x
// Channel (an HTTP/2 aggregator's body, USK-1401).
type foreignBodySource struct{ data []byte }

func (s *foreignBodySource) Read(p []byte) (int, error) {
	if len(s.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, s.data)
	s.data = s.data[n:]
	return n, nil
}

func (s *foreignBodySource) Finish(error) envelope.BodyResult { return envelope.BodyResult{} }

// TestSendResponse_ForeignBodyStreamRefused (USK-1401 T17): an HTTP/1.x
// client Channel refuses a streamed response body another protocol produced
// (it can only forward its own upstream's wire bytes verbatim) and closes
// the stream, so the producer is released.
func TestSendResponse_ForeignBodyStreamRefused(t *testing.T) {
	l, peer := newStreamingClient(t, nil)
	go func() { _, _ = io.Copy(io.Discard, peer) }()
	if _, err := peer.Write([]byte("GET / HTTP/1.1\r\nHost: x.test\r\n\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	ch := nextChannelWithin(t, l)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := ch.Next(ctx); err != nil {
		t.Fatalf("Next: %v", err)
	}

	bs := envelope.NewBodyStream(&foreignBodySource{data: []byte("from another protocol")})
	resp := &envelope.Envelope{
		Direction: envelope.Receive,
		Protocol:  envelope.ProtocolHTTP,
		Message:   &envelope.HTTPMessage{Status: 200, BodyStream: bs},
	}
	if err := ch.Send(ctx, resp); err == nil {
		t.Fatal("Send of a foreign body stream succeeded, want an error")
	}
	select {
	case <-bs.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the refused body stream was not closed")
	}
}
