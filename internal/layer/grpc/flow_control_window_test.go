package grpc_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	nethttp "net/http"
	"testing"
	"time"

	xhttp2 "golang.org/x/net/http2"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// TestGRPC_MessageLargerThanStreamWindowCompletes (USK-1399): a gRPC
// message larger than the advertised stream window only arrives if the h2
// Layer returns stream credit as the gRPC channel reads DATA frames, not
// when the whole message has been reassembled. The peer is x/net's HTTP/2
// client, which honours flow control exactly; the Layer advertises the RFC
// 9113 default 65535-byte window, so a 1 MiB message needs ~16 window
// refills.
func TestGRPC_MessageLargerThanStreamWindowCompletes(t *testing.T) {
	cliConn, srvConn := net.Pipe()
	t.Cleanup(func() { _ = cliConn.Close(); _ = srvConn.Close() })

	type res struct {
		l   *http2.Layer
		err error
	}
	lc := make(chan res, 1)
	go func() {
		l, err := http2.New(srvConn, "grpc-window", http2.ServerRole, http2.WithInitialSettings(http2.DefaultSettings()))
		lc <- res{l, err}
	}()

	tr := &xhttp2.Transport{}
	cc, err := tr.NewClientConn(cliConn)
	if err != nil {
		t.Fatalf("NewClientConn: %v", err)
	}
	t.Cleanup(func() { _ = cc.Close() })
	r := <-lc
	if r.err != nil {
		t.Fatalf("http2.New: %v", r.err)
	}
	t.Cleanup(func() { _ = r.l.Close() })

	msg := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	lpm := make([]byte, 5, 5+len(msg))
	binary.BigEndian.PutUint32(lpm[1:], uint32(len(msg)))
	lpm = append(lpm, msg...)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, _ := nethttp.NewRequestWithContext(ctx, "POST", "https://example.com/pkg.Svc/Method", bytes.NewReader(lpm))
	req.Header.Set("Content-Type", "application/grpc")
	req.Header.Set("Te", "trailers")
	go func() {
		resp, rerr := cc.RoundTrip(req)
		if rerr == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
		}
	}()

	var stream interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case ch := <-r.l.Channels():
		stream = grpclayer.Wrap(ch, nil, grpclayer.RoleServer)
	case <-ctx.Done():
		t.Fatal("no stream accepted")
	}
	for {
		env, err := stream.Next(ctx)
		if err != nil {
			t.Fatalf("gRPC Next before the message completed: %v", err)
		}
		if d, ok := env.Message.(*envelope.GRPCDataMessage); ok {
			if !bytes.Equal(d.Payload, msg) {
				t.Fatalf("message payload = %d bytes, want the %d-byte message", len(d.Payload), len(msg))
			}
			return
		}
	}
}
