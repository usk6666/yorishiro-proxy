package pipeline

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// realH1RequestEnvelope feeds rawRequest (a complete HTTP/1.x request as
// written by a client) through the production client-facing HTTP/1.x
// Layer and returns the Send envelope it yields. USK-1139 tests use it so
// HTTPMessage.Path comes from the real parser, not from a hand-built
// fixture.
func realH1RequestEnvelope(t *testing.T, scheme, rawRequest string) *envelope.Envelope {
	t.Helper()
	cli, srv := net.Pipe()
	l := http1.New(srv, "usk1139-h1", envelope.Send, http1.WithScheme(scheme))
	t.Cleanup(func() {
		_ = l.Close()
		_ = cli.Close()
	})
	go func() { _, _ = cli.Write([]byte(rawRequest)) }()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var ch interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case c := <-l.Channels():
		ch = c
	case <-ctx.Done():
		t.Fatalf("http1 Layer yielded no channel")
	}
	env, err := ch.Next(ctx)
	if err != nil {
		t.Fatalf("http1 Next(%q): %v", rawRequest, err)
	}
	if _, ok := env.Message.(*envelope.HTTPMessage); !ok {
		t.Fatalf("http1 Next: Message = %T, want *HTTPMessage", env.Message)
	}
	return env
}

// realH2RequestEnvelope sends a request whose :path is wirePath (plus
// "?"+rawQuery when non-empty) from a ClientRole HTTP/2 Layer to a
// ServerRole HTTP/2 Layer over net.Pipe, aggregates the server-side stream
// with httpaggregator (the production live-path wiring) and returns the
// resulting Send envelope. HTTPMessage.Path therefore comes from the real
// HPACK decode + assembler :path split.
func realH2RequestEnvelope(t *testing.T, scheme, authority, wirePath, rawQuery string) *envelope.Envelope {
	t.Helper()
	cliConn, srvConn := net.Pipe()

	type srvResult struct {
		l   *http2.Layer
		err error
	}
	srvCh := make(chan srvResult, 1)
	go func() {
		l, err := http2.New(srvConn, "usk1139-h2-srv", http2.ServerRole)
		srvCh <- srvResult{l, err}
	}()
	cl, err := http2.New(cliConn, "usk1139-h2-cli", http2.ClientRole, http2.WithScheme(scheme))
	if err != nil {
		t.Fatalf("client http2.New: %v", err)
	}
	sr := <-srvCh
	if sr.err != nil {
		t.Fatalf("server http2.New: %v", sr.err)
	}
	t.Cleanup(func() {
		_ = cl.Close()
		_ = sr.l.Close()
		_ = cliConn.Close()
		_ = srvConn.Close()
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	stream, err := cl.OpenStream(ctx)
	if err != nil {
		t.Fatalf("OpenStream: %v", err)
	}
	if err := stream.Send(ctx, &envelope.Envelope{
		Direction: envelope.Send,
		Protocol:  envelope.ProtocolHTTP,
		Message: &http2.H2HeadersEvent{
			Method:    "GET",
			Scheme:    scheme,
			Authority: authority,
			Path:      wirePath,
			RawQuery:  rawQuery,
			EndStream: true,
		},
	}); err != nil {
		t.Fatalf("client Send: %v", err)
	}

	var agg interface {
		Next(context.Context) (*envelope.Envelope, error)
	}
	select {
	case sch := <-sr.l.Channels():
		agg = httpaggregator.WrapWithDefaults(sch, httpaggregator.RoleServer, nil)
	case <-ctx.Done():
		t.Fatalf("server http2 Layer yielded no stream")
	}
	env, err := agg.Next(ctx)
	if err != nil {
		t.Fatalf("aggregator Next: %v", err)
	}
	if _, ok := env.Message.(*envelope.HTTPMessage); !ok {
		t.Fatalf("aggregator Next: Message = %T, want *HTTPMessage", env.Message)
	}
	return env
}
