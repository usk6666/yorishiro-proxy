package session

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/bytechunk"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// rawServerFirstFixture wires two bytechunk Layers over loopback TCP
// pairs — the [bytechunk → bytechunk] stack the tcp_forwards raw arm and
// the CONNECT / TLS raw-passthrough arms build — and runs
// RunPreDialedStackSession on it. "client" is the test's view of the
// downstream peer, "server" the upstream peer.
type rawServerFirstFixture struct {
	client net.Conn
	server net.Conn
	done   chan error

	mu          sync.Mutex
	completeID  []string
	completeErr []error
}

func (f *rawServerFirstFixture) completions() ([]string, []error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.completeID...), append([]error(nil), f.completeErr...)
}

func startRawServerFirstFixture(t *testing.T, ctx context.Context) *rawServerFirstFixture {
	t.Helper()

	client, proxyClientSide := pipePair()
	proxyUpstreamSide, server := pipePair()

	stack := connector.NewConnectionStack("test-raw-server-first")
	stack.PushClient(bytechunk.New(proxyClientSide, "conn-raw/client", envelope.Send))
	stack.PushUpstream(bytechunk.New(proxyUpstreamSide, "conn-raw/upstream", envelope.Receive))
	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
		_ = stack.Close()
	})

	f := &rawServerFirstFixture{client: client, server: server, done: make(chan error, 1)}
	opt := SessionOptions{
		OnComplete: func(_ context.Context, streamID string, err error) {
			f.mu.Lock()
			f.completeID = append(f.completeID, streamID)
			f.completeErr = append(f.completeErr, err)
			f.mu.Unlock()
		},
	}
	go func() {
		f.done <- RunPreDialedStackSession(ctx, stack, pipeline.New(), opt)
	}()
	return f
}

func readFullWithin(t *testing.T, c net.Conn, n int, d time.Duration) ([]byte, error) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	buf := make([]byte, n)
	got, err := io.ReadFull(c, buf)
	return buf[:got], err
}

// expectEOFWithin asserts that the next read on c returns io.EOF (a FIN
// relayed by the proxy) before d elapses.
func expectEOFWithin(t *testing.T, c net.Conn, d time.Duration, who string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	defer func() { _ = c.SetReadDeadline(time.Time{}) }()
	var one [1]byte
	n, err := c.Read(one[:])
	if n != 0 || !errors.Is(err, io.EOF) {
		t.Fatalf("%s read = (%d, %v), want (0, EOF) — FIN not relayed within %s", who, n, err, d)
	}
}

// TestRunPreDialedStackSession_RawServerFirstBannerRelayed pins USK-1216:
// on a raw relay the upstream's banner reaches the client although the
// client never sends a byte (SMTP / MySQL / FTP / IMAP greet first).
func TestRunPreDialedStackSession_RawServerFirstBannerRelayed(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f := startRawServerFirstFixture(t, ctx)

	const banner = "220 smtp.example ESMTP ready\r\n"
	if _, err := f.server.Write([]byte(banner)); err != nil {
		t.Fatalf("server write banner: %v", err)
	}
	got, err := readFullWithin(t, f.client, len(banner), 2*time.Second)
	if err != nil || string(got) != banner {
		t.Fatalf("client read banner = %q, %v; want %q without any client send", got, err, banner)
	}

	// The conversation continues normally afterwards.
	if _, err := f.client.Write([]byte("EHLO me\r\n")); err != nil {
		t.Fatalf("client write: %v", err)
	}
	got, err = readFullWithin(t, f.server, len("EHLO me\r\n"), 2*time.Second)
	if err != nil || string(got) != "EHLO me\r\n" {
		t.Fatalf("server read = %q, %v; want EHLO", got, err)
	}

	_ = f.client.Close()
	_ = f.server.Close()
	select {
	case err := <-f.done:
		if err != nil {
			t.Errorf("RunPreDialedStackSession = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("session did not return after both peers closed")
	}
	ids, _ := f.completions()
	if len(ids) != 1 || ids[0] != "conn-raw/client" {
		t.Errorf("OnComplete stream IDs = %v, want [conn-raw/client]", ids)
	}
}

// TestRunPreDialedStackSession_RawFINRelay pins the user-approved FIN
// relay on bytechunk sessions: a clean EOF on one side is passed on as a
// half-close to the other, never as a full close, so the opposite
// direction keeps flowing.
func TestRunPreDialedStackSession_RawFINRelay(t *testing.T) {
	t.Run("client closes without sending; upstream sees EOF", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := startRawServerFirstFixture(t, ctx)

		_ = f.client.Close()
		expectEOFWithin(t, f.server, 2*time.Second, "upstream")
		_ = f.server.Close()
		select {
		case err := <-f.done:
			if err != nil {
				t.Errorf("RunPreDialedStackSession = %v, want nil", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("session did not return after both peers closed")
		}
	})

	t.Run("upstream sends banner and closes; client gets banner then EOF", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := startRawServerFirstFixture(t, ctx)

		const banner = "421 too busy\r\n"
		if _, err := f.server.Write([]byte(banner)); err != nil {
			t.Fatalf("server write: %v", err)
		}
		_ = f.server.Close()
		got, err := readFullWithin(t, f.client, len(banner), 2*time.Second)
		if err != nil || string(got) != banner {
			t.Fatalf("client read banner = %q, %v; want %q", got, err, banner)
		}
		expectEOFWithin(t, f.client, 2*time.Second, "client")
	})

	t.Run("client half-close keeps the response direction flowing", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		f := startRawServerFirstFixture(t, ctx)

		const req = "QUERY everything\n"
		const resp = "RESULT: all of it\n"
		serverDone := make(chan error, 1)
		go func() {
			// Read until the relayed FIN, then answer — the shape of
			// protocols that use a half-close as end-of-request.
			_ = f.server.SetReadDeadline(time.Now().Add(5 * time.Second))
			in, err := io.ReadAll(f.server)
			if err != nil {
				serverDone <- err
				return
			}
			if string(in) != req {
				serverDone <- errors.New("server got " + string(in))
				return
			}
			_, err = f.server.Write([]byte(resp))
			_ = f.server.Close()
			serverDone <- err
		}()

		if _, err := f.client.Write([]byte(req)); err != nil {
			t.Fatalf("client write: %v", err)
		}
		if err := f.client.(*net.TCPConn).CloseWrite(); err != nil {
			t.Fatalf("client CloseWrite: %v", err)
		}
		_ = f.client.SetReadDeadline(time.Now().Add(5 * time.Second))
		got, err := io.ReadAll(f.client)
		if err != nil || string(got) != resp {
			t.Fatalf("client read = %q, %v; want %q then EOF", got, err, resp)
		}
		if err := <-serverDone; err != nil {
			t.Fatalf("server side: %v", err)
		}
	})
}
