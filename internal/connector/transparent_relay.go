package connector

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
)

// relayTransparent relays bytes between client and upstream until both
// directions end, counting each direction (decision R12). It is the
// transparent listener's own relay, deliberately not the bytechunk
// session nor the shared TLS-passthrough relay:
//
//   - a direction that ends with EOF half-closes the peer (CloseWrite),
//     so the other direction keeps flowing (server-first protocols, a
//     client that half-closes after its request);
//   - a direction that ends with any other error (RST, write failure)
//     aborts the relay: both connections are closed at once, so neither
//     side hangs on a dead peer;
//   - ctx cancellation (policy revoke, listener shutdown) aborts it too,
//     and the returned error is context.Cause(ctx).
//
// Teardown is centralised in abort (sync.Once). Both conns are closed
// when relayTransparent returns. beforeClient, when non-nil, runs on the
// client→upstream goroutine before it copies a byte (the late-TLS
// ClientHello peek); the upstream→client direction is already running
// then, so a server banner is never held back. A non-nil error from it
// aborts the relay before a client byte is copied, and is returned.
func relayTransparent(ctx context.Context, client, upstream net.Conn, c2u, u2c *atomic.Int64, beforeClient func() error) error {
	var (
		once     sync.Once
		mu       sync.Mutex
		firstErr error
	)
	abort := func(err error) {
		once.Do(func() {
			mu.Lock()
			firstErr = err
			mu.Unlock()
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	done := make(chan struct{})
	watcherDone := make(chan struct{})
	go func() {
		defer close(watcherDone)
		select {
		case <-ctx.Done():
			abort(context.Cause(ctx))
		case <-done:
		}
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if beforeClient != nil {
			if err := beforeClient(); err != nil {
				abort(err)
				return
			}
		}
		if err := copyCounted(upstream, client, c2u); err != nil {
			abort(err)
			return
		}
		halfClose(upstream)
	}()
	go func() {
		defer wg.Done()
		if err := copyCounted(client, upstream, u2c); err != nil {
			abort(err)
			return
		}
		halfClose(client)
	}()
	wg.Wait()
	close(done)
	<-watcherDone
	_ = client.Close()
	_ = upstream.Close()

	if ctx.Err() != nil {
		return context.Cause(ctx)
	}
	mu.Lock()
	defer mu.Unlock()
	return firstErr
}

// copyCounted copies src to dst until EOF (nil error), counting the bytes
// written into n.
func copyCounted(dst io.Writer, src io.Reader, n *atomic.Int64) error {
	buf := make([]byte, 32<<10)
	for {
		nr, rerr := src.Read(buf)
		if nr > 0 {
			nw, werr := dst.Write(buf[:nr])
			n.Add(int64(nw))
			if werr != nil {
				return werr
			}
			if nw != nr {
				return io.ErrShortWrite
			}
		}
		if rerr == io.EOF {
			return nil
		}
		if rerr != nil {
			return rerr
		}
	}
}

// halfClose sends FIN on c when it can half-close.
func halfClose(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}
