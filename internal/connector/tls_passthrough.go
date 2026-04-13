package connector

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
)

// RelayTLSPassthrough performs a bidirectional raw TCP relay between the
// client connection and an upstream connection dialed to the given target.
// No TLS termination occurs — the proxy forwards the client's encrypted
// TLS traffic directly to upstream (and vice versa).
//
// This is used for hosts in the TLS passthrough list where the proxy should
// not perform MITM. No Pipeline, Layer, or ConnectionStack is involved.
//
// The function blocks until both directions are complete or ctx is cancelled.
func RelayTLSPassthrough(ctx context.Context, clientConn net.Conn, target string, opts DialRawOpts) error {
	// Dial upstream as plain TCP (no TLS — we relay the client's TLS directly).
	opts.TLSConfig = nil
	upstreamConn, _, err := DialUpstreamRaw(ctx, target, opts)
	if err != nil {
		return err
	}

	slog.Debug("connector: TLS passthrough relay started", "target", target)

	err = relayBidirectional(ctx, clientConn, upstreamConn)

	slog.Debug("connector: TLS passthrough relay ended",
		"target", target,
		"error", err,
	)
	return err
}

// relayBidirectional copies data between a and b in both directions
// concurrently. It returns when both directions are done or ctx is cancelled.
// Both connections are closed when the function returns.
func relayBidirectional(ctx context.Context, a, b net.Conn) error {
	defer a.Close()
	defer b.Close()

	// Cancel-driven shutdown: when ctx is cancelled, close both connections
	// to unblock the io.Copy goroutines. The done channel ensures the
	// goroutine exits promptly when the relay completes normally without
	// waiting for context cancellation.
	done := make(chan struct{})
	defer close(done)

	if ctx.Done() != nil {
		go func() {
			select {
			case <-ctx.Done():
				a.Close()
				b.Close()
			case <-done:
			}
		}()
	}

	var (
		wg      sync.WaitGroup
		errOnce sync.Once
		copyErr error
	)

	wg.Add(2)

	go func() {
		defer wg.Done()
		if _, err := io.Copy(b, a); err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		// Half-close: signal the other direction that this side is done.
		if tc, ok := b.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	go func() {
		defer wg.Done()
		if _, err := io.Copy(a, b); err != nil {
			errOnce.Do(func() { copyErr = err })
		}
		if tc, ok := a.(interface{ CloseWrite() error }); ok {
			_ = tc.CloseWrite()
		}
	}()

	wg.Wait()

	// If the context was cancelled, report that instead of the copy error.
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return copyErr
}
