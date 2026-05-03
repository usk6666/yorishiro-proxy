package tcp

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// relayBufSize is the buffer size for bidirectional data relay.
// 32 KB balances memory usage and throughput for typical TCP traffic.
const relayBufSize = 32 * 1024

// RelayConfig holds the parameters for RunRelay.
type RelayConfig struct {
	// Store is the flow writer for recording messages. May be nil to skip recording.
	Store flow.Writer
	// StreamID is the ID of the flow to record messages against.
	StreamID string
	// Logger is the structured logger.
	Logger *slog.Logger
	// Target is the upstream target address (kept for diagnostic logging).
	Target string
}

// RunRelay performs a bidirectional relay between client and upstream,
// recording each chunk as a flow message. This is the exported entry point
// used by both the TCP handler and the SOCKS5 raw TCP dispatch path.
func RunRelay(ctx context.Context, client, upstream net.Conn, cfg RelayConfig) error {
	r := &relay{
		store:  cfg.Store,
		flowID: cfg.StreamID,
		logger: cfg.Logger,
		target: cfg.Target,
	}
	return r.run(ctx, client, upstream)
}

// relay copies data bidirectionally between a client and an upstream
// connection, recording each chunk as a message in the flow store.
type relay struct {
	store  flow.Writer
	flowID string
	logger *slog.Logger
	target string       // forward target address
	seq    atomic.Int64 // next message sequence number
}

// run performs the bidirectional relay until one side closes, an error occurs,
// or the context is cancelled.
func (r *relay) run(ctx context.Context, client, upstream net.Conn) error {
	// Wrap ctx in a relay-scoped cancel context so the watcher goroutine
	// exits when the relay terminates normally (e.g., peer EOF), not only
	// when the parent context is cancelled.
	relayCtx, relayCancel := context.WithCancel(ctx)
	defer relayCancel()

	// Watch for context cancellation and interrupt blocking reads.
	go func() {
		<-relayCtx.Done()
		client.SetReadDeadline(time.Now())
		upstream.SetReadDeadline(time.Now())
	}()

	var (
		once     sync.Once
		firstErr error
	)

	errCh := make(chan error, 2)

	// client -> upstream (send direction)
	go func() {
		err := r.copyAndRecord(ctx, upstream, client, "send")
		once.Do(func() { firstErr = err })
		errCh <- err
		// Signal the other goroutine by unblocking its read.
		upstream.SetReadDeadline(time.Now())
	}()

	// upstream -> client (receive direction)
	go func() {
		err := r.copyAndRecord(ctx, client, upstream, "receive")
		once.Do(func() { firstErr = err })
		errCh <- err
		// Signal the other goroutine by unblocking its read.
		client.SetReadDeadline(time.Now())
	}()

	// Wait for both goroutines.
	<-errCh
	<-errCh

	// Context cancellation is normal during shutdown.
	if ctx.Err() != nil {
		return ctx.Err()
	}

	return firstErr
}

// copyAndRecord reads from src and writes to dst, recording each chunk as a
// message in the flow store. The direction is "send" (client -> upstream)
// or "receive" (upstream -> client).
func (r *relay) copyAndRecord(ctx context.Context, dst, src net.Conn, direction string) error {
	buf := make([]byte, relayBufSize)

	for {
		n, readErr := src.Read(buf)
		if n > 0 {
			chunk := buf[:n]

			// Write to destination first (low latency is more important than recording).
			if _, writeErr := dst.Write(chunk); writeErr != nil {
				return fmt.Errorf("write %s: %w", direction, writeErr)
			}

			// Record the chunk.
			r.record(ctx, direction, chunk)
		}

		if readErr != nil {
			// Check context before returning the read error.
			if ctx.Err() != nil {
				return ctx.Err()
			}
			// EOF and other network close errors are normal termination.
			return nil
		}
	}
}

// record appends a message to the flow store for one data chunk.
// Recording errors are logged but do not interrupt the relay.
func (r *relay) record(ctx context.Context, direction string, data []byte) {
	if r.store == nil {
		return
	}

	seq := int(r.seq.Add(1) - 1)

	// Copy the data to avoid aliasing the read buffer.
	raw := make([]byte, len(data))
	copy(raw, data)

	msg := &flow.Flow{
		StreamID:  r.flowID,
		Sequence:  seq,
		Direction: direction,
		Timestamp: time.Now(),
		RawBytes:  raw,
		Metadata: map[string]string{
			"chunk_size": fmt.Sprintf("%d", len(data)),
		},
	}

	if err := r.store.SaveFlow(ctx, msg); err != nil {
		r.logger.Error("TCP message record failed",
			"flow_id", r.flowID,
			"seq", seq,
			"direction", direction,
			"error", err)
	}
}
