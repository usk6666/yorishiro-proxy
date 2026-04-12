// Package session implements the universal session loop that drives all
// protocols through the Channel + Pipeline architecture. RunSession is
// protocol-agnostic: it only knows Channel (read/write envelopes) and Pipeline
// (ordered processing steps). Two goroutines handle the bidirectional data
// flow: client-to-upstream and upstream-to-client.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"golang.org/x/sync/errgroup"
)

// DialFunc creates an upstream Channel lazily. It is called with the first
// Send Envelope so that the target address can be derived from the envelope's
// Context.TargetHost.
type DialFunc func(ctx context.Context, env *envelope.Envelope) (layer.Channel, error)

// SessionOptions configures optional callbacks for RunSession.
type SessionOptions struct {
	// OnComplete is called after both goroutines have terminated.
	// streamID is the StreamID captured from the first Envelope (may be empty
	// if no Envelope was processed). err is nil on normal EOF termination, or
	// the error that caused the session to end.
	//
	// The context passed to OnComplete is derived from the original context
	// (not the errgroup context), so it remains valid for store writes even
	// after the errgroup cancels its derived context.
	OnComplete func(ctx context.Context, streamID string, err error)
}

// streamCapture captures the StreamID from the first Envelope in a
// goroutine-safe manner.
type streamCapture struct {
	mu       sync.Mutex
	streamID string
	captured bool
}

// set records the StreamID if it has not been captured yet.
func (s *streamCapture) set(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.captured {
		s.streamID = id
		s.captured = true
	}
}

// get returns the captured StreamID.
func (s *streamCapture) get() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.streamID
}

// upstreamHolder passes the upstream Channel from goroutine 1 to goroutine 2
// with proper synchronization via the ready channel. The done channel is
// closed when goroutine 1 exits, allowing goroutine 2 to detect that no
// upstream will ever be established.
type upstreamHolder struct {
	ch    layer.Channel
	ready chan struct{} // closed when upstream Channel is established
	done  chan struct{} // closed when goroutine 1 (client->upstream) exits
}

// RunSession is the universal session loop for all protocols.
//
// It reads Envelopes from the client Channel, runs them through the Pipeline,
// and forwards them to an upstream Channel created lazily via dial. A second
// goroutine reads responses from upstream, runs them through the Pipeline,
// and sends them back to the client.
//
// Both goroutines are managed by errgroup.WithContext: if either returns an
// error the context is cancelled and the other goroutine terminates. io.EOF
// from Channel.Next is treated as normal stream termination, not an error.
func RunSession(ctx context.Context, client layer.Channel, dial DialFunc, p *pipeline.Pipeline, opts ...SessionOptions) error {
	defer client.Close()

	var opt SessionOptions
	if len(opts) > 0 {
		opt = opts[0]
	}

	// Keep a reference to the original context for OnComplete, because
	// errgroup.WithContext creates a derived context that is cancelled when
	// Wait() returns — making it unusable for store writes.
	origCtx := ctx

	uh := &upstreamHolder{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	defer func() {
		if uh.ch != nil {
			uh.ch.Close()
		}
	}()

	sc := &streamCapture{}

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(uh.done)
		return clientToUpstream(ctx, client, dial, p, uh, sc)
	})

	g.Go(func() error {
		return upstreamToClient(ctx, client, p, uh, sc)
	})

	result := g.Wait()

	if opt.OnComplete != nil {
		opt.OnComplete(context.WithoutCancel(origCtx), sc.get(), result)
	}

	return result
}

// clientToUpstream reads Envelopes from the client, runs them through the
// Pipeline, and forwards them to the upstream Channel. It creates the upstream
// Channel lazily on the first forwarded Envelope and signals uh.ready.
func clientToUpstream(
	ctx context.Context,
	client layer.Channel,
	dial DialFunc,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
	sc *streamCapture,
) error {
	for {
		env, err := client.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("client.Next: %w", err)
		}

		sc.set(env.StreamID)

		env, action, resp := p.Run(ctx, env)
		switch action {
		case pipeline.Drop:
			continue
		case pipeline.Respond:
			if err := client.Send(ctx, resp); err != nil {
				return fmt.Errorf("client.Send (respond): %w", err)
			}
			continue
		}

		// Continue: forward to upstream.
		if uh.ch == nil {
			u, err := dial(ctx, env)
			if err != nil {
				return fmt.Errorf("dial: %w", err)
			}
			uh.ch = u
			close(uh.ready)
		}

		if err := uh.ch.Send(ctx, env); err != nil {
			return fmt.Errorf("upstream.Send: %w", err)
		}
	}
}

// upstreamToClient waits for the upstream Channel to be established, then reads
// Envelopes from it, runs them through the Pipeline, and sends them to the
// client Channel. It returns nil on io.EOF (normal termination) or if goroutine 1
// exits without establishing upstream.
func upstreamToClient(
	ctx context.Context,
	client layer.Channel,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
	sc *streamCapture,
) error {
	// Wait for upstream to be established, goroutine 1 to exit, or context
	// cancellation. If goroutine 1 exits without establishing upstream
	// (e.g., all Envelopes were dropped), we return immediately.
	//
	// Priority handling: goroutine 1 closes uh.ready before uh.done, so if
	// we see uh.done we must re-check uh.ready before bailing out — the
	// select-random-choice rule means a naive select could pick uh.done even
	// when uh.ready was closed first. The outer non-blocking probe handles
	// the common fast-path where ready is already closed on entry; the
	// inner re-check handles the case where ready closes just before done
	// while we are waiting.
	select {
	case <-uh.ready:
	default:
		select {
		case <-uh.ready:
		case <-uh.done:
			// goroutine 1 may have closed ready immediately before done.
			// Re-check non-blockingly: if ready is now closed, upstream was
			// established and we must process it; otherwise bail.
			select {
			case <-uh.ready:
			default:
				return nil
			}
		case <-ctx.Done():
			return nil
		}
	}

	for {
		env, err := uh.ch.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("upstream.Next: %w", err)
		}

		sc.set(env.StreamID)

		env, action, _ := p.Run(ctx, env)
		if action == pipeline.Drop {
			continue
		}

		if err := client.Send(ctx, env); err != nil {
			return fmt.Errorf("client.Send: %w", err)
		}
	}
}
