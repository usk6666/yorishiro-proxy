// Package session implements the universal session loop that drives all
// protocols through the Codec + Pipeline architecture. RunSession is
// protocol-agnostic: it only knows Codec (parse/serialize) and Pipeline
// (ordered processing steps). Two goroutines handle the bidirectional
// data flow: client-to-upstream and upstream-to-client.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/codec"
	"github.com/usk6666/yorishiro-proxy/internal/exchange"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"golang.org/x/sync/errgroup"
)

// DialFunc creates an upstream Codec lazily. It is called with the first
// Send Exchange so that the target address can be derived from the request
// (e.g., HTTP forward proxy uses the URL to determine the upstream host).
type DialFunc func(ctx context.Context, ex *exchange.Exchange) (codec.Codec, error)

// upstreamHolder passes the upstream Codec from goroutine 1 to goroutine 2
// with proper synchronization via the ready channel. The done channel is
// closed when goroutine 1 exits, allowing goroutine 2 to detect that no
// upstream will ever be established.
type upstreamHolder struct {
	codec codec.Codec
	ready chan struct{} // closed when upstream Codec is established
	done  chan struct{} // closed when goroutine 1 (client→upstream) exits
}

// RunSession is the universal session loop for all protocols.
//
// It reads Exchanges from the client Codec, runs them through the Pipeline,
// and forwards them to an upstream Codec created lazily via dial. A second
// goroutine reads responses from upstream, runs them through the Pipeline,
// and sends them back to the client.
//
// Both goroutines are managed by errgroup.WithContext: if either returns an
// error the context is cancelled and the other goroutine terminates. io.EOF
// from Codec.Next is treated as normal stream termination, not an error.
func RunSession(ctx context.Context, client codec.Codec, dial DialFunc, p *pipeline.Pipeline) error {
	defer client.Close()

	uh := &upstreamHolder{
		ready: make(chan struct{}),
		done:  make(chan struct{}),
	}
	defer func() {
		if uh.codec != nil {
			uh.codec.Close()
		}
	}()

	g, ctx := errgroup.WithContext(ctx)

	g.Go(func() error {
		defer close(uh.done)
		return clientToUpstream(ctx, client, dial, p, uh)
	})

	g.Go(func() error {
		return upstreamToClient(ctx, client, p, uh)
	})

	return g.Wait()
}

// clientToUpstream reads Exchanges from the client, runs them through the
// Pipeline, and forwards them to the upstream Codec. It creates the upstream
// Codec lazily on the first forwarded Exchange and signals uh.ready.
func clientToUpstream(
	ctx context.Context,
	client codec.Codec,
	dial DialFunc,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
) error {
	for {
		ex, err := client.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("client.Next: %w", err)
		}

		ex, action, resp := p.Run(ctx, ex)
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
		if uh.codec == nil {
			u, err := dial(ctx, ex)
			if err != nil {
				return fmt.Errorf("dial: %w", err)
			}
			uh.codec = u
			close(uh.ready)
		}

		if err := uh.codec.Send(ctx, ex); err != nil {
			return fmt.Errorf("upstream.Send: %w", err)
		}
	}
}

// upstreamToClient waits for the upstream Codec to be established, then reads
// Exchanges from it, runs them through the Pipeline, and sends them to the
// client Codec. It returns nil on io.EOF (normal termination) or if goroutine 1
// exits without establishing upstream.
func upstreamToClient(
	ctx context.Context,
	client codec.Codec,
	p *pipeline.Pipeline,
	uh *upstreamHolder,
) error {
	// Wait for upstream to be established, goroutine 1 to exit, or context
	// cancellation. If goroutine 1 exits without establishing upstream
	// (e.g., all Exchanges were dropped), we return immediately.
	select {
	case <-uh.ready:
	case <-uh.done:
		return nil
	case <-ctx.Done():
		return nil
	}

	for {
		ex, err := uh.codec.Next(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("upstream.Next: %w", err)
		}

		ex, action, _ := p.Run(ctx, ex)
		if action == pipeline.Drop {
			continue
		}

		if err := client.Send(ctx, ex); err != nil {
			return fmt.Errorf("client.Send: %w", err)
		}
	}
}
