package connector

import (
	"context"
	"log/slog"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// H2CHandlerConfig holds dependencies for the h2c (cleartext HTTP/2) handler
// factory. The handler constructs a ServerRole HTTP/2 Layer on top of a
// PeekConn whose HTTP/2 preface has been peeked by the FullListener's
// protocol-detection stage, then dispatches each incoming stream to OnStream
// on its own goroutine.
type H2CHandlerConfig struct {
	// OnStream is invoked once per HTTP/2 stream accepted on the client-side
	// Layer. The callback owns the upstream dial, Pipeline wiring, and
	// session.RunSession invocation. A nil value causes every stream to be
	// closed immediately (useful for lifecycle-only tests).
	OnStream func(ctx context.Context, clientCh layer.Channel)

	// Logger for handler-level logging. Nil uses slog.Default().
	Logger *slog.Logger
}

// NewH2CHandler returns a HandlerFunc that accepts a cleartext HTTP/2 (h2c)
// connection on a PeekConn whose HTTP/2 preface has already been peeked by
// the FullListener's detection stage.
//
// The handler:
//  1. Builds an HTTP/2 Layer (ServerRole) on the PeekConn. The buffered
//     preface bytes flow back through PeekConn.Read into the Layer's frame
//     reader during runServerPreface.
//  2. Iterates clientLayer.Channels() and invokes OnStream per stream in
//     its own goroutine.
//  3. Waits for all per-stream goroutines to exit before returning, then
//     closes the Layer (which cascades to the underlying conn).
//
// The caller's OnStream callback is responsible for the upstream dial,
// Pipeline wiring, session.RunSession invocation, and upstream Layer
// cleanup. Keeping those concerns in the callback avoids an import cycle
// between connector and pipeline/session — same pattern as OnStack.
func NewH2CHandler(cfg H2CHandlerConfig) HandlerFunc {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return func(ctx context.Context, pc *PeekConn) error {
		connLogger := LoggerFromContext(ctx, logger)

		connID := ConnIDFromContext(ctx)
		if connID == "" {
			// Defensive fallback. FullListener populates the ConnID on the
			// context, but any direct caller (including tests) may not.
			connID = GenerateConnID()
		}

		envCtx := envelope.EnvelopeContext{
			ConnID: connID,
			// ClientAddr is a net.Addr; the context helper stores a string.
			// Leave nil here — per-stream :authority lives on HTTPMessage,
			// and ClientAddr is not needed to produce a correct envelope.
			// TargetHost is blank by design: per RFC-001 §3.1 the h2c
			// per-stream target is carried by HTTPMessage.Authority.
		}

		clientLayer, err := http2.New(pc, connID+"/client", http2.ServerRole,
			http2.WithScheme("http"),
			http2.WithEnvelopeContext(envCtx),
		)
		if err != nil {
			connLogger.Debug("h2c: server layer construction failed", "error", err)
			return nil
		}
		defer func() { _ = clientLayer.Close() }()

		var wg sync.WaitGroup
		for {
			select {
			case <-ctx.Done():
				// Close the Layer to unblock the reader/writer loops and any
				// per-stream callbacks that honour ch.Next context. Then wait
				// for the callbacks to finish before returning so the handler
				// never leaks goroutines into the caller's lifecycle.
				_ = clientLayer.Close()
				wg.Wait()
				return nil
			case ch, ok := <-clientLayer.Channels():
				if !ok {
					wg.Wait()
					return nil
				}
				wg.Add(1)
				go func(ch layer.Channel) {
					defer wg.Done()
					streamLogger := connLogger.With("h2_stream_id", ch.StreamID())
					streamCtx := ContextWithLogger(ctx, streamLogger)
					if cfg.OnStream != nil {
						cfg.OnStream(streamCtx, ch)
					} else {
						_ = ch.Close()
					}
				}(ch)
			}
		}
	}
}
