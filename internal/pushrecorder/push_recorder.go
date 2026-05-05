// Package pushrecorder drains HTTP/2 push channels from a ClientRole Layer
// and records each pushed stream into the flow Store as an independent
// flow.Stream.
//
// Context: the HTTP/2 Layer surfaces PUSH_PROMISE as a new *channel with
// isPush=true via Layer.Channels(). On a ClientRole upstream Layer the
// regular OpenStream-initiated streams are NOT sent on Channels(), so an
// upstream Layer's Channels() yields exclusively push channels. Nothing in
// the session loop consumes these — session.RunSession drains only the
// client-facing ServerRole Layer's channels plus the upstream channel it
// got from dial.
//
// Without an explicit drainer pushed streams are never recorded AND the
// Layer.channelOut buffer (size 8) eventually fills, blocking the reader
// goroutine on emitChannel — a correctness problem independent of the
// observability feature.
//
// This package runs one drainer per upstream Layer; the drainer spawns a
// per-channel recorder goroutine that creates the Stream record explicitly
// (RecordStep.createStream is gated on Direction=Send which push envelopes
// never satisfy), pumps the channel through a minimal pipeline, and marks
// Stream.State terminal on EOF/error.
//
// See USK-623.
package pushrecorder

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	intHTTP2 "github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// OriginStreamTag is the flow.Stream.Tags key used to link a pushed stream
// to the client-initiated request stream that carried the PUSH_PROMISE.
// The value is the origin channel's layer.Channel.StreamID() (a UUID), not
// the HTTP/2 wire stream id.
const OriginStreamTag = "push_origin_stream_id"

// RunUpstream drains push channels from an HTTP/2 upstream ClientRole
// Layer and records each pushed stream into store.
//
// The function blocks until upstreamH2.Channels() closes (layer shutdown)
// or ctx is cancelled. It spawns one goroutine per push channel and waits
// for all of them before returning. Callers typically run RunUpstream in
// its own goroutine, tied to the upstream Layer's lifetime.
//
// store is required. When store is nil, RunUpstream returns immediately —
// draining would leak pushes rather than record them, and the design goal
// is specifically to record.
//
// The pipeline applied to each envelope is minimal: Envelope-only steps
// only (HostScopeStep + RecordStep). Intercept/Transform/Safety are
// intentionally skipped — MITM proxies cannot meaningfully mutate a
// server-pushed stream because the client never asked for it, and the
// issue acceptance criteria says "Intercept/Transform cannot be applied to
// push".
func RunUpstream(ctx context.Context, upstreamH2 *intHTTP2.Layer, store flow.Writer, logger *slog.Logger) {
	if upstreamH2 == nil || store == nil {
		return
	}
	if logger == nil {
		logger = slog.Default()
	}

	lopts := httpaggregator.OptionsFromLayer(upstreamH2)

	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case ch, ok := <-upstreamH2.Channels():
			if !ok {
				wg.Wait()
				return
			}
			// Defence in depth: only push channels should arrive on a
			// ClientRole Layer's Channels().
			if !intHTTP2.IsPushChannel(ch) {
				logger.Debug("pushrecorder: non-push channel on upstream Layer ignored",
					"stream_id", ch.StreamID())
				_ = ch.Close()
				continue
			}
			wg.Add(1)
			go func(pushCh layer.Channel) {
				defer wg.Done()
				// USK-637: push channels are event-granular post-split.
				// Wrap with the HTTPAggregator so the recorder sees one
				// HTTPMessage envelope (built from the synthetic
				// PUSH_PROMISE H2HeadersEvent the Layer delivered as the
				// push channel's first envelope) and subsequent response
				// headers/body/trailers as a second aggregated envelope.
				//
				// The synthetic first event carries EndStream=true (see
				// http2.handleStreamPushPromise) so the aggregator emits
				// it immediately as a bodyless HTTPMessage — matching the
				// pre-split behavior where ensureStream used the first
				// envelope's HTTPMessage to seed the Stream row.
				aggCh := httpaggregator.Wrap(pushCh, httpaggregator.RoleClient, nil, lopts)
				record(ctx, aggCh, pushCh, store, logger)
			}(ch)
		}
	}
}

// record drains one push channel to the store. aggCh is the aggregator-
// wrapped channel used for envelope iteration; rawCh is the underlying
// event-granular channel (used for IsPushChannel / PushOriginChannelStreamID
// type assertions that the aggregator does not forward).
func record(ctx context.Context, aggCh, rawCh layer.Channel, store flow.Writer, logger *slog.Logger) {
	defer aggCh.Close()

	streamID := rawCh.StreamID()
	origin, _ := intHTTP2.PushOriginChannelStreamID(rawCh)

	p := pipeline.New(
		pipeline.NewHostScopeStep(nil),
		pipeline.NewRecordStep(store, logger),
	)

	streamCreated := false
	for {
		env, err := aggCh.Next(ctx)
		if err != nil {
			finalizeStream(ctx, store, logger, streamID, origin, streamCreated, err)
			return
		}

		// The first envelope is the synthetic PUSH_PROMISE delivered by
		// the Layer reader (request-side fields populated on HTTPMessage).
		// Create the Stream record now so subsequent SaveFlow calls have a
		// parent row. RecordStep does not create the Stream itself because
		// its createStream gate fires only on Direction=Send+Sequence==0
		// and push envelopes are always Direction=Receive.
		if !streamCreated {
			ensureStream(ctx, store, logger, env, streamID, origin)
			streamCreated = true
		}

		env, _, _ = p.Run(ctx, env)
		// Pipeline.Run may return action=Drop; nothing to forward on a
		// push channel, so the action is ignored. RecordStep has already
		// fired by the time Run returns.
		_ = env
	}
}

// ensureStream saves the initial Stream row for a pushed stream. Scheme
// is taken from the synthetic PUSH_PROMISE HTTPMessage (which carries the
// :scheme pseudo-header from the promise); Protocol is "http" to match
// the RecordStep-created HTTPMessage streams.
func ensureStream(ctx context.Context, store flow.Writer, logger *slog.Logger, env *envelope.Envelope, streamID, origin string) {
	st := &flow.Stream{
		ID:        streamID,
		ConnID:    env.Context.ConnID,
		Protocol:  string(envelope.ProtocolHTTP),
		State:     "active",
		Timestamp: time.Now(),
	}
	if m, ok := env.Message.(*envelope.HTTPMessage); ok && m.Scheme != "" {
		st.Scheme = m.Scheme
	}
	if origin != "" {
		st.Tags = map[string]string{OriginStreamTag: origin}
	}

	if err := store.SaveStream(ctx, st); err != nil {
		logger.Error("pushrecorder: save stream failed",
			"stream_id", streamID,
			"error", err,
		)
	}
}

// finalizeStream writes the Stream's terminal State on drain completion.
// When the channel terminated before delivering any envelope the Stream
// was never created — we do not create an empty Stream row just to mark
// it terminated.
func finalizeStream(ctx context.Context, store flow.Writer, logger *slog.Logger, streamID, origin string, streamCreated bool, err error) {
	if !streamCreated {
		// Nothing was recorded; the pushed stream died before its
		// synthetic PUSH_PROMISE envelope was delivered. Nothing
		// meaningful to surface.
		return
	}
	state := "complete"
	if err != nil && !errors.Is(err, io.EOF) {
		state = "error"
	}
	update := flow.StreamUpdate{
		State:         state,
		FailureReason: session.ClassifyError(err),
	}
	if upErr := store.UpdateStream(ctx, streamID, update); upErr != nil {
		logger.Error("pushrecorder: update stream failed",
			"stream_id", streamID,
			"origin_stream_id", origin,
			"error", upErr,
		)
	}
}
