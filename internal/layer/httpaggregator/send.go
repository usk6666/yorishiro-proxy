package httpaggregator

import (
	"context"
	"fmt"
	"io"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
)

// sendChunkSize bounds the in-memory chunk size when emitting a large
// BodyBuffer body as DATA events. The Layer's writer further splits these
// at MAX_FRAME_SIZE, so this value is mostly a convenience for streaming
// file-backed readers without materializing the entire body into memory.
const sendChunkSize = 64 * 1024

// Send decomposes the aggregated HTTPMessage envelope into events and
// dispatches them sequentially on the underlying Channel: first an
// H2HeadersEvent, then H2DataEvent (optionally), then H2TrailersEvent
// (optionally). EndStream placement follows RFC 9113 §8.1 (trailers carry
// END_STREAM when present, else the last DATA, else the HEADERS event).
//
// TODO(USK-637 follow-up / USK-617 perf): Opaque zero-copy fast path
// dropped for N6.7 — Send always re-encodes via the event path. Restore
// if profiling warrants.
func (a *aggregatorChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok {
		return fmt.Errorf("httpaggregator: Send requires *HTTPMessage, got %T", env.Message)
	}

	hasBody := len(msg.Body) > 0 || msg.BodyBuffer != nil || msg.BodyStream != nil
	hasTrailers := len(msg.Trailers) > 0

	// 1. HEADERS event.
	hdrEvt := &http2.H2HeadersEvent{
		Method:       msg.Method,
		Scheme:       msg.Scheme,
		Authority:    msg.Authority,
		Path:         msg.Path,
		RawQuery:     msg.RawQuery,
		Status:       msg.Status,
		StatusReason: msg.StatusReason,
		Headers:      cloneKVs(msg.Headers),
		EndStream:    !hasBody && !hasTrailers,
	}
	hdrEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   hdrEvt,
		Context:   env.Context,
	}
	if err := a.inner.Send(ctx, hdrEnv); err != nil {
		return err
	}

	// 2. DATA event(s).
	if hasBody {
		if err := a.sendBody(ctx, env, msg, !hasTrailers); err != nil {
			return err
		}
	}

	// 3. TRAILERS event.
	if hasTrailers {
		tEvt := &http2.H2TrailersEvent{
			Trailers: cloneKVs(msg.Trailers),
		}
		tEnv := &envelope.Envelope{
			StreamID:  env.StreamID,
			FlowID:    env.FlowID,
			Sequence:  env.Sequence,
			Direction: env.Direction,
			Protocol:  envelope.ProtocolHTTP,
			Message:   tEvt,
			Context:   env.Context,
		}
		if err := a.inner.Send(ctx, tEnv); err != nil {
			return err
		}
	}

	return nil
}

// sendBody emits the body as one or more H2DataEvent envelopes. The final
// DATA event carries END_STREAM iff endStreamOnFinal is true (i.e., no
// trailers follow).
func (a *aggregatorChannel) sendBody(ctx context.Context, env *envelope.Envelope, msg *envelope.HTTPMessage, endStreamOnFinal bool) error {
	// Fast path: memory-resident body.
	if msg.Body != nil {
		return a.sendDataEventForBytes(ctx, env, msg.Body, endStreamOnFinal)
	}

	// Disk-backed BodyBuffer: stream through its Reader in chunks.
	if msg.BodyBuffer != nil {
		r, rerr := msg.BodyBuffer.Reader()
		if rerr != nil {
			return fmt.Errorf("httpaggregator: open body buffer reader: %w", rerr)
		}
		defer r.Close()
		return a.streamBodyFromReader(ctx, env, r, endStreamOnFinal)
	}

	// Explicit BodyStream (future streaming path).
	if msg.BodyStream != nil {
		return a.streamBodyFromReader(ctx, env, msg.BodyStream, endStreamOnFinal)
	}

	return nil
}

// sendDataEventForBytes wraps payload in a single H2DataEvent envelope and
// sends it. The Layer's writer is responsible for splitting at
// MAX_FRAME_SIZE; the aggregator does not need to fragment here.
func (a *aggregatorChannel) sendDataEventForBytes(ctx context.Context, env *envelope.Envelope, payload []byte, endStream bool) error {
	evt := &http2.H2DataEvent{
		Payload:   payload,
		EndStream: endStream,
	}
	dEnv := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  envelope.ProtocolHTTP,
		Message:   evt,
		Context:   env.Context,
	}
	return a.inner.Send(ctx, dEnv)
}

// streamBodyFromReader reads from r in sendChunkSize chunks and emits
// H2DataEvent envelopes for each. The final event carries END_STREAM iff
// endStreamOnFinal is true and EOF is reached.
func (a *aggregatorChannel) streamBodyFromReader(ctx context.Context, env *envelope.Envelope, r io.Reader, endStreamOnFinal bool) error {
	buf := make([]byte, sendChunkSize)
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		n, rerr := io.ReadFull(r, buf)
		eof := rerr == io.EOF || rerr == io.ErrUnexpectedEOF
		if !eof && rerr != nil {
			return fmt.Errorf("httpaggregator: read body: %w", rerr)
		}

		if n == 0 {
			if eof && endStreamOnFinal {
				// Emit empty END_STREAM DATA to close the stream.
				return a.sendDataEventForBytes(ctx, env, nil, true)
			}
			return nil
		}

		chunk := buf[:n]
		endStream := eof && endStreamOnFinal
		if err := a.sendDataEventForBytes(ctx, env, append([]byte(nil), chunk...), endStream); err != nil {
			return err
		}
		if eof {
			return nil
		}
	}
}
