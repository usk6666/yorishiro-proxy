package pipeline

import (
	"context"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// streamBodyCapture accumulates a streamed body for the record, each side
// capped at the record cap (max_record_body_size). The forwarded body is
// never bounded by it. Written on the reading goroutine; read in the
// completion callback, which BodyStream orders after the last write.
type streamBodyCapture struct {
	limit    int64
	semantic []byte
	raw      []byte
	semCut   bool
	rawCut   bool
}

func (c *streamBodyCapture) onSemantic(p []byte) {
	c.semantic, c.semCut = appendCapped(c.semantic, p, c.limit, c.semCut)
}

func (c *streamBodyCapture) onRaw(p []byte) {
	c.raw, c.rawCut = appendCapped(c.raw, p, c.limit, c.rawCut)
}

func appendCapped(dst, p []byte, limit int64, cut bool) ([]byte, bool) {
	if cut {
		return dst, true
	}
	room := limit - int64(len(dst))
	if int64(len(p)) > room {
		if room > 0 {
			dst = append(dst, p[:room]...)
		}
		return dst, true
	}
	return append(dst, p...), false
}

// recordStreamedHTTP records an HTTP message whose body is a BodyStream
// (USK-1409, RFC-001 §3.2.1). The head is projected now (header-arrival
// time, the snapshot / current variant decision); the body and its wire
// bytes are observed while the consumer forwards them, capped at the
// record cap; the Flow rows are saved once the body ended — on whichever
// goroutine ended it — exactly once. A truncated or aborted body is saved
// with what was observed and the anomalies the producer reported.
//
// The modified variant's RawBytes are the encoder's head (the body cannot
// be re-encoded; EncodeWireBytes returns it with ErrPartialWireBytes)
// followed by the observed raw body: a streamed body is never rewritten, so
// that is what reached the wire. env.Raw is never mutated.
func (s *RecordStep) recordStreamedHTTP(ctx context.Context, snap, env *envelope.Envelope, bs *envelope.BodyStream) {
	saveCtx := context.WithoutCancel(ctx)
	headerAt := time.Now()
	capture := &streamBodyCapture{limit: s.recordCap()}

	var flows []*flow.Flow
	if snap != nil && envelopeModified(snap, env) {
		orig := s.envelopeToFlow(saveCtx, snap)
		orig.Metadata["variant"] = "original"
		mod := s.envelopeToFlow(saveCtx, env)
		mod.ID = uuid.NewString()
		mod.Metadata["variant"] = "modified"
		mod.Metadata["base_flow_id"] = env.FlowID
		s.applyWireEncode(saveCtx, env, mod)
		flows = []*flow.Flow{orig, mod}
	} else {
		flows = []*flow.Flow{s.envelopeToFlow(saveCtx, env)}
	}

	bs.Observe(capture.onSemantic, capture.onRaw)
	var once sync.Once
	bs.OnComplete(func(res envelope.BodyResult) {
		once.Do(func() {
			for _, fl := range flows {
				s.finishStreamedFlow(fl, headerAt, capture, res)
				if err := s.store.SaveFlow(saveCtx, fl); err != nil {
					s.logger.Error("record step: streamed flow save failed",
						"stream_id", fl.StreamID,
						"flow_id", fl.ID,
						"direction", fl.Direction,
						"error", err,
					)
				}
			}
		})
	})
}

// finishStreamedFlow completes a head-only Flow with the observed body.
func (s *RecordStep) finishStreamedFlow(fl *flow.Flow, headerAt time.Time, c *streamBodyCapture, res envelope.BodyResult) {
	limit := s.recordCap()
	fl.Timestamp = headerAt
	fl.Body = c.semantic
	fl.BodyTruncated = c.semCut

	raw := make([]byte, 0, len(fl.RawBytes)+len(c.raw))
	raw = append(raw, fl.RawBytes...)
	raw = append(raw, c.raw...)
	cut := c.rawCut
	if int64(len(raw)) > limit {
		raw = raw[:limit:limit]
		cut = true
	}
	fl.RawBytes = raw
	if fl.Metadata["wire_bytes"] == "partial" {
		// The head came from the encoder and the body's wire bytes are
		// appended: the record is the whole wire image (or cut below).
		delete(fl.Metadata, "wire_bytes")
	}
	if cut && !strings.Contains(fl.Metadata[rawTruncatedMetadataKey], "max_record_body_size") {
		markRecordRawTruncated(fl, limit)
	}

	if trlrs := keyValuesToMap(res.Trailers); trlrs != nil {
		fl.Trailers = trlrs
	}
	for _, a := range res.Anomalies {
		if key := httpAnomalyMetadataKey(a.Type); key != "" {
			fl.Metadata[key] = a.Detail
		}
	}
}
