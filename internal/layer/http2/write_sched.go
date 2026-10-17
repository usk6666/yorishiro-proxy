package http2

import (
	"errors"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/layer"
)

// errWriteAbandoned is delivered to the done channel of a DATA request whose
// caller gave up (ctx cancelled) before the writer finished it. The caller
// has already returned ctx.Err(), so nobody normally reads this value; it
// exists so done is still signalled exactly once.
var errWriteAbandoned = errors.New("http2: DATA write abandoned by caller")

// writeSched is the writer goroutine's flow-control scheduler (USK-1166).
//
// RFC 9113 §5.2 / §6.9 make DATA the only flow-controlled frame. The writer
// therefore never waits for window inline: a DATA request that does not fit
// the stream / connection send window is parked on its stream's FIFO and the
// writer goes back to serving the queue. Everything else — other streams'
// HEADERS and DATA, RST_STREAM, WINDOW_UPDATE, PING ACK, SETTINGS (ACK),
// GOAWAY — keeps flowing. Parked streams are resumed when the reader signals
// new window (WINDOW_UPDATE, SETTINGS_INITIAL_WINDOW_SIZE), and purged when
// the stream is reset in either direction or refused by a GOAWAY.
//
// Per-stream ordering: once a stream has parked writes, any later HEADERS
// (trailers) or DATA for that stream is appended behind them, so a stream's
// frames reach the wire in Send order. A stream's FIRST HEADERS can never be
// parked (nothing precedes it on that stream), which keeps the USK-740
// invariant that client stream ids reach the wire in allocation order.
//
// parked / order / reset are owned by the writer goroutine and are touched
// only from it. pending is the cross-goroutine hand-off for resets observed
// by the reader goroutine; it is guarded by mu and drained by the writer.
type writeSched struct {
	parked map[uint32]*parkedStream
	order  []uint32 // stream ids with parked writes, in parking order

	// reset holds every stream on which no further HEADERS / DATA may be
	// written (RFC 9113 §5.1: closed after RST_STREAM sent or received; or
	// refused by GOAWAY). The value is the result delivered to the done
	// channel of a request for that stream; nil means RST_STREAM(NO_ERROR),
	// the peer's "stop sending, without error" (RFC 9113 §8.1). Entries
	// live for the connection's lifetime, like StreamMap entries (pruning
	// both is USK-1176).
	reset map[uint32]error

	mu      sync.Mutex
	pending []streamReset
}

// parkedStream is one stream's FIFO of writes waiting on flow control. The
// head is always a DATA request (possibly partially written).
type parkedStream struct {
	reqs []writeRequest
}

type streamReset struct {
	streamID uint32
	err      error
}

func newWriteSched() *writeSched {
	return &writeSched{
		parked: make(map[uint32]*parkedStream),
		reset:  make(map[uint32]error),
	}
}

// resetStreamWrites tells the writer that no further HEADERS / DATA may be
// written on streamID; any parked or later-queued write for it completes
// with err (nil for RST_STREAM(NO_ERROR)). Safe from any goroutine; never
// blocks (the reader must not wait on the writer).
func (l *Layer) resetStreamWrites(streamID uint32, err error) {
	l.sched.mu.Lock()
	l.sched.pending = append(l.sched.pending, streamReset{streamID: streamID, err: err})
	l.sched.mu.Unlock()
	l.signalWindowUpdate()
}

// applyPendingResets moves resets recorded by other goroutines into the
// writer-owned state. Writer goroutine only.
func (l *Layer) applyPendingResets() {
	l.sched.mu.Lock()
	pending := l.sched.pending
	l.sched.pending = nil
	l.sched.mu.Unlock()
	for _, r := range pending {
		l.purgeStream(r.streamID, r.err)
	}
}

// purgeStream marks streamID reset and completes its parked writes with err.
// Writer goroutine only. The first reset recorded for a stream wins.
func (l *Layer) purgeStream(streamID uint32, err error) {
	if _, ok := l.sched.reset[streamID]; !ok {
		l.sched.reset[streamID] = err
	} else {
		err = l.sched.reset[streamID]
	}
	ps, ok := l.sched.parked[streamID]
	if !ok {
		return
	}
	for _, req := range ps.reqs {
		failWriteRequest(req, err)
	}
	l.unpark(streamID)
}

// unpark removes streamID from the parked set. Writer goroutine only.
func (l *Layer) unpark(streamID uint32) {
	delete(l.sched.parked, streamID)
	for i, id := range l.sched.order {
		if id == streamID {
			l.sched.order = append(l.sched.order[:i], l.sched.order[i+1:]...)
			return
		}
	}
}

// park appends req to streamID's parked FIFO. Writer goroutine only.
func (l *Layer) park(streamID uint32, req writeRequest) {
	ps, ok := l.sched.parked[streamID]
	if !ok {
		ps = &parkedStream{}
		l.sched.parked[streamID] = ps
		l.sched.order = append(l.sched.order, streamID)
	}
	ps.reqs = append(ps.reqs, req)
}

// scheduleStreamWrite routes a HEADERS or DATA request for streamID: it is
// failed if the stream was reset, appended behind the stream's parked writes
// if it has any, and otherwise written now (DATA that runs out of window is
// parked). Writer goroutine only.
func (l *Layer) scheduleStreamWrite(streamID uint32, req writeRequest) {
	if err, ok := l.sched.reset[streamID]; ok {
		failWriteRequest(req, err)
		return
	}
	if _, ok := l.sched.parked[streamID]; ok {
		l.park(streamID, req)
		return
	}
	if !l.writeStreamRequest(req) {
		l.park(streamID, req)
	}
}

// writeStreamRequest writes a HEADERS request, or as much of a DATA request
// as the windows allow. It reports false when a DATA request is out of
// window and must stay parked; true when the request is finished (its done
// has been signalled). Writer goroutine only.
func (l *Layer) writeStreamRequest(req writeRequest) bool {
	if req.headers != nil {
		l.handleWriteHeaders(req.headers)
		return true
	}
	return l.writeDataProgress(req.dataEvent)
}

// serviceParked resumes parked streams in parking order after a window
// change or a reset. Writer goroutine only.
func (l *Layer) serviceParked() {
	for i := 0; i < len(l.sched.order); {
		id := l.sched.order[i]
		ps := l.sched.parked[id]
		for len(ps.reqs) > 0 && l.writeStreamRequest(ps.reqs[0]) {
			ps.reqs[0] = writeRequest{}
			ps.reqs = ps.reqs[1:]
		}
		if len(ps.reqs) == 0 {
			delete(l.sched.parked, id)
			l.sched.order = append(l.sched.order[:i], l.sched.order[i+1:]...)
			continue
		}
		i++
	}
}

// failParkedWrites completes every parked write with err. Runs as a defer in
// writerLoop so no Send waiting in waitDone is left without a result.
func (l *Layer) failParkedWrites(err error) {
	for _, id := range append([]uint32(nil), l.sched.order...) {
		for _, req := range l.sched.parked[id].reqs {
			failWriteRequest(req, err)
		}
		l.unpark(id)
	}
}

// localResetError is the result delivered to writes withdrawn because this
// endpoint sent RST_STREAM(code) on their stream.
func localResetError(code uint32) error {
	return &layer.StreamError{
		Code:   translateH2StreamError(code),
		Reason: "RST_STREAM sent (" + ErrCodeString(code) + ")",
	}
}
