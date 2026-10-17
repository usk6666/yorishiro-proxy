package http2

import (
	"errors"
	"sync"
	"sync/atomic"

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
// The writer also peeks pending between DATA frames (resetErr) so a reset
// stops a large window grant at the next frame boundary.
type writeSched struct {
	parked map[uint32]*parkedStream
	order  []uint32 // stream ids with parked writes, in parking order

	// reset holds every stream on which no further HEADERS / DATA may be
	// written (RFC 9113 §5.1: closed after RST_STREAM sent or received; or
	// refused by GOAWAY). The value is the result delivered to the done
	// channel of a request for that stream; nil means RST_STREAM(NO_ERROR),
	// the peer's "stop sending, without error" (RFC 9113 §8.1). Entries
	// live for the connection's lifetime, like StreamMap entries (pruning
	// both is USK-1176). Only streams StreamMap knows are recorded, so
	// reset never outgrows StreamMap (see purgeStream).
	reset map[uint32]error

	mu sync.Mutex
	// pending maps stream id to the reset result recorded by another
	// goroutine and not yet applied by the writer. Keyed by stream so a
	// peer repeating RST_STREAM (accepted on a closed stream) or GOAWAY
	// cannot grow it while the writer is stuck in a socket write; the first
	// result recorded wins.
	pending map[uint32]error
	// hasPending mirrors len(pending) > 0 so the writer's per-frame check
	// is a single atomic load when no reset is in flight. Written under mu.
	hasPending atomic.Bool
}

// parkedStream is one stream's FIFO of writes waiting on flow control. The
// head is always a DATA request (possibly partially written).
type parkedStream struct {
	reqs []writeRequest
}

func newWriteSched() *writeSched {
	return &writeSched{
		parked:  make(map[uint32]*parkedStream),
		reset:   make(map[uint32]error),
		pending: make(map[uint32]error),
	}
}

// resetStreamWrites tells the writer that no further HEADERS / DATA may be
// written on streamID; any parked or later-queued write for it completes
// with err (nil for RST_STREAM(NO_ERROR)). Safe from any goroutine; never
// blocks (the reader must not wait on the writer).
func (l *Layer) resetStreamWrites(streamID uint32, err error) {
	l.sched.mu.Lock()
	if _, ok := l.sched.pending[streamID]; !ok {
		l.sched.pending[streamID] = err
	}
	l.sched.hasPending.Store(true)
	l.sched.mu.Unlock()
	l.signalWindowUpdate()
}

// applyPendingResets moves resets recorded by other goroutines into the
// writer-owned state. Writer goroutine only.
func (l *Layer) applyPendingResets() {
	if !l.sched.hasPending.Load() {
		return
	}
	l.sched.mu.Lock()
	pending := l.sched.pending
	l.sched.pending = make(map[uint32]error)
	l.sched.hasPending.Store(false)
	l.sched.mu.Unlock()
	for id, err := range pending {
		l.purgeStream(id, err)
	}
}

// resetErr reports whether streamID has been reset — applied or still
// pending — and the result its writes complete with. It does not modify
// scheduler state, so it is safe in the middle of serviceParked. Writer
// goroutine only.
func (l *Layer) resetErr(streamID uint32) (bool, error) {
	if err, ok := l.sched.reset[streamID]; ok {
		return true, err
	}
	if !l.sched.hasPending.Load() {
		return false, nil
	}
	l.sched.mu.Lock()
	err, ok := l.sched.pending[streamID]
	l.sched.mu.Unlock()
	return ok, err
}

// purgeStream marks streamID reset and completes its parked writes with err.
// Writer goroutine only. The first reset recorded for a stream wins.
//
// A stream StreamMap does not know is not recorded: every local HEADERS /
// DATA is for a stream that already has a StreamMap entry (lazy client id
// allocation transitions the stream before enqueueing its first HEADERS;
// peer streams are transitioned before their Channel is emitted), so there
// is nothing to suppress. This keeps reset no larger than StreamMap when
// the reader refuses a flood of new peer streams with RST_STREAM (CWE-770).
func (l *Layer) purgeStream(streamID uint32, err error) {
	ps, parked := l.sched.parked[streamID]
	if prev, ok := l.sched.reset[streamID]; ok {
		err = prev
	} else if parked || l.conn.Streams().Get(streamID) != nil {
		l.sched.reset[streamID] = err
	}
	if !parked {
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
	// A reset recorded while this stream's earlier writes were going out
	// (serviceParked) withdraws the rest of its FIFO too.
	if ok, err := l.resetErr(streamIDOf(req)); ok {
		failWriteRequest(req, err)
		return true
	}
	if req.headers != nil {
		l.handleWriteHeaders(req.headers)
		return true
	}
	return l.writeDataProgress(req.dataEvent)
}

// streamIDOf returns the stream of a HEADERS or DATA request.
func streamIDOf(req writeRequest) uint32 {
	if req.headers != nil {
		return req.headers.streamID
	}
	return req.dataEvent.streamID
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
