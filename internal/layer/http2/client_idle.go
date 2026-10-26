package http2

import (
	"log/slog"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/frame"
)

// Client idle bound (USK-1188).
//
// A client-facing (ServerRole) Layer configured with WithClientIdleTimeout
// closes the connection once it has had no open stream for the bound: it
// sends GOAWAY(NO_ERROR, last processed client stream id), lingers briefly so
// the GOAWAY reaches the client, and closes. This is the shape of Go
// x/net/http2's Server.IdleTimeout:
//
//   - The idle period starts when the connection starts (after the preface)
//     and again each time the last open stream closes. It is absolute: PING,
//     SETTINGS, WINDOW_UPDATE and PRIORITY do not reset it.
//   - While any stream is open or half-closed (StreamMap.ActiveCount) there
//     is no deadline, so gRPC streaming, SSE and extended-CONNECT tunnels
//     are never cut. A header block still waiting for CONTINUATION also
//     defers the GOAWAY.
//   - A HEADERS that races the deadline either wins (the stream is
//     registered first: no GOAWAY while it is open) or loses (GOAWAY is
//     sent first with a last_stream_id below it: the stream is ignored, so
//     the client may retry it on a new connection, RFC 9113 §6.8). The
//     decision is serialized by l.mu: assemblerFor registers new peer
//     streams under it, and idleGoAway checks and marks GOAWAY under it.
//
// One idleLoop goroutine per such Layer owns the timer. The retire
// functions (stream_retire.go) wake it through streamsChanged whenever a
// stream closes; it exits on l.shutdown, or after closing the Layer itself.

// idleGoAwayLingerDefault is how long the Layer keeps the connection after
// the idle GOAWAY was written before closing it, so the client reads the
// GOAWAY rather than a bare connection reset (Go's goAwayTimeout,
// golang/go#18701). The peer closing first ends it early.
const idleGoAwayLingerDefault = time.Second

// setPendingHeaderStream records which stream's header block awaits
// CONTINUATION (0 = none). Reader goroutine only.
func (l *Layer) setPendingHeaderStream(streamID uint32) {
	l.pendingHeaderStream = streamID
	l.headerBlockOpen.Store(streamID != 0)
}

// signalStreamsChanged wakes idleLoop after a stream was retired. Never
// blocks; a no-op when the Layer runs no idleLoop.
func (l *Layer) signalStreamsChanged() {
	if l.streamsChanged == nil {
		return
	}
	select {
	case l.streamsChanged <- struct{}{}:
	default:
	}
}

// idleLoop runs the client idle bound. It terminates on l.shutdown or after
// closing the Layer when the bound elapsed.
func (l *Layer) idleLoop() {
	defer close(l.idleDone)

	timer := time.NewTimer(time.Hour)
	timer.Stop()
	defer timer.Stop()

	// epochLast is LastPeerStreamID when the current idle period started; a
	// different value at the deadline means a stream arrived since.
	var epochLast uint32
	if l.conn.Streams().ActiveCount() == 0 {
		epochLast = l.startIdlePeriod(timer)
	}
	for {
		select {
		case <-l.shutdown:
			return
		case <-l.streamsChanged:
			if l.conn.Streams().ActiveCount() == 0 {
				epochLast = l.startIdlePeriod(timer)
			} else {
				timer.Stop()
			}
		case <-timer.C:
			if done, ok := l.idleGoAway(epochLast); ok {
				l.lingerAndClose(done)
				return
			}
			// Not idle after all (a stream arrived or is mid-header-block):
			// start over if nothing is open; otherwise the stream's close
			// wakes us.
			if l.conn.Streams().ActiveCount() == 0 {
				epochLast = l.startIdlePeriod(timer)
			}
		}
	}
}

// startIdlePeriod arms timer for a new idle period, resolving the bound now
// so a runtime change applies from the next idle period, and returns the
// period's LastPeerStreamID. A disabled bound leaves the timer stopped.
func (l *Layer) startIdlePeriod(timer *time.Timer) uint32 {
	l.mu.Lock()
	last := l.conn.Streams().LastPeerStreamID()
	l.mu.Unlock()
	d, ok := l.opts.clientIdleTimeout()
	if !ok || d <= 0 {
		timer.Stop()
		return last
	}
	timer.Reset(d)
	return last
}

// idleGoAway sends the idle GOAWAY if the connection is still idle in the
// period that started with epochLast. It returns the GOAWAY's done channel
// and true when it was sent. GoAwaySent is marked under l.mu — so a new peer
// stream is either registered before (and this declines) or refused after —
// and the GOAWAY is enqueued outside l.mu so a full writer queue cannot
// block Close (which takes l.mu).
func (l *Layer) idleGoAway(epochLast uint32) (chan error, bool) {
	l.mu.Lock()
	sent, _ := l.conn.GoAwaySent()
	sm := l.conn.Streams()
	if l.closed || sent || sm.ActiveCount() > 0 || l.headerBlockOpen.Load() ||
		sm.LastPeerStreamID() != epochLast || l.peerStreamOpeningLocked(epochLast) {
		l.mu.Unlock()
		return nil, false
	}
	l.conn.MarkGoAwaySent(epochLast)
	l.mu.Unlock()

	d, _ := l.opts.clientIdleTimeout()
	slog.Debug("http2: client connection idle; sending GOAWAY(NO_ERROR)",
		slog.String("role", l.role.String()),
		slog.String("conn_stream_id", l.streamID),
		slog.Uint64("last_stream_id", uint64(epochLast)),
		slog.Duration("idle", d),
	)
	// Bounded like Close's GOAWAY: a writer stuck on a peer that stopped
	// reading can leave the queue full, and shutdown is not closed yet. On
	// timeout done carries ErrWriterClosed and lingerAndClose closes.
	done := make(chan error, 1)
	l.enqueueWriteBounded(writeRequest{goAway: &writeGoAway{
		lastStreamID: epochLast,
		code:         ErrCodeNo,
		done:         done,
	}}, closeDrainTimeout)
	return done, true
}

// peerStreamOpeningLocked reports whether the newest peer stream, last, is
// registered (assemblerFor ran) but not yet open in StreamMap — the short
// window in handleStreamHeaders between the two. ActiveCount does not see
// such a stream yet; if the idle period happened to start inside that
// window, LastPeerStreamID already includes it, so only this check keeps
// the GOAWAY from closing the connection under it. Caller holds l.mu.
func (l *Layer) peerStreamOpeningLocked(last uint32) bool {
	if last == 0 {
		return false
	}
	if _, ok := l.assemblers[last]; !ok {
		return false
	}
	sm := l.conn.Streams()
	return sm.Get(last) == nil && !sm.IsClosed(last)
}

// lingerAndClose waits for the idle GOAWAY to be written, keeps the
// connection for the linger (the reader keeps answering PING and ignoring
// streams above last_stream_id), then closes the Layer. Shutdown — the peer
// closing, or Close — ends either wait early. The write wait is bounded by
// closeDrainTimeout, as in Close: a peer that stopped reading leaves the
// writer stuck in a socket write and done undelivered, and only closing the
// connection unblocks it.
func (l *Layer) lingerAndClose(done chan error) {
	drain := time.NewTimer(closeDrainTimeout)
	select {
	case err := <-done:
		drain.Stop()
		if err == nil {
			linger := l.opts.idleGoAwayLinger
			if linger <= 0 {
				linger = idleGoAwayLingerDefault
			}
			t := time.NewTimer(linger)
			select {
			case <-t.C:
			case <-l.shutdown:
			}
			t.Stop()
		}
	case <-drain.C:
		slog.Debug("http2: idle GOAWAY not written within the drain timeout; closing",
			slog.String("role", l.role.String()),
			slog.String("conn_stream_id", l.streamID),
		)
	case <-l.shutdown:
		drain.Stop()
	}
	_ = l.close(false)
}

// afterLocalGoAway reports whether streamID is a peer-initiated stream above
// the last_stream_id of a GOAWAY this Layer sent. Such a stream was not
// processed and never will be (RFC 9113 §6.8): its frames are ignored.
func (l *Layer) afterLocalGoAway(streamID uint32) bool {
	if l.isLocallyInitiated(streamID) {
		return false
	}
	sent, last := l.conn.GoAwaySent()
	return sent && streamID > last
}

// handleFrameAfterGoAway ignores a frame for a stream above the sent
// GOAWAY's last_stream_id, keeping the connection state consistent: a header
// block still reaches the HPACK decoder (RFC 9113 §4.3), and DATA's
// connection flow-control window is returned (§6.9). CONTINUATION is not
// handled here; it follows its HEADERS through the discard path in
// handleStreamContinuation.
func (l *Layer) handleFrameAfterGoAway(f *frame.Frame) error {
	switch f.Header.Type {
	case frame.TypeHeaders:
		fragment, err := f.HeaderBlockFragment()
		if err != nil {
			return err
		}
		return l.discardHeaderFragment(f.Header.StreamID, fragment, f.Header.Flags.Has(frame.FlagEndHeaders))
	case frame.TypeData:
		if _, err := f.DataPayload(); err != nil {
			return err
		}
		if f.Header.Length > 0 {
			if err := l.conn.ConsumeRecvWindow(int32(f.Header.Length)); err != nil {
				return err
			}
			l.connWindowUpdate(f.Header.Length)
		}
		return nil
	default:
		// RST_STREAM, WINDOW_UPDATE, PRIORITY, unknown types: nothing to do
		// for a stream that does not exist.
		return nil
	}
}
