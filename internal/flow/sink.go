package flow

// Flow sink (USK-1119): a best-effort, near-real-time replica of the
// SQLite record, streamed as JSONL so the evidence survives off-host.
//
// SQLite stays the system of record. The SQLiteStore notifies a
// CommitObserver from its single writer goroutine after each SaveStream /
// UpdateStream / SaveFlow commits; the Sink turns that into a small
// descriptor and hands it to a bounded queue without blocking (a full
// queue drops the event and counts it). A worker goroutine drains the
// queue, re-reads stream snapshots off the writer goroutine, encodes each
// event as a superset of the export_flows JSONL record and writes it to a
// sinkLineWriter (the rotating file writer in sink_file.go).
//
// Nothing is masked: the Output Filter applies only at the MCP boundary
// (CLAUDE.md MITM Principle 7), and the sink is a copy of the record, not
// an MCP response.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
)

// SinkEvent names the kind of a flow sink line (ExportRecord.Event).
type SinkEvent string

const (
	// SinkEventStreamCreated marks a line emitted after a SaveStream commit.
	SinkEventStreamCreated SinkEvent = "stream_created"
	// SinkEventStreamUpdated marks a line emitted after an UpdateStream commit.
	SinkEventStreamUpdated SinkEvent = "stream_updated"
	// SinkEventFlowSaved marks a line emitted after a SaveFlow commit.
	SinkEventFlowSaved SinkEvent = "flow_saved"
	// SinkEventGap marks a line reporting events the sink dropped.
	SinkEventGap SinkEvent = "gap"
)

// Flow sink defaults, applied to zero SinkConfig fields.
const (
	// DefaultSinkMaxFileBytes is the size at which the active file rotates.
	DefaultSinkMaxFileBytes int64 = 64 << 20
	// DefaultSinkQueueMaxEvents bounds the number of queued events.
	DefaultSinkQueueMaxEvents = 4096
	// DefaultSinkQueueMaxBytes bounds the body + raw bytes held by queued
	// events.
	DefaultSinkQueueMaxBytes int64 = 256 << 20
)

// sinkCloseTimeout bounds how long Close waits for the queue to flush.
const sinkCloseTimeout = drainTimeout

// SinkConfig configures a flow sink. Zero numeric fields take the
// defaults above.
type SinkConfig struct {
	// Dir is the directory holding flows.jsonl and its rotated files.
	Dir string
	// MaxFileBytes is the size at which flows.jsonl is rotated.
	MaxFileBytes int64
	// MaxFiles is the number of rotated files to keep; 0 keeps all (the
	// consumer deletes what it has ingested).
	MaxFiles int
	// QueueMaxEvents bounds the number of queued events.
	QueueMaxEvents int
	// QueueMaxBytes bounds the body + raw bytes held by queued events.
	QueueMaxBytes int64
	// IncludeBodies writes flow body and raw_bytes (base64).
	IncludeBodies bool
	// WireLevel restricts flow_saved events to one wire_level (e.g.
	// WireLevelSemantic); empty emits every wire_level.
	WireLevel string
	// Fsync syncs the file after every line.
	Fsync bool
}

func (c SinkConfig) withDefaults() SinkConfig {
	if c.MaxFileBytes <= 0 {
		c.MaxFileBytes = DefaultSinkMaxFileBytes
	}
	if c.QueueMaxEvents <= 0 {
		c.QueueMaxEvents = DefaultSinkQueueMaxEvents
	}
	if c.QueueMaxBytes <= 0 {
		c.QueueMaxBytes = DefaultSinkQueueMaxBytes
	}
	return c
}

// SinkStats is a snapshot of a flow sink's counters, published as
// query(resource:"status").flow_sink.
type SinkStats struct {
	// Dir is the sink directory.
	Dir string `json:"dir"`
	// RunID is the run_id stamped on every line this process writes.
	RunID string `json:"run_id"`
	// Emitted counts event lines written (gap lines excluded).
	Emitted int64 `json:"emitted"`
	// DroppedEvents counts events dropped because the queue was full.
	DroppedEvents int64 `json:"dropped_events"`
	// DroppedBytes counts the body + raw bytes of dropped events.
	DroppedBytes int64 `json:"dropped_bytes"`
	// WriteErrors counts events that could not be written (write or
	// snapshot read failure).
	WriteErrors int64 `json:"write_errors"`
}

// SinkGap describes a run of events the sink dropped. Their sequence
// numbers are FirstSeq..LastSeq (inclusive).
type SinkGap struct {
	Dropped      int64  `json:"dropped"`
	DroppedBytes int64  `json:"dropped_bytes"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
}

// CommitObserver is notified by SQLiteStore after a write commits. The
// notification methods run on the store's single writer goroutine, so
// they must return immediately and must not call back into the store.
// Close is called by SQLiteStore.Close after the writer goroutine has
// drained and before the database closes.
type CommitObserver interface {
	// StreamCommitted reports a committed SaveStream (created) or
	// UpdateStream (!created) of stream id.
	StreamCommitted(id string, created bool)
	// FlowCommitted reports a committed SaveFlow. f must not be modified.
	FlowCommitted(f *Flow)
	// Close flushes and releases the observer.
	Close() error
}

// sinkLineWriter is the output end of a Sink. It is used by the worker
// goroutine only; line carries no trailing newline.
type sinkLineWriter interface {
	WriteLine(line []byte) error
	Close() error
}

// sinkItem is the descriptor queued per event. It holds the *Flow by
// reference: producers build a fresh Flow per SaveFlow and do not modify
// it afterwards.
type sinkItem struct {
	kind     SinkEvent
	streamID string
	flow     *Flow
	seq      uint64
	charge   int64 // bytes counted against QueueMaxBytes
	omit     bool  // oversize: write body / raw bytes as size + hash only
	gap      *SinkGap
}

// Sink streams committed records to a sinkLineWriter. It implements
// CommitObserver.
type Sink struct {
	cfg    SinkConfig
	reader StreamReader
	out    sinkLineWriter
	logger *slog.Logger
	runID  string

	queue       chan sinkItem
	queuedBytes atomic.Int64
	// oversizeQueued is set while a metadata-only (oversize) event is
	// queued; see FlowCommitted.
	oversizeQueued atomic.Bool

	// prodMu serialises the producer side (seq, pending gap, closed).
	// The worker never takes it, so a stuck writer cannot block a
	// producer on it.
	prodMu  sync.Mutex
	seq     uint64
	pending *SinkGap
	closed  bool

	emitted       atomic.Int64
	droppedEvents atomic.Int64
	droppedBytes  atomic.Int64
	writeErrors   atomic.Int64

	ctx       context.Context
	cancel    context.CancelFunc
	done      chan struct{}
	closeOnce sync.Once
	closeErr  error
	// closeTimeout bounds Close (sinkCloseTimeout; tests shorten it).
	closeTimeout time.Duration

	// failing is worker-owned: true after a write error, so only the
	// first error of a run is logged.
	failing bool
}

// NewFileSink opens the rotating JSONL file sink in cfg.Dir (created with
// mode 0700 when missing) and starts its worker. reader is used to read
// stream snapshots; pass the store the sink observes.
func NewFileSink(cfg SinkConfig, reader StreamReader, logger *slog.Logger) (*Sink, error) {
	cfg = cfg.withDefaults()
	w, err := openFileSinkWriter(cfg.Dir, cfg.MaxFileBytes, cfg.MaxFiles, cfg.Fsync)
	if err != nil {
		return nil, err
	}
	return newSink(cfg, reader, w, logger), nil
}

func newSink(cfg SinkConfig, reader StreamReader, out sinkLineWriter, logger *slog.Logger) *Sink {
	cfg = cfg.withDefaults()
	if logger == nil {
		logger = slog.Default()
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := &Sink{
		cfg:    cfg,
		reader: reader,
		out:    out,
		logger: logger,
		runID:  uuid.New().String(),
		queue:  make(chan sinkItem, cfg.QueueMaxEvents),
		ctx:    ctx,
		cancel: cancel,
		done:   make(chan struct{}),

		closeTimeout: sinkCloseTimeout,
	}
	go s.run()
	return s
}

// StreamCommitted implements CommitObserver.
func (s *Sink) StreamCommitted(id string, created bool) {
	kind := SinkEventStreamUpdated
	if created {
		kind = SinkEventStreamCreated
	}
	s.enqueue(sinkItem{kind: kind, streamID: id})
}

// FlowCommitted implements CommitObserver.
func (s *Sink) FlowCommitted(f *Flow) {
	if f == nil {
		return
	}
	// The wire_level filter is a string compare, applied here so a
	// filtered row does not consume a sequence number (which would read
	// as an unexplained gap).
	if s.cfg.WireLevel != "" {
		wl := f.WireLevel
		if wl == "" {
			wl = WireLevelSemantic
		}
		if wl != s.cfg.WireLevel {
			return
		}
	}
	it := sinkItem{kind: SinkEventFlowSaved, streamID: f.StreamID, flow: f}
	if s.cfg.IncludeBodies {
		size := int64(len(f.Body)) + int64(len(f.RawBytes))
		if size > s.cfg.QueueMaxBytes {
			// An event that could never fit the byte budget is written
			// metadata-only instead of being dropped forever. It is not
			// charged against the budget, but it keeps a reference to the
			// recorded bytes until the worker hashes them, so at most one
			// such event is queued at a time (enqueue drops the next).
			it.omit = true
			size = 0
		}
		it.charge = size
	}
	s.enqueue(it)
}

// enqueue assigns the next sequence number and queues it without
// blocking; on a full queue the event is dropped and recorded in the
// pending gap, which rides on the next queued event.
func (s *Sink) enqueue(it sinkItem) {
	s.prodMu.Lock()
	defer s.prodMu.Unlock()
	if s.closed {
		return
	}
	s.seq++
	it.seq = s.seq
	it.gap = s.pending

	if it.omit && !s.oversizeQueued.CompareAndSwap(false, true) {
		s.recordDropLocked(it)
		return
	}
	if s.queuedBytes.Add(it.charge) <= s.cfg.QueueMaxBytes {
		select {
		case s.queue <- it:
			s.pending = nil
			return
		default:
		}
	}
	s.queuedBytes.Add(-it.charge)
	if it.omit {
		s.oversizeQueued.Store(false)
	}
	s.recordDropLocked(it)
}

func (s *Sink) recordDropLocked(it sinkItem) {
	size := int64(0)
	if it.flow != nil {
		size = int64(len(it.flow.Body)) + int64(len(it.flow.RawBytes))
	}
	s.droppedEvents.Add(1)
	s.droppedBytes.Add(size)
	if s.pending == nil {
		s.pending = &SinkGap{FirstSeq: it.seq}
	}
	s.pending.Dropped++
	s.pending.DroppedBytes += size
	s.pending.LastSeq = it.seq
}

// Stats returns the sink counters.
func (s *Sink) Stats() SinkStats {
	return SinkStats{
		Dir:           s.cfg.Dir,
		RunID:         s.runID,
		Emitted:       s.emitted.Load(),
		DroppedEvents: s.droppedEvents.Load(),
		DroppedBytes:  s.droppedBytes.Load(),
		WriteErrors:   s.writeErrors.Load(),
	}
}

// Close stops accepting events, flushes the queue (including a trailing
// gap line for drops no later event reported) and closes the writer. It
// waits at most closeTimeout; on timeout the worker is cancelled and
// left to finish its current write. Safe to call more than once.
func (s *Sink) Close() error {
	s.closeOnce.Do(func() {
		// One deadline for the whole Close: a context, because a timer
		// channel fires only once and both waits below must see it.
		deadline, stop := context.WithTimeout(context.Background(), s.closeTimeout)
		defer stop()

		s.prodMu.Lock()
		s.closed = true
		trailing := s.pending
		s.pending = nil
		s.prodMu.Unlock()

		if trailing != nil {
			select {
			case s.queue <- sinkItem{kind: SinkEventGap, gap: trailing}:
			case <-deadline.Done():
				s.logger.Warn("flow sink: could not queue the final gap line before close",
					"dropped", trailing.Dropped, "first_seq", trailing.FirstSeq, "last_seq", trailing.LastSeq)
			}
		}
		// No producer can send any more: every send happens under prodMu
		// with closed checked first.
		close(s.queue)

		select {
		case <-s.done:
		case <-deadline.Done():
			s.cancel()
			s.closeErr = fmt.Errorf("flow sink: close timed out after %v with events still queued", s.closeTimeout)
			s.logger.Warn("flow sink close timed out; queued events were not written",
				"dir", s.cfg.Dir, "timeout", s.closeTimeout)
			return
		}
		s.cancel()
	})
	return s.closeErr
}

// run is the worker goroutine. It exits when the queue is closed and
// drained, then closes the writer (the worker is its only user).
func (s *Sink) run() {
	defer close(s.done)
	for it := range s.queue {
		if it.gap != nil {
			s.writeGap(it.gap)
		}
		if it.kind != SinkEventGap {
			s.writeEvent(it)
		}
		s.queuedBytes.Add(-it.charge)
		if it.omit {
			s.oversizeQueued.Store(false)
		}
	}
	if err := s.out.Close(); err != nil {
		s.logger.Warn("flow sink: close output", "dir", s.cfg.Dir, "error", err)
	}
}

func (s *Sink) writeGap(g *SinkGap) {
	s.logger.Warn("flow sink dropped events: queue full",
		"dir", s.cfg.Dir, "dropped", g.Dropped, "dropped_bytes", g.DroppedBytes,
		"first_seq", g.FirstSeq, "last_seq", g.LastSeq)
	rec := ExportRecord{
		Version:   ExportFormatVersion,
		Event:     string(SinkEventGap),
		RunID:     s.runID,
		EmittedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Gap:       g,
	}
	if err := s.writeRecord(&rec); err != nil {
		s.writeFailed("gap", err)
	}
}

func (s *Sink) writeEvent(it sinkItem) {
	st, err := s.reader.GetStream(s.ctx, it.streamID)
	if err != nil {
		s.writeFailed(string(it.kind), fmt.Errorf("read stream %s: %w", it.streamID, err))
		return
	}
	rec := ExportRecord{
		Stream:    streamToExport(st),
		Flows:     []*ExportFlow{},
		Version:   ExportFormatVersion,
		Event:     string(it.kind),
		Seq:       it.seq,
		RunID:     s.runID,
		EmittedAt: time.Now().UTC().Format(time.RFC3339Nano),
	}
	if it.flow != nil {
		rec.Flows = []*ExportFlow{s.exportFlow(it)}
	}
	if err := s.writeRecord(&rec); err != nil {
		s.writeFailed(string(it.kind), err)
		return
	}
	s.emitted.Add(1)
	if s.failing {
		s.failing = false
		s.logger.Info("flow sink writes recovered", "dir", s.cfg.Dir)
	}
	s.logger.Debug("flow sink event written", "event", it.kind, "seq", it.seq, "stream_id", it.streamID)
}

func (s *Sink) exportFlow(it sinkItem) *ExportFlow {
	ef := flowsToExport([]*Flow{it.flow}, s.cfg.IncludeBodies && !it.omit)[0]
	if ef.WireLevel == "" {
		// The store persists an unset wire_level as semantic; emit the
		// stored value.
		ef.WireLevel = WireLevelSemantic
	}
	if !it.omit {
		return ef
	}
	if n := len(it.flow.Body); n > 0 {
		size, sum := int64(n), sha256.Sum256(it.flow.Body)
		ef.BodyOmitted, ef.BodySize, ef.BodySHA256 = true, &size, hex.EncodeToString(sum[:])
	}
	if n := len(it.flow.RawBytes); n > 0 {
		size, sum := int64(n), sha256.Sum256(it.flow.RawBytes)
		ef.RawBytesOmitted, ef.RawBytesSize, ef.RawBytesSHA256 = true, &size, hex.EncodeToString(sum[:])
	}
	return ef
}

func (s *Sink) writeRecord(rec *ExportRecord) error {
	line, err := marshalSinkLine(rec)
	if err != nil {
		return err
	}
	return s.out.WriteLine(line)
}

// writeFailed counts a lost event and logs the first failure of a run.
func (s *Sink) writeFailed(what string, err error) {
	s.writeErrors.Add(1)
	if s.failing || errors.Is(err, context.Canceled) {
		return
	}
	s.failing = true
	s.logger.Warn("flow sink write failed; further failures are counted in write_errors until a write succeeds",
		"dir", s.cfg.Dir, "event", what, "error", err)
}

// marshalSinkLine encodes rec as one JSON line without HTML escaping,
// matching export_flows.
func marshalSinkLine(rec *ExportRecord) ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, fmt.Errorf("encode flow sink record: %w", err)
	}
	// Encode appends '\n'; the writer adds its own.
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), nil
}

// sinkSuppressedKey marks a context whose writes the observer skips.
type sinkSuppressedKey struct{}

// withSinkSuppressed marks ctx so SQLiteStore does not notify its
// CommitObserver of writes made with it. ImportStreams uses it: imported
// rows are copies of records that already exist elsewhere.
func withSinkSuppressed(ctx context.Context) context.Context {
	return context.WithValue(ctx, sinkSuppressedKey{}, true)
}

func sinkSuppressed(ctx context.Context) bool {
	v, _ := ctx.Value(sinkSuppressedKey{}).(bool)
	return v
}
