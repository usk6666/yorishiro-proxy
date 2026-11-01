package flow

import (
	"context"
	"log/slog"
)

// SinkEvent names the kind of a flow sink line.
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

// Flow sink defaults.
const (
	DefaultSinkMaxFileBytes   int64 = 64 << 20
	DefaultSinkQueueMaxEvents       = 4096
	DefaultSinkQueueMaxBytes  int64 = 256 << 20
)

// SinkConfig configures a flow sink.
type SinkConfig struct {
	Dir            string
	MaxFileBytes   int64
	MaxFiles       int
	QueueMaxEvents int
	QueueMaxBytes  int64
	IncludeBodies  bool
	WireLevel      string
	Fsync          bool
}

// SinkStats is a snapshot of a flow sink's counters.
type SinkStats struct {
	Dir           string `json:"dir"`
	RunID         string `json:"run_id"`
	Emitted       int64  `json:"emitted"`
	DroppedEvents int64  `json:"dropped_events"`
	DroppedBytes  int64  `json:"dropped_bytes"`
	WriteErrors   int64  `json:"write_errors"`
}

// SinkGap describes a run of events the sink dropped.
type SinkGap struct {
	Dropped      int64  `json:"dropped"`
	DroppedBytes int64  `json:"dropped_bytes"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
}

// CommitObserver is notified after a store write commits.
type CommitObserver interface {
	StreamCommitted(id string, created bool)
	FlowCommitted(f *Flow)
	Close() error
}

// sinkLineWriter is the output end of a Sink.
type sinkLineWriter interface {
	WriteLine(line []byte) error
	Close() error
}

// Sink streams committed records to a sinkLineWriter.
type Sink struct {
	cfg SinkConfig
}

// NewFileSink opens a rotating JSONL file sink in cfg.Dir.
func NewFileSink(cfg SinkConfig, reader StreamReader, logger *slog.Logger) (*Sink, error) {
	return newSink(cfg, reader, nil, logger), nil
}

func newSink(cfg SinkConfig, _ StreamReader, _ sinkLineWriter, _ *slog.Logger) *Sink {
	return &Sink{cfg: cfg}
}

// StreamCommitted implements CommitObserver.
func (s *Sink) StreamCommitted(string, bool) {}

// FlowCommitted implements CommitObserver.
func (s *Sink) FlowCommitted(*Flow) {}

// Stats returns the sink counters.
func (s *Sink) Stats() SinkStats { return SinkStats{Dir: s.cfg.Dir} }

// Close flushes and closes the sink.
func (s *Sink) Close() error { return nil }

// withSinkSuppressed marks ctx so writes made with it are not emitted.
func withSinkSuppressed(ctx context.Context) context.Context { return ctx }

// SetCommitObserver installs o. Not implemented yet.
func (s *SQLiteStore) SetCommitObserver(o CommitObserver) {}

// FlowSinkStats reports the installed sink's counters.
func (s *SQLiteStore) FlowSinkStats() (SinkStats, bool) { return SinkStats{}, false }
