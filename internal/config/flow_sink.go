package config

import (
	"fmt"
	"strings"
)

// FlowSinkConfig configures the flow sink (USK-1119): every committed
// Stream / Flow record is streamed, as it is written, to rotating JSONL
// files in Dir so an external consumer can ship the record off-host.
// SQLite stays the system of record; the sink is a best-effort replica
// (a full queue drops events and reports them with "gap" lines).
//
// The sink is NOT masked by the SafetyFilter Output Filter: the Output
// Filter applies only where an MCP tool returns recorded data to the
// agent (CLAUDE.md MITM Principle 7). Protect Dir like the database.
//
// Boot-only: set in the config file; not changeable through configure or
// proxy_start. A nil pointer (key omitted) disables the sink.
type FlowSinkConfig struct {
	// Dir is the sink directory (required). It is created with mode
	// 0700 when missing and must not overlap the export directory.
	Dir string `json:"dir"`
	// MaxFileBytes rotates flows.jsonl once the next line would take it
	// past this size. 0 selects 64 MiB.
	MaxFileBytes int64 `json:"max_file_bytes,omitempty"`
	// MaxFiles is the number of rotated files kept. 0 (default) keeps
	// all: the consumer deletes what it has ingested.
	MaxFiles int `json:"max_files,omitempty"`
	// QueueMaxEvents bounds the in-memory event queue. 0 selects 4096.
	QueueMaxEvents int `json:"queue_max_events,omitempty"`
	// QueueMaxBytes bounds the body + raw bytes held by queued events.
	// 0 selects 256 MiB. A single event larger than this is written
	// metadata-only (body_omitted / body_size / body_sha256).
	QueueMaxBytes int64 `json:"queue_max_bytes,omitempty"`
	// IncludeBodies writes flow bodies and raw bytes (base64). Default
	// true.
	IncludeBodies *bool `json:"include_bodies,omitempty"`
	// WireLevel selects which flow rows are streamed, with the
	// export_flows vocabulary: "semantic" (default), one overlay level
	// ("h2-frame", "h1-chunk", "grpc-lpm-frame", "grpcweb-base64"), or
	// "all".
	WireLevel string `json:"wire_level,omitempty"`
	// Fsync syncs the file after every line. Default false.
	Fsync bool `json:"fsync,omitempty"`
}

// Flow sink defaults. They mirror flow.DefaultSink* (config does not
// import flow).
const (
	DefaultFlowSinkMaxFileBytes   int64 = 64 << 20
	DefaultFlowSinkQueueMaxEvents       = 4096
	DefaultFlowSinkQueueMaxBytes  int64 = 256 << 20
)

// flowSinkWireLevels is the accepted wire_level vocabulary (the
// export_flows filter.wire_level set).
var flowSinkWireLevels = []string{"semantic", "h2-frame", "h1-chunk", "grpc-lpm-frame", "grpcweb-base64", "all"}

// Validate checks the flow sink settings. A nil receiver (no sink) is
// valid.
func (c *FlowSinkConfig) Validate() error {
	if c == nil {
		return nil
	}
	if strings.TrimSpace(c.Dir) == "" {
		return fmt.Errorf("flow_sink.dir is required")
	}
	if c.MaxFileBytes < 0 {
		return fmt.Errorf("flow_sink.max_file_bytes must be >= 0, got %d", c.MaxFileBytes)
	}
	if c.MaxFiles < 0 {
		return fmt.Errorf("flow_sink.max_files must be >= 0, got %d", c.MaxFiles)
	}
	if c.QueueMaxEvents < 0 {
		return fmt.Errorf("flow_sink.queue_max_events must be >= 0, got %d", c.QueueMaxEvents)
	}
	if c.QueueMaxBytes < 0 {
		return fmt.Errorf("flow_sink.queue_max_bytes must be >= 0, got %d", c.QueueMaxBytes)
	}
	if c.WireLevel != "" {
		ok := false
		for _, v := range flowSinkWireLevels {
			if c.WireLevel == v {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("flow_sink.wire_level %q is not one of %s", c.WireLevel, strings.Join(flowSinkWireLevels, ", "))
		}
	}
	return nil
}

// ResolvedFlowSink is FlowSinkConfig with defaults applied. WireLevel is
// the exact flow wire_level to stream, or "" for every level ("all").
type ResolvedFlowSink struct {
	Dir            string
	MaxFileBytes   int64
	MaxFiles       int
	QueueMaxEvents int
	QueueMaxBytes  int64
	IncludeBodies  bool
	WireLevel      string
	Fsync          bool
}

// Resolved applies the defaults to a validated config.
func (c *FlowSinkConfig) Resolved() ResolvedFlowSink {
	r := ResolvedFlowSink{
		Dir:            c.Dir,
		MaxFileBytes:   c.MaxFileBytes,
		MaxFiles:       c.MaxFiles,
		QueueMaxEvents: c.QueueMaxEvents,
		QueueMaxBytes:  c.QueueMaxBytes,
		IncludeBodies:  c.IncludeBodies == nil || *c.IncludeBodies,
		WireLevel:      c.WireLevel,
		Fsync:          c.Fsync,
	}
	if r.MaxFileBytes == 0 {
		r.MaxFileBytes = DefaultFlowSinkMaxFileBytes
	}
	if r.QueueMaxEvents == 0 {
		r.QueueMaxEvents = DefaultFlowSinkQueueMaxEvents
	}
	if r.QueueMaxBytes == 0 {
		r.QueueMaxBytes = DefaultFlowSinkQueueMaxBytes
	}
	switch r.WireLevel {
	case "":
		r.WireLevel = "semantic"
	case "all":
		r.WireLevel = ""
	}
	return r
}
