package config

// FlowSinkConfig configures the flow sink (USK-1119).
type FlowSinkConfig struct {
	Dir            string `json:"dir"`
	MaxFileBytes   int64  `json:"max_file_bytes,omitempty"`
	MaxFiles       int    `json:"max_files,omitempty"`
	QueueMaxEvents int    `json:"queue_max_events,omitempty"`
	QueueMaxBytes  int64  `json:"queue_max_bytes,omitempty"`
	IncludeBodies  *bool  `json:"include_bodies,omitempty"`
	WireLevel      string `json:"wire_level,omitempty"`
	Fsync          bool   `json:"fsync,omitempty"`
}

// Validate checks the flow sink settings. Not implemented yet.
func (c *FlowSinkConfig) Validate() error { return nil }

// ResolvedFlowSink is FlowSinkConfig with defaults applied.
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

// Resolved applies defaults. Not implemented yet.
func (c *FlowSinkConfig) Resolved() ResolvedFlowSink { return ResolvedFlowSink{} }
