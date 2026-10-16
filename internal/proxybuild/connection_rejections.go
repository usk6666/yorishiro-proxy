package proxybuild

import (
	"log/slog"

	"golang.org/x/time/rate"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
)

// connectionRejectionsRingSize is the number of recent rejections kept for
// the status view.
const connectionRejectionsRingSize = 32

// ConnectionRejectionsConfig configures NewConnectionRejections.
type ConnectionRejectionsConfig struct {
	Store       flow.Writer
	Scope       *flow.RecordScope
	Logger      *slog.Logger
	RecordRate  rate.Limit
	RecordBurst int
	QueueSize   int
}

// ConnectionRejections aggregates capacity rejections (USK-1142).
type ConnectionRejections struct{}

// NewConnectionRejections constructs the aggregator.
func NewConnectionRejections(cfg ConnectionRejectionsConfig) *ConnectionRejections {
	return &ConnectionRejections{}
}

// Record registers one rejection.
func (c *ConnectionRejections) Record(info connector.RejectInfo) {}

// Snapshot returns the current aggregate.
func (c *ConnectionRejections) Snapshot() ConnectionRejectionsSnapshot {
	return ConnectionRejectionsSnapshot{}
}

// Close stops the recorder goroutine.
func (c *ConnectionRejections) Close() {}

// ConnectionRejectionsByKind counts rejections per detected protocol kind.
type ConnectionRejectionsByKind struct {
	HTTP1   int64 `json:"http1"`
	Connect int64 `json:"connect"`
	SOCKS5  int64 `json:"socks5"`
	HTTP2   int64 `json:"http2"`
	TCP     int64 `json:"tcp"`
	Unknown int64 `json:"unknown"`
}

// ConnectionRejectionEntry is one recent rejection.
type ConnectionRejectionEntry struct {
	At              string `json:"at"`
	Listener        string `json:"listener"`
	ForwardPort     string `json:"forward_port,omitempty"`
	RemoteAddr      string `json:"remote_addr"`
	DetectedKind    string `json:"detected_kind"`
	Method          string `json:"method,omitempty"`
	Target          string `json:"target,omitempty"`
	TargetTruncated bool   `json:"target_truncated,omitempty"`
	Wrote503        bool   `json:"wrote_503"`
	MaxConnections  int    `json:"max_connections"`
	Recorded        bool   `json:"recorded"`
}

// ConnectionRejectionsSnapshot is the status view of ConnectionRejections.
type ConnectionRejectionsSnapshot struct {
	Total      int64                      `json:"total"`
	LastAt     string                     `json:"last_at,omitempty"`
	ByKind     ConnectionRejectionsByKind `json:"by_kind"`
	Recent     []ConnectionRejectionEntry `json:"recent"`
	Unrecorded int64                      `json:"unrecorded"`
	OutOfScope int64                      `json:"out_of_scope"`
}
