package proxybuild

import (
	"context"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"golang.org/x/time/rate"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/flow"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

const (
	// connectionRejectionsRingSize is the number of most recent
	// rejections kept for the status view.
	connectionRejectionsRingSize = 32

	// defaultRejectionRecordRate / defaultRejectionRecordBurst bound how
	// many audit Streams capacity rejections may write. Rejections happen
	// exactly when the proxy is saturated, so one DB row per rejection
	// would amplify the overload (CWE-770); the rest are counted only.
	defaultRejectionRecordRate  = rate.Limit(10)
	defaultRejectionRecordBurst = 100

	// defaultRejectionRecordQueue is the bounded hand-off between the
	// reject path and the recorder goroutine. A full queue sheds the
	// record instead of blocking the reject path.
	defaultRejectionRecordQueue = 128

	// rejectionRecordTimeout bounds one audit Stream write.
	rejectionRecordTimeout = 5 * time.Second
)

// ConnectionRejectionsConfig configures NewConnectionRejections.
type ConnectionRejectionsConfig struct {
	// Store receives the blocked_by="capacity" audit Streams. nil disables
	// recording; the status aggregate is still maintained.
	Store flow.Writer
	// Scope is the capture_scope filter (USK-776). Out-of-scope targets
	// are counted but not written, mirroring the TLS-error recorder
	// (USK-791). nil records everything.
	Scope *flow.RecordScope
	// Logger receives write-failure logs. nil uses slog.Default().
	Logger *slog.Logger
	// RecordRate / RecordBurst set the audit-Stream token bucket. Zero
	// values use 10/s with a burst of 100.
	RecordRate  rate.Limit
	RecordBurst int
	// QueueSize is the recorder queue capacity. Zero uses 128.
	QueueSize int
}

// ConnectionRejections is the Manager-level aggregator of connections the
// proxy refused because max_connections was saturated (USK-1142). It is
// fed by the FullListener's OnReject and by the TCP forward accept loop,
// and serves two consumers:
//
//   - query(resource:"status").connection_rejections — cumulative counters
//     for the process lifetime (across proxy_stop / proxy_start) plus a
//     ring of the most recent rejections;
//   - query(resource:"flows") — one State="error", BlockedBy="capacity"
//     Stream per rejection, rate-capped and capture-scope gated.
//
// Record is O(1), never blocks, and performs no I/O: the audit write is
// handed to a single recorder goroutine through a bounded queue. That
// goroutine starts on demand and exits when the queue is empty (or on
// Close), so an idle aggregator holds no goroutine.
type ConnectionRejections struct {
	store   flow.Writer
	scope   *flow.RecordScope
	logger  *slog.Logger
	limiter *rate.Limiter
	queue   chan rejectionRecord

	mu         sync.Mutex
	total      int64
	lastAt     time.Time
	byKind     ConnectionRejectionsByKind
	ring       [connectionRejectionsRingSize]ConnectionRejectionEntry
	ringNext   int
	ringLen    int
	unrecorded int64
	outOfScope int64

	// Recorder goroutine lifecycle. running is true while a drainer owns
	// the queue. lifeMu serialises drainer start against Close so no
	// drainer can be started (wg.Add) once Close has begun waiting.
	// closed is closed exactly once by Close; ctx is cancelled by Close
	// to abort an in-flight write; wg lets Close wait for the drainer.
	running  atomic.Bool
	lifeMu   sync.Mutex
	isClosed bool
	closed   chan struct{}
	ctx      context.Context
	cancel   context.CancelFunc
	wg       sync.WaitGroup

	// beforeRelease is a test-only seam, nil in production. When set
	// before the first Record, the drainer calls it after observing an
	// empty queue and before releasing ownership — the exact window the
	// release-then-recheck in drain exists to cover.
	beforeRelease func()
}

// rejectionRecord is one queued audit write.
type rejectionRecord struct {
	info      connector.RejectInfo
	kindLabel string
}

// NewConnectionRejections constructs the aggregator. Call Close to stop
// the recorder goroutine; an aggregator that is never closed holds no
// goroutine while idle.
func NewConnectionRejections(cfg ConnectionRejectionsConfig) *ConnectionRejections {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	r := cfg.RecordRate
	if r == 0 {
		r = defaultRejectionRecordRate
	}
	burst := cfg.RecordBurst
	if burst <= 0 {
		burst = defaultRejectionRecordBurst
	}
	qsize := cfg.QueueSize
	if qsize <= 0 {
		qsize = defaultRejectionRecordQueue
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &ConnectionRejections{
		store:   cfg.Store,
		scope:   cfg.Scope,
		logger:  logger,
		limiter: rate.NewLimiter(r, burst),
		queue:   make(chan rejectionRecord, qsize),
		closed:  make(chan struct{}),
		ctx:     ctx,
		cancel:  cancel,
	}
}

// Record registers one rejection. Safe for concurrent use; O(1); never
// blocks and performs no I/O, so it may run on the reject path.
func (c *ConnectionRejections) Record(info connector.RejectInfo) {
	if c == nil {
		return
	}
	if info.At.IsZero() {
		info.At = time.Now()
	}
	label := rejectKindLabel(info.DetectedKind)

	recorded, shed, outOfScope := c.submit(info, label)

	entry := ConnectionRejectionEntry{
		At:              info.At.Format(time.RFC3339Nano),
		Listener:        info.Listener,
		ForwardPort:     info.ForwardPort,
		RemoteAddr:      info.RemoteAddr,
		DetectedKind:    label,
		Method:          info.Method,
		Target:          info.Target,
		TargetTruncated: info.TargetTruncated,
		Wrote503:        info.WroteResponse,
		MaxConnections:  info.MaxConnections,
		Recorded:        recorded,
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.total++
	if info.At.After(c.lastAt) {
		c.lastAt = info.At
	}
	c.byKind.inc(label)
	c.ring[c.ringNext] = entry
	c.ringNext = (c.ringNext + 1) % connectionRejectionsRingSize
	if c.ringLen < connectionRejectionsRingSize {
		c.ringLen++
	}
	if shed {
		c.unrecorded++
	}
	if outOfScope {
		c.outOfScope++
	}
}

// submit decides whether the rejection gets an audit Stream and, if so,
// queues it. Order: no store → nothing; capture_scope miss → outOfScope
// (no token spent); rate cap or full queue → shed.
func (c *ConnectionRejections) submit(info connector.RejectInfo, label string) (recorded, shed, outOfScope bool) {
	if c.store == nil {
		return false, false, false
	}
	authority := rejectAuthority(info)
	switch {
	case !c.inScope(info, authority):
		return false, false, true
	case !c.limiter.Allow():
		return false, true, false
	case c.enqueue(rejectionRecord{info: info, kindLabel: label}):
		return true, false, false
	default:
		return false, true, false
	}
}

// Snapshot returns a copy of the aggregate. Recent is newest first and
// never nil.
func (c *ConnectionRejections) Snapshot() ConnectionRejectionsSnapshot {
	if c == nil {
		return ConnectionRejectionsSnapshot{Recent: []ConnectionRejectionEntry{}}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	snap := ConnectionRejectionsSnapshot{
		Total:      c.total,
		ByKind:     c.byKind,
		Recent:     make([]ConnectionRejectionEntry, 0, c.ringLen),
		Unrecorded: c.unrecorded,
		OutOfScope: c.outOfScope,
	}
	if !c.lastAt.IsZero() {
		snap.LastAt = c.lastAt.Format(time.RFC3339Nano)
	}
	for i := 1; i <= c.ringLen; i++ {
		idx := (c.ringNext - i + connectionRejectionsRingSize) % connectionRejectionsRingSize
		snap.Recent = append(snap.Recent, c.ring[idx])
	}
	return snap
}

// Close stops the recorder goroutine, aborting an in-flight write, and
// waits for it to exit. Queued records are dropped. Idempotent; Record
// after Close still counts but no longer writes.
func (c *ConnectionRejections) Close() {
	if c == nil {
		return
	}
	c.lifeMu.Lock()
	if !c.isClosed {
		c.isClosed = true
		close(c.closed)
		c.cancel()
	}
	c.lifeMu.Unlock()
	c.wg.Wait()
}

// inScope reports whether the rejection passes capture_scope. The synthetic
// envelope carries only what was observed before the refusal: the target
// authority and, for HTTP/1.x, the request line.
//
// With no authority (HTTP/1.x origin-form, an unparsable absolute-form
// target, or a kind that never names a target) no hostname rule can
// match. The live pipeline would have had the Host header, so an exclude
// rule on Hostname might well have dropped this request; fail closed and
// count it as out of scope rather than persist a target the operator may
// have excluded (USK-1142 review S-1).
func (c *ConnectionRejections) inScope(info connector.RejectInfo, authority string) bool {
	if c.scope.IsEmpty() {
		return true
	}
	if authority == "" && c.scope.HasHostnameExclude() {
		return false
	}
	env := &envelope.Envelope{Context: envelope.EnvelopeContext{TargetHost: authority}}
	if info.DetectedKind == connector.ProtocolHTTP1 {
		msg := &envelope.HTTPMessage{Method: info.Method, Authority: authority}
		if u, err := url.Parse(info.Target); err == nil {
			msg.Path = u.Path
		}
		env.Message = msg
	}
	return c.scope.ShouldRecord(env)
}

// enqueue hands rec to the recorder without blocking and makes sure a
// drainer is running. Returns false when the queue is full or the
// aggregator is closed.
func (c *ConnectionRejections) enqueue(rec rejectionRecord) bool {
	select {
	case <-c.closed:
		return false
	default:
	}
	select {
	case c.queue <- rec:
	default:
		return false
	}
	c.startDrainer()
	return true
}

// startDrainer starts the single recorder goroutine unless one is already
// running.
func (c *ConnectionRejections) startDrainer() {
	if c.running.Load() {
		// Fast path: the running drainer re-checks the queue before it
		// exits, so this record is not stranded.
		return
	}
	c.lifeMu.Lock()
	defer c.lifeMu.Unlock()
	if c.isClosed || !c.running.CompareAndSwap(false, true) {
		return
	}
	c.wg.Add(1)
	go c.drain()
}

// drain writes queued records until the queue is empty or Close is called.
// Termination: on Close (closed channel) or when it observes an empty queue
// after releasing ownership. The release-then-recheck closes the race with
// an enqueue that saw running==true just before the release.
func (c *ConnectionRejections) drain() {
	defer c.wg.Done()
	for {
		select {
		case <-c.closed:
			c.running.Store(false)
			return
		default:
		}
		select {
		case rec := <-c.queue:
			c.write(rec)
		case <-c.closed:
			c.running.Store(false)
			return
		default:
			if c.beforeRelease != nil {
				c.beforeRelease()
			}
			c.running.Store(false)
			// Store-buffer pattern against enqueue's send + running.Load.
			// len(chan) is not a synchronising operation in the Go memory
			// model; this relies on the runtime reading qcount after the
			// seq-cst Store (true on amd64, and on arm64 via chanlen's
			// internals). Guarded by the DrainerRecheck tests.
			if len(c.queue) == 0 || !c.running.CompareAndSwap(false, true) {
				return
			}
		}
	}
}

// write persists one audit Stream.
func (c *ConnectionRejections) write(rec rejectionRecord) {
	info := rec.info
	protocol := string(envelope.ProtocolRaw)
	if info.DetectedKind == connector.ProtocolHTTP1 || info.DetectedKind == connector.ProtocolHTTPConnect {
		protocol = string(envelope.ProtocolHTTP)
	}
	tags := map[string]string{
		"detected_kind": rec.kindLabel,
		"listener":      info.Listener,
	}
	if info.Target != "" {
		tags["target"] = info.Target
	}
	if info.TargetTruncated {
		tags["target_truncated"] = "true"
	}
	if info.Method != "" {
		tags["method"] = info.Method
	}
	if info.ForwardPort != "" {
		tags["forward_port"] = info.ForwardPort
	}
	tags["wrote_503"] = strconv.FormatBool(info.WroteResponse)

	st := &flow.Stream{
		ID:            uuid.New().String(),
		Protocol:      protocol,
		State:         "error",
		BlockedBy:     pipeline.BlockedByCapacity,
		FailureReason: fmt.Sprintf("rejected: max_connections=%d reached", info.MaxConnections),
		Timestamp:     info.At,
		Tags:          tags,
		// ServerAddr stays empty: a refused connection never had an
		// upstream socket peer. The refused target is Tags["target"],
		// which query filter.host also matches.
		ConnInfo: &flow.ConnectionInfo{
			ClientAddr: info.RemoteAddr,
		},
		ListenerName: info.Listener,
	}
	ctx, cancel := context.WithTimeout(c.ctx, rejectionRecordTimeout)
	defer cancel()
	if err := c.store.SaveStream(ctx, st); err != nil {
		if c.ctx.Err() != nil {
			// Aborted by Close at shutdown: expected, not data loss to
			// alert on.
			c.logger.Debug("proxybuild: capacity-rejection stream save aborted by close",
				"listener", info.Listener,
				"error", err,
			)
			return
		}
		c.logger.Error("proxybuild: capacity-rejection stream save failed",
			"listener", info.Listener,
			"target", info.Target,
			"error", err,
		)
	}
}

// rejectCallback adapts an aggregator to FullListenerConfig.OnReject; nil
// stays nil so the listener keeps its log-only behaviour.
func rejectCallback(c *ConnectionRejections) func(connector.RejectInfo) {
	if c == nil {
		return nil
	}
	return c.Record
}

// rejectKindLabel maps a detected protocol kind to the status/tag label.
func rejectKindLabel(k connector.ProtocolKind) string {
	switch k {
	case connector.ProtocolHTTP1:
		return "http1"
	case connector.ProtocolHTTPConnect:
		return "connect"
	case connector.ProtocolSOCKS5:
		return "socks5"
	case connector.ProtocolHTTP2:
		return "http2"
	case connector.ProtocolTCP:
		return "tcp"
	default:
		return "unknown"
	}
}

// rejectAuthority returns the host[:port] the refused connection was bound
// for, used for capture-scope evaluation. CONNECT and TCP forward targets
// are already an authority. For an HTTP/1.x absolute-form request-target
// the authority component is extracted as-is (no case folding, no default
// port); origin-form targets carry no authority without parsing headers,
// which the reject path never does.
func rejectAuthority(info connector.RejectInfo) string {
	switch info.DetectedKind {
	case connector.ProtocolHTTP1:
		if u, err := url.Parse(info.Target); err == nil {
			return u.Host
		}
		return ""
	case connector.ProtocolHTTPConnect:
		return info.Target
	default:
		if info.ForwardPort != "" {
			return info.Target
		}
		return ""
	}
}

// ConnectionRejectionsByKind counts rejections per detected protocol kind.
type ConnectionRejectionsByKind struct {
	HTTP1   int64 `json:"http1"`
	Connect int64 `json:"connect"`
	SOCKS5  int64 `json:"socks5"`
	HTTP2   int64 `json:"http2"`
	TCP     int64 `json:"tcp"`
	Unknown int64 `json:"unknown"`
}

// inc increments the counter for a rejectKindLabel value.
func (b *ConnectionRejectionsByKind) inc(label string) {
	switch label {
	case "http1":
		b.HTTP1++
	case "connect":
		b.Connect++
	case "socks5":
		b.SOCKS5++
	case "http2":
		b.HTTP2++
	case "tcp":
		b.TCP++
	default:
		b.Unknown++
	}
}

// ConnectionRejectionEntry is one recent rejection in the status view.
type ConnectionRejectionEntry struct {
	// At is the rejection time (RFC 3339).
	At string `json:"at"`
	// Listener is the listener name the connection arrived on.
	Listener string `json:"listener"`
	// ForwardPort is set for rejections on a tcp_forwards port.
	ForwardPort string `json:"forward_port,omitempty"`
	// RemoteAddr is the client address.
	RemoteAddr string `json:"remote_addr"`
	// DetectedKind is one of http1, connect, socks5, http2, tcp, unknown.
	DetectedKind string `json:"detected_kind"`
	// Method is the request-line method (HTTP/1.x and CONNECT).
	Method string `json:"method,omitempty"`
	// Target is the request-target as observed on the wire (HTTP/1.x and
	// CONNECT) or the configured forward target (TCP forward).
	Target string `json:"target,omitempty"`
	// TargetTruncated reports that Target was cut at 512 bytes.
	TargetTruncated bool `json:"target_truncated,omitempty"`
	// Wrote503 reports that a 503 response was written to the client.
	Wrote503 bool `json:"wrote_503"`
	// MaxConnections is the cap in force at the time.
	MaxConnections int `json:"max_connections"`
	// Recorded reports that an audit Stream was accepted for writing.
	Recorded bool `json:"recorded"`
}

// ConnectionRejectionsSnapshot is the status view of ConnectionRejections,
// published as query(resource:"status").connection_rejections.
type ConnectionRejectionsSnapshot struct {
	// Total counts every rejection since process start.
	Total int64 `json:"total"`
	// LastAt is the most recent rejection time (RFC 3339); empty if none.
	LastAt string `json:"last_at,omitempty"`
	// ByKind splits Total by detected protocol kind.
	ByKind ConnectionRejectionsByKind `json:"by_kind"`
	// Recent holds the most recent rejections, newest first.
	Recent []ConnectionRejectionEntry `json:"recent"`
	// Unrecorded counts rejections whose audit Stream was shed by the
	// write rate cap or a full recorder queue.
	Unrecorded int64 `json:"unrecorded"`
	// OutOfScope counts rejections not recorded because capture_scope
	// excludes their target, or because the target names no host while a
	// hostname exclude rule is set (fail closed).
	OutOfScope int64 `json:"out_of_scope"`
}
