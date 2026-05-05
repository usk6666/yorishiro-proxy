package session

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
)

// UpgradeKind identifies which protocol upgrade was observed mid-Pipeline.
//
// The empty string is a valid zero-value meaning "no upgrade observed".
type UpgradeKind string

const (
	// UpgradeWS marks an HTTP→WebSocket Upgrade (RFC 6455). Both the
	// client side and the upstream side swap to ws.Layer.
	UpgradeWS UpgradeKind = "ws"
	// UpgradeSSE marks an HTTP→Server-Sent-Events response (text/event-stream).
	// Only the upstream side swaps; the client side keeps its http1.Layer
	// because the response body is server-to-client only (RFC 8895, RFC-001
	// N7 D-U3).
	UpgradeSSE UpgradeKind = "sse"
)

// ErrUpgradePending is the sentinel returned by clientToUpstream /
// upstreamToClient when an UpgradeNotice has been latched. RunStackSession
// detects this via errors.Is to distinguish upgrade-driven session exit
// from genuine errors / EOF.
//
// ErrUpgradePending must NOT cascade as a "real" error: clientToUpstream's
// upstream-Close defer skips it (see session.go), and RunStackSession's
// OnComplete wrapper suppresses the first session's OnComplete callback
// when this sentinel is observed.
var ErrUpgradePending = errors.New("session: upgrade pending")

// UpgradeNotice is the session-scoped state machine the UpgradeStep mutates
// when it observes an HTTP→WS Upgrade or HTTP→SSE response. It is plumbed
// through the request context (mirroring pipeline.withSnapshot) so the Step
// can update it without the Pipeline knowing about the session.
//
// All accessors are mutex-guarded (sync.Mutex; Set/Pending are infrequent
// per RFC-001 N7 — at most a handful of calls per upgraded session).
type UpgradeNotice struct {
	mu              sync.Mutex
	seenSendUpgrade bool        // saw a Send envelope carrying Upgrade: websocket + Connection: upgrade
	pending         UpgradeKind // empty until the swap is required
	// upstreamCh holds the live upstream Channel at the moment the first
	// session exited with ErrUpgradePending. RunStackSession reads it back
	// to construct the post-upgrade Layer without re-dialing. Set exactly
	// once by RunSession before OnComplete fires.
	upstreamCh layer.Channel
	// sseFirstResp caches the actual SSE first response envelope captured
	// by UpgradeStep when it latches pending=UpgradeSSE. runUpgradeSSE
	// hands this to sse.Wrap together with WithSkipFirstEmit so the
	// production swap path uses real headers and Context (not a synthesized
	// placeholder) without re-recording the response post-swap.
	sseFirstResp *envelope.Envelope
}

// markSendUpgrade is called by UpgradeStep when it observes a Send envelope
// that requests a WebSocket upgrade. The pending kind is NOT set yet —
// only the corresponding 101 response on the Receive side flips pending.
func (n *UpgradeNotice) markSendUpgrade() {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.seenSendUpgrade = true
}

// hasSendUpgrade reports whether the WS request side has been observed.
func (n *UpgradeNotice) hasSendUpgrade() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.seenSendUpgrade
}

// trySetPending records the upgrade kind exactly once. Returns true if
// this call latched the value, false if a prior call already did. Idempotent
// from the caller's viewpoint: subsequent calls are no-ops.
func (n *UpgradeNotice) trySetPending(k UpgradeKind) (set bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.pending != "" {
		return false
	}
	n.pending = k
	return true
}

// Pending returns the latched UpgradeKind, or the empty string if no upgrade
// has been observed yet.
func (n *UpgradeNotice) Pending() UpgradeKind {
	if n == nil {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.pending
}

// attachUpstream caches the live upstream Channel at upgrade time. Called by
// RunSession after g.Wait() observed ErrUpgradePending so RunStackSession
// can reuse the wire for the post-upgrade Layer.
func (n *UpgradeNotice) attachUpstream(ch layer.Channel) {
	if n == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.upstreamCh = ch
}

// Upstream returns the cached upstream Channel set by attachUpstream, or nil
// if no upgrade was observed.
func (n *UpgradeNotice) Upstream() layer.Channel {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.upstreamCh
}

// attachSSEFirstResponse caches a defensive deep-clone of the first SSE
// response envelope so runUpgradeSSE can supply real headers / Context to
// sse.Wrap. Called by UpgradeStep when it latches pending=UpgradeSSE.
//
// We deep-clone because the Pipeline may mutate env.Message downstream of
// UpgradeStep (e.g. Transform Step swapping headers); the cache must
// remain stable for the post-swap consumer.
func (n *UpgradeNotice) attachSSEFirstResponse(env *envelope.Envelope) {
	if n == nil || env == nil {
		return
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	n.sseFirstResp = cloneEnvelope(env)
}

// SSEFirstResponse returns the cached first SSE response envelope, or
// nil if attachSSEFirstResponse was never called.
func (n *UpgradeNotice) SSEFirstResponse() *envelope.Envelope {
	if n == nil {
		return nil
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.sseFirstResp
}

// cloneEnvelope returns a defensive deep clone of env. Message is cloned
// via its CloneMessage method; Raw is byte-copied. Opaque is dropped — the
// cached envelope is for read-only consumption, not for re-sending on the
// wire.
func cloneEnvelope(env *envelope.Envelope) *envelope.Envelope {
	if env == nil {
		return nil
	}
	out := &envelope.Envelope{
		StreamID:  env.StreamID,
		FlowID:    env.FlowID,
		Sequence:  env.Sequence,
		Direction: env.Direction,
		Protocol:  env.Protocol,
		Context:   env.Context,
	}
	if len(env.Raw) > 0 {
		out.Raw = make([]byte, len(env.Raw))
		copy(out.Raw, env.Raw)
	}
	if env.Message != nil {
		out.Message = env.Message.CloneMessage()
	}
	return out
}

// upgradeNoticeKey is the unique context key under which the UpgradeNotice
// pointer is stored. Empty struct keeps the key allocation-free.
type upgradeNoticeKey struct{}

// WithUpgradeNotice attaches n to ctx so UpgradeStep can retrieve it
// without taking a reference at construction time. Returns ctx unchanged
// if n is nil (callers that opt out of upgrade detection — RunSession used
// directly without RunStackSession — never plumb a notice and the Step
// becomes a no-op via UpgradeNoticeFromContext returning nil).
func WithUpgradeNotice(ctx context.Context, n *UpgradeNotice) context.Context {
	if n == nil {
		return ctx
	}
	return context.WithValue(ctx, upgradeNoticeKey{}, n)
}

// UpgradeNoticeFromContext returns the UpgradeNotice stored in ctx, or nil
// if no notice was attached. Steps that do not find a notice should treat
// this as "session does not care about upgrades" and skip mutation.
func UpgradeNoticeFromContext(ctx context.Context) *UpgradeNotice {
	if v, ok := ctx.Value(upgradeNoticeKey{}).(*UpgradeNotice); ok {
		return v
	}
	return nil
}

// UpgradeStep is an Envelope-only Pipeline Step that observes HTTP messages
// for protocol-upgrade signals (HTTP→WS Upgrade, HTTP→SSE response). When a
// signal is observed, the Step mutates the session-scoped UpgradeNotice
// stored in ctx — it never modifies the envelope or returns Drop/Respond.
//
// Per RFC-001 N7 D-U3 and the design review (R1), UpgradeStep MUST run
// AFTER RecordStep so the 101 / first SSE response is recorded as a normal
// HTTP envelope before the session swaps Layers.
//
// The Step is purely observational: it never mutates Headers (the wire-
// fidelity rule MITM-1 forbids normalization or rewriting) and never
// short-circuits the Pipeline.
type UpgradeStep struct{}

// NewUpgradeStep returns a new UpgradeStep. The Step has no configuration —
// detection rules are fixed by RFC 6455 / RFC 8895.
func NewUpgradeStep() *UpgradeStep { return &UpgradeStep{} }

// Process implements pipeline.Step. It type-switches on env.Message: only
// HTTPMessage envelopes carry upgrade signals, all other Message types are
// ignored. The Step never returns Drop or Respond.
func (s *UpgradeStep) Process(ctx context.Context, env *envelope.Envelope) pipeline.Result {
	notice := UpgradeNoticeFromContext(ctx)
	if notice == nil || env == nil || env.Message == nil {
		return pipeline.Result{}
	}

	msg, ok := env.Message.(*envelope.HTTPMessage)
	if !ok || msg == nil {
		return pipeline.Result{}
	}

	switch env.Direction {
	case envelope.Send:
		if isWSUpgradeRequest(msg) {
			notice.markSendUpgrade()
		}
	case envelope.Receive:
		// WS branch: 101 + Upgrade: websocket + Connection: upgrade after
		// a matching Send-side request. SSE check is independent (no
		// Send-side prerequisite).
		if notice.hasSendUpgrade() && isWS101Response(msg) {
			notice.trySetPending(UpgradeWS)
			return pipeline.Result{}
		}
		if isSSEResponse(msg) {
			if notice.trySetPending(UpgradeSSE) {
				notice.attachSSEFirstResponse(env)
			}
		}
	}
	return pipeline.Result{}
}

// isWSUpgradeRequest reports whether msg looks like an HTTP request that
// initiates a WebSocket upgrade per RFC 6455 §4.1: it must carry an
// Upgrade header whose token includes "websocket" (case-insensitive) AND
// a Connection header whose token includes "upgrade" (case-insensitive).
//
// We do NOT validate Sec-WebSocket-Key / Sec-WebSocket-Version here: the
// proxy's job is to detect the wire-observed pattern, not enforce client
// correctness. A malformed upgrade request that the upstream rejects with
// non-101 will not flip pending=UpgradeWS because the Receive-side check
// requires Status==101.
func isWSUpgradeRequest(msg *envelope.HTTPMessage) bool {
	if msg == nil {
		return false
	}
	if !headerHasToken(msg.Headers, "Upgrade", "websocket") {
		return false
	}
	if !headerHasToken(msg.Headers, "Connection", "upgrade") {
		return false
	}
	return true
}

// isWS101Response reports whether msg is an HTTP/1.1 101 Switching Protocols
// response carrying the same Upgrade/Connection token pattern. The Send-side
// match (notice.hasSendUpgrade) is checked by the caller — this helper only
// looks at the response shape.
func isWS101Response(msg *envelope.HTTPMessage) bool {
	if msg == nil {
		return false
	}
	if msg.Status != 101 {
		return false
	}
	if !headerHasToken(msg.Headers, "Upgrade", "websocket") {
		return false
	}
	if !headerHasToken(msg.Headers, "Connection", "upgrade") {
		return false
	}
	return true
}

// isSSEResponse reports whether msg is a 2xx HTTP response whose
// Content-Type media type is text/event-stream (case-insensitive token
// match; parameters such as ";charset=utf-8" are ignored).
//
// Per RFC 8895 the canonical content-type for SSE is text/event-stream;
// we accept any 2xx status because servers occasionally use 200, 206,
// 207 etc. for streamed responses (and the wire-fidelity principle says
// the proxy reports what the server sent).
func isSSEResponse(msg *envelope.HTTPMessage) bool {
	if msg == nil {
		return false
	}
	if msg.Status < 200 || msg.Status >= 300 {
		return false
	}
	ct := lookupHeader(msg.Headers, "Content-Type")
	if ct == "" {
		return false
	}
	// Strip parameters (everything after the first ';') and trim spaces.
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	ct = strings.TrimSpace(ct)
	return strings.EqualFold(ct, "text/event-stream")
}

// lookupHeader returns the first header value whose name matches needle
// case-insensitively, or the empty string if absent. READ-ONLY — never
// mutates the slice (MITM principle: do not normalize the wire).
func lookupHeader(headers []envelope.KeyValue, needle string) string {
	for _, kv := range headers {
		if strings.EqualFold(kv.Name, needle) {
			return kv.Value
		}
	}
	return ""
}

// headerHasToken returns true when any header named needle (case-insensitive)
// carries a comma-separated token that case-insensitive-equals token.
//
// Multiple headers with the same name (or different casing) are scanned
// independently — duplicates are NOT merged, preserving wire fidelity.
func headerHasToken(headers []envelope.KeyValue, needle, token string) bool {
	for _, kv := range headers {
		if !strings.EqualFold(kv.Name, needle) {
			continue
		}
		for _, part := range strings.Split(kv.Value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// drainedChannel is a no-op layer.Channel used as the client-side "still
// here, but no traffic" stand-in during SSE upgrades. SSE swaps only the
// upstream side (per N7 D-U3); the second RunStackSession invocation needs
// SOMETHING to read from the client side, so we hand it a Channel whose
// Next returns io.EOF immediately and whose Send is a no-op.
//
// drainedChannel does NOT touch the actual underlying connection — the
// post-upgrade client-side traffic on SSE is conceptually empty (SSE is
// half-duplex server→client), so a permanently-EOF reader is correct.
type drainedChannel struct {
	streamID string
	closed   chan struct{}
	once     sync.Once
}

// newDrainedChannel constructs a drainedChannel whose Closed() signal is
// already fired so observers see the terminal state immediately.
func newDrainedChannel(streamID string) *drainedChannel {
	closed := make(chan struct{})
	close(closed)
	return &drainedChannel{streamID: streamID, closed: closed}
}

// StreamID returns the captured stream identifier.
func (d *drainedChannel) StreamID() string { return d.streamID }

// Next always returns io.EOF — the client side has no more traffic to deliver.
func (d *drainedChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return nil, io.EOF
}

// Send is a silent no-op. SSE is server→client only; the upstream side's
// upstreamToClient goroutine still calls client.Send for forwarded events,
// but the only consumer here is the test harness or a dropped recursive
// call. Errors would surface as session failures, which is wrong: drained
// is "intentionally empty", not "broken".
func (d *drainedChannel) Send(_ context.Context, _ *envelope.Envelope) error { return nil }

// Close is idempotent.
func (d *drainedChannel) Close() error {
	d.once.Do(func() {})
	return nil
}

// Closed returns a pre-closed channel — observers fire immediately.
func (d *drainedChannel) Closed() <-chan struct{} { return d.closed }

// Err always returns io.EOF (the terminal state is normal stream end).
func (d *drainedChannel) Err() error { return io.EOF }

// sseLayerAdapter wraps an SSE layer.Channel as a layer.Layer so it can be
// installed into ConnectionStack via ReplaceUpstreamTop. sse.Wrap returns
// a Channel rather than a Layer because SSE has no independent layer
// lifecycle of its own — the inner http1.Layer is detached at swap time
// and the SSE Channel takes ownership of the body io.Reader.
//
// The adapter yields exactly one Channel (the wrapped sse.Channel) and is
// then closed; Layer.Close cascades to channel.Close.
type sseLayerAdapter struct {
	ch        layer.Channel
	channels  chan layer.Channel
	closeOnce sync.Once
}

// newSSELayerAdapter constructs an sseLayerAdapter over the given SSE
// Channel. The Channels() output is one-shot.
func newSSELayerAdapter(ch layer.Channel) *sseLayerAdapter {
	out := make(chan layer.Channel, 1)
	out <- ch
	close(out)
	return &sseLayerAdapter{ch: ch, channels: out}
}

// Channels returns the one-shot Channel output.
func (a *sseLayerAdapter) Channels() <-chan layer.Channel { return a.channels }

// Close cascades to the wrapped Channel.
func (a *sseLayerAdapter) Close() error {
	var err error
	a.closeOnce.Do(func() {
		if a.ch != nil {
			err = a.ch.Close()
		}
	})
	return err
}
