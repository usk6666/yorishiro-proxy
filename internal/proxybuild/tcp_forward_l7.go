package proxybuild

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/connector"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1"
	"github.com/usk6666/yorishiro-proxy/internal/pipeline"
	"github.com/usk6666/yorishiro-proxy/internal/session"
)

// exchangeFilter is the per-exchange first-envelope filter applied by the
// L7 forward dispatch (USK-913). It is consulted twice per exchange:
//
//   - phase="request" with the first envelope read from the client Channel
//     (the HTTP/1.x request). The filter decides whether the operator-
//     declared expectation ("websocket" → Upgrade: websocket; "sse" → no
//     pre-check) is satisfied.
//
//   - phase="response" with the first envelope read from the upstream
//     Channel (the HTTP/1.x response). The filter decides whether the
//     operator-declared expectation ("sse" → Content-Type:
//     text/event-stream; "websocket" → already validated at request phase)
//     is satisfied.
//
// A nil return value means "pass"; a non-nil return is the human-readable
// "blocked_by" attribution that the synthetic 502 + audit Stream uses.
type exchangeFilter func(phase string, env *envelope.Envelope) (blockedBy string)

// exchangeFilterFor returns the appropriate filter for the operator-declared
// protocol. http / raw / auto return nil (no filter); websocket / sse return
// the matching predicate. The logger is captured for the phase=hit Debug
// log.
func exchangeFilterFor(protocol string, logger *slog.Logger) exchangeFilter {
	switch protocol {
	case "websocket":
		return func(phase string, env *envelope.Envelope) string {
			if phase != "request" || env == nil {
				return ""
			}
			msg, ok := env.Message.(*envelope.HTTPMessage)
			if !ok || msg == nil {
				return ""
			}
			if isWSUpgradeHTTPMessage(msg) {
				return ""
			}
			logger.Debug("tcp forward websocket filter rejected non-Upgrade request",
				"method", msg.Method, "path", msg.Path)
			return "forward_protocol_mismatch:websocket_vs_http"
		}
	case "sse":
		return func(phase string, env *envelope.Envelope) string {
			if phase != "response" || env == nil {
				return ""
			}
			msg, ok := env.Message.(*envelope.HTTPMessage)
			if !ok || msg == nil {
				return ""
			}
			if isSSEHTTPMessage(msg) {
				return ""
			}
			logger.Debug("tcp forward sse filter rejected non-SSE response",
				"status", msg.Status, "content_type", lookupHTTPHeader(msg.Headers, "Content-Type"))
			return "forward_protocol_mismatch:sse_vs_http"
		}
	default:
		return nil
	}
}

// runTCPForwardHTTP1ExchangeLoop is the forward-side sibling of
// runHTTP1ExchangeLoop (builder.go). It iterates the client http1 Layer's
// Channels(), runs one goroutine per exchange, and dispatches via
// session.RunStackSessionExchange — same shape as the MITM-routed path.
//
// The difference vs runHTTP1ExchangeLoop is the optional per-exchange
// filter: when filter is non-nil, the first request envelope is peeked
// before the exchange enters the upstream dial closure. If the filter
// returns a non-empty blockedBy attribution the exchange is short-circuited:
//
//  1. A synthetic 502 response is written to the client via clientCh.Send.
//  2. The Pipeline-Drop audit hook (sessOpts.OnPipelineDrop) is invoked
//     so the operator-visible Stream lands in the flow store with
//     State="error" + BlockedBy="forward_protocol_mismatch:...".
//  3. The exchange is closed; the spawn loop continues to the next one
//     (HTTP/1.x keep-alive may carry more requests on the same conn,
//     each filtered independently).
//
// The response-phase filter is checked inside a Pipeline.Step-equivalent
// wrapping closure on the upstream dial: the first response envelope is
// inspected before forwarding back to the client.
func runTCPForwardHTTP1ExchangeLoop(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientH1, upstreamH1 *http1.Layer,
	parentStack *Stack,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
	filter exchangeFilter,
) {
	// USK-934: derive base grpc-web Layer Options from the parent Stack's
	// BuildConfig (matches the live data path's
	// GRPCWebOptionsFromBuildConfig invocation in builder.go). The
	// per-exchange goroutine layers the wire-record callback on top via
	// session.GRPCWebBase64RecordOption — same wiring shape as the
	// MITM-routed path.
	var baseGRPCWebOpts []grpcweb.Option
	if parentStack != nil {
		baseGRPCWebOpts = connector.GRPCWebOptionsFromBuildConfig(parentStack.BuildConfig)
	}
	var wg sync.WaitGroup
	for {
		select {
		case <-ctx.Done():
			wg.Wait()
			return
		case clientCh, ok := <-clientH1.Channels():
			if !ok {
				wg.Wait()
				return
			}
			wg.Add(1)
			go func(ch layer.Channel) {
				defer wg.Done()
				runForwardHTTP1Exchange(ctx, stack, ch, upstreamH1, p, sessOpts, target, logger, filter, baseGRPCWebOpts)
			}(clientCh)
		}
	}
}

// runForwardHTTP1Exchange runs a single client http1 exchange through the
// forward dispatch. When filter is nil this is equivalent to the body of
// the runHTTP1ExchangeLoop goroutine (RunStackSessionExchange with a
// upstream-OpenExchange dial closure).
//
// When filter is non-nil we apply the filter as follows:
//
//   - phase="request": before dispatching to RunStackSessionExchange the
//     first envelope is peeked via filterPeekChannel. A mismatch synthesises
//     a 502 + Pipeline-Drop audit Stream and the function returns without
//     touching the upstream dial.
//
//   - phase="response": the dial closure wraps the upstream Channel in a
//     filterUpstreamChannel that peeks the first Receive envelope (the
//     upstream response). A mismatch writes a 502 back to the client via
//     the original client Channel and aborts the session by closing the
//     wrapper.
//
// The session loop sees these as normal channel terminations
// (io.EOF on the filtered Channel after the drop), so OnComplete fires
// with state="error" via the synthesised wrapper (or via the
// OnPipelineDrop audit hook + state="error" from the existing
// tcpForwardSessionOpts classifier).
func runForwardHTTP1Exchange(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientCh layer.Channel,
	upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
	filter exchangeFilter,
	baseGRPCWebOpts []grpcweb.Option,
) {
	// USK-934: per-exchange grpc-web auto-classify Options. The same
	// closure is installed on both the client-side DispatchH1Channel and
	// the upstream-side WrapH1UpstreamForDispatch so wire-record envelopes
	// from both wraps land under the same Stream row.
	streamFlowCtx := envelope.EnvelopeContext{ConnID: stack.ConnID, TargetHost: target}
	grpcWebBase64Opt := session.GRPCWebBase64RecordOption(ctx, p, clientCh.StreamID(), streamFlowCtx)
	streamGRPCWebOpts := make([]grpcweb.Option, 0, len(baseGRPCWebOpts)+1)
	streamGRPCWebOpts = append(streamGRPCWebOpts, baseGRPCWebOpts...)
	streamGRPCWebOpts = append(streamGRPCWebOpts, grpcWebBase64Opt)

	if filter == nil {
		runForwardHTTP1ExchangeNoFilter(ctx, stack, clientCh, upstreamH1, p, sessOpts, target, logger, streamGRPCWebOpts)
		return
	}
	runForwardHTTP1ExchangeWithFilter(ctx, stack, clientCh, upstreamH1, p, sessOpts, target, logger, filter, streamGRPCWebOpts)
}

// runForwardHTTP1ExchangeNoFilter is the no-filter arm of
// runForwardHTTP1Exchange. Dispatches through H1 grpc-web auto-classify
// (USK-934) and runs the vanilla per-exchange session. Mirrors
// builder.go runHTTP1Exchange.
func runForwardHTTP1ExchangeNoFilter(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientCh layer.Channel,
	upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
	streamGRPCWebOpts []grpcweb.Option,
) {
	dispatchedCh, err := connector.DispatchH1Channel(ctx, clientCh, grpcweb.RoleServer, streamGRPCWebOpts, logger)
	if err != nil {
		_ = clientCh.Close()
		if !errors.Is(err, context.Canceled) {
			logger.Debug("proxybuild: tcp forward http1 dispatch failed",
				"target", target, "stream_id", clientCh.StreamID(), "error", err)
		}
		return
	}
	dial := func(_ context.Context, env *envelope.Envelope) (layer.Channel, error) {
		upCh := upstreamH1.OpenExchange()
		if upCh == nil {
			return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
		}
		var reqProto envelope.Protocol
		if env != nil {
			reqProto = env.Protocol
		}
		return connector.WrapH1UpstreamForDispatch(upCh, reqProto, streamGRPCWebOpts), nil
	}
	if err := session.RunStackSessionExchange(ctx, stack, dispatchedCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
		logger.Debug("proxybuild: tcp forward http1 exchange ended with error", "target", target, "error", err)
	}
}

// runForwardHTTP1ExchangeWithFilter is the filter arm of
// runForwardHTTP1Exchange. The Protocol="websocket"/"sse" expectation
// filter is applied first on the first request envelope. If the filter
// passes, the request is replayed through DispatchH1Channel for
// grpc-web auto-classify (USK-934); the response-phase filter remains
// in place via filterUpstreamChannel. A websocket/sse filtered exchange
// will not be a grpc-web request in practice (Upgrade: websocket header
// is incompatible with application/grpc-web), so the DispatchH1Channel
// branch on the replay channel will be the default no-wrap path — but
// we keep it for symmetry with the no-filter arm and to preserve
// protocol-detection correctness if the filter ever loosens.
func runForwardHTTP1ExchangeWithFilter(
	ctx context.Context,
	stack *connector.ConnectionStack,
	clientCh layer.Channel,
	upstreamH1 *http1.Layer,
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
	filter exchangeFilter,
	streamGRPCWebOpts []grpcweb.Option,
) {
	// Request-phase filter: peek the first envelope. If the filter rejects,
	// synthesise a 502, fire the Pipeline-Drop audit, and return without
	// touching upstream.
	peekCtx, peekCancel := context.WithTimeout(ctx, tcpForwardRequestPeekTimeout)
	first, err := clientCh.Next(peekCtx)
	peekCancel()
	if err != nil {
		// Peer disconnected before sending a request — nothing to do.
		_ = clientCh.Close()
		logger.Debug("proxybuild: tcp forward http1 exchange peer hung up before request", "target", target, "error", err)
		return
	}

	if blockedBy := filter("request", first); blockedBy != "" {
		writeForwardSynth502(clientCh, blockedBy)
		if sessOpts.OnPipelineDrop != nil {
			sessOpts.OnPipelineDrop(context.WithoutCancel(ctx), first, blockedBy)
		}
		_ = clientCh.Close()
		return
	}

	// Request passed the filter: build a replay-channel that yields `first`
	// once then delegates to the underlying Channel, then run it through
	// DispatchH1Channel for grpc-web auto-classify (USK-934).
	replayCh := &http1ReplayChannel{
		underlying: clientCh,
		queued:     []*envelope.Envelope{first},
	}
	dispatchedCh, err := connector.DispatchH1Channel(ctx, replayCh, grpcweb.RoleServer, streamGRPCWebOpts, logger)
	if err != nil {
		_ = clientCh.Close()
		if !errors.Is(err, context.Canceled) {
			logger.Debug("proxybuild: tcp forward http1 dispatch failed",
				"target", target, "stream_id", clientCh.StreamID(), "error", err)
		}
		return
	}

	// Response-phase filter: wrap the upstream dial so the upstream
	// Channel's first Receive is checked. The wrapper writes a 502 back
	// to the client when the first response fails the filter and returns
	// io.EOF on subsequent Next calls so the session loop unwinds.
	dial := func(_ context.Context, env *envelope.Envelope) (layer.Channel, error) {
		upCh := upstreamH1.OpenExchange()
		if upCh == nil {
			return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
		}
		var reqProto envelope.Protocol
		if env != nil {
			reqProto = env.Protocol
		}
		wrappedUp := connector.WrapH1UpstreamForDispatch(upCh, reqProto, streamGRPCWebOpts)
		return &filterUpstreamChannel{
			Channel:  wrappedUp,
			filter:   filter,
			clientCh: clientCh,
			onDrop: func(env *envelope.Envelope, blockedBy string) {
				if sessOpts.OnPipelineDrop != nil {
					sessOpts.OnPipelineDrop(context.WithoutCancel(ctx), env, blockedBy)
				}
			},
		}, nil
	}

	if err := session.RunStackSessionExchange(ctx, stack, dispatchedCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
		logger.Debug("proxybuild: tcp forward http1 exchange ended with error", "target", target, "error", err)
	}
}

// tcpForwardRequestPeekTimeout bounds the first-envelope peek used by the
// websocket/sse expectation filter. A client that opens the conn but
// never sends a request should not hold up the goroutine indefinitely.
// Aligned with targetOverrideAutoPeekTimeout (5s) — small enough to limit
// slow-loris goroutine occupation on filtered arms (review finding S-1
// from review-gate), generous enough to absorb legitimate brief pauses
// between conn open and request write.
const tcpForwardRequestPeekTimeout = 5 * time.Second

// tcpForwardSynth502WriteTimeout bounds the synthetic 502 write to a
// rejected client. The Send is best-effort (the conn is about to close
// anyway), so a short ctx is sufficient — without it a wedged client TCP
// write buffer can park filterUpstreamChannel.Next indefinitely (review
// finding S-2 from review-gate).
const tcpForwardSynth502WriteTimeout = 3 * time.Second

// writeForwardSynth502 writes a minimal synthetic 502 response back to
// the client via the supplied Channel. The response identifies the proxy
// in the Server header and includes the blockedBy attribution in the
// body so an operator running curl sees the rejection cause.
//
// Best-effort: Send errors are swallowed — the conn is about to close.
// We do NOT touch the underlying conn directly because the channel's
// Send path owns wire writes (preserving the http1 Layer's write-mu
// serialization).
func writeForwardSynth502(ch layer.Channel, blockedBy string) {
	if ch == nil {
		return
	}
	body := []byte("yorishiro-proxy: " + blockedBy + "\r\n")
	resp := &envelope.HTTPMessage{
		HTTPVersion:  envelope.HTTPVersion11,
		Status:       502,
		StatusReason: "Bad Gateway",
		Headers: []envelope.KeyValue{
			{Name: "Server", Value: "yorishiro-proxy"},
			{Name: "Content-Type", Value: "text/plain; charset=utf-8"},
			{Name: "Content-Length", Value: fmt.Sprintf("%d", len(body))},
			{Name: "Connection", Value: "close"},
		},
		Body: body,
	}
	env := &envelope.Envelope{
		Protocol:  envelope.ProtocolHTTP,
		Direction: envelope.Receive,
		Message:   resp,
	}
	// Bound the write so a wedged client TCP buffer cannot park the
	// caller (filterUpstreamChannel.Next) indefinitely. Best-effort
	// only — the conn is about to close after this Send returns.
	sendCtx, cancel := context.WithTimeout(context.Background(), tcpForwardSynth502WriteTimeout)
	defer cancel()
	_ = ch.Send(sendCtx, env)
}

// http1ReplayChannel wraps a Channel so the first Next call returns a
// previously-peeked envelope before delegating to the underlying Channel.
// All other operations (Send, Close, Closed, Err, StreamID) pass through.
//
// Used by the L7 forward path to peek the first request envelope for the
// websocket/sse expectation filter without disturbing the session loop's
// view of the Channel.
type http1ReplayChannel struct {
	underlying layer.Channel
	mu         sync.Mutex
	queued     []*envelope.Envelope
}

func (c *http1ReplayChannel) StreamID() string { return c.underlying.StreamID() }

func (c *http1ReplayChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	if len(c.queued) > 0 {
		env := c.queued[0]
		c.queued = c.queued[1:]
		c.mu.Unlock()
		return env, nil
	}
	c.mu.Unlock()
	return c.underlying.Next(ctx)
}

func (c *http1ReplayChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return c.underlying.Send(ctx, env)
}

func (c *http1ReplayChannel) Close() error { return c.underlying.Close() }

func (c *http1ReplayChannel) Closed() <-chan struct{} { return c.underlying.Closed() }

func (c *http1ReplayChannel) Err() error { return c.underlying.Err() }

// filterUpstreamChannel wraps an upstream Channel so the first Receive
// envelope is checked against the operator-declared expectation. When the
// filter rejects, the wrapper writes a synthetic 502 back to the client
// (via the original clientCh — the wrapper has direct access to it) and
// returns io.EOF on subsequent Next calls so the session loop unwinds.
//
// Used by the L7 forward path to apply the Protocol="sse" expectation
// filter on the upstream response.
type filterUpstreamChannel struct {
	layer.Channel
	filter      exchangeFilter
	clientCh    layer.Channel
	onDrop      func(env *envelope.Envelope, blockedBy string)
	checkedOnce sync.Once
	mu          sync.Mutex
	rejected    bool
}

func (c *filterUpstreamChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
	c.mu.Lock()
	if c.rejected {
		c.mu.Unlock()
		return nil, io.EOF
	}
	c.mu.Unlock()

	env, err := c.Channel.Next(ctx)
	if err != nil {
		return nil, err
	}

	// Only the first envelope is checked. Subsequent envelopes (the body
	// of a passed-response, for instance) flow through unchanged.
	var blockedBy string
	c.checkedOnce.Do(func() {
		blockedBy = c.filter("response", env)
	})
	if blockedBy == "" {
		return env, nil
	}

	// Filter rejected the response: synthesise a 502 to the client and
	// abort by marking the wrapper rejected so the next Next returns EOF.
	c.mu.Lock()
	c.rejected = true
	c.mu.Unlock()
	if c.onDrop != nil {
		c.onDrop(env, blockedBy)
	}
	writeForwardSynth502(c.clientCh, blockedBy)
	return nil, io.EOF
}

// isWSUpgradeHTTPMessage is a public-friendly mirror of
// session.isWSUpgradeRequest, scoped to the proxybuild forward dispatch.
// It checks the wire-observed Upgrade / Connection token pattern per RFC
// 6455 §4.1. We re-implement here rather than exporting the session
// version because the session predicate is shaped for the in-Pipeline
// path; this helper is shaped for the pre-dispatch filter and the
// behaviour is identical.
func isWSUpgradeHTTPMessage(msg *envelope.HTTPMessage) bool {
	if msg == nil {
		return false
	}
	if !httpHeaderHasToken(msg.Headers, "Upgrade", "websocket") {
		return false
	}
	if !httpHeaderHasToken(msg.Headers, "Connection", "upgrade") {
		return false
	}
	return true
}

// isSSEHTTPMessage reports whether msg is a 2xx HTTP response carrying a
// Content-Type whose media type is text/event-stream (case-insensitive,
// ignoring parameters per RFC 7231 §3.1.1.1). Mirrors the session-side
// isSSEResponse predicate.
func isSSEHTTPMessage(msg *envelope.HTTPMessage) bool {
	if msg == nil {
		return false
	}
	if msg.Status < 200 || msg.Status >= 300 {
		return false
	}
	ct := lookupHTTPHeader(msg.Headers, "Content-Type")
	if ct == "" {
		return false
	}
	mediaType := ct
	if semi := strings.IndexByte(mediaType, ';'); semi >= 0 {
		mediaType = mediaType[:semi]
	}
	mediaType = strings.TrimSpace(mediaType)
	return strings.EqualFold(mediaType, "text/event-stream")
}

// httpHeaderHasToken reports whether headers contains a name (case-
// insensitive) whose comma-separated tokenised value includes token
// (case-insensitive). Mirrors session.headerHasToken; package-private
// here because the session export is internal-internal.
func httpHeaderHasToken(headers []envelope.KeyValue, name, token string) bool {
	for _, kv := range headers {
		if !strings.EqualFold(kv.Name, name) {
			continue
		}
		for _, t := range strings.Split(kv.Value, ",") {
			if strings.EqualFold(strings.TrimSpace(t), token) {
				return true
			}
		}
	}
	return false
}

// lookupHTTPHeader returns the FIRST header value matching name
// (case-insensitive). Empty if not present. Mirrors session.lookupHeader.
func lookupHTTPHeader(headers []envelope.KeyValue, name string) string {
	for _, kv := range headers {
		if strings.EqualFold(kv.Name, name) {
			return kv.Value
		}
	}
	return ""
}
