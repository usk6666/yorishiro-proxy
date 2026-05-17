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
	p *pipeline.Pipeline,
	sessOpts session.SessionOptions,
	target string,
	logger *slog.Logger,
	filter exchangeFilter,
) {
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
				runForwardHTTP1Exchange(ctx, stack, ch, upstreamH1, p, sessOpts, target, logger, filter)
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
) {
	// No filter: vanilla per-exchange dispatch — same shape as the
	// builder.go runHTTP1ExchangeLoop goroutine.
	if filter == nil {
		dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
			upCh := upstreamH1.OpenExchange()
			if upCh == nil {
				return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
			}
			return upCh, nil
		}
		if err := session.RunStackSessionExchange(ctx, stack, clientCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
			logger.Debug("proxybuild: tcp forward http1 exchange ended with error", "target", target, "error", err)
		}
		return
	}

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
	// once then delegates to the underlying Channel. RunStackSessionExchange
	// is otherwise oblivious to the peek.
	replayCh := &replayChannel{
		underlying: clientCh,
		queued:     []*envelope.Envelope{first},
	}

	// Response-phase filter: wrap the upstream dial so the upstream
	// Channel's first Receive is checked. The wrapper writes a 502 back
	// to the client when the first response fails the filter and returns
	// io.EOF on subsequent Next calls so the session loop unwinds.
	dial := func(_ context.Context, _ *envelope.Envelope) (layer.Channel, error) {
		upCh := upstreamH1.OpenExchange()
		if upCh == nil {
			return nil, fmt.Errorf("proxybuild: upstream http1 layer closed before opening exchange for %s", target)
		}
		return &filterUpstreamChannel{
			Channel:  upCh,
			filter:   filter,
			clientCh: clientCh,
			onDrop: func(env *envelope.Envelope, blockedBy string) {
				if sessOpts.OnPipelineDrop != nil {
					sessOpts.OnPipelineDrop(context.WithoutCancel(ctx), env, blockedBy)
				}
			},
		}, nil
	}

	if err := session.RunStackSessionExchange(ctx, stack, replayCh, dial, p, sessOpts); err != nil && !errors.Is(err, context.Canceled) {
		logger.Debug("proxybuild: tcp forward http1 exchange ended with error", "target", target, "error", err)
	}
}

// tcpForwardRequestPeekTimeout bounds the first-envelope peek used by the
// websocket/sse expectation filter. A client that opens the conn but
// never sends a request should not hold up the goroutine indefinitely.
// Kept generous (10s) because legitimate clients may pause briefly
// between conn open and request write.
const tcpForwardRequestPeekTimeout = 10 * time.Second

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
	_ = ch.Send(context.Background(), env)
}

// replayChannel wraps a Channel so the first Next call returns a
// previously-peeked envelope before delegating to the underlying Channel.
// All other operations (Send, Close, Closed, Err, StreamID) pass through.
//
// Used by the L7 forward path to peek the first request envelope for the
// websocket/sse expectation filter without disturbing the session loop's
// view of the Channel.
type replayChannel struct {
	underlying layer.Channel
	mu         sync.Mutex
	queued     []*envelope.Envelope
}

func (c *replayChannel) StreamID() string { return c.underlying.StreamID() }

func (c *replayChannel) Next(ctx context.Context) (*envelope.Envelope, error) {
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

func (c *replayChannel) Send(ctx context.Context, env *envelope.Envelope) error {
	return c.underlying.Send(ctx, env)
}

func (c *replayChannel) Close() error { return c.underlying.Close() }

func (c *replayChannel) Closed() <-chan struct{} { return c.underlying.Closed() }

func (c *replayChannel) Err() error { return c.underlying.Err() }

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
