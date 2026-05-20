package connector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
)

// DispatchH1Channel peeks the first envelope on an HTTP/1.x per-exchange
// Channel, inspects the request's content-type for protocol detection, and
// wraps the channel with the gRPC-Web Layer when the content-type matches:
//
//   - application/grpc-web[-text][+proto|...] → grpcweb.Wrap (returned
//     Channel emits GRPCStart/Data*/End envelopes stamped
//     Protocol=ProtocolGRPCWeb instead of *envelope.HTTPMessage).
//   - any other content-type → returned Channel re-yields the peeked
//     envelope verbatim on the first Next call; no protocol upgrade.
//
// This is the HTTP/1.x sibling of [DispatchH2Stream]. It exists because
// HTTP/1.1 keep-alive can mix grpc-web POST requests and JSON POST
// requests on the same connection, so the protocol decision must be made
// per-exchange — not at stack-build time.
//
// role selects the gRPC-Web Layer's direction convention:
//   - [grpcweb.RoleServer] for the downstream (client → proxy) wrap; the
//     proxy behaves as the gRPC-Web server reading the request.
//   - [grpcweb.RoleClient] for the upstream (proxy → upstream) wrap; the
//     proxy behaves as the gRPC-Web client assembling the request back to
//     the wire via inner.Send.
//
// grpcwebOpts are passed to [grpcweb.Wrap] on the gRPC-Web branch (e.g.,
// the per-stream [grpcweb.WithEncodedFormRecordCallback] installed by
// session.GRPCWebBase64RecordOption). Ignored on the default branch.
//
// The returned [layer.Channel] is what the caller should run RunSession
// or other consumers against. The peeked envelope is replayed via an
// internal replay-channel so no data is lost.
//
// Errors from the initial peek (clientCh.Next) are returned as-is so the
// caller can distinguish "peer hung up before request" from "stream
// error".
//
// USK-934: before this dispatcher existed, HTTP/1.x grpc-web traffic was
// recorded with Stream.Protocol="http", invisible to
// `query filter.protocol=grpc-web` / `manage delete_flows protocol=grpc-web`.
// Wire bytes were preserved (the http1 Layer captured them in Raw) but
// the protocol classification was wrong. This helper closes the gap by
// applying the H2 sibling's content-type-based wrap to H1 as well.
func DispatchH1Channel(
	ctx context.Context,
	clientCh layer.Channel,
	role grpcweb.Role,
	grpcwebOpts []grpcweb.Option,
	logger *slog.Logger,
) (layer.Channel, error) {
	if logger == nil {
		logger = slog.Default()
	}

	firstEnv, err := clientCh.Next(ctx)
	if err != nil {
		return nil, err
	}

	// The first envelope on an HTTP/1.x per-exchange Channel is always an
	// *envelope.HTTPMessage (the parsed request). Anything else means the
	// caller wired us against the wrong Channel type.
	msg, ok := firstEnv.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("connector: DispatchH1Channel: first envelope is %T, expected *HTTPMessage", firstEnv.Message)
	}

	ct := extractHTTPContentType(msg)
	replay := &http1ReplayChannel{
		underlying: clientCh,
		queued:     []*envelope.Envelope{firstEnv},
	}

	if grpcweb.IsGRPCWebContentType(ct) {
		logger.Debug("connector: DispatchH1Channel: gRPC-Web content-type detected; wrapping with grpcweb",
			"stream_id", firstEnv.StreamID,
			"method", msg.Method,
			"path", msg.Path,
			"content_type", ct,
		)
		return grpcweb.Wrap(replay, role, grpcwebOpts...), nil
	}

	return replay, nil
}

// WrapH1UpstreamForDispatch wraps a freshly opened upstream HTTP/1.x
// Channel with the same per-protocol layer the client-side dispatcher
// chose for the request. The session loop calls Send on this Channel
// with envelopes drawn from the client side, so the upstream Channel's
// Send method MUST accept the same Message types.
//
// Concretely:
//
//   - reqProto == [envelope.ProtocolGRPCWeb] → wrap with [grpcweb.Wrap]
//     in [grpcweb.RoleClient] so the gRPC-Web Send path (which accepts
//     GRPCStart / GRPCData / GRPCEnd envelopes and assembles them back
//     into an outbound HTTPMessage via inner.Send) reaches the upstream
//     wire correctly.
//   - any other Protocol (or empty) → return upCh unchanged.
//
// This is the HTTP/1.x sibling of [WrapH2UpstreamForDispatch]. Without
// this symmetry the upstream http1 Channel would see a
// GRPCStartMessage on the first Send and reject it (the http1 Channel
// only accepts *envelope.HTTPMessage), aborting the exchange before any
// envelope reached the Pipeline — exactly the failure pattern USK-771
// fixed for HTTP/2.
//
// grpcwebOpts are passed to [grpcweb.Wrap] on the gRPC-Web branch
// (matching the dispatcher's downstream wrap), ignored otherwise.
func WrapH1UpstreamForDispatch(
	upCh layer.Channel,
	reqProto envelope.Protocol,
	grpcwebOpts []grpcweb.Option,
) layer.Channel {
	if reqProto == envelope.ProtocolGRPCWeb {
		return grpcweb.Wrap(upCh, grpcweb.RoleClient, grpcwebOpts...)
	}
	return upCh
}

// extractHTTPContentType returns the value of the first content-type
// header found on msg (case-insensitive name match), or "" if none is
// present. Multiple content-type headers are not merged; the first wins
// (matching extractContentType's H2 semantics).
func extractHTTPContentType(msg *envelope.HTTPMessage) string {
	if msg == nil {
		return ""
	}
	for _, kv := range msg.Headers {
		if strings.EqualFold(kv.Name, "content-type") {
			return kv.Value
		}
	}
	return ""
}

// http1ReplayChannel wraps a [layer.Channel] so the first Next call
// returns a previously-peeked envelope before delegating to the
// underlying Channel. All other operations (Send, Close, Closed, Err,
// StreamID) pass through.
//
// Used by [DispatchH1Channel] to peek the first request envelope for
// content-type classification without disturbing the session loop's
// view of the Channel. The proxybuild package has an identical type for
// the tcp_forward L7 filter — both call sites accept light duplication
// per CLAUDE.md (prefer light duplication over premature abstraction
// when the shared interface is not yet stable across all four
// implementations).
//
// USK-934 (sibling of the proxybuild.http1ReplayChannel introduced in
// USK-913 for the websocket/sse filter): a common shared helper across
// connector and proxybuild is deferred — the connector copy is
// internal-internal so the import direction (proxybuild → connector) is
// preserved.
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
