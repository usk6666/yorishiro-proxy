package connector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// DispatchH2Stream peeks the first event-granular envelope on an HTTP/2
// stream Channel, inspects its content-type for gRPC detection, and wraps
// the channel with the appropriate application-layer wrapper:
//
//   - application/grpc[+proto|+json|...]  → grpclayer.Wrap (per USK-640)
//   - any other content-type              → httpaggregator.Wrap
//
// role selects which direction convention the aggregator (or gRPC Layer)
// uses. lopts threads the Layer's body-buffer configuration into the
// aggregator so disk spill behavior matches the HTTP/1.x path; the
// gRPC Layer manages its own LPM-bounded buffer and ignores lopts.
//
// grpcOpts are passed to grpclayer.Wrap on the gRPC branch (e.g.
// grpclayer.WithMaxMessageSize from BuildConfig.GRPCMaxMessageSize).
// They are ignored when content-type is not application/grpc*.
//
// The returned layer.Channel is what the caller should run RunSession or
// other consumers against. The first event is replayed as the first
// emitted envelope (via the firstHeaders argument on Wrap), so no data is
// lost by the peek.
//
// Errors from the initial peek (ch.Next) are returned as-is so the caller
// can distinguish "no stream activity" from "stream error".
func DispatchH2Stream(
	ctx context.Context,
	ch layer.Channel,
	role httpaggregator.Role,
	lopts httpaggregator.WrapOptions,
	logger *slog.Logger,
	grpcOpts ...grpclayer.Option,
) (layer.Channel, error) {
	if logger == nil {
		logger = slog.Default()
	}

	firstEnv, err := ch.Next(ctx)
	if err != nil {
		return nil, err
	}

	// The first envelope on an HTTP/2 event-granular channel is always an
	// H2HeadersEvent (the initial request/response HEADERS block). Any
	// other event type indicates a malformed stream or a bug in the Layer.
	evt, ok := firstEnv.Message.(*http2.H2HeadersEvent)
	if !ok {
		return nil, fmt.Errorf("connector: DispatchH2Stream: first envelope is %T, expected *H2HeadersEvent", firstEnv.Message)
	}

	// gRPC detection: content-type: application/grpc[+proto|+json|...] on
	// the request HEADERS (or the response HEADERS in ClientRole) signals
	// a gRPC stream. Wrap with GRPCLayer (USK-640) — it consumes the
	// peeked first envelope as the initial GRPCStartMessage source.
	if isGRPCHeaders(evt) {
		logger.Debug("connector: DispatchH2Stream: gRPC content-type detected; wrapping with grpclayer",
			"stream_id", firstEnv.StreamID,
			"path", evt.Path,
		)
		return grpclayer.Wrap(ch, firstEnv, translateRoleForGRPC(role), grpcOpts...), nil
	}

	return httpaggregator.Wrap(ch, role, firstEnv, lopts), nil
}

// GRPCOptionsFromBuildConfig assembles the [grpclayer.Option] slice from
// BuildConfig fields that the gRPC Layer accepts. Returns an empty slice
// when cfg is nil or no fields are populated, so the result is safe to
// splat into DispatchH2Stream regardless of caller context.
func GRPCOptionsFromBuildConfig(cfg *BuildConfig) []grpclayer.Option {
	if cfg == nil {
		return nil
	}
	var out []grpclayer.Option
	if cfg.GRPCMaxMessageSize > 0 {
		out = append(out, grpclayer.WithMaxMessageSize(cfg.GRPCMaxMessageSize))
	}
	return out
}

// translateRoleForGRPC converts an httpaggregator.Role into the
// equivalent grpclayer.Role. The two enums are independent (sibling
// Layers, no shared base type) but their semantics agree.
func translateRoleForGRPC(r httpaggregator.Role) grpclayer.Role {
	switch r {
	case httpaggregator.RoleServer:
		return grpclayer.RoleServer
	case httpaggregator.RoleClient:
		return grpclayer.RoleClient
	default:
		return grpclayer.RoleServer
	}
}

// isGRPCHeaders reports whether evt carries a content-type that indicates
// gRPC (including the +proto / +json subtype variants).
func isGRPCHeaders(evt *http2.H2HeadersEvent) bool {
	for _, kv := range evt.Headers {
		if !strings.EqualFold(kv.Name, "content-type") {
			continue
		}
		// Check only the leading type; subtypes ("+proto", "+json") and
		// parameters (; charset=...) are permitted variations.
		v := strings.ToLower(kv.Value)
		if strings.HasPrefix(v, "application/grpc") {
			return true
		}
	}
	return false
}

// EnvelopeIsH2Event reports whether env.Message is one of the HTTP/2 event
// types. Useful in callers that want to sanity-check a Channel they have
// NOT yet wrapped with the aggregator.
func EnvelopeIsH2Event(env *envelope.Envelope) bool {
	if env == nil || env.Message == nil {
		return false
	}
	switch env.Message.(type) {
	case *http2.H2HeadersEvent, *http2.H2DataEvent, *http2.H2TrailersEvent:
		return true
	}
	return false
}
