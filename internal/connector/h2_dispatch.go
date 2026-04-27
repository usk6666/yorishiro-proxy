package connector

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	grpclayer "github.com/usk6666/yorishiro-proxy/internal/layer/grpc"
	"github.com/usk6666/yorishiro-proxy/internal/layer/grpcweb"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/layer/httpaggregator"
)

// DispatchH2Stream peeks the first event-granular envelope on an HTTP/2
// stream Channel, inspects its content-type for protocol detection, and
// wraps the channel with the appropriate application-layer chain:
//
//   - application/grpc-web[-text][+proto|...] → httpaggregator.Wrap →
//     grpcweb.Wrap (gRPC-Web frames embedded in an HTTP body)
//   - application/grpc[+proto|+json|...]      → grpclayer.Wrap (USK-640)
//   - any other content-type                  → httpaggregator.Wrap
//
// gRPC-Web is checked BEFORE native gRPC. The discriminator is precise
// enough that branch order does not affect correctness (USK-658), but
// matching the more specific prefix first is defense-in-depth against
// future regressions in the native-gRPC matcher.
//
// role selects which direction convention the aggregator (and any wrapper
// above it) uses. lopts threads the Layer's body-buffer configuration
// into the aggregator so disk spill behavior matches the HTTP/1.x path;
// the gRPC Layer manages its own LPM-bounded buffer and ignores lopts.
//
// grpcOpts are passed to grpclayer.Wrap on the native-gRPC branch (e.g.
// grpclayer.WithMaxMessageSize from BuildConfig.GRPCMaxMessageSize).
// They are ignored on the gRPC-Web and default branches.
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

	ct := extractContentType(evt)

	// gRPC-Web detection: content-type: application/grpc-web[-text][+proto|...]
	// indicates gRPC-Web frames embedded in an HTTP body. Wrap with the
	// httpaggregator so each request/response surfaces as one HTTPMessage,
	// then layer grpcweb on top to surface GRPCStart/Data/End envelopes.
	// This must precede the native-gRPC check because pre-USK-658 callers
	// observed application/grpc-web getting routed to grpclayer.
	if grpcweb.IsGRPCWebContentType(ct) {
		logger.Debug("connector: DispatchH2Stream: gRPC-Web content-type detected; wrapping with httpaggregator + grpcweb",
			"stream_id", firstEnv.StreamID,
			"path", evt.Path,
			"content_type", ct,
		)
		aggCh := httpaggregator.Wrap(ch, role, firstEnv, lopts)
		return grpcweb.Wrap(aggCh, translateRoleForGRPCWeb(role)), nil
	}

	// Native gRPC detection: content-type: application/grpc[+proto|+json|...]
	// (per RFC 6838 §4.2.8 structured-syntax suffix) signals a gRPC stream
	// over HTTP/2 trailers. Wrap with GRPCLayer (USK-640) — it consumes
	// the peeked first envelope as the initial GRPCStartMessage source.
	if isGRPCContentType(ct) {
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

// translateRoleForGRPCWeb converts an httpaggregator.Role into the
// equivalent grpcweb.Role. The two enums are independent (separate types,
// per Friction 4-C in envelope-implementation.md) and must not be relied
// on to coincide numerically.
func translateRoleForGRPCWeb(r httpaggregator.Role) grpcweb.Role {
	switch r {
	case httpaggregator.RoleServer:
		return grpcweb.RoleServer
	case httpaggregator.RoleClient:
		return grpcweb.RoleClient
	default:
		return grpcweb.RoleServer
	}
}

// extractContentType returns the value of the first content-type header
// found on evt (case-insensitive name match), or "" if none is present.
// Multiple content-type headers are not merged; the first wins, matching
// the pre-USK-658 dispatcher semantics.
func extractContentType(evt *http2.H2HeadersEvent) string {
	for _, kv := range evt.Headers {
		if strings.EqualFold(kv.Name, "content-type") {
			return kv.Value
		}
	}
	return ""
}

// isGRPCContentType reports whether ct is a native-gRPC media type:
// exactly application/grpc, or application/grpc with a structured-syntax
// suffix (application/grpc+proto, application/grpc+json, ...). Parameters
// (; charset=utf-8) are stripped before comparison. Crucially this does
// NOT match application/grpc-web* — the previous prefix-only check did,
// which was the USK-658 bug.
func isGRPCContentType(ct string) bool {
	mt := ct
	if i := strings.IndexByte(mt, ';'); i >= 0 {
		mt = mt[:i]
	}
	mt = strings.TrimSpace(strings.ToLower(mt))
	if mt == "application/grpc" {
		return true
	}
	return strings.HasPrefix(mt, "application/grpc+")
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
