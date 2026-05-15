package httpaggregator

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
	"github.com/usk6666/yorishiro-proxy/internal/pluginv2"
)

// Role identifies whether the aggregated Channel is server-side (local
// endpoint behaves as an HTTP server, sees requests as Send) or client-
// side (local endpoint behaves as an HTTP client, sees responses as
// Receive). Matches the HTTP/2 Layer's Role semantics.
type Role uint8

const (
	// RoleServer: local endpoint is the HTTP server. Client Envelopes
	// (method/path/etc.) arrive with Direction=Send. Response Envelopes
	// are sent with Direction=Receive.
	RoleServer Role = iota
	// RoleClient: local endpoint is the HTTP client. Response Envelopes
	// arrive with Direction=Receive. Request Envelopes are sent with
	// Direction=Send.
	RoleClient
)

// WrapOptions tunes the aggregator's behavior. Zero-value options fall
// back to package defaults.
type WrapOptions struct {
	// BodySpillDir is the directory used for disk-backed BodyBuffer temp
	// files. Empty means os.TempDir() (resolved by the bodybuf package).
	BodySpillDir string

	// BodySpillThreshold is the cumulative body size above which the
	// aggregator promotes its in-memory buffer to a file-backed buffer.
	// Zero means use config.DefaultBodySpillThreshold.
	BodySpillThreshold int64

	// MaxBodySize caps the absolute body size. Exceeding this cap yields
	// a *layer.StreamError with Code=ErrorInternalError from Next() and
	// RST_STREAMs the underlying stream. Zero means use config.MaxBodySize.
	MaxBodySize int64

	// StateReleaser is the optional pluginv2 hook the wrapper invokes at
	// Close() with each emitted HTTPMessage's (ConnID, FlowID), releasing
	// the corresponding ctx.transaction_state scope. nil = no-op (legacy
	// parallel: the aggregator runs without pluginv2 wired up).
	StateReleaser pluginv2.StateReleaser
}

// WrapOption is a functional option applied on top of WrapOptions. The
// variadic-option shape lets callers configure per-Channel behaviour without
// expanding the WrapOptions struct surface (USK-897). Today the only Option
// is WithH2FrameRecordCallback; the type stays open for forward-compat.
//
// Naming and shape mirrors sibling Layers (http2.DetachOption /
// grpclayer.Option / http1 streaming-body Options) — see
// internal/layer/grpc/layer.go WithLPMFrameRecordCallback for the Rule of
// Three reference. A common WireLevelTap interface is intentionally
// deferred to a follow-up Issue (see USK-897 PR description for the
// proposed shape).
type WrapOption func(*wrapState)

// wrapState is the resolved per-Channel configuration produced by applying
// the variadic WrapOption slice. Kept private so the Option surface stays
// the only way to set fields.
type wrapState struct {
	// h2FrameCB is the optional synchronous per-H2DataEvent callback
	// installed by WithH2FrameRecordCallback. nil = no-op (the aggregator
	// behaves identically to the pre-USK-897 contract).
	h2FrameCB func(*envelope.Envelope)
}

// WithH2FrameRecordCallback installs a synchronous per-H2DataEvent
// wire-record callback on the aggregator Channel (USK-897 v2 wave #3 —
// aggregator-path symmetry fix for the USK-889 detach-path coverage).
//
// The callback fires once per H2DataEvent absorbed by the aggregator,
// BEFORE the DATA payload is appended to the in-flight body buffer. This
// ordering reflects the CLAUDE.md MITM Principle 3 contract — the
// recorder's snapshot must mirror on-wire observation, not the post-body
// state. The envelope passed to the callback is a fresh struct allocated
// inside the aggregator; its Raw field is a defensive copy of the
// H2DataEvent payload bytes (callable consumers may retain the slice
// across return).
//
// Envelope contract:
//
//   - Protocol  = envelope.ProtocolHTTP (per the H2DataEvent provenance —
//     NOT a new ProtocolHTTP2 value)
//   - StreamID  = the inner channel's StreamID (the lower-layer view; the
//     session orchestrator rewrites this to the session-scope
//     identity before dispatching to the record-only Pipeline)
//   - Direction = the H2DataEvent's Direction (preserved from the inner
//     envelope so Send / Receive symmetry is observable)
//   - Sequence  = the H2DataEvent's Sequence (the orchestrator rewrites
//     this to a per-direction counter scoped to
//     (sessionStreamID, WireLevel=h2-frame))
//   - Raw       = the DATA frame payload bytes (no 9-byte frame header;
//     the header is reconstructable from EndStream + payload
//     length, matching the USK-889 detach-path envelope shape)
//   - Message   = nil (DATA frame wire envelopes have no L7 structured
//     view — the matching HTTPMessage envelope queued AFTER
//     absorption already provides that)
//   - Context   = the H2DataEvent envelope's Context (carries ConnID /
//     TargetHost / TLS / ClientAddr unchanged; the callback
//     expects to stamp flow.WireLevelH2Frame before
//     dispatching to the record-only Pipeline)
//
// Contract:
//   - Non-blocking: runs synchronously on the aggregator's Next goroutine.
//     A slow callback delays the HTTPMessage finalisation for the current
//     exchange. If the caller's recording path needs to perform IO that
//     may block (DB write under contention, network call), it must
//     dispatch its own goroutine inside cb.
//   - Single-goroutine fire: invoked from absorbData under the
//     aggregator's mutex, so the callback MUST NOT call back into the
//     aggregator. The mutex hold is brief — the callback fires inline
//     before the DATA payload is appended to the body buffer.
//   - nil = no-op (no wire-record envelope is produced; aggregator behaves
//     identically to the pre-USK-897 contract).
//
// Mirrors the per-Layer Option shape used by
// http2.WithFrameRecordCallback (USK-889),
// http1.WithChunkRecordCallback (USK-895), and
// grpclayer.WithLPMFrameRecordCallback (USK-896). A common WireLevelTap
// interface is intentionally deferred to a follow-up Issue (USK-897 hits
// the Rule of Three; the refactor is scoped separately for PR size
// control).
func WithH2FrameRecordCallback(cb func(*envelope.Envelope)) WrapOption {
	return func(s *wrapState) { s.h2FrameCB = cb }
}

// OptionsFromLayer returns a WrapOptions populated from the given HTTP/2
// Layer's BodyOpts. Callers that built the Layer with WithBodySpillDir /
// WithBodySpillThreshold / WithMaxBodySize can thread those values here
// without redundant plumbing.
func OptionsFromLayer(l *http2.Layer) WrapOptions {
	if l == nil {
		return WrapOptions{}
	}
	o := l.BodyOpts()
	return WrapOptions{
		BodySpillDir:       o.SpillDir,
		BodySpillThreshold: o.SpillThreshold,
		MaxBodySize:        o.MaxBody,
	}
}

// Wrap consumes a single event-granular HTTP/2 stream Channel and returns
// a Channel that yields aggregated HTTPMessage envelopes. role selects
// the direction convention (RoleServer: request Send / response Receive;
// RoleClient: response Receive / request Send).
//
// firstHeaders, if non-nil, is a pre-peeked H2HeadersEvent envelope
// (typically obtained by the caller to inspect content-type for gRPC
// detection). The aggregator treats it as if it had been the first
// envelope read from stream.Next() — i.e., it becomes the source of the
// first aggregated HTTPMessage. Pass nil when no peek occurred.
//
// Close on the returned Channel closes only the aggregator wrapper; the
// caller still owns the lifecycle of the underlying stream Channel.
//
// Optional WrapOption values tune per-Channel behaviour layered on top of
// the WrapOptions struct (e.g. WithH2FrameRecordCallback for the USK-897
// h2-frame wire-record callback). The variadic shape keeps existing
// call sites source-compatible — pre-USK-897 callers pass no Options and
// the aggregator behaves identically to the prior contract.
func Wrap(stream layer.Channel, role Role, firstHeaders *envelope.Envelope, opts WrapOptions, wopts ...WrapOption) layer.Channel {
	st := wrapState{}
	for _, o := range wopts {
		if o != nil {
			o(&st)
		}
	}
	ac := &aggregatorChannel{
		inner:     stream,
		role:      role,
		opts:      opts,
		peeked:    firstHeaders,
		recvDone:  make(chan struct{}),
		h2FrameCB: st.h2FrameCB,
	}
	return ac
}

// WrapWithDefaults is Wrap with zero-value options (i.e., use package
// defaults for all body-buffer knobs).
func WrapWithDefaults(stream layer.Channel, role Role, firstHeaders *envelope.Envelope) layer.Channel {
	return Wrap(stream, role, firstHeaders, WrapOptions{})
}
