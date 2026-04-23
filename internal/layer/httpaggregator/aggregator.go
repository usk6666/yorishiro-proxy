package httpaggregator

import (
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2"
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
func Wrap(stream layer.Channel, role Role, firstHeaders *envelope.Envelope, opts WrapOptions) layer.Channel {
	ac := &aggregatorChannel{
		inner:    stream,
		role:     role,
		opts:     opts,
		peeked:   firstHeaders,
		recvDone: make(chan struct{}),
	}
	return ac
}

// WrapWithDefaults is Wrap with zero-value options (i.e., use package
// defaults for all body-buffer knobs).
func WrapWithDefaults(stream layer.Channel, role Role, firstHeaders *envelope.Envelope) layer.Channel {
	return Wrap(stream, role, firstHeaders, WrapOptions{})
}
