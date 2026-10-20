package grpcweb

import (
	"slices"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// controlKind identifies one of the four D7 control headers that
// refillFromHTTPMessage lifts out of GRPCStartMessage.Metadata into
// structured fields.
type controlKind int

const (
	controlContentType controlKind = iota
	controlEncoding
	controlAcceptEncoding
	controlTimeout
	numControlKinds
)

// controlKindOf maps a header name to its controlKind (case-insensitive).
func controlKindOf(name string) (controlKind, bool) {
	switch strings.ToLower(name) {
	case "content-type":
		return controlContentType, true
	case "grpc-encoding":
		return controlEncoding, true
	case "grpc-accept-encoding":
		return controlAcceptEncoding, true
	case "grpc-timeout":
		return controlTimeout, true
	}
	return 0, false
}

// controlEntry is one observed control-header entry: its wire name and raw
// value, and anchor — the number of retained Metadata entries that preceded
// it on the wire.
type controlEntry struct {
	kind   controlKind
	name   string
	value  string
	anchor int
}

// headerLayout records where and how the D7 control headers appeared on
// the wire (USK-1219). D7 keeps them out of Metadata so the structured
// fields are the single editable source; this is what lets the opposite
// Send put them back with the observed casing, position, raw value and
// duplicates instead of re-synthesizing them lowercase at the front
// (MITM Principle 1).
//
// The parsed* fields snapshot the structured values the Layer derived from
// the entries, so rebuildStartHeaders can tell an untouched field from one
// an Intercept / Transform / plugin Step edited.
type headerLayout struct {
	entries []controlEntry

	parsedContentType    string
	parsedEncoding       string
	parsedAcceptEncoding []string
	parsedTimeout        time.Duration
}

// newHeaderLayout records the control entries of headers (the inbound
// HTTPMessage's header list, wire order) and snapshots the structured
// values start was given from them.
func newHeaderLayout(headers []envelope.KeyValue, start *envelope.GRPCStartMessage) *headerLayout {
	l := &headerLayout{
		parsedContentType:    start.ContentType,
		parsedEncoding:       start.Encoding,
		parsedAcceptEncoding: slices.Clone(start.AcceptEncoding),
		parsedTimeout:        start.Timeout,
	}
	retained := 0
	for _, kv := range headers {
		if kind, ok := controlKindOf(kv.Name); ok {
			l.entries = append(l.entries, controlEntry{kind: kind, name: kv.Name, value: kv.Value, anchor: retained})
			continue
		}
		if !isStartStripName(kv.Name) {
			retained++
		}
	}
	return l
}

// layoutFromEnv returns the headerLayout attached to env's Opaque, or nil
// when env is nil or carries none (a fresh or Clone()d Envelope).
func layoutFromEnv(env *envelope.Envelope) *headerLayout {
	if env == nil {
		return nil
	}
	if o, ok := env.Opaque.(*opaqueGRPCWeb); ok {
		return o.layout
	}
	return nil
}

// rebuildStartHeaders returns the outbound header list for start: the
// preserved Metadata in its order with the four control headers re-inserted.
//
// With a layout (the Start came from refillFromHTTPMessage), each observed
// control entry is re-inserted at its anchor, clamped to the end when
// Metadata was shortened. Per kind:
//
//   - field still equals the value parsed from the wire: every entry is
//     emitted with its observed name and raw value, so duplicates and values
//     the Layer could not parse (e.g. "grpc-timeout: soon") survive.
//   - field changed: every entry of the kind is rewritten in place — name
//     casing and position kept, value replaced (the reconcileBodyFraming
//     rule, USK-1203).
//   - field cleared: the kind's entries are dropped.
//   - field set but the kind was never observed: synthesized lowercase at
//     the front, as before.
//
// Without a layout — a synthetic producer, or an Envelope that went
// through Envelope.Clone (which drops Opaque; intercept modify_and_forward
// does this) — every set field is synthesized lowercase at the front, the
// pre-USK-1219 layout. Same trade-off as the http1 synthetic send path.
func rebuildStartHeaders(start *envelope.GRPCStartMessage, layout *headerLayout) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(start.Metadata)+4)
	var observed [numControlKinds]bool
	if layout != nil {
		for _, e := range layout.entries {
			observed[e.kind] = true
		}
	}
	for kind := controlKind(0); kind < numControlKinds; kind++ {
		if observed[kind] {
			continue
		}
		if v, set := controlValue(start, kind); set {
			out = append(out, envelope.KeyValue{Name: controlSynthName(kind), Value: v})
		}
	}
	if layout == nil {
		return append(out, start.Metadata...)
	}

	var changed [numControlKinds]bool
	for kind := controlKind(0); kind < numControlKinds; kind++ {
		changed[kind] = !layout.unchanged(start, kind)
	}
	emit := func(e controlEntry) {
		if !changed[e.kind] {
			out = append(out, envelope.KeyValue{Name: e.name, Value: e.value})
			return
		}
		if v, set := controlValue(start, e.kind); set {
			out = append(out, envelope.KeyValue{Name: e.name, Value: v})
		}
	}
	next := 0
	for i, kv := range start.Metadata {
		for next < len(layout.entries) && layout.entries[next].anchor <= i {
			emit(layout.entries[next])
			next++
		}
		out = append(out, kv)
	}
	for ; next < len(layout.entries); next++ {
		emit(layout.entries[next])
	}
	return out
}

// unchanged reports whether start's structured field for kind still equals
// the value the Layer parsed from the wire.
func (l *headerLayout) unchanged(start *envelope.GRPCStartMessage, kind controlKind) bool {
	switch kind {
	case controlContentType:
		return start.ContentType == l.parsedContentType
	case controlEncoding:
		return start.Encoding == l.parsedEncoding
	case controlAcceptEncoding:
		return slices.Equal(start.AcceptEncoding, l.parsedAcceptEncoding)
	default:
		return start.Timeout == l.parsedTimeout
	}
}

// controlValue renders start's structured field for kind as a header value.
// set is false when the field is at its zero value (header absent).
func controlValue(start *envelope.GRPCStartMessage, kind controlKind) (string, bool) {
	switch kind {
	case controlContentType:
		return start.ContentType, start.ContentType != ""
	case controlEncoding:
		return start.Encoding, start.Encoding != ""
	case controlAcceptEncoding:
		return strings.Join(start.AcceptEncoding, ","), len(start.AcceptEncoding) > 0
	default:
		return formatGRPCTimeout(start.Timeout), start.Timeout > 0
	}
}

// controlSynthName is the lowercase name used when a control header is
// synthesized rather than restored from the observed layout.
func controlSynthName(kind controlKind) string {
	switch kind {
	case controlContentType:
		return "content-type"
	case controlEncoding:
		return "grpc-encoding"
	case controlAcceptEncoding:
		return "grpc-accept-encoding"
	default:
		return "grpc-timeout"
	}
}
