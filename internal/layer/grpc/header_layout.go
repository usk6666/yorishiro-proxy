package grpc

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// opaqueGRPC is per-RPC-direction Layer-internal state attached to the
// GRPCStartMessage envelope absorbHeaders emits (and, for a response
// HEADERS frame that carried END_STREAM, to the End it synthesizes from
// the same frame). The opposite-side Channel's Send reads it; Pipeline
// Steps must not type-assert on Opaque (RFC-001 §3.1). It lives on the
// envelope rather than on the Channel because the Channel that absorbed
// the frame is not the one that sends it (USK-1251).
type opaqueGRPC struct {
	// layout records the observed D7 control headers so sendStart can
	// restore them (rebuildStartHeaders).
	layout *headerLayout

	// endStreamEnd is non-nil when the Receive HEADERS frame carried
	// END_STREAM: a trailers-only response (grpc-status in the headers) or
	// a bare response without any grpc-status (e.g. a load balancer's
	// "HEADERS(:status 503, END_STREAM)"). It snapshots the End this Layer
	// emitted for the frame, so the opposite-side Send can tell an End
	// edit from an untouched End and writes the response back as ONE
	// HEADERS frame with END_STREAM (sendEnd).
	endStreamEnd *envelope.GRPCEndMessage
}

// opaqueFromEnv returns env's opaqueGRPC, or nil when env is nil or
// carries none (a fresh or Clone()d Envelope — intercept
// modify_and_forward Clone()s — or a synthetic producer's).
func opaqueFromEnv(env *envelope.Envelope) *opaqueGRPC {
	if env == nil {
		return nil
	}
	o, _ := env.Opaque.(*opaqueGRPC)
	return o
}

// controlKind identifies one of the four D7 control headers that
// buildStartMessage lifts out of GRPCStartMessage.Metadata into structured
// fields.
//
// This file mirrors internal/layer/grpcweb/header_layout.go (USK-1219).
// The copies are deliberate: the strip sets differ (gRPC-Web also strips
// HTTP framing headers) and there are only two users (Principle 2 /
// rule of three).
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
// the wire. D7 keeps them out of Metadata so the structured fields are the
// single editable source; this lets the opposite-side Send put them back
// with the observed position, raw value and duplicates instead of
// re-synthesizing them at the front (MITM Principle 1).
//
// The parsed* fields snapshot the structured values buildStartMessage
// derived from the entries, so rebuildStartHeaders can tell an untouched
// field from one an Intercept / Transform / plugin Step edited.
type headerLayout struct {
	entries []controlEntry

	parsedContentType    string
	parsedEncoding       string
	parsedAcceptEncoding []string
	parsedTimeout        time.Duration
}

// newHeaderLayout records the control entries of headers (the inbound
// H2HeadersEvent's regular fields, wire order) and snapshots the
// structured values start was given from them.
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
		if !strings.HasPrefix(kv.Name, ":") {
			retained++
		}
	}
	return l
}

// rebuildStartHeaders returns the outbound header list for a Start that
// carries the observed layout: Metadata in its order with each observed
// control entry re-inserted at its anchor (clamped to the end when
// Metadata was shortened). Per kind:
//
//   - field still equals the value parsed from the wire: every entry is
//     emitted with its observed name and raw value, so duplicates and
//     values the Layer could not parse (e.g. "grpc-timeout: soon") survive.
//   - field changed: every entry of the kind is rewritten in place —
//     position kept, value replaced.
//   - field cleared: the kind's entries are dropped.
//   - field set but the kind was never observed: synthesized lowercase at
//     the front.
//
// Nothing is synthesized for an unset field: no default content-type and
// no te: trailers (a client that omitted them is not repaired, and a bare
// upstream error response gains no content-type). The no-layout path is
// buildStartHeaderKVs.
func rebuildStartHeaders(start *envelope.GRPCStartMessage, layout *headerLayout) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(start.Metadata)+len(layout.entries))
	var observed [numControlKinds]bool
	for _, e := range layout.entries {
		observed[e.kind] = true
	}
	for kind := controlKind(0); kind < numControlKinds; kind++ {
		if observed[kind] {
			continue
		}
		if v, set := controlValue(start, kind); set {
			out = append(out, envelope.KeyValue{Name: controlSynthName(kind), Value: v})
		}
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

// snapshotEnd copies the fields of m an edit can change, for the
// endStreamEnd baseline.
func snapshotEnd(m *envelope.GRPCEndMessage) *envelope.GRPCEndMessage {
	return &envelope.GRPCEndMessage{
		Status:        m.Status,
		Message:       m.Message,
		StatusDetails: bytes.Clone(m.StatusDetails),
		Trailers:      slices.Clone(m.Trailers),
	}
}

// endTrailersEdited reports whether m's trailer metadata differs from the
// baseline the Layer emitted. nil and empty compare equal (a plugin
// rebuild may turn one into the other).
func endTrailersEdited(m, baseline *envelope.GRPCEndMessage) bool {
	if len(m.Trailers) == 0 && len(baseline.Trailers) == 0 {
		return false
	}
	return !slices.Equal(m.Trailers, baseline.Trailers)
}

// withEndStatusInHeaders projects an End edit onto the header list of a
// response sent as one END_STREAM HEADERS frame (trailers-only, or a bare
// response without grpc-status). That End was derived from the frame's own
// grpc-status / grpc-message / grpc-status-details-bin entries and no
// trailer frame is written for it, so an End edit (Transform set_status /
// set_status_message, intercept, plugin) must land in those entries or it
// is silently a no-op on the wire.
//
// An edit is detected by comparing m with baseline — the End as the Layer
// emitted it — never with the headers being sent: a Start-side edit of
// grpc-status reaches the wire as edited, and an untouched End does not
// revert it. Only fields that changed are rewritten: every entry of that
// name in place (position kept), a cleared grpc-message /
// grpc-status-details-bin drops its entries, and a value the wire never
// carried is appended lowercase. headers is the final outbound list
// (control headers already restored), so a dropped entry cannot shift a
// control header's anchor. Mirrors the gRPC-Web Layer's function of the
// same name (USK-1219), with the HTTP/2 value encodings.
func withEndStatusInHeaders(headers []envelope.KeyValue, m, baseline *envelope.GRPCEndMessage) []envelope.KeyValue {
	if m.Status != baseline.Status {
		headers = setHeaderValues(headers, "grpc-status", strconv.FormatUint(uint64(m.Status), 10))
	}
	if m.Message != baseline.Message {
		headers = setHeaderValues(headers, "grpc-message", percentEncode(m.Message))
	}
	if !bytes.Equal(m.StatusDetails, baseline.StatusDetails) {
		v := ""
		if len(m.StatusDetails) > 0 {
			v = encodeBase64URL(m.StatusDetails)
		}
		headers = setHeaderValues(headers, "grpc-status-details-bin", v)
	}
	return headers
}

// setHeaderValues returns a copy of kvs with every entry named name
// (case-insensitive) set to value in place, or dropped when value is empty.
// When no entry exists and value is non-empty, a lowercase entry is
// appended. kvs is not modified.
func setHeaderValues(kvs []envelope.KeyValue, name, value string) []envelope.KeyValue {
	out := make([]envelope.KeyValue, 0, len(kvs)+1)
	found := false
	for _, kv := range kvs {
		if strings.EqualFold(kv.Name, name) {
			found = true
			if value == "" {
				continue
			}
			kv.Value = value
		}
		out = append(out, kv)
	}
	if !found && value != "" {
		out = append(out, envelope.KeyValue{Name: name, Value: value})
	}
	return out
}

// hasPlaceholderStatus reports whether m is the End this Layer synthesizes
// for a response without any grpc-status (AnomalyGRPCMissingStatus) with
// its status fields still untouched (Status 0, no message, no details).
// Its Trailers may have been edited. Sending it must not fabricate a
// grpc-status the upstream never sent: Status 0 here means "absent", not
// OK.
func hasPlaceholderStatus(m *envelope.GRPCEndMessage) bool {
	if m.Status != 0 || m.Message != "" || len(m.StatusDetails) > 0 {
		return false
	}
	for _, a := range m.Anomalies {
		if a.Type == envelope.AnomalyGRPCMissingStatus {
			return true
		}
	}
	return false
}
