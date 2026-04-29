package pluginv2

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// ErrBodyTooLarge is returned by convertMessageToDict when an HTTPMessage's
// body (Body or materialized BodyBuffer) exceeds maxPluginBodySize. Per
// RFC §9.3 D7 and design decision #16, the Pipeline integration (USK-671)
// must skip the plugin in this case rather than mutate or hide the body.
var ErrBodyTooLarge = errors.New("pluginv2: body exceeds plugin size cap")

// ErrUnsupportedMessageType is returned by convertMessageToDict when the
// concrete envelope.Message type has no per-type schema yet. Currently
// applies to TLSHandshakeMessage (deferred per design decision #24) and
// any future protocol whose Message hasn't been wired in.
var ErrUnsupportedMessageType = errors.New("pluginv2: unsupported message type")

// maxPluginBodySize bounds the bytes a plugin can observe through
// msg["body"]. Matches the per-plugin state value cap (state.go) for
// symmetry — operators should expect a single uniform "1 MiB or less"
// rule across plugin-visible blobs. Larger bodies surface
// ErrBodyTooLarge so USK-671 skips the plugin (preserving wire fidelity:
// the body never ships in a truncated form to the plugin).
const maxPluginBodySize = 1 << 20

// convertMessageToDict produces the Starlark `msg` value for a hook
// invocation. The returned *MessageDict implements starlark.HasSetKey, so
// msg["raw"] = b"..." traps as RFC §9.3 D4 requires, and unknown / read-
// only keys fail loudly rather than dropping silently.
//
// Returns ErrUnsupportedMessageType when env.Message is a type without a
// schema (e.g., a future TLSHandshakeMessage). Returns ErrBodyTooLarge
// when an HTTPMessage body exceeds maxPluginBodySize. The Pipeline
// integration must treat these as "skip plugin" signals — never
// materialize a truncated view.
func convertMessageToDict(env *envelope.Envelope) (*MessageDict, error) {
	if env == nil {
		return nil, fmt.Errorf("pluginv2: nil envelope")
	}
	if env.Message == nil {
		return nil, fmt.Errorf("pluginv2: envelope has nil message")
	}

	d := &MessageDict{
		origEnv:  env,
		origRaw:  env.Raw,
		rawValue: env.Raw,
		values:   make(map[string]starlark.Value),
		readOnly: make(map[string]bool),
	}

	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		if err := buildHTTPDict(d, m); err != nil {
			return nil, err
		}
	case *envelope.WSMessage:
		buildWSDict(d, m)
	case *envelope.GRPCStartMessage:
		buildGRPCStartDict(d, m)
	case *envelope.GRPCDataMessage:
		buildGRPCDataDict(d, m)
	case *envelope.GRPCEndMessage:
		buildGRPCEndDict(d, m)
	case *envelope.RawMessage:
		buildRawDict(d, m)
	case *envelope.SSEMessage:
		buildSSEDict(d, m)
	default:
		return nil, fmt.Errorf("%w: %T", ErrUnsupportedMessageType, env.Message)
	}
	return d, nil
}

// dictToMessage reads a MessageDict back into an envelope.Message and
// returns the mutation classification. On MutationUnchanged the returned
// Message and []byte are aliased to the originals (zero-copy). On
// MutationRawOnly the Message is the original alias and the []byte is
// the new raw bytes. On MutationMessageOnly the Message is freshly
// constructed and []byte is the original alias. On MutationBoth both are
// returned, and the caller chooses which to ship per RFC §9.3 D4
// ("raw wins").
func dictToMessage(d *MessageDict) (envelope.Message, []byte, MutationKind, error) {
	if d == nil {
		return nil, nil, MutationUnchanged, fmt.Errorf("pluginv2: nil dict")
	}
	kind := d.classify()
	switch kind {
	case MutationUnchanged:
		return d.origEnv.Message, d.origRaw, kind, nil
	case MutationRawOnly:
		return d.origEnv.Message, d.rawValue, kind, nil
	case MutationMessageOnly, MutationBoth:
		if d.builder == nil {
			return nil, nil, kind, fmt.Errorf("pluginv2: no builder for %s", d.typeLabel)
		}
		msg, err := d.builder(d)
		if err != nil {
			return nil, nil, kind, err
		}
		raw := d.origRaw
		if kind == MutationBoth {
			raw = d.rawValue
		}
		return msg, raw, kind, nil
	default:
		return nil, nil, kind, fmt.Errorf("pluginv2: unknown mutation kind %d", kind)
	}
}

// snakeCase converts a Go PascalCase identifier to snake_case using the
// "insert _ before any uppercase that follows a lowercase, or any
// uppercase followed by a lowercase" rule. Acronym runs collapse to a
// single lowercase block (URL → url, JA3 → ja3) and runs followed by a
// lowercase letter break correctly (FlowID → flow_id, HTTPCode →
// http_code). Pinned by a golden test in convert_test.go to discharge
// RFC §9.3 D2's "mechanical" mandate.
func snakeCase(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + 4)
	runes := []rune(s)
	for i, r := range runes {
		if i > 0 && unicode.IsUpper(r) {
			prev := runes[i-1]
			next := rune(0)
			if i+1 < len(runes) {
				next = runes[i+1]
			}
			if unicode.IsLower(prev) || (unicode.IsUpper(prev) && unicode.IsLower(next)) {
				b.WriteRune('_')
			}
		}
		b.WriteRune(unicode.ToLower(r))
	}
	return b.String()
}

// setKV is a small helper that registers an ordered key with its initial
// Starlark value. Per-type build functions call it for every field; the
// snake_case conversion is owned by snakeCase to keep the rule centralized.
func (d *MessageDict) setKV(goName string, v starlark.Value) string {
	k := snakeCase(goName)
	d.keys = append(d.keys, k)
	d.values[k] = v
	return k
}

// setHeadersKV is setKV plus tracking the resulting key in headersFields
// so MessageMutated() can consult HeadersValue.Mutated() at read-back
// time.
func (d *MessageDict) setHeadersKV(goName string, kvs []envelope.KeyValue) string {
	k := d.setKV(goName, NewHeadersValue(cloneKVs(kvs)))
	d.headersFields = append(d.headersFields, k)
	return k
}

// markReadOnly marks the given snake_case key as rejected by SetKey.
func (d *MessageDict) markReadOnly(key string) {
	d.readOnly[key] = true
}

// cloneKVs returns a deep copy of the given KeyValue slice. The dict
// owns its own slice so plugin mutation through *HeadersValue methods
// doesn't reach the original Envelope.Message until dictToMessage
// commits the read-back (and even then a fresh slice is produced for
// the new Message).
func cloneKVs(in []envelope.KeyValue) []envelope.KeyValue {
	if in == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(in))
	copy(out, in)
	return out
}

// --- HTTPMessage ---

func buildHTTPDict(d *MessageDict, m *envelope.HTTPMessage) error {
	d.typeLabel = "HTTPMessage"

	d.setKV("Method", starlark.String(m.Method))
	d.setKV("Scheme", starlark.String(m.Scheme))
	d.setKV("Authority", starlark.String(m.Authority))
	d.setKV("Path", starlark.String(m.Path))
	d.setKV("RawQuery", starlark.String(m.RawQuery))
	d.setKV("Status", starlark.MakeInt(m.Status))
	d.setKV("StatusReason", starlark.String(m.StatusReason))
	d.setHeadersKV("Headers", m.Headers)
	d.setHeadersKV("Trailers", m.Trailers)

	body, err := materializeHTTPBody(m)
	if err != nil {
		return err
	}
	d.setKV("Body", starlark.Bytes(body))

	anomKey := d.setKV("Anomalies", anomaliesToStarlark(m.Anomalies))
	d.markReadOnly(anomKey)

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.HTTPMessage{
			// Anomalies are read-only at the SetKey boundary; preserve
			// the original slice shape exactly. BodyStream is internal
			// to the Layer and is never reachable from a plugin; if it
			// was non-nil on the original, we also preserve it (the
			// plugin's view of body comes from the materialized Body).
			Anomalies:  m.Anomalies,
			BodyStream: m.BodyStream,
			BodyBuffer: m.BodyBuffer,
		}
		if err := readScalar(d, "method", &out.Method); err != nil {
			return nil, err
		}
		if err := readScalar(d, "scheme", &out.Scheme); err != nil {
			return nil, err
		}
		if err := readScalar(d, "authority", &out.Authority); err != nil {
			return nil, err
		}
		if err := readScalar(d, "path", &out.Path); err != nil {
			return nil, err
		}
		if err := readScalar(d, "raw_query", &out.RawQuery); err != nil {
			return nil, err
		}
		if err := readScalar(d, "status", &out.Status); err != nil {
			return nil, err
		}
		if err := readScalar(d, "status_reason", &out.StatusReason); err != nil {
			return nil, err
		}
		if hv, err := readHeaders(d, "headers", m.Headers); err == nil {
			out.Headers = hv
		} else {
			return nil, err
		}
		if hv, err := readHeaders(d, "trailers", m.Trailers); err == nil {
			out.Trailers = hv
		} else {
			return nil, err
		}
		if d.Dirty("body") {
			b, err := readBytes(d, "body")
			if err != nil {
				return nil, err
			}
			out.Body = b
			// Plugin authored a new body; the original BodyBuffer no
			// longer represents the wire payload. Drop the reference
			// from the new Message so downstream consumers do not
			// double-count or read stale spilled bytes. (The original
			// BodyBuffer still belongs to the original Message and is
			// released by its owner.)
			out.BodyBuffer = nil
			out.BodyStream = nil
		} else {
			// Body untouched; preserve the original Body bytes so
			// variant-recording sees the same input the plugin saw.
			out.Body = m.Body
		}
		return out, nil
	}
	return nil
}

// materializeHTTPBody returns the bytes a plugin will see under
// msg["body"]. Body []byte takes precedence; BodyBuffer is materialized
// when Body is nil. Returns ErrBodyTooLarge when the materialized size
// exceeds maxPluginBodySize so USK-671 can skip the plugin without ever
// presenting truncated bytes.
func materializeHTTPBody(m *envelope.HTTPMessage) ([]byte, error) {
	if m.Body != nil {
		if len(m.Body) > maxPluginBodySize {
			return nil, fmt.Errorf("%w: %d > %d", ErrBodyTooLarge, len(m.Body), maxPluginBodySize)
		}
		return m.Body, nil
	}
	if m.BodyBuffer != nil {
		if m.BodyBuffer.Len() > maxPluginBodySize {
			return nil, fmt.Errorf("%w: %d > %d", ErrBodyTooLarge, m.BodyBuffer.Len(), maxPluginBodySize)
		}
		// Background ctx is acceptable: BodyBuffer.Bytes for an in-spec
		// Layer-owned buffer is bounded by Len(), already checked above.
		b, err := m.BodyBuffer.Bytes(context.Background())
		if err != nil {
			return nil, fmt.Errorf("pluginv2: read body buffer: %w", err)
		}
		return b, nil
	}
	return nil, nil
}

// --- WSMessage ---

func buildWSDict(d *MessageDict, m *envelope.WSMessage) {
	d.typeLabel = "WSMessage"

	d.setKV("Opcode", starlark.MakeInt(int(m.Opcode)))
	d.setKV("Fin", starlark.Bool(m.Fin))
	d.setKV("Masked", starlark.Bool(m.Masked))
	d.setKV("Mask", starlark.Bytes(m.Mask[:]))
	d.setKV("Payload", starlark.Bytes(m.Payload))
	d.setKV("CloseCode", starlark.MakeInt(int(m.CloseCode)))
	d.setKV("CloseReason", starlark.String(m.CloseReason))
	d.setKV("Compressed", starlark.Bool(m.Compressed))

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.WSMessage{}
		var opcode int
		if err := readScalar(d, "opcode", &opcode); err != nil {
			return nil, err
		}
		// Opcode is uint8 on the wire; reject negative or out-of-range
		// values rather than silently truncating. Symmetry with the
		// neighboring close_code / wire_length / status checks.
		if opcode < 0 || opcode > 0xFF {
			return nil, fmt.Errorf("msg[\"opcode\"]: must fit in uint8, got %d", opcode)
		}
		out.Opcode = envelope.WSOpcode(opcode)
		if err := readScalar(d, "fin", &out.Fin); err != nil {
			return nil, err
		}
		if err := readScalar(d, "masked", &out.Masked); err != nil {
			return nil, err
		}
		mask, err := readBytes(d, "mask")
		if err != nil {
			return nil, err
		}
		if len(mask) != 4 {
			return nil, fmt.Errorf("msg[\"mask\"]: must be exactly 4 bytes, got %d", len(mask))
		}
		copy(out.Mask[:], mask)
		if out.Payload, err = readBytes(d, "payload"); err != nil {
			return nil, err
		}
		var closeCode int
		if err := readScalar(d, "close_code", &closeCode); err != nil {
			return nil, err
		}
		// CloseCode is uint16 on the wire; reject negative or
		// out-of-range values rather than silently truncating.
		if closeCode < 0 || closeCode > 0xFFFF {
			return nil, fmt.Errorf("msg[\"close_code\"]: must fit in uint16, got %d", closeCode)
		}
		out.CloseCode = uint16(closeCode)
		if err := readScalar(d, "close_reason", &out.CloseReason); err != nil {
			return nil, err
		}
		if err := readScalar(d, "compressed", &out.Compressed); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// --- GRPCStartMessage ---

func buildGRPCStartDict(d *MessageDict, m *envelope.GRPCStartMessage) {
	d.typeLabel = "GRPCStartMessage"

	d.setKV("Service", starlark.String(m.Service))
	d.setKV("Method", starlark.String(m.Method))
	d.setHeadersKV("Metadata", m.Metadata)
	d.setKV("Timeout", starlark.MakeInt64(int64(m.Timeout)))
	d.setKV("ContentType", starlark.String(m.ContentType))
	d.setKV("Encoding", starlark.String(m.Encoding))
	d.setKV("AcceptEncoding", stringsToList(m.AcceptEncoding))

	anomKey := d.setKV("Anomalies", anomaliesToStarlark(m.Anomalies))
	d.markReadOnly(anomKey)

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.GRPCStartMessage{Anomalies: m.Anomalies}
		if err := readScalar(d, "service", &out.Service); err != nil {
			return nil, err
		}
		if err := readScalar(d, "method", &out.Method); err != nil {
			return nil, err
		}
		if md, err := readHeaders(d, "metadata", m.Metadata); err == nil {
			out.Metadata = md
		} else {
			return nil, err
		}
		var timeout int64
		if err := readScalar(d, "timeout", &timeout); err != nil {
			return nil, err
		}
		out.Timeout = time.Duration(timeout)
		if err := readScalar(d, "content_type", &out.ContentType); err != nil {
			return nil, err
		}
		if err := readScalar(d, "encoding", &out.Encoding); err != nil {
			return nil, err
		}
		if ss, err := readStringList(d, "accept_encoding", m.AcceptEncoding); err == nil {
			out.AcceptEncoding = ss
		} else {
			return nil, err
		}
		return out, nil
	}
}

// --- GRPCDataMessage ---

func buildGRPCDataDict(d *MessageDict, m *envelope.GRPCDataMessage) {
	d.typeLabel = "GRPCDataMessage"

	svcKey := d.setKV("Service", starlark.String(m.Service))
	mtdKey := d.setKV("Method", starlark.String(m.Method))
	d.markReadOnly(svcKey)
	d.markReadOnly(mtdKey)

	d.setKV("Compressed", starlark.Bool(m.Compressed))
	d.setKV("WireLength", starlark.MakeUint64(uint64(m.WireLength)))
	d.setKV("Payload", starlark.Bytes(m.Payload))
	d.setKV("EndStream", starlark.Bool(m.EndStream))

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		// Service/Method are read-only at the SetKey boundary; preserve
		// from the original to match the wire-derived denormalization.
		out := &envelope.GRPCDataMessage{
			Service: m.Service,
			Method:  m.Method,
		}
		if err := readScalar(d, "compressed", &out.Compressed); err != nil {
			return nil, err
		}
		var wl uint64
		if err := readScalar(d, "wire_length", &wl); err != nil {
			return nil, err
		}
		if wl > 0xFFFFFFFF {
			return nil, fmt.Errorf("msg[\"wire_length\"]: must fit in uint32, got %d", wl)
		}
		out.WireLength = uint32(wl)
		var err error
		if out.Payload, err = readBytes(d, "payload"); err != nil {
			return nil, err
		}
		if err := readScalar(d, "end_stream", &out.EndStream); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// --- GRPCEndMessage ---

func buildGRPCEndDict(d *MessageDict, m *envelope.GRPCEndMessage) {
	d.typeLabel = "GRPCEndMessage"

	d.setKV("Status", starlark.MakeUint64(uint64(m.Status)))
	d.setKV("Message", starlark.String(m.Message))
	d.setKV("StatusDetails", starlark.Bytes(m.StatusDetails))
	d.setHeadersKV("Trailers", m.Trailers)

	anomKey := d.setKV("Anomalies", anomaliesToStarlark(m.Anomalies))
	d.markReadOnly(anomKey)

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.GRPCEndMessage{Anomalies: m.Anomalies}
		var status uint64
		if err := readScalar(d, "status", &status); err != nil {
			return nil, err
		}
		if status > 0xFFFFFFFF {
			return nil, fmt.Errorf("msg[\"status\"]: must fit in uint32, got %d", status)
		}
		out.Status = uint32(status)
		if err := readScalar(d, "message", &out.Message); err != nil {
			return nil, err
		}
		var err error
		if out.StatusDetails, err = readBytes(d, "status_details"); err != nil {
			return nil, err
		}
		if hv, err := readHeaders(d, "trailers", m.Trailers); err == nil {
			out.Trailers = hv
		} else {
			return nil, err
		}
		return out, nil
	}
}

// --- RawMessage ---

func buildRawDict(d *MessageDict, m *envelope.RawMessage) {
	d.typeLabel = "RawMessage"

	d.setKV("Bytes", starlark.Bytes(m.Bytes))

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.RawMessage{}
		var err error
		if out.Bytes, err = readBytes(d, "bytes"); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// --- SSEMessage ---

func buildSSEDict(d *MessageDict, m *envelope.SSEMessage) {
	d.typeLabel = "SSEMessage"

	d.setKV("Event", starlark.String(m.Event))
	d.setKV("Data", starlark.String(m.Data))
	d.setKV("ID", starlark.String(m.ID))
	d.setKV("Retry", starlark.MakeInt64(int64(m.Retry)))

	anomKey := d.setKV("Anomalies", anomaliesToStarlark(m.Anomalies))
	d.markReadOnly(anomKey)

	d.builder = func(d *MessageDict) (envelope.Message, error) {
		out := &envelope.SSEMessage{Anomalies: m.Anomalies}
		if err := readScalar(d, "event", &out.Event); err != nil {
			return nil, err
		}
		if err := readScalar(d, "data", &out.Data); err != nil {
			return nil, err
		}
		if err := readScalar(d, "id", &out.ID); err != nil {
			return nil, err
		}
		var retry int64
		if err := readScalar(d, "retry", &retry); err != nil {
			return nil, err
		}
		out.Retry = time.Duration(retry)
		return out, nil
	}
}

// --- shared helpers ---

// anomaliesToStarlark renders an []Anomaly as a frozen starlark.List of
// frozen 2-key dicts. Plugins observe but cannot mutate these (the
// containing key is registered via markReadOnly).
func anomaliesToStarlark(in []envelope.Anomaly) starlark.Value {
	if in == nil {
		// Expose absence as an empty list rather than None — keeps the
		// schema uniform across all message types and lets plugins
		// iterate without nil-checking first.
		empty := starlark.NewList(nil)
		empty.Freeze()
		return empty
	}
	items := make([]starlark.Value, 0, len(in))
	for _, a := range in {
		entry := starlark.NewDict(2)
		_ = entry.SetKey(starlark.String("type"), starlark.String(a.Type))
		_ = entry.SetKey(starlark.String("detail"), starlark.String(a.Detail))
		entry.Freeze()
		items = append(items, entry)
	}
	list := starlark.NewList(items)
	list.Freeze()
	return list
}

// stringsToList renders a []string as a frozen Starlark list of
// starlark.String. Empty input returns an empty (still frozen) list for
// schema uniformity.
//
// The list is frozen so plugin in-place mutations (e.g.
// msg["accept_encoding"].append("gzip")) fail loudly rather than vanishing.
// *starlark.List mutations do not flow through MessageDict.SetKey, so a
// non-frozen list would let plugins silently drop changes — violating
// RFC §9.3 D2's "no silent drop" promise. Plugins that wish to modify a
// list-typed field must reassign:
//
//	msg["accept_encoding"] = ["gzip", "identity"]
//
// which trips SetKey and the dirty/messageMutated tracking.
func stringsToList(in []string) starlark.Value {
	items := make([]starlark.Value, 0, len(in))
	for _, s := range in {
		items = append(items, starlark.String(s))
	}
	list := starlark.NewList(items)
	list.Freeze()
	return list
}

// readScalar pulls a typed value out of d.values. The output dst pointer
// disambiguates the expected Starlark type (string for *string,
// starlark.Int for *int / *int64 / *uint64, starlark.Bool for *bool).
// Mismatched types return a clear "expected X, got Y" error.
func readScalar(d *MessageDict, key string, dst any) error {
	v, ok := d.values[key]
	if !ok {
		return fmt.Errorf("msg[%q]: not present (internal: missing in values map)", key)
	}
	switch p := dst.(type) {
	case *string:
		s, ok := v.(starlark.String)
		if !ok {
			return fmt.Errorf("msg[%q]: expected string, got %s", key, v.Type())
		}
		*p = string(s)
	case *bool:
		b, ok := v.(starlark.Bool)
		if !ok {
			return fmt.Errorf("msg[%q]: expected bool, got %s", key, v.Type())
		}
		*p = bool(b)
	case *int:
		n, ok := v.(starlark.Int)
		if !ok {
			return fmt.Errorf("msg[%q]: expected int, got %s", key, v.Type())
		}
		i, err := starlark.AsInt32(n)
		if err != nil {
			return fmt.Errorf("msg[%q]: %w", key, err)
		}
		*p = i
	case *int64:
		n, ok := v.(starlark.Int)
		if !ok {
			return fmt.Errorf("msg[%q]: expected int, got %s", key, v.Type())
		}
		i, ok := n.Int64()
		if !ok {
			return fmt.Errorf("msg[%q]: int does not fit in int64", key)
		}
		*p = i
	case *uint64:
		n, ok := v.(starlark.Int)
		if !ok {
			return fmt.Errorf("msg[%q]: expected int, got %s", key, v.Type())
		}
		i, ok := n.Uint64()
		if !ok {
			return fmt.Errorf("msg[%q]: int does not fit in uint64", key)
		}
		*p = i
	default:
		return fmt.Errorf("msg[%q]: unsupported readScalar destination %T", key, dst)
	}
	return nil
}

// readBytes pulls a starlark.Bytes value out of d.values, returning the
// raw []byte. Type mismatches are reported with the field name so plugin
// authors immediately see which assignment was wrong.
func readBytes(d *MessageDict, key string) ([]byte, error) {
	v, ok := d.values[key]
	if !ok {
		return nil, fmt.Errorf("msg[%q]: not present (internal: missing in values map)", key)
	}
	b, ok := v.(starlark.Bytes)
	if !ok {
		return nil, fmt.Errorf("msg[%q]: expected bytes, got %s", key, v.Type())
	}
	return []byte(b), nil
}

// readHeaders returns the KeyValue slice for a headers/trailers/metadata
// field. If the plugin replaced the value (SetKey on the parent dict
// with a new HeadersValue or wrong type), that is rejected. If the
// plugin only mutated through methods, the result is the HeadersValue's
// current snapshot. If neither, the original slice is returned verbatim
// for zero-copy aliasing into the new Message.
func readHeaders(d *MessageDict, key string, original []envelope.KeyValue) ([]envelope.KeyValue, error) {
	v, ok := d.values[key]
	if !ok {
		return nil, fmt.Errorf("msg[%q]: not present (internal: missing in values map)", key)
	}
	hv, ok := v.(*HeadersValue)
	if !ok {
		return nil, fmt.Errorf("msg[%q]: expected headers, got %s", key, v.Type())
	}
	if d.Dirty(key) || hv.Mutated() {
		return hv.Snapshot(), nil
	}
	return original, nil
}

// readStringList returns the []string for a list-typed field. Honors the
// dirty flag: untouched fields preserve the original slice verbatim
// (zero-copy alias into the new Message).
func readStringList(d *MessageDict, key string, original []string) ([]string, error) {
	if !d.Dirty(key) {
		return original, nil
	}
	v, ok := d.values[key]
	if !ok {
		return nil, fmt.Errorf("msg[%q]: not present (internal: missing in values map)", key)
	}
	list, ok := v.(*starlark.List)
	if !ok {
		return nil, fmt.Errorf("msg[%q]: expected list, got %s", key, v.Type())
	}
	out := make([]string, 0, list.Len())
	iter := list.Iterate()
	defer iter.Done()
	var elem starlark.Value
	for iter.Next(&elem) {
		s, ok := elem.(starlark.String)
		if !ok {
			return nil, fmt.Errorf("msg[%q]: list element must be string, got %s", key, elem.Type())
		}
		out = append(out, string(s))
	}
	return out, nil
}
