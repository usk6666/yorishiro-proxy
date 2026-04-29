package pluginv2

import (
	"fmt"
	"sort"

	"go.starlark.net/starlark"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
)

// MutationKind classifies the outcome of a plugin hook's interaction with
// a MessageDict. Per RFC §9.3 D4, the Pipeline-level integration (USK-671)
// uses this to choose between zero-copy passthrough, WireEncoder
// regeneration, and verbatim raw injection.
type MutationKind int

const (
	// MutationUnchanged means neither the message-side fields nor the raw
	// bytes were modified. The original Envelope.Raw and Envelope.Message
	// must be reused without copy.
	MutationUnchanged MutationKind = iota

	// MutationMessageOnly means at least one message-side field was
	// modified but msg["raw"] was not assigned. The Layer's WireEncoder
	// must regenerate Envelope.Raw from the new Message.
	MutationMessageOnly

	// MutationRawOnly means msg["raw"] was assigned but no message-side
	// field was modified. The new raw bytes are written verbatim to the
	// wire; the Message-side view becomes whatever the parser would
	// derive (left as the original Message for variant-recording).
	MutationRawOnly

	// MutationBoth means both raw and at least one message-side field
	// were modified. Per RFC §9.3 D4 raw wins: the new raw bytes are
	// written verbatim and the message mutations are reported only in
	// the variant-recording metadata.
	MutationBoth
)

// String returns a stable lowercase identifier suitable for log output.
func (k MutationKind) String() string {
	switch k {
	case MutationUnchanged:
		return "unchanged"
	case MutationMessageOnly:
		return "message_only"
	case MutationRawOnly:
		return "raw_only"
	case MutationBoth:
		return "both"
	default:
		return fmt.Sprintf("MutationKind(%d)", int(k))
	}
}

// rawKey is the literal Starlark dict key under which Envelope.Raw is
// surfaced. RFC §9.3 D4 first-class status. The plugin sees `msg["raw"]`
// for both reads and writes.
const rawKey = "raw"

// maxPluginRawSize bounds the bytes a plugin can inject through
// msg["raw"] = b"...". Defense-in-depth against accidental plugin bugs
// that synthesize unbounded byte strings; operator-authored plugins are
// trusted (CLAUDE.md threat model) but a 16 MiB ceiling limits the
// blast radius of a runaway script. The cap is intentionally larger
// than maxPluginBodySize (1 MiB) because a plugin may legitimately
// inject a fully reframed wire payload that includes the body plus
// headers plus framing.
const maxPluginRawSize = 16 << 20

// MessageDict is the Starlark value handed to a plugin hook as `msg`. It
// surfaces a snake_case view of an envelope.Message plus the magic "raw"
// key bound to Envelope.Raw, intercepting writes to detect mutation.
//
// MessageDict implements starlark.Value, Mapping, IterableMapping, and
// HasSetKey. SetKey is the load-bearing surface for the per-RFC §9.3 D4
// classification: it traps msg["raw"] and rejects unknown / read-only
// fields rather than silently dropping data on read-back (one of yorishiro
// MITM's hard rules — never normalize without user intent).
type MessageDict struct {
	// origEnv is the Envelope that produced this dict; held by reference so
	// the Unchanged classification can return it without allocation.
	origEnv *envelope.Envelope

	// origRaw is the captured raw byte slice. msg["raw"] reads return this
	// (or rawValue if rawMutated). It is never mutated in place; on a
	// rawMutated SetKey the new bytes are written into rawValue.
	origRaw []byte

	// keys is the ordered list of message-side dict keys (snake_case).
	// Iteration over the dict visits keys in this order plus the "raw"
	// key at the end.
	keys []string

	// values maps each known key to its current Starlark value. Mutating
	// msg["x"] = v rewrites this map.
	values map[string]starlark.Value

	// readOnly is the set of keys that must not be assigned by plugin code.
	// Currently used for parser-derived state (HTTPMessage.Anomalies) and
	// denormalized fields (GRPCDataMessage.Service / Method).
	readOnly map[string]bool

	// headersFields is the set of dict keys whose value is a
	// *HeadersValue — used at dictToMessage time to decide whether the
	// message side was mutated via headers methods alone.
	headersFields []string

	// rawValue is the current bytes for msg["raw"]. Equal to origRaw on
	// construction; replaced on SetKey("raw", v).
	rawValue []byte

	// rawMutated is set true exactly when SetKey("raw", v) succeeds.
	rawMutated bool

	// messageMutated is set true exactly when SetKey on a message-side
	// (non-raw, non-read-only, known) key succeeds. This catches plain
	// scalar reassignments like msg["method"] = "POST". Header mutations
	// performed via *HeadersValue methods do not flow through SetKey, so
	// dictToMessage also consults each HeadersValue's Mutated() flag.
	messageMutated bool

	// dirty tracks which message-side keys were assigned via SetKey.
	// dictToMessage uses it to decide which fields to read from values[]
	// (mutated) versus preserve verbatim from the original Message
	// (not mutated) — important for fields like HTTPMessage.BodyBuffer
	// that have no Starlark representation but must survive untouched.
	dirty map[string]bool

	// frozen stops further mutation once Freeze() has been called. The
	// Pipeline integration freezes a variant snapshot before publishing.
	frozen bool

	// typeLabel is a human-readable identifier ("HTTPMessage", "WSMessage",
	// ...) used in error messages so the plugin author sees which schema
	// they violated.
	typeLabel string

	// builder is the per-type read-back closure that constructs a fresh
	// envelope.Message from the current values map. Set by
	// convertMessageToDict; called only when MessageOnly or Both
	// classification needs the new Message.
	builder func(*MessageDict) (envelope.Message, error)
}

// OriginalEnvelope returns the Envelope passed to convertMessageToDict.
// Callers (USK-671) use this to retrieve the original Message for
// zero-copy aliasing on the Unchanged path.
func (d *MessageDict) OriginalEnvelope() *envelope.Envelope {
	return d.origEnv
}

// RawMutated reports whether msg["raw"] was assigned. Cheap predicate.
func (d *MessageDict) RawMutated() bool { return d.rawMutated }

// MessageMutated reports whether any message-side field (scalar or
// header collection) was modified. Cheap predicate; consults every
// tracked *HeadersValue.
func (d *MessageDict) MessageMutated() bool {
	if d.messageMutated {
		return true
	}
	for _, k := range d.headersFields {
		if hv, ok := d.values[k].(*HeadersValue); ok && hv.Mutated() {
			return true
		}
	}
	return false
}

// classify returns the MutationKind for this dict based on the cheap
// predicates. Callers must not mutate the dict between the hook return
// and this call.
func (d *MessageDict) classify() MutationKind {
	rm := d.rawMutated
	mm := d.MessageMutated()
	switch {
	case !rm && !mm:
		return MutationUnchanged
	case rm && !mm:
		return MutationRawOnly
	case !rm && mm:
		return MutationMessageOnly
	default:
		return MutationBoth
	}
}

// --- starlark.Value ---

func (d *MessageDict) String() string {
	return fmt.Sprintf("msg(%s, %d fields)", d.typeLabel, len(d.keys))
}

func (d *MessageDict) Type() string { return "msg" }

// Freeze implements the starlark.Value contract. It is idempotent and
// cycle-safe: it short-circuits if already frozen before recursing into
// child values, matching the documented Freeze pattern (set first, then
// visit). No cycles exist in the current schema, but the guard makes
// future schema additions safe.
func (d *MessageDict) Freeze() {
	if d.frozen {
		return
	}
	d.frozen = true
	for _, v := range d.values {
		v.Freeze()
	}
}

func (d *MessageDict) Truth() starlark.Bool { return starlark.True }

func (d *MessageDict) Hash() (uint32, error) {
	return 0, fmt.Errorf("unhashable type: msg")
}

// --- starlark.Mapping ---

// Get implements both `msg["k"]` reads and `"k" in msg` membership.
func (d *MessageDict) Get(k starlark.Value) (starlark.Value, bool, error) {
	key, ok := k.(starlark.String)
	if !ok {
		return nil, false, fmt.Errorf("msg: key must be string, got %s", k.Type())
	}
	s := string(key)
	if s == rawKey {
		return starlark.Bytes(d.rawValue), true, nil
	}
	v, found := d.values[s]
	if !found {
		return nil, false, nil
	}
	return v, true, nil
}

// --- starlark.HasSetKey ---

// SetKey enforces the load-bearing schema rules for plugin mutation:
//   - "raw" accepts only starlark.Bytes; sets rawMutated.
//   - Read-only keys (anomalies, denormalized service/method) are rejected
//     loudly so plugin authors see a clear error rather than silent drop.
//   - Unknown keys are rejected loudly so a typo like msg["headerz"]
//     fails at the hook return rather than dropping the assignment.
//   - All other known keys store the value and set messageMutated.
//
// Frozen dicts reject all SetKey.
func (d *MessageDict) SetKey(k, v starlark.Value) error {
	key, ok := k.(starlark.String)
	if !ok {
		return fmt.Errorf("msg: key must be string, got %s", k.Type())
	}
	if d.frozen {
		return fmt.Errorf("msg: cannot mutate frozen dict")
	}
	s := string(key)
	if s == rawKey {
		b, ok := v.(starlark.Bytes)
		if !ok {
			return fmt.Errorf("msg[\"raw\"]: value must be bytes, got %s", v.Type())
		}
		if len(b) > maxPluginRawSize {
			return fmt.Errorf("msg[\"raw\"]: bytes size %d exceeds limit %d", len(b), maxPluginRawSize)
		}
		d.rawValue = []byte(b)
		d.rawMutated = true
		return nil
	}
	if d.readOnly[s] {
		return fmt.Errorf("msg[%q]: field is read-only on %s", s, d.typeLabel)
	}
	existing, known := d.values[s]
	if !known {
		return fmt.Errorf("msg[%q]: unknown field on %s", s, d.typeLabel)
	}
	// Type-check at SetKey time for collection-typed fields so plugin
	// authors see the error at assignment rather than at the per-type
	// builder's read-back. Headers-typed keys only accept *HeadersValue.
	if _, isHeaders := existing.(*HeadersValue); isHeaders {
		if _, ok := v.(*HeadersValue); !ok {
			return fmt.Errorf("msg[%q]: expected headers, got %s", s, v.Type())
		}
	}
	d.values[s] = v
	d.messageMutated = true
	if d.dirty == nil {
		d.dirty = make(map[string]bool)
	}
	d.dirty[s] = true
	return nil
}

// Dirty reports whether key was assigned via SetKey since construction.
// Used by per-type read-back logic to decide between "take new value from
// the dict" and "preserve the original Message's field verbatim".
func (d *MessageDict) Dirty(key string) bool {
	return d.dirty[key]
}

// --- starlark.IterableMapping ---

func (d *MessageDict) Iterate() starlark.Iterator {
	all := make([]string, 0, len(d.keys)+1)
	all = append(all, d.keys...)
	all = append(all, rawKey)
	return &messageDictIterator{keys: all, i: 0}
}

func (d *MessageDict) Items() []starlark.Tuple {
	out := make([]starlark.Tuple, 0, len(d.keys)+1)
	for _, k := range d.keys {
		out = append(out, starlark.Tuple{starlark.String(k), d.values[k]})
	}
	out = append(out, starlark.Tuple{starlark.String(rawKey), starlark.Bytes(d.rawValue)})
	return out
}

type messageDictIterator struct {
	keys []string
	i    int
}

func (it *messageDictIterator) Next(p *starlark.Value) bool {
	if it.i >= len(it.keys) {
		return false
	}
	*p = starlark.String(it.keys[it.i])
	it.i++
	return true
}

func (it *messageDictIterator) Done() {}

// sortedKeysForTest returns the dict's known keys (excluding "raw") in
// sorted order. Used by tests that need a stable snapshot of the schema
// without depending on insertion order. Not exposed to plugins.
func (d *MessageDict) sortedKeysForTest() []string {
	out := make([]string, len(d.keys))
	copy(out, d.keys)
	sort.Strings(out)
	return out
}
