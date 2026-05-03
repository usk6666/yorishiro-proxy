package mcp

import (
	"encoding/base64"
	"fmt"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// intercept_typed.go implements the intercept tool path that dispatches
// against common.HoldQueue with per-Message-type modify schemas. Tool
// name is "intercept" — handleInterceptTool routes every modify_and_forward
// through the typed dispatch arms below.
//
// Per Decision R7 in the design review, headers travel as ordered
// (name, value) pairs end-to-end; map[string]string is rejected on the
// dispatch path so wire-fidelity (RFC-001 §3.1 / "no normalization") is
// preserved.
//
// Per Decision R10, RawMessage modify rejects supplying both bytes_override
// and patches; the validation runs before the queue lookup so a malformed
// request never consumes an entry.

// headerKV is the order-preserved JSON form for header lists in the new
// MCP modify schemas. The MCP SDK accepts arrays of structs; we project
// onto envelope.KeyValue without re-sorting or deduplicating.
type headerKV struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// httpMessageModify carries the structured override fields for an HTTP
// envelope held by the new HoldQueue. Pointer types distinguish "field
// omitted" from "field set to zero value"; pointer-nil leaves the held
// envelope's field untouched.
//
// Headers and Trailers replace the held envelope's slices wholesale when
// non-nil. Body, when supplied, replaces HTTPMessage.Body before
// BodyPatches are applied (Decision R12). AutoContentLength is retained
// for HTTP Request Smuggling test surface (Decision R25); it is observed
// by downstream HTTP/1.x and HTTP/2 wire-encoders, not by this handler.
type httpMessageModify struct {
	Method            *string     `json:"method,omitempty" jsonschema:"HTTP method override (request side)"`
	Scheme            *string     `json:"scheme,omitempty" jsonschema:"scheme override (request side)"`
	Authority         *string     `json:"authority,omitempty" jsonschema:"authority override (request side)"`
	Path              *string     `json:"path,omitempty" jsonschema:"request path override"`
	RawQuery          *string     `json:"raw_query,omitempty" jsonschema:"raw query string override"`
	Status            *int        `json:"status,omitempty" jsonschema:"HTTP status code override (response side)"`
	StatusReason      *string     `json:"status_reason,omitempty" jsonschema:"HTTP/1.x status reason phrase override"`
	Headers           []headerKV  `json:"headers,omitempty" jsonschema:"ordered header list replacement"`
	Trailers          []headerKV  `json:"trailers,omitempty" jsonschema:"ordered trailer list replacement"`
	Body              *string     `json:"body,omitempty" jsonschema:"body replacement (text or base64 per body_encoding)"`
	BodyEncoding      string      `json:"body_encoding,omitempty" jsonschema:"text|base64; required when body is non-textual"`
	BodyPatches       []BodyPatch `json:"body_patches,omitempty" jsonschema:"body patches applied on top of any body replacement"`
	AutoContentLength *bool       `json:"auto_content_length,omitempty" jsonschema:"auto-sync Content-Length on body change (default true; false preserves CL/TE for smuggling tests)"`
}

// wsMessageModify carries the structured override fields for a WebSocket
// frame envelope. Opcode accepts either a string name (text/binary/close/
// ping/pong/continuation) or a numeric opcode in [0,15] (Decision R8). The
// canonicalisation happens server-side via wsOpcodeFromAny.
type wsMessageModify struct {
	Opcode       any     `json:"opcode,omitempty" jsonschema:"WebSocket opcode: name (text|binary|close|ping|pong|continuation) or numeric 0..15"`
	Fin          *bool   `json:"fin,omitempty" jsonschema:"Fin bit override"`
	Payload      *string `json:"payload,omitempty" jsonschema:"frame payload (text or base64 per body_encoding)"`
	BodyEncoding string  `json:"body_encoding,omitempty" jsonschema:"text|base64; required when payload is non-textual"`
	CloseCode    *int    `json:"close_code,omitempty" jsonschema:"RFC 6455 status code (Close frames only)"`
	CloseReason  *string `json:"close_reason,omitempty" jsonschema:"close reason text (Close frames only)"`
}

// grpcStartMessageModify carries override fields for a GRPCStartMessage
// (HEADERS frame opening one side of an RPC). Trailers belong to a
// distinct GRPCEndMessage envelope and are intentionally out of scope
// here (Decision R23).
type grpcStartMessageModify struct {
	Service  *string    `json:"service,omitempty" jsonschema:"gRPC service name override"`
	Method   *string    `json:"method,omitempty" jsonschema:"gRPC method name override"`
	Encoding *string    `json:"encoding,omitempty" jsonschema:"grpc-encoding override"`
	Metadata []headerKV `json:"metadata,omitempty" jsonschema:"ordered metadata list replacement (transport pseudo-headers excluded)"`
}

// grpcDataMessageModify carries override fields for a single LPM
// (length-prefixed message) on a gRPC stream. Payload is the decompressed
// bytes; the WireEncoder regenerates the wire LPM frame on Send. Setting
// Compressed=true with a non-empty Payload requires an Encoding to be
// present on the associated GRPCStartMessage envelope (validated by the
// downstream encoder, not here).
type grpcDataMessageModify struct {
	Payload         *string `json:"payload,omitempty" jsonschema:"decompressed gRPC payload (text or base64 per payload_encoding)"`
	PayloadEncoding string  `json:"payload_encoding,omitempty" jsonschema:"text|base64; required when payload is non-textual"`
	Compressed      *bool   `json:"compressed,omitempty" jsonschema:"set the compression bit in the LPM prefix"`
	EndStream       *bool   `json:"end_stream,omitempty" jsonschema:"END_STREAM flag on the carrying H2 DATA frame"`
}

// rawMessageModify carries override fields for a RawMessage envelope.
// BytesOverride and Patches are mutually exclusive (Decision R10) — the
// validation rejects requests supplying both before the queue is touched.
type rawMessageModify struct {
	BytesOverride *string    `json:"bytes_override,omitempty" jsonschema:"replacement bytes (text or base64 per bytes_encoding); mutually exclusive with patches"`
	BytesEncoding string     `json:"bytes_encoding,omitempty" jsonschema:"text|base64; required when bytes_override is non-textual"`
	Patches       []RawPatch `json:"patches,omitempty" jsonschema:"byte-level patches applied to the held envelope's RawMessage.Bytes; mutually exclusive with bytes_override"`
}

// dispatchTypedModify type-switches on the held envelope's Message and
// dispatches to the corresponding apply* helper. The supplied
// interceptInput carries a discriminated union (HTTP / WS / GRPCStart /
// GRPCData / Raw); exactly one of the corresponding pointers must be
// non-nil and must match the held Message type.
//
// rawMode signals that the caller already routed via Mode=raw and supplied
// a RawOverrideBase64 OR rawMessageModify.BytesOverride; the helper
// preserves Envelope.Raw for downstream encoders.
func dispatchTypedModify(env *envelope.Envelope, input interceptInput, rawMode bool) (*envelope.Envelope, error) {
	switch m := env.Message.(type) {
	case *envelope.HTTPMessage:
		if input.HTTP == nil {
			return nil, fmt.Errorf("modify_and_forward: held envelope is HTTP; expected http payload")
		}
		return applyHTTPModify(env, m, input.HTTP)
	case *envelope.WSMessage:
		if input.WS == nil {
			return nil, fmt.Errorf("modify_and_forward: held envelope is WebSocket; expected ws payload")
		}
		return applyWSModify(env, m, input.WS)
	case *envelope.GRPCStartMessage:
		if input.GRPCStart == nil {
			return nil, fmt.Errorf("modify_and_forward: held envelope is GRPCStart; expected grpc_start payload")
		}
		return applyGRPCStartModify(env, m, input.GRPCStart)
	case *envelope.GRPCDataMessage:
		if input.GRPCData == nil {
			return nil, fmt.Errorf("modify_and_forward: held envelope is GRPCData; expected grpc_data payload")
		}
		return applyGRPCDataModify(env, m, input.GRPCData)
	case *envelope.RawMessage:
		if input.Raw == nil {
			return nil, fmt.Errorf("modify_and_forward: held envelope is Raw; expected raw payload")
		}
		return applyRawModify(env, m, input.Raw, rawMode)
	default:
		return nil, fmt.Errorf("modify_and_forward: unsupported held message type %T", env.Message)
	}
}

// holdQueueProtocolKind returns a stable string for the held envelope's
// message-type discriminator. Used in the structured response so callers
// can confirm which dispatch arm fired.
func holdQueueProtocolKind(env *envelope.Envelope) string {
	switch env.Message.(type) {
	case *envelope.HTTPMessage:
		return "http"
	case *envelope.WSMessage:
		return "websocket"
	case *envelope.GRPCStartMessage:
		return "grpc_start"
	case *envelope.GRPCDataMessage:
		return "grpc_data"
	case *envelope.GRPCEndMessage:
		return "grpc_end"
	case *envelope.RawMessage:
		return "raw"
	case nil:
		return "unknown"
	default:
		return fmt.Sprintf("%T", env.Message)
	}
}

// applyHoldQueueRawOverride builds a RawMessage envelope from a base64-
// encoded full-bytes payload supplied via the Mode=raw path on a non-Raw
// held envelope (Decision R9). The returned envelope's Message is a
// RawMessage and Envelope.Raw equals the decoded bytes; the original
// Protocol is preserved so downstream tooling can still attribute the
// modified variant to the original layer. The decoded payload size is
// capped at maxRawOverrideSize (CWE-770).
func applyHoldQueueRawOverride(env *envelope.Envelope, b64 string) (*envelope.Envelope, error) {
	bytesNew, err := decodeBodyEncoded(b64, "base64", "raw_override_base64")
	if err != nil {
		return nil, err
	}
	if len(bytesNew) == 0 {
		return nil, fmt.Errorf("raw_override_base64: decoded to empty bytes")
	}
	if len(bytesNew) > maxRawOverrideSize {
		return nil, fmt.Errorf("raw_override_base64: decoded size %d exceeds limit %d", len(bytesNew), maxRawOverrideSize)
	}
	clone := env.Clone()
	clone.Message = &envelope.RawMessage{Bytes: bytesNew}
	clone.Raw = bytesNew
	return clone, nil
}

// resolveHoldQueueAction validates an MCP intercept input against the held
// entry and produces the HoldAction to send back through the queue. It
// runs *after* stage-1 schema validation (mutual exclusion, etc.) and
// *before* dispatch — see Decision R24.
func resolveHoldQueueAction(entry *common.HeldEntry, input interceptInput, action string) (*common.HoldAction, error) {
	switch action {
	case "release":
		return &common.HoldAction{Type: common.ActionRelease}, nil
	case "drop":
		return &common.HoldAction{Type: common.ActionDrop}, nil
	case "modify_and_forward":
		mode, err := resolveReleaseMode(input.Params.Mode)
		if err != nil {
			return nil, err
		}
		rawMode := mode == releaseModeRaw
		// raw mode + RawOverrideBase64: build a synthetic Raw envelope
		// even if the held one wasn't already Raw.
		if rawMode && input.Params.RawOverrideBase64 != nil {
			modified, err := applyHoldQueueRawOverride(entry.Envelope, *input.Params.RawOverrideBase64)
			if err != nil {
				return nil, err
			}
			return &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified}, nil
		}
		modified, err := dispatchTypedModify(entry.Envelope, input, rawMode)
		if err != nil {
			return nil, err
		}
		return &common.HoldAction{Type: common.ActionModifyAndForward, Modified: modified}, nil
	default:
		return nil, fmt.Errorf("invalid action %q", action)
	}
}

// applyHTTPModify clones the envelope, applies the supplied HTTP overrides,
// and returns the modified clone. Returns an error if validation fails.
//
// Setting Envelope.Raw=nil instructs the downstream Layer to regenerate
// the wire bytes via WireEncoderRegistry on Send; this preserves the
// invariant that Raw always reflects either the wire-observed bytes or a
// freshly encoded post-mutation snapshot, never a stale mix.
func applyHTTPModify(env *envelope.Envelope, _ *envelope.HTTPMessage, params *httpMessageModify) (*envelope.Envelope, error) {
	if params == nil {
		// No-op modify; return a clone for safety so InterceptStep can
		// not observe a shared pointer.
		return env.Clone(), nil
	}
	if err := validateHeaderKVList(params.Headers, "headers"); err != nil {
		return nil, err
	}
	if err := validateHeaderKVList(params.Trailers, "trailers"); err != nil {
		return nil, err
	}
	clone := env.Clone()
	hm, ok := clone.Message.(*envelope.HTTPMessage)
	if !ok {
		return nil, fmt.Errorf("internal: clone produced non-HTTP message")
	}
	applyHTTPScalarOverrides(hm, params)
	if params.Headers != nil {
		hm.Headers = headerKVsToKeyValues(params.Headers)
	}
	if params.Trailers != nil {
		hm.Trailers = headerKVsToKeyValues(params.Trailers)
	}
	if err := applyHTTPBodyOverrides(hm, params); err != nil {
		return nil, err
	}
	clone.Raw = nil
	return clone, nil
}

// applyHTTPScalarOverrides assigns the per-field scalar overrides from
// params onto hm. Splits out of applyHTTPModify so the cyclomatic-
// complexity threshold (15) is not exceeded by the field count alone.
func applyHTTPScalarOverrides(hm *envelope.HTTPMessage, params *httpMessageModify) {
	if params.Method != nil {
		hm.Method = *params.Method
	}
	if params.Scheme != nil {
		hm.Scheme = *params.Scheme
	}
	if params.Authority != nil {
		hm.Authority = *params.Authority
	}
	if params.Path != nil {
		hm.Path = *params.Path
	}
	if params.RawQuery != nil {
		hm.RawQuery = *params.RawQuery
	}
	if params.Status != nil {
		hm.Status = *params.Status
	}
	if params.StatusReason != nil {
		hm.StatusReason = *params.StatusReason
	}
}

// applyHTTPBodyOverrides handles the body-replacement and body_patches
// arms; body is applied first, then patches on top (Decision R12).
func applyHTTPBodyOverrides(hm *envelope.HTTPMessage, params *httpMessageModify) error {
	if params.Body != nil {
		body, err := decodeBodyEncoded(*params.Body, params.BodyEncoding, "body")
		if err != nil {
			return err
		}
		hm.Body = body
		// Spilled body buffer no longer represents truth — drop the
		// reference so the wire-encoder treats hm.Body as authoritative.
		hm.BodyBuffer = nil
	}
	if len(params.BodyPatches) > 0 {
		patched, err := applyBodyPatches(hm.Body, params.BodyPatches)
		if err != nil {
			return fmt.Errorf("body_patches: %w", err)
		}
		hm.Body = patched
	}
	return nil
}

// applyWSModify clones the envelope and applies the WS frame override
// fields. Opcode is canonicalised from string-or-int; CloseCode/CloseReason
// require the resulting opcode to be Close.
func applyWSModify(env *envelope.Envelope, _ *envelope.WSMessage, params *wsMessageModify) (*envelope.Envelope, error) {
	if params == nil {
		return env.Clone(), nil
	}
	clone := env.Clone()
	wm, ok := clone.Message.(*envelope.WSMessage)
	if !ok {
		return nil, fmt.Errorf("internal: clone produced non-WS message")
	}
	if params.Opcode != nil {
		op, err := wsOpcodeFromAny(params.Opcode)
		if err != nil {
			return nil, err
		}
		wm.Opcode = op
	}
	if params.Fin != nil {
		wm.Fin = *params.Fin
	}
	if params.Payload != nil {
		payload, err := decodeBodyEncoded(*params.Payload, params.BodyEncoding, "payload")
		if err != nil {
			return nil, err
		}
		wm.Payload = payload
	}
	if params.CloseCode != nil {
		if *params.CloseCode < 0 || *params.CloseCode > 0xFFFF {
			return nil, fmt.Errorf("close_code %d out of range [0, 65535]", *params.CloseCode)
		}
		wm.CloseCode = uint16(*params.CloseCode)
	}
	if params.CloseReason != nil {
		wm.CloseReason = *params.CloseReason
	}
	clone.Raw = nil
	return clone, nil
}

// applyGRPCStartModify clones the envelope and applies overrides to a
// GRPCStartMessage. Metadata is replaced wholesale when non-nil; transport
// pseudo-headers (:authority, :path, etc.) live on Envelope.Context and
// are intentionally not modifiable through this surface.
func applyGRPCStartModify(env *envelope.Envelope, _ *envelope.GRPCStartMessage, params *grpcStartMessageModify) (*envelope.Envelope, error) {
	if params == nil {
		return env.Clone(), nil
	}
	if err := validateHeaderKVList(params.Metadata, "metadata"); err != nil {
		return nil, err
	}
	clone := env.Clone()
	gm, ok := clone.Message.(*envelope.GRPCStartMessage)
	if !ok {
		return nil, fmt.Errorf("internal: clone produced non-GRPCStart message")
	}
	if params.Service != nil {
		gm.Service = *params.Service
	}
	if params.Method != nil {
		gm.Method = *params.Method
	}
	if params.Encoding != nil {
		gm.Encoding = *params.Encoding
	}
	if params.Metadata != nil {
		gm.Metadata = headerKVsToKeyValues(params.Metadata)
	}
	clone.Raw = nil
	return clone, nil
}

// applyGRPCDataModify clones the envelope and overrides the LPM payload
// fields. The downstream Layer regenerates the 5-byte LPM prefix from
// (Compressed, len(Payload)) when re-encoding for the wire.
func applyGRPCDataModify(env *envelope.Envelope, _ *envelope.GRPCDataMessage, params *grpcDataMessageModify) (*envelope.Envelope, error) {
	if params == nil {
		return env.Clone(), nil
	}
	clone := env.Clone()
	gm, ok := clone.Message.(*envelope.GRPCDataMessage)
	if !ok {
		return nil, fmt.Errorf("internal: clone produced non-GRPCData message")
	}
	if params.Payload != nil {
		payload, err := decodeBodyEncoded(*params.Payload, params.PayloadEncoding, "payload")
		if err != nil {
			return nil, err
		}
		gm.Payload = payload
	}
	if params.Compressed != nil {
		gm.Compressed = *params.Compressed
	}
	if params.EndStream != nil {
		gm.EndStream = *params.EndStream
	}
	clone.Raw = nil
	return clone, nil
}

// applyRawModify clones the envelope and applies either a full
// bytes_override or a patches sequence to the held RawMessage. Caller has
// already validated the mutual-exclusion invariant via
// validateRawMessageModify. In raw-mode bytes_override the new bytes also
// land on Envelope.Raw so the Layer skips re-encoding (Decision R9).
func applyRawModify(env *envelope.Envelope, _ *envelope.RawMessage, params *rawMessageModify, rawMode bool) (*envelope.Envelope, error) {
	if params == nil {
		return env.Clone(), nil
	}
	clone := env.Clone()
	rm, ok := clone.Message.(*envelope.RawMessage)
	if !ok {
		return nil, fmt.Errorf("internal: clone produced non-Raw message")
	}
	switch {
	case params.BytesOverride != nil:
		bytesNew, err := decodeBodyEncoded(*params.BytesOverride, params.BytesEncoding, "bytes_override")
		if err != nil {
			return nil, err
		}
		if len(bytesNew) > maxRawOverrideSize {
			return nil, fmt.Errorf("bytes_override: decoded size %d exceeds limit %d", len(bytesNew), maxRawOverrideSize)
		}
		rm.Bytes = bytesNew
		if rawMode {
			// In raw mode the supplied bytes are the wire bytes; record
			// them on Raw so the downstream Layer skips re-encoding.
			clone.Raw = bytesNew
			return clone, nil
		}
	case len(params.Patches) > 0:
		patched, err := applyRawPatches(rm.Bytes, params.Patches)
		if err != nil {
			return nil, fmt.Errorf("patches: %w", err)
		}
		rm.Bytes = patched
	}
	clone.Raw = nil
	return clone, nil
}

// validateRawMessageModify enforces the mutual-exclusion rule between
// bytes_override and patches (Decision R10). Returns nil for an empty
// payload (no-op modify is valid).
func validateRawMessageModify(params *rawMessageModify) error {
	if params == nil {
		return nil
	}
	hasOverride := params.BytesOverride != nil
	hasPatches := len(params.Patches) > 0
	if hasOverride && hasPatches {
		return fmt.Errorf("raw modify: bytes_override and patches are mutually exclusive")
	}
	return nil
}

// validateHeaderKVList rejects header entries with CR/LF in either the
// name or the value (CWE-113 header injection guard) and rejects entries
// with empty names. Empty values ARE valid (e.g. cleared cookies).
func validateHeaderKVList(list []headerKV, kind string) error {
	for i, kv := range list {
		if kv.Name == "" {
			return fmt.Errorf("%s[%d]: name must not be empty", kind, i)
		}
		if strings.ContainsAny(kv.Name, "\r\n") {
			return fmt.Errorf("%s[%d]: name %q contains CR/LF characters", kind, i, kv.Name)
		}
		if strings.ContainsAny(kv.Value, "\r\n") {
			return fmt.Errorf("%s[%d]: value for %q contains CR/LF characters", kind, i, kv.Name)
		}
	}
	return nil
}

// headerKVsToKeyValues projects an MCP headerKV slice onto envelope
// KeyValue, preserving order and casing exactly as supplied.
func headerKVsToKeyValues(list []headerKV) []envelope.KeyValue {
	if list == nil {
		return nil
	}
	out := make([]envelope.KeyValue, len(list))
	for i, kv := range list {
		out[i] = envelope.KeyValue{Name: kv.Name, Value: kv.Value}
	}
	return out
}

// decodeBodyEncoded interprets a body/payload string as either text (UTF-8
// passthrough) or base64. An empty encoding string defaults to "text" for
// compatibility. The field name is used in error messages.
func decodeBodyEncoded(s, encoding, field string) ([]byte, error) {
	switch encoding {
	case "", "text":
		return []byte(s), nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid base64: %w", field, err)
		}
		return decoded, nil
	default:
		return nil, fmt.Errorf("%s: unknown encoding %q (expected text or base64)", field, encoding)
	}
}

// wsOpcodeFromAny accepts either a string name or a numeric (any JSON
// number) opcode and returns the canonical envelope.WSOpcode. Numeric
// values must fit the 4-bit opcode field; string names follow Decision
// R8's case-insensitive list.
func wsOpcodeFromAny(v any) (envelope.WSOpcode, error) {
	switch x := v.(type) {
	case string:
		return wsOpcodeFromName(x)
	case float64:
		// JSON numbers decode to float64 by default.
		return wsOpcodeFromInt(int(x))
	case int:
		return wsOpcodeFromInt(x)
	case int64:
		return wsOpcodeFromInt(int(x))
	default:
		return 0, fmt.Errorf("opcode: expected string or number, got %T", v)
	}
}

// wsOpcodeFromName maps the case-insensitive opcode names to their
// envelope.WSOpcode constant.
func wsOpcodeFromName(name string) (envelope.WSOpcode, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "continuation":
		return envelope.WSContinuation, nil
	case "text":
		return envelope.WSText, nil
	case "binary":
		return envelope.WSBinary, nil
	case "close":
		return envelope.WSClose, nil
	case "ping":
		return envelope.WSPing, nil
	case "pong":
		return envelope.WSPong, nil
	default:
		return 0, fmt.Errorf("opcode: unknown name %q (text|binary|close|ping|pong|continuation)", name)
	}
}

// wsOpcodeFromInt validates that n fits the 4-bit opcode space.
func wsOpcodeFromInt(n int) (envelope.WSOpcode, error) {
	if n < 0 || n > 15 {
		return 0, fmt.Errorf("opcode: numeric value %d out of range [0, 15]", n)
	}
	return envelope.WSOpcode(n), nil
}
