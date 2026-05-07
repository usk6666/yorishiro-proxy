package http2

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// maxHeaderFragmentBytes is the upper bound on the cumulative size of an
// HPACK header block fragment accumulator (HEADERS + CONTINUATION*). This
// is a raw-HPACK-byte limit, distinct from MaxHeaderListSize which bounds
// the *decoded* header list. Without this cap, a malicious peer could
// stream an unbounded chain of CONTINUATION frames and exhaust memory
// (CONTINUATION-flood DoS, cf. the 2024 class of bugs around CVE-2024-27316).
// 1 MiB is well above any legitimate header block while bounding the worst
// case.
const maxHeaderFragmentBytes = 1 << 20

// maxContinuationFrames bounds how many CONTINUATION frames may follow a
// single HEADERS or PUSH_PROMISE before the connection is treated as
// abusive. Real header blocks fit in 1-2 frames; large clients may use a
// handful. 32 is a generous upper bound that still bounds the worst case.
const maxContinuationFrames = 32

// h1OnlyHeaders is the set of HTTP/1-specific connection-management headers
// that MUST NOT appear over HTTP/2 per RFC 9113 §8.2.2. We do not strip them
// — wire fidelity rules — but we attach an H2ConnectionSpecificHeader anomaly
// to the message.
//
// "TE: trailers" is the documented exception (allowed); any other "te:" value
// is flagged.
var h1OnlyHeaders = map[string]struct{}{
	"connection":        {},
	"keep-alive":        {},
	"proxy-connection":  {},
	"transfer-encoding": {},
	"upgrade":           {},
}

// streamEventPhase tracks which header block the stream is currently
// accumulating. The HTTP/2 reader produces H2HeadersEvent / H2DataEvent /
// H2TrailersEvent envelopes on a per-stream basis; this phase field lets the
// assembler know whether an END_HEADERS block should yield initial headers or
// trailers. DATA frames do not transition the phase — they are emitted as
// H2DataEvent directly.
type streamEventPhase uint8

const (
	// phaseInitialHeaders waits for the initial HEADERS (plus CONTINUATION*).
	// Re-entered after a 1xx informational HEADERS so the next HEADERS is
	// processed as a fresh initial block (per RFC 9110 §15.2: any number of
	// 1xx responses may precede the final response).
	phaseInitialHeaders streamEventPhase = iota
	// phaseBodyOrTrailers has emitted the *final* response/request HEADERS
	// (status >= 200, or any request HEADERS) and is waiting for DATA
	// frames or a trailer HEADERS frame.
	phaseBodyOrTrailers
	// phaseTrailers is coalescing a trailer HEADERS block (HEADERS-after-DATA).
	phaseTrailers
	// phaseDone terminal.
	phaseDone
)

// eventAssembler is the per-stream state held by the HTTP/2 reader. It
// coalesces CONTINUATION fragments into a single HPACK block, decodes the
// block, and produces event envelopes (H2HeadersEvent / H2TrailersEvent).
// DATA frames are emitted as H2DataEvent directly by the reader — the
// assembler only gets involved if it needs to observe END_STREAM on DATA
// (for state transitions).
//
// The assembler is owned by the reader goroutine and accessed only from there
// (no mutex). One assembler per stream, stored in Layer.assemblers keyed by
// HTTP/2 stream id.
type eventAssembler struct {
	streamID uint32
	channel  *channel

	phase streamEventPhase

	// fragBuf accumulates HPACK header-block fragments across HEADERS +
	// CONTINUATION (for either initial headers or trailers).
	fragBuf []byte
	// continuationCount counts CONTINUATION frames received for the current
	// header block (resets when END_HEADERS is observed).
	continuationCount int

	// fragRaw accumulates the raw fragment bytes across HEADERS + CONTINUATION
	// (or trailer HEADERS + CONTINUATION) so the emitted event's Envelope.Raw
	// reflects the complete HPACK block as observed on the wire (without the
	// 9-byte frame header — this is what a pure HPACK decoder would consume).
	//
	// The RFC-001 Raw-for-event contract says Raw = HPACK block fragment, not
	// the full DATA frame wrapper. We therefore accumulate fragment bytes
	// (post-extraction) rather than raw frame bytes.
	fragRaw []byte

	// initialDirection is the direction inferred from the first HEADERS block
	// (Send for ServerRole, Receive for ClientRole). Reused for the trailer
	// block which must share the direction of the in-flight request/response.
	initialDirection envelope.Direction
	initialDirSet    bool
}

// newEventAssembler creates an assembler for a stream owned by ch.
func newEventAssembler(streamID uint32, ch *channel) *eventAssembler {
	return &eventAssembler{
		streamID: streamID,
		channel:  ch,
		phase:    phaseInitialHeaders,
	}
}

// pseudoFields holds extracted pseudo-headers and tracks duplicates / order
// errors for anomaly attachment.
type pseudoFields struct {
	method, scheme, authority, path string
	status                          string
	protocol                        string
	hasMethod, hasScheme, hasAuth   bool
	hasPath, hasStatus              bool
	hasProtocol                     bool
	dupAnomalies                    []envelope.Anomaly
	regularBeforePseudo             bool
	invalidNames                    []string
}

// splitHeaders separates pseudo-headers from regular headers, detecting the
// usual HTTP/2-only anomalies. Pseudo-headers appearing AFTER a regular header
// flag the message but are otherwise included in pf.
func splitHeaders(decoded []hpack.HeaderField) (pf pseudoFields, regular []envelope.KeyValue, anomalies []envelope.Anomaly) {
	regular = make([]envelope.KeyValue, 0, len(decoded))
	sawRegular := false

	for _, hf := range decoded {
		if strings.HasPrefix(hf.Name, ":") {
			if sawRegular {
				pf.regularBeforePseudo = true
			}
			pf.applyPseudo(hf)
			continue
		}
		sawRegular = true
		regular = append(regular, envelope.KeyValue{Name: hf.Name, Value: hf.Value})
		anomalies = append(anomalies, regularHeaderAnomalies(hf)...)
	}

	anomalies = append(anomalies, pf.flushAnomalies()...)
	return pf, regular, anomalies
}

// applyPseudo records a pseudo-header into pf, flagging duplicates and
// unknown names. The :protocol pseudo-header (RFC 8441 §4, used by the
// extended CONNECT method to bootstrap WebSocket / other protocols over
// HTTP/2) is accepted unconditionally here; the :method == CONNECT
// precondition is enforced post-walk in flushAnomalies so duplicate
// :protocol detection still uses recordOnce.
func (pf *pseudoFields) applyPseudo(hf hpack.HeaderField) {
	switch hf.Name {
	case ":method":
		pf.recordOnce(&pf.hasMethod, &pf.method, hf)
	case ":scheme":
		pf.recordOnce(&pf.hasScheme, &pf.scheme, hf)
	case ":authority":
		pf.recordOnce(&pf.hasAuth, &pf.authority, hf)
	case ":path":
		pf.recordOnce(&pf.hasPath, &pf.path, hf)
	case ":status":
		pf.recordOnce(&pf.hasStatus, &pf.status, hf)
	case ":protocol":
		pf.recordOnce(&pf.hasProtocol, &pf.protocol, hf)
	default:
		pf.invalidNames = append(pf.invalidNames, hf.Name)
	}
}

func (pf *pseudoFields) recordOnce(seen *bool, dst *string, hf hpack.HeaderField) {
	if *seen {
		pf.dupAnomalies = append(pf.dupAnomalies, envelope.Anomaly{
			Type:   envelope.H2DuplicatePseudoHeader,
			Detail: hf.Name,
		})
	}
	*dst = hf.Value
	*seen = true
}

// flushAnomalies returns the anomalies accumulated in pf (regular-before-pseudo,
// invalid pseudo names, duplicates).
//
// :protocol enforcement (RFC 8441 §4): :protocol is only valid on extended
// CONNECT requests, so a :protocol with :method != "CONNECT" surfaces as
// H2InvalidPseudoHeader. The accept-then-flag pattern keeps the parsing
// loop simple — the precondition is a cross-pseudo-header invariant that
// can only be evaluated after every pseudo header in the block has been
// observed.
func (pf *pseudoFields) flushAnomalies() []envelope.Anomaly {
	var out []envelope.Anomaly
	if pf.regularBeforePseudo {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2PseudoHeaderAfterRegular,
			Detail: "",
		})
	}
	for _, n := range pf.invalidNames {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2InvalidPseudoHeader,
			Detail: n,
		})
	}
	if pf.hasProtocol && pf.method != "CONNECT" {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2InvalidPseudoHeader,
			Detail: ":protocol with :method=" + pf.method,
		})
	}
	// RFC 8441 §4: extended CONNECT (CONNECT + :protocol) MUST include
	// :scheme and :path. Classic CONNECT is the inverse case (MUST NOT
	// include them) — that's enforced elsewhere; here we only flag the
	// extended-CONNECT-missing-required-pseudo-header path. Each missing
	// pseudo-header is reported separately so the operator can see which
	// element of the header set was malformed.
	if pf.hasProtocol && pf.method == "CONNECT" {
		if !pf.hasScheme {
			out = append(out, envelope.Anomaly{
				Type:   envelope.H2InvalidPseudoHeader,
				Detail: "extended CONNECT missing :scheme",
			})
		}
		if !pf.hasPath {
			out = append(out, envelope.Anomaly{
				Type:   envelope.H2InvalidPseudoHeader,
				Detail: "extended CONNECT missing :path",
			})
		}
	}
	out = append(out, pf.dupAnomalies...)
	return out
}

// regularHeaderAnomalies returns the anomalies attributable to a single
// regular header (uppercase-name, h1-only-header, malformed te:).
func regularHeaderAnomalies(hf hpack.HeaderField) []envelope.Anomaly {
	var out []envelope.Anomaly
	if hasUppercase(hf.Name) {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2UppercaseHeaderName,
			Detail: hf.Name,
		})
	}
	lower := strings.ToLower(hf.Name)
	if _, ok := h1OnlyHeaders[lower]; ok {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2ConnectionSpecificHeader,
			Detail: hf.Name,
		})
	}
	if lower == "te" && hf.Value != "trailers" {
		out = append(out, envelope.Anomaly{
			Type:   envelope.H2ConnectionSpecificHeader,
			Detail: "te: " + hf.Value,
		})
	}
	return out
}

// hasUppercase returns true if s contains any A-Z character.
func hasUppercase(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			return true
		}
	}
	return false
}

// splitPath splits a :path pseudo-header value into (path, rawQuery) at the
// first '?'.
func splitPath(p string) (path, rawQuery string) {
	if idx := strings.IndexByte(p, '?'); idx >= 0 {
		return p[:idx], p[idx+1:]
	}
	return p, ""
}

// buildHeadersEvent constructs an H2HeadersEvent from a decoded initial
// HEADERS block plus anomalies. direction selects request-vs-response
// pseudo-header interpretation.
func buildHeadersEvent(decoded []hpack.HeaderField, direction envelope.Direction, endStream bool) *H2HeadersEvent {
	pf, regular, anomalies := splitHeaders(decoded)
	evt := &H2HeadersEvent{
		Headers:   regular,
		EndStream: endStream,
		Anomalies: anomalies,
	}
	if direction == envelope.Send {
		evt.Method = pf.method
		evt.Scheme = pf.scheme
		evt.Authority = pf.authority
		evt.Path, evt.RawQuery = splitPath(pf.path)
		// RFC 8441 §4: :protocol is only meaningful on extended CONNECT.
		// flushAnomalies has already flagged :protocol with non-CONNECT
		// methods as H2InvalidPseudoHeader, so the field is propagated
		// only when the precondition holds. This keeps downstream
		// (httpaggregator → HTTPMessage.ConnectProtocol → session) free
		// of the "drop on Method!=CONNECT" branch.
		if pf.hasProtocol && pf.method == "CONNECT" {
			evt.ConnectProtocol = pf.protocol
		}
	} else {
		if pf.hasStatus {
			if n, err := strconv.Atoi(pf.status); err == nil {
				evt.Status = n
				evt.StatusReason = statusReason(n)
			}
		}
	}
	return evt
}

// buildTrailersEvent constructs an H2TrailersEvent from a decoded trailer
// HEADERS block. Pseudo-headers in trailers are invalid (RFC 9113 §8.1);
// they are dropped here and an H2InvalidPseudoHeader anomaly is attached.
func buildTrailersEvent(decoded []hpack.HeaderField) *H2TrailersEvent {
	trailers := make([]envelope.KeyValue, 0, len(decoded))
	var anomalies []envelope.Anomaly
	for _, hf := range decoded {
		if strings.HasPrefix(hf.Name, ":") {
			anomalies = append(anomalies, envelope.Anomaly{
				Type:   envelope.H2InvalidPseudoHeader,
				Detail: "in trailers: " + hf.Name,
			})
			continue
		}
		trailers = append(trailers, envelope.KeyValue{Name: hf.Name, Value: hf.Value})
		anomalies = append(anomalies, regularHeaderAnomalies(hf)...)
	}
	return &H2TrailersEvent{
		Trailers:  trailers,
		Anomalies: anomalies,
	}
}

// statusReasonTable maps HTTP status codes to the canonical HTTP/1.1 reason
// phrase. HTTP/2 wire has no reason phrase (RFC 9113 §8.3.1); this surfaces
// one for HTTP/1.x parity in downstream flow.Flow.StatusCode rendering.
//
// Unknown codes are represented as the empty string via map-miss.
var statusReasonTable = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	202: "Accepted",
	204: "No Content",
	206: "Partial Content",
	301: "Moved Permanently",
	302: "Found",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	409: "Conflict",
	410: "Gone",
	413: "Payload Too Large",
	415: "Unsupported Media Type",
	418: "I'm a teapot",
	429: "Too Many Requests",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

// statusReason returns the canonical reason phrase for code, or empty
// string when unknown.
func statusReason(code int) string {
	return statusReasonTable[code]
}

// isInformationalStatus reports whether code is a 1xx informational status
// (RFC 9110 §15.2). 1xx responses precede the *real* final response on the
// same HTTP/2 stream and must not transition the assembler out of the
// initial-headers phase. See USK-721 for the reproducer that motivates this.
func isInformationalStatus(code int) bool {
	return code >= 100 && code < 200
}

// handleHeadersFrame processes a HEADERS (or CONTINUATION) fragment. When
// END_HEADERS is observed, the decoded block is converted to an event
// envelope (H2HeadersEvent for phaseInitialHeaders, H2TrailersEvent for
// phaseTrailers) and returned. Otherwise the fragment is accumulated and
// (nil, nil) is returned.
//
// Returns (*envelope.Envelope, error). A non-nil *envelope.Envelope is
// ready to deliver to the channel's recv side. A *ConnError is returned if
// the cumulative fragment size exceeds maxHeaderFragmentBytes
// (CONTINUATION-flood DoS guard) or if the decode itself fails.
func (a *eventAssembler) handleHeadersFrame(
	fragment []byte,
	endHeaders, endStream bool,
	decoder *hpack.Decoder,
	direction envelope.Direction,
) (*envelope.Envelope, error) {
	if len(a.fragBuf)+len(fragment) > maxHeaderFragmentBytes {
		return nil, &ConnError{
			Code:   ErrCodeCompression,
			Reason: fmt.Sprintf("header block fragment exceeds %d bytes (stream %d)", maxHeaderFragmentBytes, a.streamID),
		}
	}
	a.fragBuf = append(a.fragBuf, fragment...)
	a.fragRaw = append(a.fragRaw, fragment...)

	if a.phase == phaseBodyOrTrailers {
		// HEADERS-after-DATA = trailers. Switch to trailer collection.
		// 1xx informational responses do NOT reach this branch because the
		// initial-headers handler keeps phase == phaseInitialHeaders for
		// any 1xx :status — see the post-decode classification below
		// (USK-721).
		a.phase = phaseTrailers
	}

	if !endHeaders {
		a.continuationCount++
		if a.continuationCount > maxContinuationFrames {
			return nil, &ConnError{
				Code:   ErrCodeEnhanceYourCalm,
				Reason: fmt.Sprintf("too many CONTINUATION frames (>%d) for stream %d", maxContinuationFrames, a.streamID),
			}
		}
		return nil, nil
	}

	// END_HEADERS observed; reset continuation counter for any future block
	// (trailers).
	a.continuationCount = 0

	decoded, dErr := decoder.Decode(a.fragBuf)
	a.fragBuf = nil
	if dErr != nil {
		return nil, fmt.Errorf("http2: decode header block (stream %d): %w", a.streamID, dErr)
	}

	// Capture accumulated raw bytes for the event.
	rawBlock := a.fragRaw
	a.fragRaw = nil

	switch a.phase {
	case phaseInitialHeaders:
		if !a.initialDirSet {
			a.initialDirection = direction
			a.initialDirSet = true
		}
		evt := buildHeadersEvent(decoded, direction, endStream)
		env := &envelope.Envelope{
			StreamID:  a.channel.streamID,
			Sequence:  a.channel.nextSequence(),
			Direction: direction,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       rawBlock,
			Message:   evt,
		}
		// USK-721: 1xx informational responses (RFC 9110 §15.2: 100 Continue,
		// 102 Processing, 103 Early Hints) precede the *real* final response
		// on the same stream. They are bodyless and never carry END_STREAM.
		// Stay in phaseInitialHeaders so the next HEADERS is treated as a
		// fresh initial block (could be another 1xx, or the final response).
		// Direction == Receive guards request-side HEADERS (which never have
		// :status and would parse as Status == 0).
		if direction == envelope.Receive && isInformationalStatus(evt.Status) {
			return env, nil
		}
		if endStream {
			a.phase = phaseDone
		} else {
			a.phase = phaseBodyOrTrailers
		}
		return env, nil

	case phaseTrailers:
		// Trailers always END_STREAM (RFC 9113 §8.1). Direction mirrors the
		// initial HEADERS so the aggregator can associate them with the
		// right in-flight HTTPMessage.
		dir := a.initialDirection
		if !a.initialDirSet {
			dir = direction
		}
		evt := buildTrailersEvent(decoded)
		env := &envelope.Envelope{
			StreamID:  a.channel.streamID,
			Sequence:  a.channel.nextSequence(),
			Direction: dir,
			Protocol:  envelope.ProtocolHTTP,
			Raw:       rawBlock,
			Message:   evt,
		}
		a.phase = phaseDone
		return env, nil
	}

	return nil, nil
}

// handleDataFrame builds an H2DataEvent envelope for a single DATA frame.
// Every non-nil payload produces one event (deterministic 1:1 with the frame);
// empty DATA frames carrying END_STREAM also produce an event so the
// aggregator observes END_STREAM for bodyless paths.
//
// Returns the envelope to deliver. The caller (reader) is responsible for
// subsequent WINDOW_UPDATE emission (independent of aggregator drain).
//
// The returned envelope's Raw field shares the same defensive copy as the
// event's Payload — saving one allocation per DATA frame for large-body
// streams. Both slices are owned by the event consumer; neither the Layer
// nor the reader retain a reference.
func (a *eventAssembler) handleDataFrame(payload []byte, endStream bool) *envelope.Envelope {
	// One defensive copy shared by evt.Payload and env.Raw. The caller
	// (aggregator) reads evt.Payload; env.Raw is kept so per-frame wire
	// observers (e.g., future grpc LPM reassembly) can consume it.
	cp := cloneEvBytes(payload)
	evt := &H2DataEvent{
		Payload:   cp,
		EndStream: endStream,
	}

	dir := a.initialDirection
	if !a.initialDirSet {
		if a.channel != nil && a.channel.layer != nil && a.channel.layer.role == ServerRole {
			dir = envelope.Send
		} else {
			dir = envelope.Receive
		}
	}

	env := &envelope.Envelope{
		StreamID:  a.channel.streamID,
		Sequence:  a.channel.nextSequence(),
		Direction: dir,
		Protocol:  envelope.ProtocolHTTP,
		Raw:       cp,
		Message:   evt,
	}
	if endStream {
		a.phase = phaseDone
	}
	return env
}

// isDone reports whether the assembler has reached terminal state (observed
// END_STREAM on the initial HEADERS or on a DATA frame, or decoded a trailer
// HEADERS block).
func (a *eventAssembler) isDone() bool {
	return a.phase == phaseDone
}
