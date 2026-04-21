package http2

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http2/hpack"
)

// passthroughThreshold is the body size above which an envelope switches to
// passthrough mode (BodyStream instead of buffered Body). Same value as the
// HTTP/1.x layer so consumer behavior is symmetric.
const passthroughThreshold = 10 << 20 // 10 MiB

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

// asmPhase tracks the assembler's state for one stream.
type asmPhase uint8

const (
	asmInitialHeaders     asmPhase = iota // waiting for HEADERS / collecting CONTINUATION
	asmCollectingBody                     // header block decoded; collecting DATA
	asmCollectingTrailers                 // received HEADERS-after-DATA; collecting CONTINUATION
	asmPassthrough                        // body exceeds threshold; envelope already yielded; piping body
	asmDone                               // terminal — assembler will not yield more for this stream
)

// streamAssembler is the per-stream assembler state. It is owned by the
// reader goroutine and accessed only from there (no mutex).
type streamAssembler struct {
	streamID uint32
	channel  *channel // owning Channel; nil for assemblers we will discard

	phase asmPhase

	// fragBuf accumulates HPACK header-block fragments across HEADERS +
	// CONTINUATION (for either initial headers or trailers).
	fragBuf []byte
	// continuationCount counts CONTINUATION frames received for the current
	// header block (resets when END_HEADERS is observed).
	continuationCount int
	// rawAcc accumulates RawBytes from contributing frames (HEADERS/CONT/DATA).
	rawAcc []byte
	// frameBytes accumulates per-frame raw bytes for opaque resend.
	frameBytes [][]byte
	// origHeaders snapshot of decoded header fields, for opaque change detection.
	origHeaders []hpack.HeaderField

	// body buffers DATA payloads up to passthroughThreshold.
	body []byte

	// pipeWriter is non-nil in passthrough mode. The corresponding pipe reader
	// is held by the already-yielded envelope's HTTPMessage.BodyStream.
	pipeWriter *io.PipeWriter

	// inflight is the envelope being assembled. Yielded on END_STREAM (normal
	// mode) or upon entering passthrough mode.
	inflight *envelope.Envelope
}

// newStreamAssembler creates an assembler for a stream owned by ch.
func newStreamAssembler(streamID uint32, ch *channel) *streamAssembler {
	return &streamAssembler{
		streamID: streamID,
		channel:  ch,
		phase:    asmInitialHeaders,
	}
}

// pseudoFields holds extracted pseudo-headers and tracks duplicates / order
// errors for anomaly attachment.
type pseudoFields struct {
	method, scheme, authority, path string
	status                          string
	hasMethod, hasScheme, hasAuth   bool
	hasPath, hasStatus              bool
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
// unknown names.
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

// buildHTTPMessage constructs an HTTPMessage from decoded headers. The
// direction is needed to interpret pseudo-headers (request vs response).
func buildHTTPMessage(decoded []hpack.HeaderField, direction envelope.Direction) (*envelope.HTTPMessage, []envelope.Anomaly) {
	pf, regular, anomalies := splitHeaders(decoded)

	msg := &envelope.HTTPMessage{
		Headers: regular,
	}

	if direction == envelope.Send {
		msg.Method = pf.method
		msg.Scheme = pf.scheme
		msg.Authority = pf.authority
		msg.Path, msg.RawQuery = splitPath(pf.path)
	} else {
		if pf.hasStatus {
			if n, err := strconv.Atoi(pf.status); err == nil {
				msg.Status = n
			}
		}
	}
	return msg, anomalies
}

// handleHeadersFrame processes a HEADERS frame for this stream. The fragment
// has already been extracted by the caller (the reader goroutine), but the
// HPACK decode is deferred until END_HEADERS so a single header block is
// decoded as a unit (RFC 7541 §4.1).
//
// Returns a *ConnError tagged COMPRESSION_ERROR if the cumulative fragment
// size would exceed maxHeaderFragmentBytes (CONTINUATION-flood DoS guard).
func (a *streamAssembler) handleHeadersFrame(fragment, raw []byte, endHeaders, endStream bool, decoder *hpack.Decoder, direction envelope.Direction) (yieldEnv *envelope.Envelope, complete bool, err error) {
	if len(a.fragBuf)+len(fragment) > maxHeaderFragmentBytes {
		return nil, false, &ConnError{
			Code:   ErrCodeCompression,
			Reason: fmt.Sprintf("header block fragment exceeds %d bytes (stream %d)", maxHeaderFragmentBytes, a.streamID),
		}
	}
	a.rawAcc = append(a.rawAcc, raw...)
	a.frameBytes = append(a.frameBytes, cloneSlice(raw))
	a.fragBuf = append(a.fragBuf, fragment...)

	if a.phase == asmCollectingBody {
		// HEADERS-after-DATA = trailers. Switch to trailer collection.
		a.phase = asmCollectingTrailers
	}

	if !endHeaders {
		a.continuationCount++
		if a.continuationCount > maxContinuationFrames {
			return nil, false, &ConnError{
				Code:   ErrCodeEnhanceYourCalm,
				Reason: fmt.Sprintf("too many CONTINUATION frames (>%d) for stream %d", maxContinuationFrames, a.streamID),
			}
		}
		return nil, false, nil
	}
	// END_HEADERS observed; reset continuation counter for any future block
	// (trailers).
	a.continuationCount = 0

	// Decode the complete header block.
	decoded, dErr := decoder.Decode(a.fragBuf)
	a.fragBuf = nil
	if dErr != nil {
		return nil, false, fmt.Errorf("http2: decode header block (stream %d): %w", a.streamID, dErr)
	}

	switch a.phase {
	case asmInitialHeaders, asmCollectingBody:
		// Initial headers (asmCollectingBody can occur if we got headers,
		// no DATA, and then END_HEADERS — fall through equivalent).
		msg, anomalies := buildHTTPMessage(decoded, direction)
		msg.Anomalies = anomalies
		a.origHeaders = decoded

		env := &envelope.Envelope{
			StreamID:  a.channel.streamID,
			Sequence:  a.channel.nextSequence(),
			Direction: direction,
			Protocol:  envelope.ProtocolHTTP,
			Message:   msg,
		}
		a.inflight = env

		if endStream {
			// No body; finalize.
			env.Raw = a.rawAcc
			env.Opaque = &opaqueHTTP2{
				layer:       a.channel.layer,
				streamID:    a.streamID,
				frames:      a.frameBytes,
				origHeaders: cloneHeaderFields(decoded),
				origBody:    nil,
				isPush:      a.channel.isPush,
			}
			a.rawAcc = nil
			a.frameBytes = nil
			a.phase = asmDone
			return env, true, nil
		}

		a.phase = asmCollectingBody
		return nil, false, nil

	case asmCollectingTrailers:
		// Convert the decoded list (no pseudo-headers expected) to KeyValues.
		trailers := make([]envelope.KeyValue, 0, len(decoded))
		var trailerAnomalies []envelope.Anomaly
		for _, hf := range decoded {
			if strings.HasPrefix(hf.Name, ":") {
				trailerAnomalies = append(trailerAnomalies, envelope.Anomaly{
					Type:   envelope.H2InvalidPseudoHeader,
					Detail: "in trailers: " + hf.Name,
				})
				continue
			}
			trailers = append(trailers, envelope.KeyValue{Name: hf.Name, Value: hf.Value})
		}
		if a.inflight != nil {
			msg := a.inflight.Message.(*envelope.HTTPMessage)
			msg.Trailers = trailers
			if len(trailerAnomalies) > 0 {
				msg.Anomalies = append(msg.Anomalies, trailerAnomalies...)
			}
		}

		// Trailers always END_STREAM (RFC 9113 §8.1).
		env := a.inflight
		if env != nil {
			env.Raw = a.rawAcc
			// Attach buffered body if not in passthrough.
			msg := env.Message.(*envelope.HTTPMessage)
			if a.pipeWriter == nil {
				msg.Body = a.body
				a.body = nil
			} else {
				_ = a.pipeWriter.Close()
				a.pipeWriter = nil
			}
			env.Opaque = &opaqueHTTP2{
				layer:       a.channel.layer,
				streamID:    a.streamID,
				frames:      a.frameBytes,
				origHeaders: cloneHeaderFields(a.origHeaders),
				origBody:    cloneSlice(msg.Body),
				isPush:      a.channel.isPush,
			}
			a.rawAcc = nil
			a.frameBytes = nil
		}
		a.inflight = nil
		a.phase = asmDone
		return env, true, nil
	}

	return nil, false, nil
}

// handleDataFrame appends DATA payload to the in-flight body (or pipes it in
// passthrough mode). Returns the in-flight envelope on the transition to
// passthrough or on END_STREAM.
func (a *streamAssembler) handleDataFrame(payload, raw []byte, endStream bool) (yieldEnv *envelope.Envelope, complete bool, err error) {
	a.rawAcc = append(a.rawAcc, raw...)
	a.frameBytes = append(a.frameBytes, cloneSlice(raw))

	if a.phase == asmPassthrough {
		if len(payload) > 0 && a.pipeWriter != nil {
			if _, werr := a.pipeWriter.Write(payload); werr != nil {
				return nil, false, fmt.Errorf("http2: write passthrough body (stream %d): %w", a.streamID, werr)
			}
		}
		if endStream {
			if a.pipeWriter != nil {
				_ = a.pipeWriter.Close()
				a.pipeWriter = nil
			}
			a.phase = asmDone
			return nil, true, nil
		}
		return nil, false, nil
	}

	// Buffered mode.
	if len(payload) > 0 {
		a.body = append(a.body, payload...)
	}

	// Check for passthrough threshold. If exceeded, switch modes.
	if len(a.body) > passthroughThreshold {
		if a.inflight == nil {
			return nil, false, fmt.Errorf("http2: stream %d data without headers", a.streamID)
		}
		pr, pw := io.Pipe()
		buffered := a.body
		a.body = nil
		a.pipeWriter = pw
		a.phase = asmPassthrough

		msg := a.inflight.Message.(*envelope.HTTPMessage)
		// Attach the pipe reader, prefixed with the buffered bytes.
		msg.Body = nil
		msg.BodyStream = newPrefixedReader(buffered, pr)

		env := a.inflight
		// Snapshot raw at hand-off; subsequent frames append to a.rawAcc but
		// they are not retroactively visible to the consumer (acceptable —
		// passthrough is a degraded mode; consumers receive the streamed body
		// via BodyStream).
		env.Raw = a.rawAcc
		env.Opaque = &opaqueHTTP2{
			layer:       a.channel.layer,
			streamID:    a.streamID,
			frames:      a.frameBytes,
			origHeaders: cloneHeaderFields(a.origHeaders),
			origBody:    nil, // passthrough mode: body is streamed
			bodyReader:  msg.BodyStream,
			isPush:      a.channel.isPush,
		}
		a.rawAcc = nil
		a.frameBytes = nil
		a.inflight = nil

		if endStream {
			_ = a.pipeWriter.Close()
			a.pipeWriter = nil
			a.phase = asmDone
		}
		return env, true, nil
	}

	if endStream {
		if a.inflight == nil {
			return nil, false, fmt.Errorf("http2: stream %d end_stream without headers", a.streamID)
		}
		msg := a.inflight.Message.(*envelope.HTTPMessage)
		msg.Body = a.body
		a.body = nil
		env := a.inflight
		env.Raw = a.rawAcc
		env.Opaque = &opaqueHTTP2{
			layer:       a.channel.layer,
			streamID:    a.streamID,
			frames:      a.frameBytes,
			origHeaders: cloneHeaderFields(a.origHeaders),
			origBody:    cloneSlice(msg.Body),
			isPush:      a.channel.isPush,
		}
		a.rawAcc = nil
		a.frameBytes = nil
		a.inflight = nil
		a.phase = asmDone
		return env, true, nil
	}

	return nil, false, nil
}

// prefixedReader serves a buffered prefix followed by an io.Reader.
type prefixedReader struct {
	prefix []byte
	r      io.Reader
}

func newPrefixedReader(prefix []byte, r io.Reader) io.Reader {
	return &prefixedReader{prefix: prefix, r: r}
}

func (p *prefixedReader) Read(buf []byte) (int, error) {
	if len(p.prefix) > 0 {
		n := copy(buf, p.prefix)
		p.prefix = p.prefix[n:]
		return n, nil
	}
	return p.r.Read(buf)
}

// cloneSlice returns a copy of b, or nil if b is nil.
func cloneSlice(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// cloneHeaderFields returns a copy of the slice (HeaderField is a value type
// holding strings, so copy is shallow-but-safe).
func cloneHeaderFields(hf []hpack.HeaderField) []hpack.HeaderField {
	if hf == nil {
		return nil
	}
	out := make([]hpack.HeaderField, len(hf))
	copy(out, hf)
	return out
}
