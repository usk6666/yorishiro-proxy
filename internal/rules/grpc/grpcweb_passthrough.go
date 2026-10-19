package grpc

import (
	"encoding/base64"

	"github.com/usk6666/yorishiro-proxy/internal/config"
	"github.com/usk6666/yorishiro-proxy/internal/encoding/grpclpm"
	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1203 (review S-1 / S-4 / S-5): a gRPC-Web body that fails to parse is
// emitted as a Start whose Envelope.Raw is the whole observed body, followed
// by a sentinel End — no GRPCDataMessage is ever emitted for it — and the
// upstream-side grpcweb Layer forwards that body verbatim. Without the scan
// below, the payload / body targets of the Input SafetyFilter
// (destructive-sql, destructive-os-command, custom payload rules) would never
// see those bytes: a valid frame carrying `DROP TABLE users` plus one stray
// byte would reach the upstream unscanned.
//
// The scan is deny-only, so it widens rather than narrows: every plausible
// reading of the body is a candidate, and a rule matching any of them blocks.

// undecodableFrameMatch is the Violation.Match reported when a compressed
// frame in a passthrough body cannot be inflated (fail-closed).
const undecodableFrameMatch = "<compressed gRPC-Web frame could not be decompressed for inspection>"

// passthroughScan is the set of candidate forms of a gRPC-Web
// malformed-body Start's passthrough body.
type passthroughScan struct {
	forms []string
	// undecodable is true when at least one complete frame has its
	// compressed flag set but could not be inflated (unsupported
	// grpc-encoding, corrupt stream, or over the size cap). Those bytes are
	// forwarded upstream without having been inspected, so any loaded
	// payload / body rule fails closed on them (checkPassthroughBody).
	undecodable bool
}

// passthroughBodyForms returns the candidate forms of a gRPC-Web
// malformed-body Start's passthrough body for payload/body matching. Returns
// nil for every other envelope. Candidates, each tried by every
// payload/body rule:
//
//   - the wire bytes verbatim;
//   - whatever the Start's ContentType says (review S-3, below), two
//     lenient base64 decodes of them:
//     one restarting the 4-char quantum at every '=' (concatenated padded
//     chunks) and one ignoring every '=' (a decoder that skips stray
//     padding aligns the remaining characters differently, review S-5);
//   - from each binary form (wire bytes, or each decode), the payload of
//     every complete LPM frame found before the first incomplete header or
//     length (grpclpm.WalkCompleteFrames), so payload-anchored rules see the
//     same bytes as on the Data path (review F-4). A frame flagged
//     compressed is inflated with the grpc-encoding and algorithm set the
//     Layer's Data path uses (grpclpm.Decompress), bounded by
//     config.MaxGRPCMessageSize — the Layer default — so a gzip-compressed
//     destructive payload is seen too (review S-4).
//
// Read-only: env.Raw is never written.
func passthroughBodyForms(env *envelope.Envelope, msg envelope.Message) *passthroughScan {
	if !envelope.IsGRPCWebPassthroughStart(env) {
		return nil
	}
	start, ok := msg.(*envelope.GRPCStartMessage)
	if !ok {
		return nil
	}
	scan := &passthroughScan{}
	binaries := [][]byte{env.Raw}
	scan.forms = append(scan.forms, string(env.Raw))
	// The base64 readings are tried regardless of start.ContentType
	// (USK-1219 review S-3): ContentType is only the first observed
	// Content-Type entry, while duplicate entries are relayed verbatim
	// (MITM principle 1). A binary first value with a later -text value
	// and a base64 body fails LPM parsing and lands here, and a backend
	// that honours the last value decodes it — so the deny-only scan must
	// see the decoded form too. On a genuinely binary body the extra
	// candidates are only noise for the pattern match; that noise can yield
	// a blocking false positive on a malformed binary body when payload
	// rules are loaded, which is accepted (errs toward blocking; USK-1219
	// review S-R1-2).
	for _, decoded := range [][]byte{lenientBase64Decode(env.Raw), base64DecodeIgnoringPadding(env.Raw)} {
		if len(decoded) > 0 {
			binaries = append(binaries, decoded)
			scan.forms = append(scan.forms, string(decoded))
		}
	}
	for _, b := range binaries {
		for _, fr := range grpclpm.WalkCompleteFrames(b) {
			payload := fr.Payload
			if fr.Compressed() {
				inflated, err := grpclpm.Decompress(payload, start.Encoding, config.MaxGRPCMessageSize)
				if err != nil {
					scan.undecodable = true
					continue
				}
				payload = inflated
			}
			scan.forms = append(scan.forms, string(payload))
		}
	}
	return scan
}

// checkPassthroughBody matches rule's payload / body targets against the
// passthrough body forms. Input Safety is deny-only, so matching any form
// fails closed. When the body holds a compressed frame that could not be
// inflated, any payload / body-targeted rule reports a violation without a
// pattern match: those bytes would otherwise reach upstream uninspected.
func checkPassthroughBody(rule *common.CompiledRule, scan *passthroughScan) *Violation {
	if scan == nil {
		return nil
	}
	for _, target := range rule.Targets {
		if target != TargetPayload && target != common.TargetBody {
			continue
		}
		for _, form := range scan.forms {
			if v := matchRuleData(rule, form, "payload"); v != nil {
				return v
			}
		}
		if scan.undecodable {
			return &Violation{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Target:   "payload",
				Match:    undecodableFrameMatch,
			}
		}
	}
	return nil
}

// base64Sextet maps a standard or URL-safe base64 alphabet byte to its
// standard-alphabet form, reporting false for any other byte.
func base64Sextet(c byte) (byte, bool) {
	switch {
	case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
		return c, true
	case c == '-':
		return '+', true
	case c == '_':
		return '/', true
	default:
		return 0, false
	}
}

// decodeRawSegment decodes an unpadded run of standard-alphabet base64
// characters as far as it goes (a trailing lone sextet carries no full byte).
func decodeRawSegment(seg []byte) []byte {
	if len(seg)%4 == 1 {
		seg = seg[:len(seg)-1]
	}
	if len(seg) == 0 {
		return nil
	}
	buf := make([]byte, base64.RawStdEncoding.DecodedLen(len(seg)))
	n, _ := base64.RawStdEncoding.Decode(buf, seg)
	return buf[:n]
}

// lenientBase64Decode decodes as much of b as possible: bytes outside the
// standard / URL-safe base64 alphabet are skipped, '=' padding ends a
// segment (gRPC-Web text bodies may be a concatenation of independently
// padded chunks), and a trailing partial quantum is decoded as far as it
// goes. Used only to widen what the deny-only safety check sees; the wire
// bytes are never replaced with this output.
func lenientBase64Decode(b []byte) []byte {
	var out, seg []byte
	for _, c := range b {
		if s, ok := base64Sextet(c); ok {
			seg = append(seg, s)
		} else if c == '=' {
			out = append(out, decodeRawSegment(seg)...)
			seg = seg[:0]
		}
	}
	return append(out, decodeRawSegment(seg)...)
}

// base64DecodeIgnoringPadding decodes every base64 alphabet character of b as
// one string, ignoring '=' and every other non-alphabet byte. This is the
// alignment a decoder that skips stray padding would see, which differs from
// lenientBase64Decode's restart-at-'=' reading whenever '=' appears
// mid-body (review S-5).
func base64DecodeIgnoringPadding(b []byte) []byte {
	var seg []byte
	for _, c := range b {
		if s, ok := base64Sextet(c); ok {
			seg = append(seg, s)
		}
	}
	return decodeRawSegment(seg)
}
