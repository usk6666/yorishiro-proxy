package grpc

import (
	"encoding/base64"
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/rules/common"
)

// USK-1203 (review S-1): a gRPC-Web body that fails to parse is emitted as a
// Start whose Envelope.Raw is the whole observed body, followed by a sentinel
// End — no GRPCDataMessage is ever emitted for it — and the upstream-side
// grpcweb Layer forwards that body verbatim. Without the check below, the
// payload / body targets of the Input SafetyFilter (destructive-sql,
// destructive-os-command, custom payload rules) would never see those bytes:
// a valid frame carrying `DROP TABLE users` plus one stray byte would reach
// the upstream unscanned.

// passthroughBodyForms returns the candidate forms of a gRPC-Web
// malformed-body Start's passthrough body for payload/body matching: the
// wire bytes verbatim and, for grpc-web-text content types, a lenient base64
// decode of them. Returns nil for every other envelope. Read-only — the
// returned strings are copies; env.Raw is never written.
func passthroughBodyForms(env *envelope.Envelope, msg envelope.Message) []string {
	if !envelope.IsGRPCWebPassthroughStart(env) {
		return nil
	}
	start, ok := msg.(*envelope.GRPCStartMessage)
	if !ok {
		return nil
	}
	forms := []string{string(env.Raw)}
	if isGRPCWebTextContentType(start.ContentType) {
		if decoded := lenientBase64Decode(env.Raw); len(decoded) > 0 {
			forms = append(forms, string(decoded))
		}
	}
	return forms
}

// checkPassthroughBody matches rule's payload / body targets against the
// passthrough body forms. Input Safety is deny-only, so matching any form
// fails closed.
func checkPassthroughBody(rule *common.CompiledRule, forms []string) *Violation {
	if len(forms) == 0 {
		return nil
	}
	for _, target := range rule.Targets {
		if target != TargetPayload && target != common.TargetBody {
			continue
		}
		for _, form := range forms {
			if v := matchRuleData(rule, form, "payload"); v != nil {
				return v
			}
		}
	}
	return nil
}

// isGRPCWebTextContentType mirrors layer/grpcweb.IsBase64Encoded (kept local
// so the rules engine does not import a Layer package).
func isGRPCWebTextContentType(ct string) bool {
	if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	mt := strings.TrimSpace(strings.ToLower(ct))
	return mt == "application/grpc-web-text" || strings.HasPrefix(mt, "application/grpc-web-text+")
}

// lenientBase64Decode decodes as much of b as possible: bytes outside the
// standard / URL-safe base64 alphabet are skipped, '=' padding ends a
// segment (gRPC-Web text bodies may be a concatenation of independently
// padded chunks), and a trailing partial quantum is decoded as far as it
// goes. Used only to widen what the deny-only safety check sees; the wire
// bytes are never replaced with this output.
func lenientBase64Decode(b []byte) []byte {
	var out, seg []byte
	flush := func() {
		if len(seg)%4 == 1 {
			seg = seg[:len(seg)-1] // a lone sextet carries no full byte
		}
		if len(seg) > 0 {
			buf := make([]byte, base64.RawStdEncoding.DecodedLen(len(seg)))
			n, _ := base64.RawStdEncoding.Decode(buf, seg)
			out = append(out, buf[:n]...)
		}
		seg = seg[:0]
	}
	for _, c := range b {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			seg = append(seg, c)
		case c == '-':
			seg = append(seg, '+')
		case c == '_':
			seg = append(seg, '/')
		case c == '=':
			flush()
		}
	}
	flush()
	return out
}
