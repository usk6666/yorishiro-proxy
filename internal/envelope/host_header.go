package envelope

import "strings"

// HostHeaderValues returns the value of every header in headers whose name
// is "host", in wire order, duplicates included, each with surrounding
// SP / HTAB trimmed. It returns nil when there is none.
//
// The name test is strings.EqualFold (Unicode simple case folding, so it
// is a superset of an ASCII case-insensitive match: "hoſt" with U+017F
// also counts) after trimming trailing SP / HTAB from the name. The
// HTTP/1 parser keeps "Host : v" as the name "Host " (flagged as an
// anomaly, forwarded verbatim), and lenient upstreams strip that
// whitespace and route on the value, so it must be judged as Host. The
// trim is for the comparison only; the stored name is not touched.
//
// It is a read-only view for policy checks (TargetScope, USK-1167): the
// HTTP/1 serializer writes the Host line from the header list, not from
// HTTPMessage.Authority, and HTTP/2 forwards a regular "host" header next
// to :authority, so every value a server may route on must be judged.
// headers is never modified and nothing is deduplicated or merged (MITM
// Principle 1). Values are not split on commas: Host is a single
// uri-host [":" port] (RFC 9110 §7.2), not a list, so a comma-bearing
// value is judged whole. The trim only matters for values written by an
// agent (intercept, resend, fuzz, Transform) — the HTTP/1 parser already
// strips OWS from wire values.
func HostHeaderValues(headers []KeyValue) []string {
	var out []string
	for _, kv := range headers {
		if strings.EqualFold(strings.TrimRight(kv.Name, " \t"), "host") {
			out = append(out, strings.Trim(kv.Value, " \t"))
		}
	}
	return out
}
