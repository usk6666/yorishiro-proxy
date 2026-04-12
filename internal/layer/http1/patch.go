package http1

import (
	"strings"

	"github.com/usk6666/yorishiro-proxy/internal/envelope"
	"github.com/usk6666/yorishiro-proxy/internal/layer/http1/parser"
)

// applyHeaderPatch applies a minimal diff from origKV to newKV onto rawHeaders,
// preserving OWS (Optional WhiteSpace) for unmodified headers.
//
// Algorithm:
//  1. Walk newKV entries in order.
//  2. For each entry, find a matching RawHeader by index position first (same
//     index, same name = reuse). If name differs, search by name among unused
//     raw headers.
//  3. If value matches, reuse the RawHeader (preserving RawValue = OWS).
//  4. If value changed, update Value and clear RawValue.
//  5. Any origKV entries not consumed are deletions.
//  6. Any newKV entries not matched produce new RawHeaders.
func applyHeaderPatch(origKV, newKV []envelope.KeyValue, raw parser.RawHeaders) parser.RawHeaders {
	used := make([]bool, len(raw))
	result := make(parser.RawHeaders, 0, len(newKV))

	for i, nkv := range newKV {
		// Try index-based match first.
		if i < len(origKV) && i < len(raw) && !used[i] &&
			origKV[i].Name == nkv.Name && raw[i].Name == nkv.Name {
			used[i] = true
			h := raw[i]
			if nkv.Value != h.Value {
				h.Value = nkv.Value
				h.RawValue = ""
			}
			result = append(result, h)
			continue
		}

		// Search by name among unused raw headers.
		found := false
		for j := range raw {
			if !used[j] && strings.EqualFold(raw[j].Name, nkv.Name) {
				used[j] = true
				h := raw[j]
				if nkv.Value != h.Value {
					h.Value = nkv.Value
					h.RawValue = ""
				}
				result = append(result, h)
				found = true
				break
			}
		}
		if !found {
			// New header not in original.
			result = append(result, parser.RawHeader{
				Name:  nkv.Name,
				Value: nkv.Value,
			})
		}
	}

	return result
}
