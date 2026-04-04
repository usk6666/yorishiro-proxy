package exchange

import "strings"

// headerValues returns the values of all entries in headers whose name
// matches the given name case-insensitively. Returns nil if none found.
func headerValues(headers []KeyValue, name string) []string {
	var vals []string
	for _, h := range headers {
		if strings.EqualFold(h.Name, name) {
			vals = append(vals, h.Value)
		}
	}
	return vals
}
