package hpack

// HeaderField represents a single header name-value pair.
type HeaderField struct {
	Name  string
	Value string

	// Sensitive indicates the field must never be indexed (Section 6.2.3).
	Sensitive bool
}

// Size returns the size of the header field as defined in RFC 7541 Section 4.1:
// the sum of the length of the name, the length of the value, and 32.
func (hf HeaderField) Size() uint32 {
	return uint32(len(hf.Name)) + uint32(len(hf.Value)) + 32
}

// staticTable is the pre-defined static table (Appendix A, 61 entries).
// Index 0 is unused; indices are 1-based.
var staticTable = [62]HeaderField{
	{}, // index 0: unused
	{Name: ":authority"},
	{Name: ":method", Value: "GET"},
	{Name: ":method", Value: "POST"},
	{Name: ":path", Value: "/"},
	{Name: ":path", Value: "/index.html"},
	{Name: ":scheme", Value: "http"},
	{Name: ":scheme", Value: "https"},
	{Name: ":status", Value: "200"},
	{Name: ":status", Value: "204"},
	{Name: ":status", Value: "206"},
	{Name: ":status", Value: "304"},
	{Name: ":status", Value: "400"},
	{Name: ":status", Value: "404"},
	{Name: ":status", Value: "500"},
	{Name: "accept-charset"},
	{Name: "accept-encoding", Value: "gzip, deflate"},
	{Name: "accept-language"},
	{Name: "accept-ranges"},
	{Name: "accept"},
	{Name: "access-control-allow-origin"},
	{Name: "age"},
	{Name: "allow"},
	{Name: "authorization"},
	{Name: "cache-control"},
	{Name: "content-disposition"},
	{Name: "content-encoding"},
	{Name: "content-language"},
	{Name: "content-length"},
	{Name: "content-location"},
	{Name: "content-range"},
	{Name: "content-type"},
	{Name: "cookie"},
	{Name: "date"},
	{Name: "etag"},
	{Name: "expect"},
	{Name: "expires"},
	{Name: "from"},
	{Name: "host"},
	{Name: "if-match"},
	{Name: "if-modified-since"},
	{Name: "if-none-match"},
	{Name: "if-range"},
	{Name: "if-unmodified-since"},
	{Name: "last-modified"},
	{Name: "link"},
	{Name: "location"},
	{Name: "max-forwards"},
	{Name: "proxy-authenticate"},
	{Name: "proxy-authorization"},
	{Name: "range"},
	{Name: "referer"},
	{Name: "refresh"},
	{Name: "retry-after"},
	{Name: "server"},
	{Name: "set-cookie"},
	{Name: "strict-transport-security"},
	{Name: "transfer-encoding"},
	{Name: "user-agent"},
	{Name: "vary"},
	{Name: "via"},
	{Name: "www-authenticate"},
}

// staticTableLen is the number of entries in the static table (61).
const staticTableLen = 61

// staticIndex maps header name (and optionally name+value) to a static table index.
// Built once at init time for O(1) lookups.
var staticIndex map[string]uint64
var staticIndexNameValue map[string]uint64

func init() {
	staticIndex = make(map[string]uint64, staticTableLen)
	staticIndexNameValue = make(map[string]uint64, staticTableLen)
	for i := uint64(1); i <= staticTableLen; i++ {
		hf := staticTable[i]
		// Only store the first occurrence of each name.
		if _, ok := staticIndex[hf.Name]; !ok {
			staticIndex[hf.Name] = i
		}
		if hf.Value != "" {
			staticIndexNameValue[hf.Name+"\x00"+hf.Value] = i
		}
	}
}

// searchStaticTable looks up a header field in the static table.
// It returns the index and whether both name and value matched.
// If only the name matches, nameOnly is true and i is the name-only index.
// Returns 0, false if no match is found.
func searchStaticTable(name, value string) (i uint64, nameOnly bool) {
	if idx, ok := staticIndexNameValue[name+"\x00"+value]; ok {
		return idx, false
	}
	if idx, ok := staticIndex[name]; ok {
		return idx, true
	}
	return 0, false
}
