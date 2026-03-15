package hpack

// DynamicTable implements the HPACK dynamic table (RFC 7541 Section 2.3.2).
// Entries are added to the front (index 0) and evicted from the back when
// the table exceeds its maximum size.
type DynamicTable struct {
	entries  []HeaderField
	size     uint32 // current size in octets
	maxSize  uint32 // maximum allowed size
	inserted uint64 // total number of entries ever inserted (for absolute indexing)
}

// NewDynamicTable creates a dynamic table with the given maximum size.
func NewDynamicTable(maxSize uint32) *DynamicTable {
	return &DynamicTable{
		maxSize: maxSize,
	}
}

// MaxSize returns the current maximum table size.
func (dt *DynamicTable) MaxSize() uint32 {
	return dt.maxSize
}

// SetMaxSize updates the maximum table size and evicts entries as needed.
func (dt *DynamicTable) SetMaxSize(maxSize uint32) {
	dt.maxSize = maxSize
	dt.evict()
}

// Len returns the number of entries in the dynamic table.
func (dt *DynamicTable) Len() int {
	return len(dt.entries)
}

// Add inserts a header field at the beginning of the dynamic table.
// It evicts entries from the end if the table would exceed maxSize.
// Per RFC 7541 Section 4.4, if the new entry is too large to fit even in
// an empty table, the table is emptied and the entry is not added.
func (dt *DynamicTable) Add(hf HeaderField) {
	s := hf.Size()
	if s > dt.maxSize {
		dt.entries = dt.entries[:0]
		dt.size = 0
		dt.inserted++
		return
	}
	// Evict until there is room.
	for dt.size+s > dt.maxSize && len(dt.entries) > 0 {
		last := dt.entries[len(dt.entries)-1]
		dt.entries = dt.entries[:len(dt.entries)-1]
		dt.size -= last.Size()
	}
	dt.entries = append(dt.entries, HeaderField{})
	copy(dt.entries[1:], dt.entries[:len(dt.entries)-1])
	// Sensitive is intentionally not stored in the dynamic table.
	// The dynamic table is shared state; sensitivity is a per-encoding
	// property, not a property of the table entry (RFC 7541 Section 7.1.3).
	dt.entries[0] = HeaderField{Name: hf.Name, Value: hf.Value}
	dt.size += s
	dt.inserted++
}

// Entry returns the entry at the given 0-based index.
// Returns false if the index is out of range.
func (dt *DynamicTable) Entry(index int) (HeaderField, bool) {
	if index < 0 || index >= len(dt.entries) {
		return HeaderField{}, false
	}
	return dt.entries[index], true
}

// Search looks for a header field in the dynamic table.
// Returns the 0-based index and whether both name and value matched.
// If only the name matches, nameOnly is true.
// Returns -1 if no match is found.
func (dt *DynamicTable) Search(name, value string) (index int, nameOnly bool) {
	nameIdx := -1
	for i, hf := range dt.entries {
		if hf.Name == name {
			if hf.Value == value {
				return i, false
			}
			if nameIdx == -1 {
				nameIdx = i
			}
		}
	}
	if nameIdx >= 0 {
		return nameIdx, true
	}
	return -1, false
}

// evict removes entries from the end until size <= maxSize.
func (dt *DynamicTable) evict() {
	for dt.size > dt.maxSize && len(dt.entries) > 0 {
		last := dt.entries[len(dt.entries)-1]
		dt.entries = dt.entries[:len(dt.entries)-1]
		dt.size -= last.Size()
	}
	if len(dt.entries) == 0 {
		dt.size = 0
	}
}
