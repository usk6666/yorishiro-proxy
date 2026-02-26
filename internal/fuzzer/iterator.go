package fuzzer

import "fmt"

// FuzzCase represents a single fuzz iteration with the payloads to inject.
type FuzzCase struct {
	// Index is the 0-based iteration number.
	Index int
	// Payloads maps position ID to the payload value for this iteration.
	Payloads map[string]string
}

// Iterator generates FuzzCase items for the configured attack type and payloads.
type Iterator interface {
	// Total returns the total number of iterations this iterator will produce.
	Total() int
	// Next returns the next FuzzCase or false if exhausted.
	Next() (FuzzCase, bool)
}

// NewIterator creates an Iterator for the given attack type, positions, and resolved payloads.
// resolvedPayloads maps payload set name to the list of generated payloads.
func NewIterator(attackType string, positions []Position, resolvedPayloads map[string][]string) (Iterator, error) {
	switch attackType {
	case "sequential":
		return newSequentialIterator(positions, resolvedPayloads)
	case "parallel":
		return newParallelIterator(positions, resolvedPayloads)
	default:
		return nil, fmt.Errorf("unsupported attack type %q: must be sequential or parallel", attackType)
	}
}

// sequentialIterator iterates through positions one by one, applying all payloads
// from its payload set to each position while keeping other positions at their original values.
type sequentialIterator struct {
	positions        []Position
	resolvedPayloads map[string][]string
	total            int
	posIdx           int
	payloadIdx       int
	index            int
}

func newSequentialIterator(positions []Position, resolvedPayloads map[string][]string) (*sequentialIterator, error) {
	total := 0
	for _, pos := range positions {
		if pos.effectiveMode() == "remove" {
			total++ // remove has exactly one iteration (no payloads)
			continue
		}
		payloads, ok := resolvedPayloads[pos.PayloadSet]
		if !ok {
			return nil, fmt.Errorf("payload set %q not found for position %q", pos.PayloadSet, pos.ID)
		}
		total += len(payloads)
	}
	return &sequentialIterator{
		positions:        positions,
		resolvedPayloads: resolvedPayloads,
		total:            total,
	}, nil
}

func (it *sequentialIterator) Total() int {
	return it.total
}

func (it *sequentialIterator) Next() (FuzzCase, bool) {
	for it.posIdx < len(it.positions) {
		pos := it.positions[it.posIdx]

		if pos.effectiveMode() == "remove" {
			fc := FuzzCase{
				Index:    it.index,
				Payloads: map[string]string{pos.ID: ""},
			}
			it.posIdx++
			it.payloadIdx = 0
			it.index++
			return fc, true
		}

		payloads := it.resolvedPayloads[pos.PayloadSet]
		if it.payloadIdx >= len(payloads) {
			it.posIdx++
			it.payloadIdx = 0
			continue
		}

		fc := FuzzCase{
			Index:    it.index,
			Payloads: map[string]string{pos.ID: payloads[it.payloadIdx]},
		}
		it.payloadIdx++
		it.index++
		return fc, true
	}
	return FuzzCase{}, false
}

// parallelIterator applies corresponding payloads from each position's payload set
// simultaneously (zip behavior). Stops when the shortest set is exhausted.
type parallelIterator struct {
	positions        []Position
	resolvedPayloads map[string][]string
	total            int
	index            int
}

func newParallelIterator(positions []Position, resolvedPayloads map[string][]string) (*parallelIterator, error) {
	if len(positions) == 0 {
		return &parallelIterator{total: 0}, nil
	}

	// Find the minimum payload set length (zip behavior).
	minLen := -1
	for _, pos := range positions {
		if pos.effectiveMode() == "remove" {
			// Remove positions participate in every iteration.
			continue
		}
		payloads, ok := resolvedPayloads[pos.PayloadSet]
		if !ok {
			return nil, fmt.Errorf("payload set %q not found for position %q", pos.PayloadSet, pos.ID)
		}
		if minLen < 0 || len(payloads) < minLen {
			minLen = len(payloads)
		}
	}

	// If all positions are remove, we have exactly 1 iteration.
	if minLen < 0 {
		minLen = 1
	}

	return &parallelIterator{
		positions:        positions,
		resolvedPayloads: resolvedPayloads,
		total:            minLen,
	}, nil
}

func (it *parallelIterator) Total() int {
	return it.total
}

func (it *parallelIterator) Next() (FuzzCase, bool) {
	if it.index >= it.total {
		return FuzzCase{}, false
	}

	payloads := make(map[string]string)
	for _, pos := range it.positions {
		if pos.effectiveMode() == "remove" {
			payloads[pos.ID] = ""
			continue
		}
		pSet := it.resolvedPayloads[pos.PayloadSet]
		payloads[pos.ID] = pSet[it.index]
	}

	fc := FuzzCase{
		Index:    it.index,
		Payloads: payloads,
	}
	it.index++
	return fc, true
}
