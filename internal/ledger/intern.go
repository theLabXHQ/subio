package ledger

import "sync"

// interner maps a small, repeating set of strings — source ids, evidence
// families, methods, authorization roots — to byte indices.
type interner struct {
	mu    sync.RWMutex
	index map[string]uint8
	list  []string
}

func newInterner() *interner {
	return &interner{index: make(map[string]uint8, 16)}
}

// id returns the index for s, adding it if new.
func (t *interner) id(s string) uint8 {
	if s == "" {
		return 0
	}
	t.mu.RLock()
	if i, ok := t.index[s]; ok {
		t.mu.RUnlock()
		return i
	}
	t.mu.RUnlock()

	t.mu.Lock()
	defer t.mu.Unlock()
	if i, ok := t.index[s]; ok {
		return i
	}
	if len(t.list) == 0 {
		t.list = append(t.list, "")
	}
	if len(t.list) >= 255 {

		return 0
	}
	i := uint8(len(t.list))
	t.list = append(t.list, s)
	t.index[s] = i
	return i
}

// name resolves an index back to its string.
func (t *interner) name(i uint8) string {
	if i == 0 {
		return ""
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	if int(i) >= len(t.list) {
		return ""
	}
	return t.list[i]
}

// bit returns the single-bit mask for s, or 0 when the table is full.
func (t *interner) bit(s string) uint64 {
	i := t.id(s)
	if i == 0 || i > 64 {
		return 0
	}
	return 1 << (i - 1)
}

// names expands a bitmask into the strings it represents, in table order.
func (t *interner) names(mask uint64) []string {
	if mask == 0 {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	var out []string
	for i := 1; i < len(t.list) && i <= 64; i++ {
		if mask&(1<<(i-1)) != 0 {
			out = append(out, t.list[i])
		}
	}
	return out
}
