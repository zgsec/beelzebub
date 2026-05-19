// Package cache provides bounded, thread-safe state holders for per-IP
// honeypot data.
//
// Why this exists: every honeypot protocol handler that tracks state
// keyed by remote IP is exposed to a trivial memory-exhaustion attack —
// rotate source IPs, watch the per-IP map grow without bound. The
// "newest credential first, plus a periodic Clean()" pattern works for
// time-based eviction but offers no defense against a burst of unique
// IPs all observed within the cleanup window.
//
// ttlmap.Map combines:
//
//  1. Per-entry TTL — entries older than maxAge are eligible for eviction
//     on the next Get/Set (opportunistic) or via Sweep() (predictable cadence).
//  2. Total-size cap — when the map is at maxEntries and a new key arrives,
//     the LRU entry is evicted to make room.
//
// Either bound alone is insufficient. TTL alone leaks under burst (N IPs
// arrive faster than maxAge); LRU alone leaks across long-lived sessions
// (slow drip of unique IPs eventually fills the cap). The combination is
// what makes the worst-case bounded.
//
// Pair Sweep() with a lifecycle ticker if your code path doesn't naturally
// touch every entry often enough for opportunistic eviction.
package cache

import (
	"container/list"
	"sync"
	"time"
)

// entry is a single map item plus its LRU back-pointer.
type entry[V any] struct {
	key       string
	value     V
	expiresAt time.Time
	elem      *list.Element // back-pointer into the LRU list (front = newest)
}

// Map is a bounded TTL+LRU map keyed by string (typically a remote IP).
// All exported methods are safe for concurrent use.
type Map[V any] struct {
	mu         sync.Mutex
	items      map[string]*entry[V]
	lru        *list.List // front = newest, back = oldest
	maxEntries int
	maxAge     time.Duration
	now        func() time.Time // injectable for tests
}

// New constructs a Map with the given cap and TTL. maxEntries must be > 0;
// maxAge must be > 0.
func New[V any](maxEntries int, maxAge time.Duration) *Map[V] {
	if maxEntries <= 0 {
		maxEntries = 1
	}
	if maxAge <= 0 {
		maxAge = time.Hour
	}
	return &Map[V]{
		items:      make(map[string]*entry[V], maxEntries),
		lru:        list.New(),
		maxEntries: maxEntries,
		maxAge:     maxAge,
		now:        time.Now,
	}
}

// Get returns (value, true) if key is present and not expired.
// On hit, the entry is moved to the front of the LRU list.
// On expiry, the entry is removed and (zero, false) is returned.
func (m *Map[V]) Get(key string) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var zero V
	e, ok := m.items[key]
	if !ok {
		return zero, false
	}
	if m.now().After(e.expiresAt) {
		m.removeEntry(e)
		return zero, false
	}
	m.lru.MoveToFront(e.elem)
	return e.value, true
}

// Set inserts or updates the key with a fresh expiration. If the map is
// at capacity and the key is new, the LRU entry is evicted first.
func (m *Map[V]) Set(key string, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLocked(key, value)
}

// SetIfAbsent atomically returns the existing value for key (if present
// and unexpired), or calls factory(), stores the result, and returns it.
// The factory runs at most once per key per entry-lifetime, even under
// concurrent calls — this is the primitive that lets per-IP rate
// limiters be created exactly once per IP.
func (m *Map[V]) SetIfAbsent(key string, factory func() V) V {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.items[key]; ok {
		if m.now().After(e.expiresAt) {
			m.removeEntry(e)
		} else {
			m.lru.MoveToFront(e.elem)
			return e.value
		}
	}
	v := factory()
	m.setLocked(key, v)
	return v
}

// setLocked is the shared insert/update/evict path. Caller holds m.mu.
func (m *Map[V]) setLocked(key string, value V) {
	if e, ok := m.items[key]; ok {
		e.value = value
		e.expiresAt = m.now().Add(m.maxAge)
		m.lru.MoveToFront(e.elem)
		return
	}
	// Evict LRU if at cap. Loop in case the back is already expired —
	// not strictly required for correctness (we'd still be at maxEntries
	// after one eviction) but avoids holding stale entries one cycle longer.
	for len(m.items) >= m.maxEntries {
		oldest := m.lru.Back()
		if oldest == nil {
			break
		}
		m.removeEntry(oldest.Value.(*entry[V]))
	}
	e := &entry[V]{
		key:       key,
		value:     value,
		expiresAt: m.now().Add(m.maxAge),
	}
	e.elem = m.lru.PushFront(e)
	m.items[key] = e
}

// Sweep removes every entry whose expiresAt has passed. Returns the count
// removed. Use this from a periodic ticker if predictable eviction
// cadence matters more than worst-case wakeup latency.
func (m *Map[V]) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := m.now()
	removed := 0
	// Walk from the back (oldest) forward. The LRU order is by recency of
	// access, not by expiry; an entry that was Get()'d recently moved to
	// the front but its expiresAt did not refresh. So we still need to
	// check every entry, but starting from the back lets us bail early
	// once we hit a non-expired entry only if expiry == access (which it
	// isn't in general). Walk all to be safe.
	for el := m.lru.Back(); el != nil; {
		next := el.Prev()
		e := el.Value.(*entry[V])
		if now.After(e.expiresAt) {
			m.removeEntry(e)
			removed++
		}
		el = next
	}
	return removed
}

// Delete removes key if present.
func (m *Map[V]) Delete(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e, ok := m.items[key]; ok {
		m.removeEntry(e)
	}
}

// Len returns the current entry count. Includes entries that may be
// expired but not yet evicted.
func (m *Map[V]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.items)
}

// removeEntry is the single chokepoint that keeps m.items and m.lru
// consistent. Caller holds m.mu.
func (m *Map[V]) removeEntry(e *entry[V]) {
	m.lru.Remove(e.elem)
	delete(m.items, e.key)
}
