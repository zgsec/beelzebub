package plugins

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// TestChainStore_GetOrCreate_SameKeyStablePointer verifies get() returns the
// same *chainSession for the same key within the TTL window, and that
// mutations made through one returned pointer are visible via the next
// get() for that key.
func TestChainStore_GetOrCreate_SameKeyStablePointer(t *testing.T) {
	s := newChainStore(time.Hour, 100)

	first := s.get("1.2.3.4")
	if first == nil {
		t.Fatalf("get returned nil")
	}
	if first.cacheIDs == nil {
		t.Fatalf("newChainSession did not initialize cacheIDs")
	}

	first.adminCreated = true
	first.username = "wp-fabricated-user"
	first.cacheIDs["deadbeef"] = 42

	second := s.get("1.2.3.4")
	if second != first {
		t.Fatalf("get returned a different pointer for the same key")
	}
	if !second.adminCreated {
		t.Errorf("mutation via first pointer not visible via second get()")
	}
	if second.username != "wp-fabricated-user" {
		t.Errorf("username mutation not visible: got %q", second.username)
	}
	if second.cacheIDs["deadbeef"] != 42 {
		t.Errorf("cacheIDs mutation not visible: got %v", second.cacheIDs)
	}
}

// TestChainStore_GetOrCreate_DifferentKeyDifferentSession verifies distinct
// source keys never share a session.
func TestChainStore_GetOrCreate_DifferentKeyDifferentSession(t *testing.T) {
	s := newChainStore(time.Hour, 100)

	a := s.get("10.0.0.1")
	b := s.get("10.0.0.2")

	if a == b {
		t.Fatalf("different keys returned the same *chainSession pointer")
	}

	a.seeded = true
	if b.seeded {
		t.Errorf("state leaked across keys: b.seeded should still be false")
	}
}

// TestChainStore_TTLEviction verifies that once the idle TTL elapses with no
// further activity on a key, the next get() for that key starts a fresh
// session rather than resurrecting stale checkpoint state.
func TestChainStore_TTLEviction(t *testing.T) {
	ttl := 30 * time.Millisecond
	s := newChainStore(ttl, 100)

	first := s.get("203.0.113.9")
	first.uploadOpen = true
	first.slug = "stale-slug"

	time.Sleep(ttl * 3)

	second := s.get("203.0.113.9")
	if second == first {
		t.Fatalf("expected a fresh *chainSession after TTL expiry, got the same pointer")
	}
	if second.uploadOpen {
		t.Errorf("expired session's uploadOpen leaked into fresh session")
	}
	if second.slug != "" {
		t.Errorf("expired session's slug leaked into fresh session: %q", second.slug)
	}
}

// TestChainStore_EntryCapBounded verifies inserting far more unique source
// keys than maxEntries does not grow the underlying map without bound — the
// whole point of reusing internal/cache's LRU+TTL primitive instead of a raw
// sync.Map.
func TestChainStore_EntryCapBounded(t *testing.T) {
	const cap_ = 50
	s := newChainStore(time.Hour, cap_)

	for i := 0; i < 5_000; i++ {
		sess := s.get(fmt.Sprintf("198.51.100.%d", i))
		sess.seeded = true
	}

	if got := s.m.Len(); got > cap_ {
		t.Errorf("chainStore grew to %d entries, want <= cap %d", got, cap_)
	}
}

// TestChainStore_ConcurrentGet_NoRace hammers get() from many goroutines
// across a small set of shared keys (simulating one attacker IP driving
// several concurrent connections into the same in-progress chain) plus a
// stream of unique keys, so both the get-or-create race and the LRU/TTL
// eviction bookkeeping are exercised under -race. Field mutations on a
// session obtained for a shared key are done under sess.mu, per
// chainSession's documented contract — chainStore.get() being race-free
// does not by itself make unsynchronized field writes on a session shared
// across goroutines safe.
func TestChainStore_ConcurrentGet_NoRace(t *testing.T) {
	s := newChainStore(200*time.Millisecond, 300)

	const goroutines = 32
	const iterations = 500

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				// Mix of contended shared keys and a rotating set of
				// per-goroutine keys, to exercise both the concurrent
				// get-or-create path on the same key and eviction under
				// churn.
				var key string
				if i%3 == 0 {
					key = fmt.Sprintf("shared-key-%d", i%5)
				} else {
					key = fmt.Sprintf("goroutine-%d-key-%d", id, i%20)
				}

				sess := s.get(key)
				sess.mu.Lock()
				sess.seeded = true
				sess.username = "u"
				sess.cacheIDs["x"] = int64(i)
				sess.mu.Unlock()
			}
		}(g)
	}
	wg.Wait()

	if got := s.m.Len(); got > 300 {
		t.Errorf("Len=%d exceeded cap=300 after concurrent churn", got)
	}
}
