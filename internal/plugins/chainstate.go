package plugins

import (
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/cache"
)

// ChainSession holds the small cross-request state the WP gadget chain
// threads through a single attack attempt: which checkpoints have been
// reached so far, the forged identifiers minted along the way, and the
// cache IDs assigned to fabricated objects the chain needs to reference
// consistently across requests.
//
// A single source key (e.g. one attacker IP) can legitimately drive more
// than one concurrent connection into the same in-progress chain — mu
// guards every field below against that. Callers MUST touch session fields
// — reads as well as writes — only inside sess.mutate(...), never by
// locking/unlocking mu by hand or by reading a field with no lock held at
// all: cacheIDs is a plain Go map, and an unsynchronized concurrent access
// to it (even a read racing a write) is a fatal Go runtime panic, not
// merely a data race. mutate is the one sanctioned accessor; it holds mu
// for the whole callback, so a read-modify-write (e.g. "if !adminCreated {
// adminCreated = true; ... }") is automatically atomic.
type ChainSession struct {
	mu sync.Mutex

	seeded       bool
	adminCreated bool
	uploadOpen   bool

	username string
	nonce    string
	slug     string

	// cacheIDs maps a digest of a fabricated object (e.g. its md5) to the
	// fabricated cache id assigned to it, so the same object resolves to
	// the same id across requests within the session. A plain Go map, so
	// concurrent writes without mu held would be a fatal runtime error,
	// not just a data race.
	cacheIDs map[string]int64
}

// newChainSession returns a zero-value chain session with its map field
// initialized, so callers never have to nil-check cacheIDs before writing
// to it.
func newChainSession() *ChainSession {
	return &ChainSession{
		cacheIDs: make(map[string]int64),
	}
}

// mutate is the sanctioned way to read and/or modify a ChainSession's
// fields from request handlers: it locks mu, invokes fn with the session,
// and unlocks — including on panic, via defer. Callers must not read or
// write any field of s (including cacheIDs) outside of a mutate call;
// cacheIDs is a plain map, so an unsynchronized concurrent access to it is
// a fatal runtime panic, not just a race. Prefer one mutate call per
// logical operation over several smaller ones, so a read-modify-write
// stays atomic across the whole handler step.
func (s *ChainSession) mutate(fn func(*ChainSession)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s)
}

// ChainStore is a bounded, TTL-evicted map of *ChainSession keyed by a
// per-source key (typically the remote IP, optionally salted by a session
// nonce for callers that need finer-grained isolation). It reuses the same
// LRU+TTL primitive the LLM honeypot's per-IP rate limiter is built on
// (internal/cache.Map — see llm-integration.go's getRateLimiter), so a
// flood of unique source keys evicts old idle sessions instead of growing
// memory without bound.
type ChainStore struct {
	m *cache.Map[*ChainSession]
}

// NewChainStore constructs a ChainStore with the given idle TTL and entry
// cap. ttl <= 0 or maxEntries <= 0 fall back to internal/cache.New's own
// defaults (1 hour / 1 entry).
func NewChainStore(ttl time.Duration, maxEntries int) *ChainStore {
	return &ChainStore{m: cache.New[*ChainSession](maxEntries, ttl)}
}

// Get returns the ChainSession for srcKey, creating one on first sight.
// The returned pointer is stable for the lifetime of the entry: callers
// touch fields only through sess.mutate(...) (both reads and writes — see
// ChainSession's doc comment; cacheIDs is a plain map, and an
// unsynchronized concurrent access to it is a fatal panic, not just a
// race), and a later Get() for the same key (within the TTL window)
// observes those mutations rather than a fresh session. Each call
// refreshes the entry's TTL and LRU recency (idle timeout, not
// fixed-since-creation), matching the "still-in-progress attempt" shape
// the gadget chain needs. Get() itself is safe for concurrent use.
func (s *ChainStore) Get(srcKey string) *ChainSession {
	if existing, ok := s.m.Get(srcKey); ok {
		// Re-Set to slide the TTL window forward on activity. Same
		// pointer is stored back, so no in-flight checkpoint state is
		// lost or duplicated.
		s.m.Set(srcKey, existing)
		return existing
	}
	return s.m.SetIfAbsent(srcKey, newChainSession)
}
