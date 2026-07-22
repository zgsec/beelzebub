package plugins

import (
	"sync"
	"time"

	"github.com/beelzebub-labs/beelzebub/v3/internal/cache"
)

const (
	// chainStoreMaxEntries caps the checkpoint store. An attacker rotating
	// source IPs across attempts would otherwise grow this map without
	// bound — every new key allocates a *chainSession that lives forever.
	// Mirrors the sizing rationale used for the LLM honeypot's per-IP rate
	// limiter (see llm-integration.go's rateLimiterMaxEntries).
	chainStoreMaxEntries = 10_000

	// chainStoreDefaultTTL is the idle timeout for an in-progress chain
	// attempt: how long a checkpoint session survives with no further
	// activity from its source key before the next get() starts fresh.
	chainStoreDefaultTTL = 30 * time.Minute
)

// chainSession holds the small cross-request state the WP gadget chain
// threads through a single attack attempt: which checkpoints have been
// reached so far, the forged identifiers minted along the way, and the
// cache IDs assigned to fabricated objects the chain needs to reference
// consistently across requests.
//
// A single source key (e.g. one attacker IP) can legitimately drive more
// than one concurrent connection into the same in-progress chain — mu
// guards every field below against that. Callers that read or mutate more
// than one field, or that need a read-modify-write (e.g. "if !adminCreated
// { adminCreated = true; ... }"), must hold mu for the whole operation;
// chainSession does not attempt to make individual field accesses
// implicitly safe on their own.
type chainSession struct {
	mu sync.Mutex

	seeded       bool
	adminCreated bool
	authOpen     bool
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
func newChainSession() *chainSession {
	return &chainSession{
		cacheIDs: make(map[string]int64),
	}
}

// chainStore is a bounded, TTL-evicted map of *chainSession keyed by a
// per-source key (typically the remote IP, optionally salted by a session
// nonce for callers that need finer-grained isolation). It reuses the same
// LRU+TTL primitive the LLM honeypot's per-IP rate limiter is built on
// (internal/cache.Map — see llm-integration.go's getRateLimiter), so a
// flood of unique source keys evicts old idle sessions instead of growing
// memory without bound.
type chainStore struct {
	m *cache.Map[*chainSession]
}

// newChainStore constructs a chainStore with the given idle TTL and entry
// cap. ttl <= 0 or maxEntries <= 0 fall back to internal/cache.New's own
// defaults (1 hour / 1 entry).
func newChainStore(ttl time.Duration, maxEntries int) *chainStore {
	return &chainStore{m: cache.New[*chainSession](maxEntries, ttl)}
}

// get returns the chainSession for srcKey, creating one on first sight.
// The returned pointer is stable for the lifetime of the entry: callers
// mutate the fields directly, and a later get() for the same key (within
// the TTL window) observes those mutations rather than a fresh session.
// Each call refreshes the entry's TTL and LRU recency (idle timeout, not
// fixed-since-creation), matching the "still-in-progress attempt" shape
// the gadget chain needs. Safe for concurrent use.
func (s *chainStore) get(srcKey string) *chainSession {
	if existing, ok := s.m.Get(srcKey); ok {
		// Re-Set to slide the TTL window forward on activity. Same
		// pointer is stored back, so no in-flight checkpoint state is
		// lost or duplicated.
		s.m.Set(srcKey, existing)
		return existing
	}
	return s.m.SetIfAbsent(srcKey, newChainSession)
}
