package tracer

import (
	"sync"
	"time"
)

// TimingCache tracks the last event time per session key for inter-event timing.
type TimingCache struct {
	mu        sync.RWMutex
	lastEvent map[string]time.Time
}

// NewTimingCache returns an initialized TimingCache.
func NewTimingCache() *TimingCache {
	return &TimingCache{
		lastEvent: make(map[string]time.Time),
	}
}

// RecordAndDelta records the current time for a session key and returns
// the milliseconds since the last event for this key. Returns 0 on first call.
func (tc *TimingCache) RecordAndDelta(sessionKey string) int64 {
	now := time.Now()
	tc.mu.Lock()
	defer tc.mu.Unlock()

	last, ok := tc.lastEvent[sessionKey]
	tc.lastEvent[sessionKey] = now

	if !ok {
		return 0
	}
	return now.Sub(last).Milliseconds()
}

// Clean removes entries older than maxAge.
func (tc *TimingCache) Clean(maxAge time.Duration) {
	now := time.Now()
	tc.mu.Lock()
	defer tc.mu.Unlock()
	for k, v := range tc.lastEvent {
		if now.Sub(v) > maxAge {
			delete(tc.lastEvent, k)
		}
	}
}
