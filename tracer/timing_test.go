package tracer

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimingCacheFirstCallReturnsZero(t *testing.T) {
	tc := NewTimingCache()
	delta := tc.RecordAndDelta("session1")
	assert.Equal(t, int64(0), delta)
}

func TestTimingCacheSubsequentCallReturnsDelta(t *testing.T) {
	tc := NewTimingCache()
	tc.RecordAndDelta("session1")
	time.Sleep(50 * time.Millisecond)
	delta := tc.RecordAndDelta("session1")
	assert.GreaterOrEqual(t, delta, int64(40))
	assert.LessOrEqual(t, delta, int64(200))
}

func TestTimingCacheIsolatesSessions(t *testing.T) {
	tc := NewTimingCache()
	tc.RecordAndDelta("a")
	time.Sleep(50 * time.Millisecond)
	// New session "b" should return 0
	delta := tc.RecordAndDelta("b")
	assert.Equal(t, int64(0), delta)
}

func TestTimingCacheClean(t *testing.T) {
	tc := NewTimingCache()
	tc.RecordAndDelta("old")
	// Manually backdate
	tc.mu.Lock()
	tc.lastEvent["old"] = time.Now().Add(-2 * time.Hour)
	tc.mu.Unlock()

	tc.RecordAndDelta("recent")

	tc.Clean(1 * time.Hour)

	tc.mu.RLock()
	_, hasOld := tc.lastEvent["old"]
	_, hasRecent := tc.lastEvent["recent"]
	tc.mu.RUnlock()

	assert.False(t, hasOld)
	assert.True(t, hasRecent)
}
