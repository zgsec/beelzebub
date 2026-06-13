package OLLAMA

import (
	"testing"
	"time"
)

// Idle eviction must key on LastSeen, not FirstSeen — otherwise a session that
// has been continuously active for longer than the TTL gets wiped mid-stream,
// resetting its LLMjack counters and behavioral signals. A never-traced session
// (zero LastSeen) falls back to FirstSeen.
func TestOllamaStrategy_evictIdleSessionsUsesLastSeen(t *testing.T) {
	s := newTestStrategy()
	now := time.Now()

	// Active: created long ago but seen seconds ago → must survive.
	s.ipSessions["active"] = &OllamaSession{FirstSeen: now.Add(-3 * time.Hour), LastSeen: now.Add(-1 * time.Minute)}
	// Idle: last seen well past the TTL → evicted.
	s.ipSessions["idle"] = &OllamaSession{FirstSeen: now.Add(-3 * time.Hour), LastSeen: now.Add(-90 * time.Minute)}
	// New: never traced (zero LastSeen), created recently → survive via fallback.
	s.ipSessions["new"] = &OllamaSession{FirstSeen: now.Add(-1 * time.Minute)}

	s.evictIdleSessions(time.Hour, now)

	if _, ok := s.ipSessions["active"]; !ok {
		t.Error("active session (recent LastSeen) wrongly evicted")
	}
	if _, ok := s.ipSessions["idle"]; ok {
		t.Error("idle session not evicted")
	}
	if _, ok := s.ipSessions["new"]; !ok {
		t.Error("new session (zero LastSeen, recent FirstSeen) wrongly evicted")
	}
}
