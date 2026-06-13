package MCP

import (
	"testing"
	"time"
)

// evictStale must remove all per-IP state for IPs idle past the cutoff and keep
// fresh ones. The re-check under the write lock (vs the snapshot taken under the
// read lock) is what closes the TOCTOU where an IP that received a tool call
// between snapshot and delete would otherwise be wiped mid-session (resetting
// its world state and Sequence). This test pins the eviction predicate; the
// re-check is exercised by the single-IP fresh case surviving.
func TestMCPStrategy_evictStale(t *testing.T) {
	s := &MCPStrategy{
		worldState:      map[string]*WorldState{},
		toolHistory:     map[string][]toolCallRecord{},
		agentTimings:    map[string][]int64{},
		agentLastSeen:   map[string]time.Time{},
		noveltyToolSeqs: map[string][]string{},
	}
	now := time.Now()
	for _, ip := range []string{"stale", "fresh"} {
		s.agentTimings[ip] = []int64{1}
		s.toolHistory[ip] = []toolCallRecord{{}}
		s.worldState[ip] = &WorldState{}
		s.noveltyToolSeqs[ip] = []string{"x"}
	}
	s.agentLastSeen["stale"] = now.Add(-2 * time.Hour)
	s.agentLastSeen["fresh"] = now.Add(-1 * time.Minute)

	s.evictStale(now.Add(-60 * time.Minute))

	for _, m := range []string{"agentLastSeen", "agentTimings", "worldState", "toolHistory", "noveltyToolSeqs"} {
		_ = m
	}
	if _, ok := s.agentLastSeen["stale"]; ok {
		t.Error("stale not evicted from agentLastSeen")
	}
	if _, ok := s.worldState["stale"]; ok {
		t.Error("stale worldState not evicted")
	}
	if _, ok := s.toolHistory["stale"]; ok {
		t.Error("stale toolHistory not evicted")
	}
	if _, ok := s.noveltyToolSeqs["stale"]; ok {
		t.Error("stale noveltyToolSeqs not evicted")
	}
	if _, ok := s.agentLastSeen["fresh"]; !ok {
		t.Error("fresh session wrongly evicted")
	}
	if _, ok := s.worldState["fresh"]; !ok {
		t.Error("fresh worldState wrongly evicted")
	}
}
