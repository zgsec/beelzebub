package tracer

import (
	"sync"
	"testing"
	"time"
)

// TraceEvent auto-populates ActorID from the registered resolver (the bridge's
// cross-protocol actor-episode key), mirroring how CorrelationID is filled. A
// pre-set ActorID is preserved; a nil resolver leaves it empty.
func TestTraceEvent_PopulatesActorIDFromResolver(t *testing.T) {
	SetActorResolver(func(ip string, _ time.Time) string { return "actor:" + ip })
	t.Cleanup(func() { SetActorResolver(nil) })

	var wg sync.WaitGroup
	captured := Event{}
	strategy := func(e Event) { captured = e; wg.Done() }
	tr := GetInstance(strategy)
	tr.strategy = strategy

	wg.Add(1)
	tr.TraceEvent(Event{ID: "a", Protocol: HTTP.String(), SourceIp: "9.9.9.9"})
	wg.Wait()
	if captured.ActorID != "actor:9.9.9.9" {
		t.Errorf("ActorID not populated by resolver: %q", captured.ActorID)
	}

	// Pre-set ActorID must be preserved (resolver does not override).
	wg.Add(1)
	tr.TraceEvent(Event{ID: "b", Protocol: HTTP.String(), SourceIp: "9.9.9.9", ActorID: "preset"})
	wg.Wait()
	if captured.ActorID != "preset" {
		t.Errorf("pre-set ActorID should be preserved, got %q", captured.ActorID)
	}
}
