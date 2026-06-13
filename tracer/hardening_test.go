package tracer

import (
	"sync"
	"testing"
)

// Worker goroutines must read the strategy under its mutex — SetStrategy can
// swap it concurrently. Under `go test -race` a raw field read in the worker
// loop trips the detector; this guards the fix. (Latent in prod, where the
// strategy is set once, but unsound.)
func TestTraceEvent_ConcurrentStrategySwapNoRace(t *testing.T) {
	tr := GetInstance(func(Event) {})
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			tr.SetStrategy(func(Event) {})
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			tr.TraceEvent(Event{ID: "x", SourceIp: "1.1.1.1"})
		}
	}()
	wg.Wait()
}
