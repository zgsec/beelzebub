package cache

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestSet_BumpsLRU(t *testing.T) {
	m := New[int](3, time.Hour)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3)

	// Touch "a" — it should move to front so "b" becomes LRU.
	if _, ok := m.Get("a"); !ok {
		t.Fatalf("Get(a) miss")
	}

	// Insert one more; LRU ("b") should be evicted, not "a".
	m.Set("d", 4)
	if _, ok := m.Get("b"); ok {
		t.Errorf("expected b to be evicted as LRU, still present")
	}
	if _, ok := m.Get("a"); !ok {
		t.Errorf("expected a to survive (recently Got)")
	}
	if _, ok := m.Get("c"); !ok {
		t.Errorf("expected c to survive")
	}
	if _, ok := m.Get("d"); !ok {
		t.Errorf("expected d to be present (just inserted)")
	}
}

func TestGet_ExpiresOldEntries(t *testing.T) {
	m := New[string](10, 50*time.Millisecond)
	m.Set("k", "v")

	if v, ok := m.Get("k"); !ok || v != "v" {
		t.Fatalf("immediate Get failed: %v %v", v, ok)
	}

	time.Sleep(80 * time.Millisecond)

	if _, ok := m.Get("k"); ok {
		t.Errorf("expected k to be expired and evicted on Get")
	}
	if got := m.Len(); got != 0 {
		t.Errorf("expected len 0 after expiry-on-get, got %d", got)
	}
}

func TestSet_EvictsLRUWhenAtCap(t *testing.T) {
	m := New[int](2, time.Hour)
	m.Set("a", 1)
	m.Set("b", 2)
	m.Set("c", 3) // should evict "a"

	if _, ok := m.Get("a"); ok {
		t.Errorf("expected a to be evicted")
	}
	if _, ok := m.Get("b"); !ok {
		t.Errorf("expected b to remain")
	}
	if _, ok := m.Get("c"); !ok {
		t.Errorf("expected c to remain")
	}
	if got := m.Len(); got != 2 {
		t.Errorf("expected len 2, got %d", got)
	}
}

func TestSetIfAbsent_OnceOnly(t *testing.T) {
	m := New[int](10, time.Hour)

	var calls int32
	factory := func() int {
		atomic.AddInt32(&calls, 1)
		return 42
	}

	// Concurrent contention on the same key — factory must only fire once.
	const N = 200
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func() {
			defer wg.Done()
			v := m.SetIfAbsent("k", factory)
			if v != 42 {
				t.Errorf("SetIfAbsent returned %d, want 42", v)
			}
		}()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Errorf("factory called %d times, want 1", got)
	}
}

func TestSetIfAbsent_RebuildsOnExpiry(t *testing.T) {
	m := New[int](10, 30*time.Millisecond)

	var calls int32
	factory := func() int {
		return int(atomic.AddInt32(&calls, 1))
	}

	if v := m.SetIfAbsent("k", factory); v != 1 {
		t.Fatalf("first call returned %d, want 1", v)
	}
	time.Sleep(60 * time.Millisecond)
	if v := m.SetIfAbsent("k", factory); v != 2 {
		t.Errorf("after expiry returned %d, want 2 (factory should re-run)", v)
	}
}

func TestSweep_ReturnsRemovedCount(t *testing.T) {
	m := New[int](100, 30*time.Millisecond)
	for i := 0; i < 10; i++ {
		m.Set(fmt.Sprintf("old-%d", i), i)
	}
	time.Sleep(50 * time.Millisecond)
	for i := 0; i < 5; i++ {
		m.Set(fmt.Sprintf("new-%d", i), i)
	}

	removed := m.Sweep()
	if removed != 10 {
		t.Errorf("Sweep returned %d, want 10", removed)
	}
	if got := m.Len(); got != 5 {
		t.Errorf("after Sweep, Len=%d, want 5", got)
	}
}

func TestDelete(t *testing.T) {
	m := New[int](10, time.Hour)
	m.Set("a", 1)
	m.Delete("a")
	if _, ok := m.Get("a"); ok {
		t.Errorf("Delete left key alive")
	}
	if got := m.Len(); got != 0 {
		t.Errorf("Len=%d after Delete, want 0", got)
	}
	// Deleting absent key must be safe (no panic).
	m.Delete("nonexistent")
}

func TestConcurrentAccess(t *testing.T) {
	// Pound the map under -race to catch lock-ordering bugs.
	m := New[int](500, time.Second)
	const goroutines = 32
	const iterations = 2000

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iterations; i++ {
				key := fmt.Sprintf("ip-%d-%d", id, i%50)
				switch i % 5 {
				case 0:
					m.Set(key, i)
				case 1:
					_, _ = m.Get(key)
				case 2:
					m.SetIfAbsent(key, func() int { return i })
				case 3:
					m.Delete(key)
				case 4:
					_ = m.Len()
				}
			}
		}(g)
	}
	wg.Wait()

	// After all that churn, the cap must hold.
	if got := m.Len(); got > 500 {
		t.Errorf("Len=%d exceeded cap=500", got)
	}
}

// TestTypesafe_RateLimiter ensures the generic compiles cleanly for the
// concrete types we'll instantiate at the call sites.
func TestTypesafe_RateLimiter(t *testing.T) {
	m := New[*rate.Limiter](100, time.Hour)
	limiter := m.SetIfAbsent("1.2.3.4", func() *rate.Limiter {
		return rate.NewLimiter(rate.Limit(10), 10)
	})
	if limiter == nil {
		t.Fatalf("nil limiter")
	}
	if !limiter.Allow() {
		t.Errorf("expected first Allow to succeed")
	}
}

type credEntry struct {
	source, value string
	at            time.Time
}

func TestTypesafe_Slice(t *testing.T) {
	m := New[[]credEntry](100, time.Hour)
	m.Set("ip", []credEntry{{source: "ssh", value: "x", at: time.Now()}})
	got, ok := m.Get("ip")
	if !ok || len(got) != 1 {
		t.Fatalf("got %v ok=%v", got, ok)
	}
}

func TestTypesafe_Bool(t *testing.T) {
	m := New[bool](10, time.Hour)
	m.Set("k", true)
	got, ok := m.Get("k")
	if !ok || !got {
		t.Fatalf("got %v ok=%v", got, ok)
	}
}

// TestBoundedUnderBurst is the Track-5 motivating scenario: pound the
// map with many unique IPs, assert size stays bounded by the cap.
func TestBoundedUnderBurst(t *testing.T) {
	const cap_ = 1000
	m := New[int](cap_, time.Hour)
	for i := 0; i < 50_000; i++ {
		m.Set(fmt.Sprintf("ip-%d", i), i)
	}
	if got := m.Len(); got != cap_ {
		t.Errorf("Len=%d under burst, want exactly %d", got, cap_)
	}
}
