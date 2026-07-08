package lifecycle

import (
	"context"
	"sync/atomic"
	"testing"
	"time"
)

func TestCleaner_RunsOnInterval(t *testing.T) {
	t.Parallel()
	var n int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		Cleaner(ctx, 5*time.Millisecond, "test.runs", func() {
			atomic.AddInt64(&n, 1)
		})
		close(done)
	}()

	// Wait for at least 3 ticks so we can be sure the loop is iterating,
	// not running once.
	deadline := time.After(500 * time.Millisecond)
	for atomic.LoadInt64(&n) < 3 {
		select {
		case <-deadline:
			t.Fatalf("cleaner only fired %d times in 500ms; expected ≥3", atomic.LoadInt64(&n))
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleaner did not return within 200ms after cancel")
	}
}

func TestCleaner_StopsOnContextCancel(t *testing.T) {
	t.Parallel()
	var n int64
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		Cleaner(ctx, 2*time.Millisecond, "test.stops", func() {
			atomic.AddInt64(&n, 1)
		})
		close(done)
	}()

	// Let it run a few iterations.
	time.Sleep(15 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleaner did not return within 200ms after cancel")
	}

	// Snapshot count, sleep, confirm no further increments.
	before := atomic.LoadInt64(&n)
	time.Sleep(20 * time.Millisecond)
	after := atomic.LoadInt64(&n)
	if before != after {
		t.Fatalf("cleaner kept running after cancel: %d → %d", before, after)
	}
}

func TestCleaner_RecoversPanic(t *testing.T) {
	t.Parallel()
	var n int64
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		Cleaner(ctx, 2*time.Millisecond, "test.panic", func() {
			c := atomic.AddInt64(&n, 1)
			if c == 1 {
				panic("first iteration boom")
			}
		})
		close(done)
	}()

	// Wait for at least 3 iterations — panic on first must not stop the loop.
	deadline := time.After(500 * time.Millisecond)
	for atomic.LoadInt64(&n) < 3 {
		select {
		case <-deadline:
			t.Fatalf("cleaner stopped after panic: only %d iterations", atomic.LoadInt64(&n))
		case <-time.After(2 * time.Millisecond):
		}
	}

	cancel()

	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("cleaner did not return within 200ms after cancel")
	}
}

func TestCleaner_NonPositiveIntervalReturns(t *testing.T) {
	t.Parallel()
	// A non-positive interval must not start a ticker (time.NewTicker would
	// panic). We expect Cleaner to log + return.
	done := make(chan struct{})
	go func() {
		Cleaner(context.Background(), 0, "test.nointerval", func() {
			t.Errorf("fn must not run when interval is non-positive")
		})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Cleaner did not return promptly for non-positive interval")
	}
}
