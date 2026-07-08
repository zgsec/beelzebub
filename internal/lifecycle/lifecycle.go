// Package lifecycle provides cancellation-aware periodic loops for
// long-lived sensor-side cleanup work — history-store eviction, novelty
// cache trim, bridge state prune, HTTP session GC, and similar tickers
// that previously each rolled their own `for { time.Sleep(...) }`
// goroutine without a shutdown path.
//
// The goal is fewer leaked goroutines across `go test` invocations,
// fewer panic vectors that take down a long-running sensor, and one
// consistent place for cleaner-iteration logging.
//
// Typical usage from Builder.Run:
//
//	ctx, cancel := context.WithCancel(context.Background())
//	defer cancel()
//	go lifecycle.Cleaner(ctx, 5*time.Minute, "bridge.clean", func() {
//	    bridge.Clean(60 * time.Minute)
//	})
//
// Tests pass a context they cancel to deterministically shut the cleaner
// down between cases — replacing the singleton-style ticker pattern that
// leaked goroutines across `go test` invocations.
package lifecycle

import (
	"context"
	"time"

	log "github.com/sirupsen/logrus"
)

// Cleaner runs fn every interval until ctx is cancelled. Per-iteration
// panics in fn are logged and recovered — the cleaner keeps running.
//
// Semantics:
//   - The first invocation of fn is delayed by `interval`. (If you need an
//     immediate prime, call fn() once before invoking Cleaner.)
//   - On ctx.Done(), the cleaner returns; an in-flight fn is allowed to
//     finish (no preemption).
//   - A panic inside fn is logged at ERROR level and recovered. The next
//     tick still fires.
//
// Designed to be the single primitive every per-protocol cleanup
// goroutine in this codebase uses; do not duplicate the pattern inline.
func Cleaner(ctx context.Context, interval time.Duration, name string, fn func()) {
	if interval <= 0 {
		log.WithFields(log.Fields{"cleaner": name, "interval": interval}).
			Warn("cleaner interval non-positive; not starting")
		return
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	log.WithFields(log.Fields{"cleaner": name, "interval": interval}).Debug("cleaner started")
	defer log.WithField("cleaner", name).Debug("cleaner stopped")

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			runOnce(name, fn)
		}
	}
}

// runOnce invokes fn with panic recovery. Panics are logged and swallowed
// so a single bad iteration does not take down a long-lived cleaner.
func runOnce(name string, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			log.WithFields(log.Fields{"cleaner": name, "panic": r}).
				Error("cleaner iteration panicked")
		}
	}()
	fn()
}
