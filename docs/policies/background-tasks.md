# Background-task lifecycle policy

## Why

Long-lived sensor processes accumulate cleanup goroutines: HTTP session GC,
novelty cache trim, bridge state prune, OLLAMA per-IP session sweep, etc.
Every one of those that ships as `for { time.Sleep(5 * time.Minute); ... }`
or `for range ticker.C { ... }` carries the same defects:

- **No shutdown path.** `go test` invocations that import the package leak
  the goroutine across cases. Long-lived tests time out without a clean
  cancel signal.
- **No panic recovery.** A `nil` deref inside the cleaner crashes the
  goroutine silently. State accumulates from then on with nothing pruning
  it.
- **Duplicated boilerplate.** Each handler reinvents the ticker pattern
  with subtly different start-delay / panic / shutdown semantics.

## The pattern

Use [`lifecycle.Cleaner`](../../lifecycle/lifecycle.go):

```go
import "github.com/mariocandela/beelzebub/v3/lifecycle"

go lifecycle.Cleaner(ctx, 5*time.Minute, "bridge.clean", func() {
    bridge.Clean(60 * time.Minute)
})
```

Semantics:

- First invocation of `fn` is delayed by `interval`. Prime with a direct
  call before `Cleaner` if you need an immediate first run (see
  `honeypot.observer/exporter/main.go`'s heartbeat).
- On `ctx.Done()`, the cleaner returns. An in-flight `fn` is allowed to
  finish (no preemption).
- A panic inside `fn` is logged at ERROR and recovered. The next tick
  still fires.
- Non-positive interval logs a WARN and returns without starting a
  ticker (preventing a `time.NewTicker` panic).

Pass `context.Background()` only when the caller has no real lifecycle
context yet — the existing strategy-Init call sites do this and the
comment notes the seam to thread a real ctx through later.

## Migration checklist

When migrating an existing `for { time.Sleep / for range ticker.C }`
goroutine:

1. Pull the iteration body into a `func()`.
2. Replace the loop with `lifecycle.Cleaner(ctx, interval, name, fn)`.
3. Pick a stable `name` — it appears in cleaner-iteration panic logs.
4. If the loop did `time.Sleep(interval)` before the first iteration,
   semantics already match `Cleaner`. If the loop ran fn immediately
   first, prime `fn()` once before the `go Cleaner(...)` line.

## Where this is used

- `builder/builder.go` — `bridge.clean` (5 min, 60 min TTL).
- `protocols/strategies/HTTP/http.go` — `http.session.cleanup`,
  `http.novelty.cleanup` (5 min each).
- `protocols/strategies/OLLAMA/ollama.go` — `ollama.session.cleanup`
  (5 min, 1 h max age).

## See also

- `lifecycle/lifecycle.go` — the helper itself.
- `lifecycle/lifecycle_test.go` — semantic tests covering interval cadence,
  context-cancel exit, panic recovery, non-positive interval refusal.
- The honeypot.observer exporter ships a stdlib-only mirror at
  `exporter/lifecycle/lifecycle.go` (different module; behavior matched).
- The Python aggregator has a parallel helper:
  `~/projects/honeypot-research/api/lifecycle.py`
  (`background_task` + `periodic_task`). Same intent, asyncio shape.
