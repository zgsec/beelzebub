package TCP

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTCPStrategyAcceptCapsConnections opens maxConcurrentConns + extra
// connections in parallel and asserts that the in-flight goroutines never
// exceed the cap. Connections beyond the cap are closed immediately by the
// drop branch in acceptLoop.
//
// We don't sleep/coordinate inside the handler — each handler blocks on a
// channel that is only released at the end of the test, so once a connection
// is accepted *and* the handler is launched, it counts toward concurrency.
func TestTCPStrategyAcceptCapsConnections(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()

	var (
		inFlight int32
		peak     int32
	)

	release := make(chan struct{})
	defer close(release)

	done := make(chan struct{})
	go func() {
		acceptLoop(listener, func(c net.Conn) {
			defer c.Close()
			n := atomic.AddInt32(&inFlight, 1)
			for {
				p := atomic.LoadInt32(&peak)
				if n <= p || atomic.CompareAndSwapInt32(&peak, p, n) {
					break
				}
			}
			<-release
			atomic.AddInt32(&inFlight, -1)
		})
		close(done)
	}()

	// Open maxConcurrentConns + 50 connections concurrently. The dialer
	// won't block on the cap (Accept still completes; the drop happens
	// inside acceptLoop), so we just open them as fast as we can and let
	// the loop sort them.
	target := maxConcurrentConns + 50
	dialed := make([]net.Conn, 0, target)
	var dialMu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < target; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := net.DialTimeout("tcp", listener.Addr().String(), 2*time.Second)
			if err != nil {
				return
			}
			dialMu.Lock()
			dialed = append(dialed, c)
			dialMu.Unlock()
		}()
	}
	wg.Wait()

	// Give acceptLoop a moment to drain its accept queue. We need handlers
	// to actually start (or be dropped) before we sample the peak.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&peak) >= maxConcurrentConns {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// peak must NOT exceed maxConcurrentConns. (It may be slightly less if
	// the OS hasn't accepted everything yet, but it must never exceed.)
	gotPeak := atomic.LoadInt32(&peak)
	if gotPeak > int32(maxConcurrentConns) {
		t.Errorf("in-flight handlers peaked at %d, expected <= %d (cap)", gotPeak, maxConcurrentConns)
	}
	if gotPeak == 0 {
		t.Error("in-flight handlers never observed > 0; loop may not be running")
	}

	dialMu.Lock()
	for _, c := range dialed {
		_ = c.Close()
	}
	dialMu.Unlock()
}

// TestTCPStrategyExitsOnListenerClose closes the listener and asserts the
// acceptLoop returns cleanly (rather than CPU-spinning on the resulting
// net.ErrClosed or swallowing it with a tight `continue`).
func TestTCPStrategyExitsOnListenerClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		acceptLoop(listener, func(c net.Conn) { _ = c.Close() })
		close(done)
	}()

	// Give the goroutine a tick to enter Accept, then close.
	time.Sleep(20 * time.Millisecond)
	if err := listener.Close(); err != nil {
		t.Fatalf("listener.Close: %v", err)
	}

	select {
	case <-done:
		// success
	case <-time.After(2 * time.Second):
		t.Fatal("acceptLoop did not exit within 2s of listener.Close()")
	}
}
