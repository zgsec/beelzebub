package TELNET

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestTelnetStrategyAcceptCapsConnections opens maxConcurrentConns + extra
// connections in parallel and asserts that in-flight goroutines never exceed
// the cap. Mirrors TCP/tcp_acceptloop_test.go.
func TestTelnetStrategyAcceptCapsConnections(t *testing.T) {
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

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&peak) >= maxConcurrentConns {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

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

// TestTelnetStrategyExitsOnListenerClose closes the listener and asserts
// acceptLoop returns cleanly.
func TestTelnetStrategyExitsOnListenerClose(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	done := make(chan struct{})
	go func() {
		acceptLoop(listener, func(c net.Conn) { _ = c.Close() })
		close(done)
	}()

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
